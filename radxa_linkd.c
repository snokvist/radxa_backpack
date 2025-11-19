#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include <poll.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define TTY_PATH       "/dev/ttyACM0"
#define HTTP_PORT      55667
#define CRSF_UDP_PORT  14450

#define LINK_MAGIC       0xA5
#define LINK_TYPE_HTTP   0x01
#define LINK_TYPE_CRSF   0x02
#define LINK_TYPE_LOG    0x03

#define LINK_FLAG_START  0x01
#define LINK_FLAG_END    0x02
#define LINK_FLAG_ERROR  0x04
#define LINK_FLAG_ACK    0x08

#define LINK_MAX_PAYLOAD      1400
#define HTTP_BUF_MAX          16384
#define HTTP_ACK_TIMEOUT_MS   200
#define HTTP_MAX_RETRIES      8
#define HTTP_ACK_STATUS_NONE  0
#define HTTP_ACK_STATUS_OK    1
#define HTTP_ACK_STATUS_NAK   2
#define HTTP_SEND_THROTTLE_US 24000

#pragma pack(push, 1)
struct link_hdr {
    uint8_t  magic;   // 0xA5
    uint8_t  type;    // LINK_TYPE_*
    uint8_t  flags;   // LINK_FLAG_*
    uint16_t len_be;  // payload length (big endian)
    uint16_t seq_be;  // sequence (big endian)
    uint8_t  csum;    // simple checksum
};
#pragma pack(pop)

struct rx_ctx {
    enum { RX_SYNC, RX_HEADER, RX_PAYLOAD } state;
    struct link_hdr hdr;
    uint8_t  payload[LINK_MAX_PAYLOAD];
    uint16_t payload_needed;
    size_t   have;
};

struct http_acc {
    int      active;
    uint8_t  buf[HTTP_BUF_MAX];
    size_t   len;
};

struct http_tx_state {
    int      in_flight;
    uint16_t seq;
    uint8_t  flags;
    uint16_t len;
    uint8_t  buf[LINK_MAX_PAYLOAD];
    unsigned retries;
    int      ack_status;
};

struct app_ctx {
    int serial_fd;
    int udp_fd;
    uint16_t tx_seq;
    struct rx_ctx   rx;
    struct http_acc     http;
    struct http_tx_state http_tx;
    int                 http_serving;
};

static void rx_feed_bytes(struct app_ctx *ctx,
                          const uint8_t *data,
                          size_t len);

/* --- Serial setup ------------------------------------------------------ */

static int set_tty_raw(const char *path)
{
    int fd = open(path, O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (fd < 0) {
        perror("open TTY");
        return -1;
    }

    struct termios tio;
    if (tcgetattr(fd, &tio) == 0) {
        cfmakeraw(&tio);
        cfsetspeed(&tio, B115200); // speed mostly ignored for CDC ACM
        if (tcsetattr(fd, TCSANOW, &tio) < 0) {
            perror("tcsetattr");
        }
    }

    return fd;
}

/* --- UDP socket (CRSF → UDP) ------------------------------------------- */

static int udp_create_socket(void)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket UDP");
        return -1;
    }
    // No bind: we only send to localhost:14450 from an ephemeral port
    return fd;
}

/* --- Framing helpers --------------------------------------------------- */

static uint8_t link_compute_csum(const struct link_hdr *hdr,
                                 const uint8_t *payload)
{
    uint8_t csum = 0;
    const uint8_t *p = &hdr->type; // start at TYPE

    // type, flags, len_hi, len_lo, seq_hi, seq_lo
    for (size_t i = 0; i < 1 + 1 + 2 + 2; i++) {
        csum += p[i];
    }

    uint16_t len = ntohs(hdr->len_be);
    for (uint16_t i = 0; i < len; i++) {
        csum += payload[i];
    }
    return csum;
}

static int write_all_blocking(int fd, const uint8_t *buf, size_t len)
{
    while (len > 0) {
        ssize_t n = write(fd, buf, len);
        if (n > 0) {
            buf += (size_t)n;
            len -= (size_t)n;
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            struct pollfd pfd = {
                .fd     = fd,
                .events = POLLOUT,
            };
            (void)poll(&pfd, 1, 100);
            continue;
        }
        perror("write serial");
        return -1;
    }
    return 0;
}


static int link_send_frame_with_seq(struct app_ctx *ctx,
                                    uint16_t seq,
                                    uint8_t type,
                                    uint8_t flags,
                                    const void *payload,
                                    uint16_t len)
{
    if (len > LINK_MAX_PAYLOAD) {
        fprintf(stderr, "link_send_frame: len %u too large\n", len);
        return -1;
    }

    struct link_hdr hdr;
    hdr.magic  = LINK_MAGIC;
    hdr.type   = type;
    hdr.flags  = flags;
    hdr.len_be = htons(len);
    hdr.seq_be = htons(seq);
    hdr.csum   = 0;

    hdr.csum = link_compute_csum(&hdr, (const uint8_t *)payload);

    uint8_t buf[sizeof(hdr) + LINK_MAX_PAYLOAD];
    memcpy(buf, &hdr, sizeof(hdr));
    if (len > 0 && payload) {
        memcpy(buf + sizeof(hdr), payload, len);
    }

    size_t frame_len = sizeof(hdr) + len;
    return write_all_blocking(ctx->serial_fd, buf, frame_len);
}

/* --- HTTP TX retransmission helpers ----------------------------------- */

static int http_tx_wait_for_ack(struct app_ctx *ctx)
{
    struct http_tx_state *tx = &ctx->http_tx;

    for (;;) {
        if (tx->ack_status == HTTP_ACK_STATUS_OK) {
            tx->ack_status = HTTP_ACK_STATUS_NONE;
            return 0;
        }
        if (tx->ack_status == HTTP_ACK_STATUS_NAK) {
            tx->ack_status = HTTP_ACK_STATUS_NONE;
            return 1;
        }

        struct pollfd pfd = {
            .fd     = ctx->serial_fd,
            .events = POLLIN,
        };
        int ret = poll(&pfd, 1, HTTP_ACK_TIMEOUT_MS);
        if (ret == 0) {
            return 2; // timeout
        }
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            perror("poll wait ACK");
            return -1;
        }
        if (pfd.revents & POLLIN) {
            uint8_t buf[512];
            ssize_t n = read(ctx->serial_fd, buf, sizeof(buf));
            if (n > 0) {
                rx_feed_bytes(ctx, buf, (size_t)n);
            } else if (n == 0) {
                fprintf(stderr, "serial EOF while waiting for ACK\n");
                return -1;
            } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
                perror("read serial while waiting for ACK");
                return -1;
            }
        }
        if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
            fprintf(stderr, "serial poll error while waiting for ACK (revents=0x%x)\n",
                    pfd.revents);
            return -1;
        }
    }
}

static void http_tx_handle_ack(struct app_ctx *ctx,
                               const struct link_hdr *hdr)
{
    struct http_tx_state *tx = &ctx->http_tx;
    uint16_t seq = ntohs(hdr->seq_be);

    if (!tx->in_flight) {
        fprintf(stderr, "HTTP proxy: unexpected ACK seq %u (no pending frame)\n", seq);
        return;
    }

    if (seq != tx->seq) {
        fprintf(stderr, "HTTP proxy: ignoring ACK seq %u (want %u)\n", seq, tx->seq);
        return;
    }

    if (hdr->flags & LINK_FLAG_ERROR) {
        tx->ack_status = HTTP_ACK_STATUS_NAK;
    } else {
        tx->ack_status = HTTP_ACK_STATUS_OK;
    }
}

static int http_tx_send_chunk(struct app_ctx *ctx,
                              const uint8_t *payload,
                              uint16_t len,
                              uint8_t flags)
{
    struct http_tx_state *tx = &ctx->http_tx;

    if (len > 0 && payload) {
        memcpy(tx->buf, payload, len);
    }
    tx->len        = len;
    tx->flags      = flags;
    tx->seq        = ctx->tx_seq++;
    tx->retries    = 0;
    tx->ack_status = HTTP_ACK_STATUS_NONE;
    tx->in_flight  = 1;

    while (tx->retries < HTTP_MAX_RETRIES) {
        const void *pl = tx->len ? tx->buf : NULL;
        if (link_send_frame_with_seq(ctx, tx->seq, LINK_TYPE_HTTP, tx->flags,
                                     pl, tx->len) < 0) {
            tx->in_flight = 0;
            return -1;
        }

        int wait_ret = http_tx_wait_for_ack(ctx);
        if (wait_ret == 0) {
            if (HTTP_SEND_THROTTLE_US > 0) {
                usleep(HTTP_SEND_THROTTLE_US);
            }
            tx->in_flight = 0;
            return 0;
        }
        if (wait_ret == -1) {
            tx->in_flight = 0;
            return -1;
        }

        const char *reason = (wait_ret == 1) ? "remote NAK" : "ACK timeout";
        tx->retries++;
        fprintf(stderr,
                "HTTP proxy: resend seq %u (%s, attempt %u/%u)\n",
                tx->seq,
                reason,
                tx->retries,
                HTTP_MAX_RETRIES);
        tx->ack_status = HTTP_ACK_STATUS_NONE;
    }

    fprintf(stderr, "HTTP proxy: aborting seq %u after %u attempts\n",
            tx->seq,
            HTTP_MAX_RETRIES);
    tx->in_flight = 0;
    return -1;
}

static void http_tx_signal_error(struct app_ctx *ctx)
{
    if (http_tx_send_chunk(ctx, NULL, 0, LINK_FLAG_END | LINK_FLAG_ERROR) < 0) {
        fprintf(stderr, "HTTP proxy: failed to deliver HTTP error marker\n");
    }
}

/* --- HTTP proxy: HTTP request → localhost:55667 ------------------------ */

static int handle_http_request(struct app_ctx *ctx,
                               const uint8_t *req,
                               size_t req_len)
{
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        perror("socket HTTP");
        http_tx_signal_error(ctx);
        return -1;
    }

    fprintf(stderr, "HTTP proxy: dispatch %zu bytes\n", req_len);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(HTTP_PORT);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // 127.0.0.1

    if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect HTTP");
        close(s);
        http_tx_signal_error(ctx);
        return -1;
    }

    // Send request
    size_t off = 0;
    while (off < req_len) {
        ssize_t n = write(s, req + off, req_len - off);
        if (n < 0) {
            perror("write HTTP");
            close(s);
            http_tx_signal_error(ctx);
            return -1;
        }
        off += (size_t)n;
    }
    shutdown(s, SHUT_WR);

    // Read response and stream back as HTTP frames to ESP
    uint8_t buf[LINK_MAX_PAYLOAD];
    int first = 1;
    for (;;) {
        ssize_t n = read(s, buf, sizeof(buf));
        if (n < 0) {
            perror("read HTTP");
            close(s);
            http_tx_signal_error(ctx);
            return -1;
        }
        if (n == 0) {
            break; // EOF
        }

        uint8_t flags = first ? LINK_FLAG_START : 0;
        if (first)
            first = 0;

        if (http_tx_send_chunk(ctx, buf, (uint16_t)n, flags) < 0) {
            fprintf(stderr, "failed to deliver HTTP chunk to ESP\n");
            http_tx_signal_error(ctx);
            close(s);
            return -1;
        }
        fprintf(stderr,
                "HTTP proxy: sent response chunk %zd bytes%s\n",
                n,
                flags & LINK_FLAG_START ? " (START)" : "");
    }

    // Send END marker (zero-length payload) to signal response complete
    if (http_tx_send_chunk(ctx, NULL, 0, LINK_FLAG_END) < 0) {
        fprintf(stderr, "failed to send HTTP END frame\n");
        close(s);
        return -1;
    }

    close(s);
    return 0;
}

/* --- Frame dispatch ---------------------------------------------------- */

static void handle_complete_frame(struct app_ctx *ctx,
                                  const struct link_hdr *hdr,
                                  const uint8_t *payload)
{
    uint16_t len = ntohs(hdr->len_be);

    // Verify checksum
    uint8_t want = link_compute_csum(hdr, payload);
    if (want != hdr->csum) {
        fprintf(stderr, "checksum mismatch: got 0x%02x want 0x%02x\n",
                hdr->csum, want);
        return;
    }

    switch (hdr->type) {
    case LINK_TYPE_CRSF: {
        fprintf(stderr, "HTTP proxy: forwarding CRSF packet (%u bytes)\n", len);
        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin_family      = AF_INET;
        dest.sin_port        = htons(CRSF_UDP_PORT);
        dest.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

        ssize_t n = sendto(ctx->udp_fd, payload, len, 0,
                           (struct sockaddr *)&dest, sizeof(dest));
        if (n < 0) {
            perror("sendto CRSF");
        }
        break;
    }

    case LINK_TYPE_HTTP: {
        struct http_acc *h = &ctx->http;

        if (hdr->flags & LINK_FLAG_ACK) {
            http_tx_handle_ack(ctx, hdr);
            return;
        }

        if (hdr->flags & LINK_FLAG_START) {
            h->active = 1;
            h->len    = 0;
        }

        if (!h->active) {
            fprintf(stderr, "HTTP fragment received but no active request; dropping\n");
            return;
        }

        if (len > 0) {
            if (h->len + len > HTTP_BUF_MAX) {
                fprintf(stderr, "HTTP request too large (%zu + %u), dropping\n",
                        h->len, len);
                h->active = 0;
                return;
            }
            memcpy(h->buf + h->len, payload, len);
            h->len += len;
        }

        if (hdr->flags & LINK_FLAG_END) {
            // We have a complete HTTP request
            fprintf(stderr, "HTTP request complete (%zu bytes)\n", h->len);
            if (ctx->http_serving) {
                fprintf(stderr, "HTTP proxy: busy, dropping new request\n");
            } else {
                ctx->http_serving = 1;
                (void)handle_http_request(ctx, h->buf, h->len);
                ctx->http_serving = 0;
            }
            h->active = 0;
        }
        break;
    }

    case LINK_TYPE_LOG: {
        char msg[LINK_MAX_PAYLOAD + 1];
        size_t copy = len < sizeof(msg) - 1 ? len : sizeof(msg) - 1;
        memcpy(msg, payload, copy);
        msg[copy] = '\0';
        fprintf(stderr, "[ESP] %s\n", msg);
        break;
    }

    default:
        fprintf(stderr, "Unknown frame type 0x%02x (len=%u)\n", hdr->type, len);
        break;
    }
}

/* --- RX state machine -------------------------------------------------- */

static void rx_ctx_init(struct rx_ctx *rx)
{
    memset(rx, 0, sizeof(*rx));
    rx->state = RX_SYNC;
}

static void rx_feed_bytes(struct app_ctx *ctx,
                          const uint8_t *data,
                          size_t len)
{
    struct rx_ctx *rx = &ctx->rx;

    for (size_t i = 0; i < len; i++) {
        uint8_t b = data[i];

        switch (rx->state) {
        case RX_SYNC:
            if (b == LINK_MAGIC) {
                rx->hdr.magic = b;
                rx->have      = 1;
                rx->state     = RX_HEADER;
            }
            break;

        case RX_HEADER:
            ((uint8_t *)&rx->hdr)[rx->have++] = b;
            if (rx->have == sizeof(struct link_hdr)) {
                // Full header received
                uint16_t plen = ntohs(rx->hdr.len_be);
                if (plen > LINK_MAX_PAYLOAD) {
                    fprintf(stderr, "Invalid payload length %u, resyncing\n", plen);
                    rx->state = RX_SYNC;
                    rx->have  = 0;
                    break;
                }
                rx->payload_needed = plen;
                rx->have           = 0;

                if (plen == 0) {
                    // No payload: process immediately
                    handle_complete_frame(ctx, &rx->hdr, rx->payload);
                    rx->state = RX_SYNC;
                } else {
                    rx->state = RX_PAYLOAD;
                }
            }
            break;

        case RX_PAYLOAD:
            rx->payload[rx->have++] = b;
            if (rx->have >= rx->payload_needed) {
                // Got full payload
                handle_complete_frame(ctx, &rx->hdr, rx->payload);
                rx->state = RX_SYNC;
                rx->have  = 0;
            }
            break;
        }
    }
}

/* --- Main loop --------------------------------------------------------- */

int main(void)
{
    struct app_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));

    ctx.serial_fd = set_tty_raw(TTY_PATH);
    if (ctx.serial_fd < 0) {
        return 1;
    }

    ctx.udp_fd = udp_create_socket();
    if (ctx.udp_fd < 0) {
        close(ctx.serial_fd);
        return 1;
    }

    ctx.tx_seq = 0;
    rx_ctx_init(&ctx.rx);
    ctx.http.active = 0;
    ctx.http.len    = 0;
    ctx.http_tx.in_flight  = 0;
    ctx.http_tx.ack_status = HTTP_ACK_STATUS_NONE;
    ctx.http_tx.retries    = 0;
    ctx.http_serving       = 0;

    fprintf(stderr, "radxa_linkd: starting. serial=%s, http=127.0.0.1:%d, crsf=udp/%d\n",
            TTY_PATH, HTTP_PORT, CRSF_UDP_PORT);

    struct pollfd fds[1];
    fds[0].fd     = ctx.serial_fd;
    fds[0].events = POLLIN;

    for (;;) {
        int ret = poll(fds, 1, -1);
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            perror("poll");
            break;
        }

        if (fds[0].revents & POLLIN) {
            uint8_t buf[512];
            ssize_t n = read(ctx.serial_fd, buf, sizeof(buf));
            if (n > 0) {
                rx_feed_bytes(&ctx, buf, (size_t)n);
            } else if (n == 0) {
                fprintf(stderr, "serial EOF\n");
                break;
            } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
                perror("read serial");
                break;
            }
        }
    }

    close(ctx.serial_fd);
    close(ctx.udp_fd);
    return 0;
}
