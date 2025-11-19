#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <stdarg.h>

#include "driver/usb_serial_jtag.h"
#include "esp_event.h"
#include "esp_http_server.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "lwip/ip4_addr.h"
#include "nvs_flash.h"

#define LINK_MAGIC       0xA5
#define LINK_TYPE_HTTP   0x01
#define LINK_TYPE_CRSF   0x02
#define LINK_TYPE_LOG    0x03

#define LINK_FLAG_START  0x01
#define LINK_FLAG_END    0x02
#define LINK_FLAG_ERROR  0x04
#define LINK_FLAG_ACK    0x08

#define LINK_MAX_PAYLOAD 1500

#define WIFI_AP_SSID     "openipc-backpack"
#define WIFI_AP_PASSWORD "12345678"

#define LOG_TAG "backpack_stub"

#define LOG_INFO(fmt, ...)  do { (void)(fmt); } while (0)
#define LOG_WARN(fmt, ...)  do { (void)(fmt); } while (0)
#define LOG_ERROR(fmt, ...) do { (void)(fmt); } while (0)

struct __attribute__((packed)) link_hdr {
    uint8_t  magic;
    uint8_t  type;
    uint8_t  flags;
    uint16_t len_be;
    uint16_t seq_be;
    uint8_t  csum;
};

struct rx_ctx {
    enum {
        RX_SYNC = 0,
        RX_HEADER,
        RX_PAYLOAD
    } state;

    struct link_hdr hdr;
    uint8_t  payload[LINK_MAX_PAYLOAD];
    uint16_t payload_needed;
    uint16_t have;
};

static uint16_t                  s_tx_seq;
static struct rx_ctx             s_rx;
static httpd_handle_t            s_httpd;
static SemaphoreHandle_t         s_http_lock;
static volatile QueueHandle_t    s_http_resp_queue;
static portMUX_TYPE              s_http_queue_lock = portMUX_INITIALIZER_UNLOCKED;
static bool                      s_usb_ready;
static bool                      s_http_last_seq_valid;
static uint16_t                  s_http_last_seq;
static bool                      s_http_response_started;

struct http_resp_fragment {
    uint16_t len;
    uint8_t  flags;
    uint8_t  data[LINK_MAX_PAYLOAD];
};

static uint16_t to_be16(uint16_t v)
{
    return (uint16_t)((v << 8) | (v >> 8));
}

static esp_err_t stream_http_response(httpd_req_t *req, QueueHandle_t queue);

static uint8_t compute_csum(const struct link_hdr *hdr,
                            const uint8_t *payload)
{
    uint8_t csum = 0;
    csum += hdr->type;
    csum += hdr->flags;
    csum += ((uint8_t *)&hdr->len_be)[0];
    csum += ((uint8_t *)&hdr->len_be)[1];
    csum += ((uint8_t *)&hdr->seq_be)[0];
    csum += ((uint8_t *)&hdr->seq_be)[1];

    uint16_t len = (uint16_t)((hdr->len_be >> 8) | (hdr->len_be << 8));
    for (uint16_t i = 0; i < len; i++) {
        csum += payload[i];
    }
    return csum;
}

static void usb_write_all(const uint8_t *buf, size_t len)
{
    while (len > 0) {
        int written = usb_serial_jtag_write_bytes(buf, len, pdMS_TO_TICKS(100));
        if (written <= 0) {
            vTaskDelay(pdMS_TO_TICKS(10));
            continue;
        }
        buf += (size_t)written;
        len -= (size_t)written;
    }
    (void)usb_serial_jtag_wait_tx_done(pdMS_TO_TICKS(100));
}

static int send_frame_with_seq(uint16_t seq,
                               uint8_t type,
                               uint8_t flags,
                               const uint8_t *payload,
                               uint16_t len)
{
    if (len > LINK_MAX_PAYLOAD) {
        return -1;
    }

    struct link_hdr hdr = {
        .magic  = LINK_MAGIC,
        .type   = type,
        .flags  = flags,
        .len_be = to_be16(len),
        .seq_be = to_be16(seq),
        .csum   = 0,
    };

    uint8_t frame[sizeof(hdr) + LINK_MAX_PAYLOAD];
    if (len && payload) {
        memcpy(frame + sizeof(hdr), payload, len);
    }

    hdr.csum = compute_csum(&hdr, frame + sizeof(hdr));
    memcpy(frame, &hdr, sizeof(hdr));
    usb_write_all(frame, sizeof(hdr) + len);
    return 0;
}

static int send_frame(uint8_t type,
                      uint8_t flags,
                      const uint8_t *payload,
                      uint16_t len)
{
    return send_frame_with_seq(s_tx_seq++, type, flags, payload, len);
}

static void send_http_ack(uint16_t seq, bool error)
{
    uint8_t flags = LINK_FLAG_ACK;
    if (error) {
        flags |= LINK_FLAG_ERROR;
    }
    if (send_frame_with_seq(seq, LINK_TYPE_HTTP, flags, NULL, 0) != 0) {
        LOG_WARN("failed to send HTTP ACK for seq %u", seq);
    }
}

static void send_http_request(const uint8_t *payload, size_t len)
{
    bool first = true;
    LOG_INFO("TX HTTP upstream (%u bytes)", (unsigned)len);

    if (len == 0) {
        send_frame(LINK_TYPE_HTTP, LINK_FLAG_START | LINK_FLAG_END, NULL, 0);
        return;
    }

    size_t offset = 0;
    while (offset < len) {
        size_t chunk = len - offset;
        if (chunk > LINK_MAX_PAYLOAD) {
            chunk = LINK_MAX_PAYLOAD;
        }
        uint8_t flags = 0;
        if (first) {
            flags |= LINK_FLAG_START;
        }
        if (offset + chunk >= len) {
            flags |= LINK_FLAG_END;
        }
        send_frame(LINK_TYPE_HTTP, flags, payload + offset, (uint16_t)chunk);
        offset += chunk;
        first = false;
    }
}

static void send_dummy_crsf_packet(void)
{
    uint8_t payload[16];
    for (size_t i = 0; i < sizeof(payload); i++) {
        payload[i] = (uint8_t)(0x10 + i);
    }
    (void)send_frame(LINK_TYPE_CRSF,
                     LINK_FLAG_START | LINK_FLAG_END,
                     payload,
                     (uint16_t)sizeof(payload));
}

static const char *http_method_to_str(httpd_method_t method)
{
    switch (method) {
    case HTTP_GET: return "GET";
    case HTTP_POST: return "POST";
    case HTTP_PUT: return "PUT";
    case HTTP_DELETE: return "DELETE";
    case HTTP_PATCH: return "PATCH";
    default: return "GET";
    }
}

static char *strndup_safe(const char *src, size_t len)
{
    char *out = malloc(len + 1);
    if (!out) {
        return NULL;
    }
    memcpy(out, src, len);
    out[len] = '\0';
    return out;
}

static void trim_ascii_whitespace(char *str)
{
    if (!str) {
        return;
    }
    size_t len = strlen(str);
    while (len > 0 && isspace((unsigned char)str[len - 1])) {
        str[--len] = '\0';
    }
    size_t start = 0;
    while (str[start] && isspace((unsigned char)str[start])) {
        start++;
    }
    if (start > 0) {
        memmove(str, str + start, strlen(str + start) + 1);
    }
}

static bool append_fmt(uint8_t *buf,
                       size_t *offset,
                       size_t capacity,
                       const char *fmt,
                       ...)
{
    va_list ap;
    va_start(ap, fmt);
    int written = vsnprintf((char *)buf + *offset, capacity - *offset, fmt, ap);
    va_end(ap);
    if (written < 0 || (size_t)written >= capacity - *offset) {
        return false;
    }
    *offset += (size_t)written;
    return true;
}

static ssize_t find_crlf(const uint8_t *buf, size_t len, size_t start)
{
    for (size_t i = start; i + 1 < len; i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n') {
            return (ssize_t)i;
        }
    }
    return -1;
}

static ssize_t find_header_terminator(const uint8_t *buf, size_t len)
{
    for (size_t i = 0; i + 3 < len; i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n' &&
            buf[i + 2] == '\r' && buf[i + 3] == '\n') {
            return (ssize_t)i;
        }
    }
    return -1;
}

static esp_err_t push_temp_ptr(char ***arr,
                               size_t *count,
                               size_t *capacity,
                               char *ptr)
{
    if (!ptr) {
        return ESP_ERR_INVALID_ARG;
    }
    if (*count == *capacity) {
        size_t new_cap = (*capacity == 0) ? 4 : (*capacity * 2);
        char **tmp     = realloc(*arr, new_cap * sizeof(char *));
        if (!tmp) {
            return ESP_ERR_NO_MEM;
        }
        *arr       = tmp;
        *capacity  = new_cap;
    }
    (*arr)[(*count)++] = ptr;
    return ESP_OK;
}

static esp_err_t append_fragment(uint8_t **buf,
                                 size_t *len,
                                 size_t *cap,
                                 const uint8_t *data,
                                 size_t data_len)
{
    size_t needed = *len + data_len;
    if (needed > *cap) {
        size_t new_cap = (*cap == 0) ? 1024 : (*cap * 2);
        while (new_cap < needed) {
            new_cap *= 2;
        }
        uint8_t *tmp = realloc(*buf, new_cap);
        if (!tmp) {
            return ESP_ERR_NO_MEM;
        }
        *buf = tmp;
        *cap = new_cap;
    }
    memcpy(*buf + *len, data, data_len);
    *len += data_len;
    return ESP_OK;
}

static esp_err_t parse_and_apply_headers(httpd_req_t *req,
                                         const uint8_t *buf,
                                         size_t len,
                                         char ***held_ptrs,
                                         size_t *held_count,
                                         size_t *held_cap,
                                         size_t *body_offset)
{
    ssize_t header_end = find_header_terminator(buf, len);
    if (header_end < 0) {
        return ESP_FAIL;
    }
    ssize_t status_end = find_crlf(buf, (size_t)header_end, 0);
    if (status_end < 0) {
        return ESP_FAIL;
    }

    size_t status_len = (size_t)status_end;
    char  *status_line = strndup_safe((const char *)buf, status_len);
    if (!status_line) {
        return ESP_ERR_NO_MEM;
    }
    trim_ascii_whitespace(status_line);
    LOG_INFO("Upstream status line: %s", status_line);
    const char *space = strchr(status_line, ' ');
    if (!space || *(space + 1) == '\0') {
        free(status_line);
        return ESP_FAIL;
    }
    httpd_resp_set_status(req, space + 1);
    if (push_temp_ptr(held_ptrs, held_count, held_cap, status_line) != ESP_OK) {
        free(status_line);
        return ESP_ERR_NO_MEM;
    }

    size_t offset = (size_t)status_end + 2;
    while (offset < (size_t)header_end) {
        ssize_t line_end = find_crlf(buf, (size_t)header_end, offset);
        if (line_end < 0) {
            break;
        }
        if (line_end == (ssize_t)offset) {
            offset += 2;
            break;
        }
        size_t line_len = (size_t)line_end - offset;
        const uint8_t *line = buf + offset;
        const uint8_t *colon = memchr(line, ':', line_len);
        if (colon) {
            size_t key_len   = (size_t)(colon - line);
            size_t value_len = line_len - key_len - 1;
            char *key   = strndup_safe((const char *)line, key_len);
            char *value = strndup_safe((const char *)(colon + 1), value_len);
            if (key && value) {
                trim_ascii_whitespace(key);
                trim_ascii_whitespace(value);
                if (strcasecmp(key, "Content-Type") == 0) {
                    httpd_resp_set_type(req, value);
                    if (push_temp_ptr(held_ptrs, held_count, held_cap, value) == ESP_OK) {
                        value = NULL;
                    }
                } else if (strcasecmp(key, "Content-Length") == 0 ||
                           strcasecmp(key, "Transfer-Encoding") == 0 ||
                           strcasecmp(key, "Connection") == 0) {
                    // handled internally
                } else {
                    httpd_resp_set_hdr(req, key, value);
                    if (push_temp_ptr(held_ptrs, held_count, held_cap, value) == ESP_OK) {
                        value = NULL;
                    }
                }
                if (push_temp_ptr(held_ptrs, held_count, held_cap, key) != ESP_OK) {
                    free(key);
                    if (value) {
                        free(value);
                    }
                    return ESP_ERR_NO_MEM;
                }
                key = NULL;
            }
            if (key) {
                free(key);
            }
            if (value) {
                free(value);
            }
        }
        offset = (size_t)line_end + 2;
    }

    *body_offset = (size_t)header_end + 4;
    return ESP_OK;
}

static esp_err_t forward_http_over_link(httpd_req_t *req)
{
    esp_err_t   err          = ESP_FAIL;
    uint8_t    *body         = NULL;
    char       *content_type = NULL;
    char       *full_path    = NULL;
    uint8_t    *request_buf  = NULL;
    QueueHandle_t queue      = NULL;

    size_t body_len = req->content_len;
    if (body_len > 0) {
        body = malloc(body_len);
        if (!body) {
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "OOM");
            return ESP_FAIL;
        }
        size_t received = 0;
        while (received < body_len) {
            int ret = httpd_req_recv(req,
                                     (char *)body + received,
                                     body_len - received);
            if (ret < 0) {
                if (ret == HTTPD_SOCK_ERR_TIMEOUT) {
                    continue;
                }
                httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Body read failed");
                goto cleanup;
            }
            received += (size_t)ret;
        }
    }

    size_t query_len = httpd_req_get_url_query_len(req);
    if (query_len > 0) {
        char *query = malloc(query_len + 1);
        if (!query) {
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "OOM");
            goto cleanup;
        }
        if (httpd_req_get_url_query_str(req, query, query_len + 1) != ESP_OK) {
            free(query);
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Query read failed");
            goto cleanup;
        }
        size_t full_len = strlen(req->uri) + 1 + strlen(query) + 1;
        full_path = malloc(full_len);
        if (!full_path) {
            free(query);
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "OOM");
            goto cleanup;
        }
        snprintf(full_path, full_len, "%s?%s", req->uri, query);
        free(query);
    } else {
        full_path = strdup(req->uri);
    }
    if (!full_path) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "OOM");
        goto cleanup;
    }

    size_t ct_len = httpd_req_get_hdr_value_len(req, "Content-Type");
    if (ct_len > 0) {
        content_type = malloc(ct_len + 1);
        if (!content_type) {
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "OOM");
            goto cleanup;
        }
        if (httpd_req_get_hdr_value_str(req,
                                        "Content-Type",
                                        content_type,
                                        ct_len + 1) != ESP_OK) {
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Header read failed");
            goto cleanup;
        }
    }

    size_t capacity = strlen(http_method_to_str(req->method)) +
                      strlen(full_path) + body_len + 256 +
                      (content_type ? strlen(content_type) : 0);
    request_buf = malloc(capacity);
    if (!request_buf) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "OOM");
        goto cleanup;
    }
    size_t offset = 0;
    if (!append_fmt(request_buf, &offset, capacity, "%s %s HTTP/1.1\r\n",
                    http_method_to_str(req->method),
                    full_path) ||
        !append_fmt(request_buf, &offset, capacity, "Host: 127.0.0.1\r\n") ||
        !append_fmt(request_buf, &offset, capacity, "Connection: close\r\n")) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Request build failed");
        goto cleanup;
    }
    if (content_type &&
        !append_fmt(request_buf, &offset, capacity, "Content-Type: %s\r\n", content_type)) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Request build failed");
        goto cleanup;
    }
    if (!append_fmt(request_buf,
                    &offset,
                    capacity,
                    "Content-Length: %u\r\n\r\n",
                    (unsigned)body_len)) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Request build failed");
        goto cleanup;
    }
    if (body_len > 0) {
        memcpy(request_buf + offset, body, body_len);
        offset += body_len;
    }

    queue = xQueueCreate(8, sizeof(struct http_resp_fragment));
    if (!queue) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "OOM");
        goto cleanup;
    }

    portENTER_CRITICAL(&s_http_queue_lock);
    bool busy = (s_http_resp_queue != NULL);
    if (!busy) {
        s_http_resp_queue = queue;
    }
    portEXIT_CRITICAL(&s_http_queue_lock);
    if (busy) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Bridge busy");
        goto cleanup;
    }

    LOG_INFO("Forwarding HTTP %s %s (%u body bytes)",
             http_method_to_str(req->method),
             full_path,
             (unsigned)body_len);
    send_http_request(request_buf, offset);

    esp_err_t wait = stream_http_response(req, queue);

    portENTER_CRITICAL(&s_http_queue_lock);
    if (s_http_resp_queue == queue) {
        s_http_resp_queue = NULL;
    }
    portEXIT_CRITICAL(&s_http_queue_lock);

    if (wait != ESP_OK) {
        goto cleanup;
    }

    err = ESP_OK;

cleanup:
    if (queue) {
        vQueueDelete(queue);
    }
    free(body);
    free(content_type);
    free(full_path);
    free(request_buf);
    return err;
}

static esp_err_t proxy_http_handler(httpd_req_t *req)
{
    if (!s_http_lock) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Bridge offline");
        return ESP_FAIL;
    }

    if (xSemaphoreTake(s_http_lock, pdMS_TO_TICKS(5000)) != pdTRUE) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Busy");
        return ESP_FAIL;
    }
    esp_err_t res = forward_http_over_link(req);
    xSemaphoreGive(s_http_lock);
    return res;
}

static void rx_ctx_reset(struct rx_ctx *rx)
{
    memset(rx, 0, sizeof(*rx));
    rx->state = RX_SYNC;
}

static void handle_complete_frame(const struct link_hdr *hdr,
                                  const uint8_t *payload)
{
    uint16_t len = (uint16_t)((hdr->len_be >> 8) | (hdr->len_be << 8));

    switch (hdr->type) {
    case LINK_TYPE_HTTP: {
        uint16_t seq = (uint16_t)((hdr->seq_be >> 8) | (hdr->seq_be << 8));
        if (hdr->flags & LINK_FLAG_ACK) {
            // Host currently doesn't ACK our requests; ignore if it does.
            break;
        }

        if ((hdr->flags & LINK_FLAG_START) && !s_http_response_started) {
            s_http_last_seq_valid = false;
        }

        bool handled  = false;
        bool new_data = false;

        if (s_http_last_seq_valid && seq == s_http_last_seq) {
            handled = true; // retransmit of a chunk we already processed
        } else {
            QueueHandle_t queue;
            portENTER_CRITICAL(&s_http_queue_lock);
            queue = s_http_resp_queue;
            portEXIT_CRITICAL(&s_http_queue_lock);
            if (!queue) {
                LOG_WARN("HTTP fragment with no waiter (flags=0x%02x len=%u)",
                         hdr->flags,
                         len);
            } else {
                struct http_resp_fragment frag = {
                    .len   = len,
                    .flags = hdr->flags,
                };
                if (len > 0) {
                    memcpy(frag.data, payload, len);
                }
                if (xQueueSend(queue, &frag, portMAX_DELAY) == pdPASS) {
                    handled               = true;
                    new_data              = true;
                    s_http_last_seq       = seq;
                    s_http_last_seq_valid = true;
                    if (hdr->flags & LINK_FLAG_END) {
                        portENTER_CRITICAL(&s_http_queue_lock);
                        if (s_http_resp_queue == queue) {
                            s_http_resp_queue = NULL;
                        }
                        portEXIT_CRITICAL(&s_http_queue_lock);
                    }
                } else {
                    LOG_WARN("HTTP response queue full, dropping fragment");
                }
            }
        }

        if (new_data && (hdr->flags & LINK_FLAG_START)) {
            s_http_response_started = true;
        }
        if (new_data && (hdr->flags & LINK_FLAG_END)) {
            s_http_response_started = false;
        }

        send_http_ack(seq, !handled);
        break;
    }

    case LINK_TYPE_CRSF:
        break;

    default:
        LOG_WARN("RX unknown type 0x%02x len=%u", hdr->type, len);
        break;
    }
}

static void rx_feed_bytes(struct rx_ctx *rx,
                          const uint8_t *data,
                          size_t len)
{
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
                uint16_t plen = (uint16_t)((rx->hdr.len_be >> 8) | (rx->hdr.len_be << 8));
                if (plen > LINK_MAX_PAYLOAD) {
                    LOG_WARN("invalid RX payload len %u", plen);
                    rx_ctx_reset(rx);
                    break;
                }
                rx->payload_needed = plen;
                rx->have           = 0;
                if (plen == 0) {
                    handle_complete_frame(&rx->hdr, rx->payload);
                    rx_ctx_reset(rx);
                } else {
                    rx->state = RX_PAYLOAD;
                }
            }
            break;

        case RX_PAYLOAD:
            rx->payload[rx->have++] = b;
            if (rx->have >= rx->payload_needed) {
                handle_complete_frame(&rx->hdr, rx->payload);
                rx_ctx_reset(rx);
            }
            break;
        }
    }
}

static void usb_rx_task(void *arg)
{
    (void)arg;
    uint8_t buf[256];

    while (true) {
        int got = usb_serial_jtag_read_bytes(buf, sizeof(buf), portMAX_DELAY);
        if (got > 0) {
            rx_feed_bytes(&s_rx, buf, (size_t)got);
        }
    }
}

static void start_http_server(void)
{
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.uri_match_fn   = httpd_uri_match_wildcard;
    if (httpd_start(&s_httpd, &config) != ESP_OK) {
        LOG_ERROR("failed to start HTTP server");
        s_httpd = NULL;
        return;
    }

    const httpd_uri_t proxy_get = {
        .uri      = "/*",
        .method   = HTTP_GET,
        .handler  = proxy_http_handler,
        .user_ctx = NULL,
    };
    const httpd_uri_t proxy_post = {
        .uri      = "/*",
        .method   = HTTP_POST,
        .handler  = proxy_http_handler,
        .user_ctx = NULL,
    };
    const httpd_uri_t proxy_put = {
        .uri      = "/*",
        .method   = HTTP_PUT,
        .handler  = proxy_http_handler,
        .user_ctx = NULL,
    };
    const httpd_uri_t proxy_delete = {
        .uri      = "/*",
        .method   = HTTP_DELETE,
        .handler  = proxy_http_handler,
        .user_ctx = NULL,
    };
    const httpd_uri_t proxy_head = {
        .uri      = "/*",
        .method   = HTTP_HEAD,
        .handler  = proxy_http_handler,
        .user_ctx = NULL,
    };
    const httpd_uri_t proxy_options = {
        .uri      = "/*",
        .method   = HTTP_OPTIONS,
        .handler  = proxy_http_handler,
        .user_ctx = NULL,
    };
    httpd_register_uri_handler(s_httpd, &proxy_get);
    httpd_register_uri_handler(s_httpd, &proxy_post);
    httpd_register_uri_handler(s_httpd, &proxy_put);
    httpd_register_uri_handler(s_httpd, &proxy_delete);
    httpd_register_uri_handler(s_httpd, &proxy_head);
    httpd_register_uri_handler(s_httpd, &proxy_options);
#ifdef HTTP_PATCH
    const httpd_uri_t proxy_patch = {
        .uri      = "/*",
        .method   = HTTP_PATCH,
        .handler  = proxy_http_handler,
        .user_ctx = NULL,
    };
    httpd_register_uri_handler(s_httpd, &proxy_patch);
#endif

    LOG_INFO("HTTP server ready on 10.0.0.1");
}

static void init_usb_serial(void)
{
    usb_serial_jtag_driver_config_t cfg = USB_SERIAL_JTAG_DRIVER_CONFIG_DEFAULT();
    cfg.rx_buffer_size = 512;
    cfg.tx_buffer_size = 512;
    ESP_ERROR_CHECK(usb_serial_jtag_driver_install(&cfg));
    xTaskCreate(usb_rx_task, "usb_rx", 4096, NULL, 5, NULL);
}

static void init_wifi_ap(void)
{
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_t *ap_netif = esp_netif_create_default_wifi_ap();

    esp_netif_ip_info_t ip_info = { 0 };
    IP4_ADDR(&ip_info.ip, 10, 0, 0, 1);
    IP4_ADDR(&ip_info.gw, 10, 0, 0, 1);
    IP4_ADDR(&ip_info.netmask, 255, 255, 255, 0);

    ESP_ERROR_CHECK(esp_netif_dhcps_stop(ap_netif));
    ESP_ERROR_CHECK(esp_netif_set_ip_info(ap_netif, &ip_info));
    ESP_ERROR_CHECK(esp_netif_dhcps_start(ap_netif));

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    wifi_config_t wifi_config = { 0 };
    strncpy((char *)wifi_config.ap.ssid, WIFI_AP_SSID, sizeof(wifi_config.ap.ssid));
    wifi_config.ap.ssid_len = strlen(WIFI_AP_SSID);
    strncpy((char *)wifi_config.ap.password, WIFI_AP_PASSWORD, sizeof(wifi_config.ap.password));
    wifi_config.ap.channel        = 1;
    wifi_config.ap.max_connection = 4;
    wifi_config.ap.pmf_cfg.required = false;

    size_t pass_len = strlen(WIFI_AP_PASSWORD);
    if (pass_len >= 8) {
        wifi_config.ap.authmode = WIFI_AUTH_WPA_WPA2_PSK;
    } else if (pass_len > 0) {
        wifi_config.ap.authmode = WIFI_AUTH_OPEN;
        wifi_config.ap.password[0] = '\0';
        LOG_WARN("AP password too short (%u), starting open network", (unsigned)pass_len);
    } else {
        wifi_config.ap.authmode = WIFI_AUTH_OPEN;
    }

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    LOG_INFO("Wi-Fi AP ready (SSID=\"%s\", security=%s)",
             WIFI_AP_SSID,
             (wifi_config.ap.authmode == WIFI_AUTH_OPEN) ? "OPEN" : "WPA/WPA2");
    start_http_server();
}

void app_main(void)
{
    esp_log_level_set("*", ESP_LOG_NONE);
    rx_ctx_reset(&s_rx);
    s_http_last_seq_valid  = false;
    s_http_last_seq        = 0;
    s_http_response_started = false;
    s_http_lock = xSemaphoreCreateMutex();
    if (!s_http_lock) {
        LOG_ERROR("failed to create HTTP lock");
        return;
    }
    init_wifi_ap();
    init_usb_serial();
    LOG_INFO("waiting for host connection...");
    while (!usb_serial_jtag_is_connected()) {
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    s_usb_ready = true;
    LOG_INFO("host connected, starting traffic");

    while (true) {
        send_dummy_crsf_packet();
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}
static esp_err_t stream_http_response(httpd_req_t *req, QueueHandle_t queue)
{
    uint8_t *header_buf = NULL;
    size_t   header_len = 0;
    size_t   header_cap = 0;
    char   **held_ptrs  = NULL;
    size_t   held_count = 0;
    size_t   held_cap   = 0;
    bool     headers_done = false;
    bool     saw_error    = false;
    size_t   total_body   = 0;
    esp_err_t result      = ESP_FAIL;

    for (;;) {
        struct http_resp_fragment frag;
        if (xQueueReceive(queue, &frag, pdMS_TO_TICKS(10000)) != pdPASS) {
            LOG_WARN("timeout waiting for HTTP response");
            result = ESP_ERR_TIMEOUT;
            break;
        }

        if (frag.flags & LINK_FLAG_ERROR) {
            saw_error = true;
        }

        if (frag.len > 0) {
            if (!headers_done) {
                if (append_fragment(&header_buf, &header_len, &header_cap, frag.data, frag.len) != ESP_OK) {
                    LOG_ERROR("OOM buffering HTTP headers");
                    result = ESP_ERR_NO_MEM;
                    break;
                }
                ssize_t header_end = find_header_terminator(header_buf, header_len);
                if (header_end >= 0) {
                    size_t body_offset = 0;
                    if (parse_and_apply_headers(req,
                                                header_buf,
                                                (size_t)header_end + 4,
                                                &held_ptrs,
                                                &held_count,
                                                &held_cap,
                                                &body_offset) != ESP_OK) {
                        LOG_WARN("failed to parse upstream headers");
                        result = ESP_FAIL;
                        break;
                    }
                    headers_done = true;
                    if (header_len > body_offset) {
                        size_t chunk_len = header_len - body_offset;
                        if (httpd_resp_send_chunk(req,
                                                  (const char *)(header_buf + body_offset),
                                                  chunk_len) != ESP_OK) {
                            LOG_WARN("failed to send response chunk");
                            result = ESP_FAIL;
                            break;
                        }
                        total_body += chunk_len;
                    }
                    free(header_buf);
                    header_buf = NULL;
                    header_len = header_cap = 0;
                }
            } else {
                if (httpd_resp_send_chunk(req, (const char *)frag.data, frag.len) != ESP_OK) {
                    LOG_WARN("failed to send response chunk");
                    result = ESP_FAIL;
                    break;
                }
                total_body += frag.len;
            }
        }

        if (frag.flags & LINK_FLAG_END) {
            if (!headers_done) {
                LOG_WARN("HTTP response ended before headers completed");
                result = ESP_FAIL;
            } else if (saw_error) {
                LOG_WARN("HTTP response flagged upstream error");
                result = ESP_FAIL;
            } else if (httpd_resp_send_chunk(req, NULL, 0) != ESP_OK) {
                LOG_WARN("failed to finalize chunked response");
                result = ESP_FAIL;
            } else {
                LOG_INFO("Upstream body length: %u", (unsigned)total_body);
                result = ESP_OK;
            }
            break;
        }
    }

    free(header_buf);
    for (size_t i = 0; i < held_count; i++) {
        free(held_ptrs[i]);
    }
    free(held_ptrs);

    if (result != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Upstream proxy error");
    }
    return result;
}
