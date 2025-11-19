# Radxa Backpack Link Bridge

This repo couples the **host-side bridge (`radxa_linkd.c`)** with an **ESP32‑C3 “backpack” stub (`esp_fw/`)** so we can exercise the OpenIPC USB framing, HTTP proxying, and CRSF telemetry path end to end.

## Current Capabilities

- Radxa host daemon (`radxa_linkd`) forwards:
  - CRSF frames from USB → UDP `127.0.0.1:14450`.
  - HTTP frames from USB → localhost TCP `127.0.0.1:55667`, streaming the response back to the ESP with stop-and-wait ACKs so large payloads survive noisy UART links (each chunk idles ~24 ms after the ACK to keep the UART from overflowing).
  - Detailed stderr logging for every proxied request/response chunk.
- ESP32‑C3 stub firmware:
  - Sets up a SoftAP named `openipc-backpack` (WPA2 passphrase `12345678`) at `10.0.0.1/24` with DHCP service.
  - Acts as a transparent HTTP proxy: every request from Wi‑Fi clients is serialized into LINK frames, sent over USB, and the upstream response is replayed byte-for-byte back to the client (no local HTML anymore).
  - ACKs every HTTP response chunk from the host (`LINK_FLAG_ACK`, mirroring the host `seq`) and uses `LINK_FLAG_ERROR` in the ACK to request retransmits when a chunk can’t be queued.
  - Replays dummy CRSF traffic once per second so the Radxa path stays hot.

Keep this file updated whenever we change behaviors, credentials, or logging so the next agent can pick up from here without spelunking commits.

## Building

### Host bridge (`radxa_linkd.c`)

```
gcc -O2 -Wall -Wextra -o radxa_linkd radxa_linkd.c
```

- Add `-fsanitize=address` if you need to chase heap issues.
- Run `./radxa_linkd` while the ESP32 is enumerated as `/dev/ttyACM0`.

### ESP32‑C3 stub (`esp_fw/`)

Prereqs: ESP-IDF v6.1+, `idf.py` in your shell (`. $HOME/esp/esp-idf/export.sh`).

```
cd esp_fw
idf.py set-target esp32c3   # once
idf.py build
idf.py -p /dev/ttyACM0 flash
idf.py -p /dev/ttyACM0 monitor
```

## Usage Flow

1. **Flash the ESP32‑C3** with the latest stub. On boot it:
   - Brings up `openipc-backpack` AP and DHCP.
   - Waits for `/dev/ttyACM0` host connection, then starts proxying.
2. **Run the host bridge** (`./radxa_linkd`) on the Radxa. You should see stderr logs like:
   ```
   HTTP request complete (83 bytes)
   HTTP proxy: dispatch 83 bytes
   HTTP proxy: sent response chunk 65 bytes
   ...
   ```
3. **Connect a client** to `openipc-backpack`, browse to the target UI through `http://10.0.0.1/<path>`.
   - Every HTTP verb hits `proxy_http_handler`, which forwards over USB and mirrors the upstream response back to the client. The ESP monitor prints:
   ```
   Forwarding HTTP GET /sync/slots (0 body bytes)
   TX HTTP upstream (123 bytes)
   RX HTTP upstream (211 bytes)
   ```
4. **Monitor CRSF output** with `tcpdump -n udp port 14450` on the host if needed.
5. HTTP responses now require ACKs: every frame sent back to the ESP must be acknowledged with a zero-length HTTP frame tagged `LINK_FLAG_ACK`. The host times out after 200 ms and retries the same sequence (up to 8 attempts) before surfacing an error.

### HTTP ACK / retransmit contract

- Every HTTP response frame from the host carries a monotonically increasing `seq`.
- The ESP must emit a matching `LINK_TYPE_HTTP | LINK_FLAG_ACK` frame (len = 0) when it has accepted the chunk. Add `LINK_FLAG_ERROR` to the ACK if you want the host to resend immediately.
- The host keeps a copy of the in-flight chunk, waits up to 200 ms for the ACK, and retries up to eight times before emitting an `END|ERROR` marker.
- If the host cannot even open the upstream TCP connection it pushes a zero-length `END|ERROR` frame so the ESP can fail the HTTP transaction cleanly.

## Troubleshooting

- **`/dev/ttyACM0` missing / permission denied**: add your user to `dialout` or run commands via `sudo`. Make sure the ESP is in runtime mode (BOOT button released).
- **Bridge busy**: The ESP proxy is single-flight. If you see `Bridge busy` errors, wait for the outstanding request to finish (or improve the queueing logic before stacking more calls).
- **HTTP errors in UI**:
  - Check host logs for `HTTP proxy: dispatch …` without matching chunk logs.
  - Check ESP monitor for `TX HTTP upstream` without `RX HTTP upstream` – the host likely never replied.
  - Use `strace ./radxa_linkd` to see if localhost `127.0.0.1:55667` is refusing connections.
- **ACK/retry stalls**:
  - Host stderr prints `HTTP proxy: resend seq …` when ACKs are missing; ensure the ESP firmware is mirroring the correct `seq` in its ACK frames.
  - After eight misses the host sends an `END|ERROR` frame and aborts the transaction; capture UART traffic with `socat -x` if you need to debug framing.

## Updating Docs

Whenever we change commands, passwords, logging strings, or workflow, update both `README.md` and `AGENTS.md`. The goal is to keep this section actionable for whoever picks up the next task. Remove stale sections instead of letting them linger.*** End Patch
