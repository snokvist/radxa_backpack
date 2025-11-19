# ESP32-C3 Backpack Stub Firmware

This stub exercises the `radxa_linkd.c` link framing so you can validate HTTP
and CRSF plumbing before wiring real peripherals. It now behaves as a **transparent
HTTP proxy**: every request from Wi-Fi clients is serialized over USB to the host,
and the upstream response is streamed back to the client unchanged.

## Building

```
idf.py set-target esp32c3
idf.py -p /dev/ttyACM0 build flash monitor
```

Requirements:
- ESP-IDF v5+ with the TinyUSB component enabled (default in `idf.py create-project`).
- `CONFIG_ESP_CONSOLE_USB_CDC` disabled so TinyUSB owns the USB pins.

Place `backpack_stub.c` under `main/` of a standard ESP-IDF project (or use
`esp_fw/` as-is) and ensure `main/CMakeLists.txt` lists the source.

## Operation

1. Boot the ESP32-C3 with USB connected; it enumerates as a CDC device.
2. Run `radxa_linkd` on the host so it listens to `/dev/ttyACM0`.
3. The firmware emits a dummy CRSF packet every second so the host forwards UDP
   payloads to port 14450 (`tcpdump -n udp port 14450` to observe).
4. Any HTTP request you issue against `http://10.0.0.1/...` is forwarded over USB
   to the host, which calls `http://127.0.0.1:55667/...` and streams the response
   back through the same path. Tail `idf.py monitor` plus the host stderr logs to
   follow both directions.

Use the UART/USB log (`idf.py monitor`) to confirm frame activity and host
responses. There is no local HTML served anymore; all content originates from
the upstream web server reached via `radxa_linkd`.
