idf_component_register(SRCS "backpack_stub.c"
                      INCLUDE_DIRS "."
                      REQUIRES esp_driver_usb_serial_jtag esp_wifi esp_event esp_netif nvs_flash esp_http_server)
