signature dpd_ssdp_request {
  ip-proto == udp
  payload /^M-SEARCH \* HTTP\/1\.1\x0d\x0a/
  eval ssdp::ssdp_request
}

signature dpd_ssdp_response {
  ip-proto == udp
  payload /^(NOTIFY \* HTTP\/1\.1|HTTP\/1\.1 200 OK)\x0d\x0a/
  eval ssdp::ssdp_response
}
