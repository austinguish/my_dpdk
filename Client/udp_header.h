//
// Created by jiangyw on 24-9-20.
//
#include <rte_udp.h>
#ifndef UDP_HEADER_H
#define UDP_HEADER_H
// wrap the udp header with 16 bit window size
struct udp_header_extra {
  struct rte_udp_hdr udp_hdr;
  uint64_t window_size;
  uint64_t seq;
  uint64_t send_time;
};
#endif // UDP_HEADER_H
