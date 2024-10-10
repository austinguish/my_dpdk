//
// Created by yiwei on 24-10-7.
//

#ifndef FLOWSTATE_H
#define FLOWSTATE_H
#define WINDOW_SIZE 1024
#include <map>
#include <queue>
#include <unordered_map>
struct packet_time {
  uint64_t send_time;
  uint64_t ack_time;
};

struct flow_state_receiver {
  uint16_t advertised_window;
  std::unordered_map<int, uint64_t> next_seq_num_expected;
  std::unordered_map<int, uint64_t> last_read;
  std::unordered_map<int, uint64_t> last_received;
  std::unordered_map<int, std::unordered_map<int, struct rte_mbuf *>>
      window_packets;
};

#endif // FLOWSTATE_H
