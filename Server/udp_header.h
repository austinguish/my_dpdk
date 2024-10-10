//
// Created by tianyi on 24-10-7.
//

#ifndef FLOWSTATE_H
#define FLOWSTATE_H
#define WINDOW_SIZE 10
#include <atomic>
#include <map>
#include <queue>
#include <unordered_map>

struct flow_state_sender {
  uint16_t next_seq_num; // last packet sent
  uint16_t effective_window;
  uint16_t advertised_window;
  // struct rte_mbuf *window_packets[WINDOW_SIZE];
  // use queue<int> to store the unacked seq
  std::unordered_map<int, struct rte_mbuf *> unacked_packets;
  std::queue<int> unacked_seq;
  uint64_t send_times[WINDOW_SIZE];
  int last_acked; // acked packets
  // last written to the window
  uint16_t last_written; // last packet send to window
  uint16_t in_flight_packets;
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
