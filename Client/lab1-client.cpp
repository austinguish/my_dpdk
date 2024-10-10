#include "udp_header.h"
#include <atomic>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_spinlock.h>
#include <unordered_map>
#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024
#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 128
#define MAX_FLOW_NUM 100
#define PORT_NUM 5001
#define RETRANSMISSION_TIMEOUT 10000000000 // 1 second in nanoseconds
const rte_ether_addr dst = {{0x14, 0x58, 0xD0, 0x58, 0xdf, 0x43}};

struct rte_mempool *mbuf_pool = NULL;
static struct rte_ether_addr my_eth;
uint64_t flow_size = 10000;
int packet_len = 1000;
int flow_num = 1;
uint32_t NUM_PING = 100;
std::atomic<int> active_flows;

struct packet_info {
  uint64_t send_time;
  bool acked;
};

// struct packet_time
// {
//     uint64_t send_time;
//     uint64_t acked_time;
// };

struct flow_state {
  uint64_t next_seq_num;
  uint64_t last_acked;
  std::unordered_map<uint64_t, packet_info> packets;
  rte_spinlock_t lock;
  uint64_t window_size;
  // std::unordered_map<uint64_t, packet_time> packet_times;
};

struct flow_state *flow_table;

static uint64_t get_current_time(void) {
  return rte_get_timer_cycles() * 1000000000 / rte_get_timer_hz();
}

static void prepare_packet(struct rte_mbuf *pkt, int flow_id,
                           uint64_t seq_num) {
  size_t header_size = 0;
  uint8_t *ptr = rte_pktmbuf_mtod(pkt, uint8_t *);

  // Ethernet header
  struct rte_ether_hdr *eth_hdr = (struct rte_ether_hdr *)ptr;
  rte_ether_addr_copy(&my_eth, &eth_hdr->src_addr);
  // Assuming dst is a global variable
  rte_ether_addr_copy(&dst, &eth_hdr->dst_addr);
  eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
  ptr += sizeof(*eth_hdr);
  header_size += sizeof(*eth_hdr);

  // IPv4 header
  struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)ptr;
  ip_hdr->version_ihl = 0x45;
  ip_hdr->type_of_service = 0;
  ip_hdr->total_length =
      rte_cpu_to_be_16(sizeof(struct rte_ipv4_hdr) +
                       sizeof(struct udp_header_extra) + packet_len);
  ip_hdr->packet_id = 0;
  ip_hdr->fragment_offset = 0;
  ip_hdr->time_to_live = 64;
  ip_hdr->next_proto_id = IPPROTO_UDP;
  ip_hdr->src_addr = rte_cpu_to_be_32(0x0A000001); // 10.0.0.1
  ip_hdr->dst_addr = rte_cpu_to_be_32(0x0A000002); // 10.0.0.2
  ip_hdr->hdr_checksum = 0;                        // Will be filled by hardware
  ptr += sizeof(*ip_hdr);
  header_size += sizeof(*ip_hdr);

  // UDP header with extra fields
  struct udp_header_extra *udp_hdr_extra = (struct udp_header_extra *)ptr;
  udp_hdr_extra->udp_hdr.src_port = rte_cpu_to_be_16(PORT_NUM + flow_id);
  udp_hdr_extra->udp_hdr.dst_port = rte_cpu_to_be_16(PORT_NUM + flow_id);
  udp_hdr_extra->udp_hdr.dgram_len =
      rte_cpu_to_be_16(sizeof(struct udp_header_extra) + packet_len);
  udp_hdr_extra->udp_hdr.dgram_cksum = 0; // Will be filled by hardware
  udp_hdr_extra->window_size = flow_table[flow_id].window_size;
  udp_hdr_extra->seq = seq_num;
  udp_hdr_extra->send_time = get_current_time();
  ptr += sizeof(*udp_hdr_extra);
  header_size += sizeof(*udp_hdr_extra);

  // Payload
  memset(ptr, 'a', packet_len); // Fill payload with 'a'

  // Set packet attributes
  pkt->data_len = header_size + packet_len;
  pkt->pkt_len = pkt->data_len;
  pkt->l2_len = sizeof(struct rte_ether_hdr);
  pkt->l3_len = sizeof(struct rte_ipv4_hdr);
  pkt->l4_len = sizeof(struct udp_header_extra);
}

static int parse_packet(struct rte_mbuf *pkt, uint64_t *ack_num,
                        uint64_t *window_size) {
  uint8_t *ptr = rte_pktmbuf_mtod(pkt, uint8_t *);

  // Skip Ethernet header
  ptr += sizeof(struct rte_ether_hdr);

  // Skip IP header
  ptr += sizeof(struct rte_ipv4_hdr);

  // Parse UDP header extra
  struct udp_header_extra *udp_hdr_extra = (struct udp_header_extra *)ptr;
  int flow_id = rte_be_to_cpu_16(udp_hdr_extra->udp_hdr.dst_port) - PORT_NUM;
  *ack_num = udp_hdr_extra->seq;
  *window_size = udp_hdr_extra->window_size;

  return flow_id;
}

static inline int port_init(uint16_t port, struct rte_mempool *mbuf_pool) {
  rte_eth_conf port_conf;
  const uint16_t rx_rings = 1, tx_rings = flow_num;
  uint16_t nb_rxd = RX_RING_SIZE;
  uint16_t nb_txd = TX_RING_SIZE;
  int retval;
  uint16_t q;
  rte_eth_dev_info dev_info;
  rte_eth_txconf txconf;

  if (!rte_eth_dev_is_valid_port(port))
    return -1;

  memset(&port_conf, 0, sizeof(struct rte_eth_conf));

  retval = rte_eth_dev_info_get(port, &dev_info);
  if (retval != 0) {
    printf("Error during getting device (port %u) info: %s\n", port,
           strerror(-retval));
    return retval;
  }

  if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
    port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

  /* Configure the Ethernet device. */
  retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
  if (retval != 0)
    return retval;

  retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
  if (retval != 0)
    return retval;

  /* Allocate and set up RX queues */
  for (q = 0; q < rx_rings; q++) {
    retval = rte_eth_rx_queue_setup(
        port, q, nb_rxd, rte_eth_dev_socket_id(port), NULL, mbuf_pool);
    if (retval < 0)
      return retval;
  }

  txconf = dev_info.default_txconf;
  txconf.offloads = port_conf.txmode.offloads;
  /* Allocate and set up TX queues */
  for (q = 0; q < tx_rings; q++) {
    retval = rte_eth_tx_queue_setup(port, q, nb_txd,
                                    rte_eth_dev_socket_id(port), &txconf);
    if (retval < 0)
      return retval;
  }

  /* Start the Ethernet port. */
  retval = rte_eth_dev_start(port);
  if (retval < 0)
    return retval;

  /* Display the port MAC address. */
  retval = rte_eth_macaddr_get(port, &my_eth);
  if (retval != 0)
    return retval;

  printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8
         " %02" PRIx8 " %02" PRIx8 "\n",
         port, RTE_ETHER_ADDR_BYTES(&my_eth));

  /* Enable RX in promiscuous mode for the Ethernet device. */
  retval = rte_eth_promiscuous_enable(port);
  if (retval != 0)
    return retval;

  return 0;
}

static void send_packet(int flow_id, uint64_t seq_num) {
  struct rte_mbuf *pkt = rte_pktmbuf_alloc(mbuf_pool);
  if (pkt == NULL) {
    printf("Error allocating tx mbuf\n");
    return;
  }

  prepare_packet(pkt, flow_id, seq_num);

  int sent = rte_eth_tx_burst(1, flow_id, &pkt, 1);
  if (sent == 1) {
    rte_spinlock_lock(&flow_table[flow_id].lock);
    flow_table[flow_id].packets[seq_num] = {get_current_time(), false};
    // add the packet time
    rte_spinlock_unlock(&flow_table[flow_id].lock);
  } else {
    printf("Error sending packet %lu for flow %d\n", seq_num, flow_id);
    rte_pktmbuf_free(pkt);
  }
}

static void check_and_retransmit(int flow_id) {
  flow_state *state = &flow_table[flow_id];
  uint64_t current_time = get_current_time();

  rte_spinlock_lock(&state->lock);
  for (auto &pair : state->packets) {
    uint64_t seq = pair.first;
    packet_info &pinfo = pair.second;
    if (!pinfo.acked &&
        (current_time - pinfo.send_time) > RETRANSMISSION_TIMEOUT) {
      printf("Retransmitting packet %lu for flow %d\n", seq, flow_id);
      rte_spinlock_unlock(&state->lock);
      send_packet(flow_id, seq);
      rte_spinlock_lock(&state->lock);
    }
  }
  rte_spinlock_unlock(&state->lock);
}

static int receive_thread(__attribute__((unused)) void *arg) {
  struct rte_mbuf *pkts[BURST_SIZE];
  uint64_t ack_num, received_window_size;

  while (active_flows > 0) {
    const uint16_t nb_rx = rte_eth_rx_burst(1, 0, pkts, BURST_SIZE);

    for (int i = 0; i < nb_rx; i++) {
      int flow_id = parse_packet(pkts[i], &ack_num, &received_window_size);

      if (flow_id >= 0 && flow_id < flow_num) {
        rte_spinlock_lock(&flow_table[flow_id].lock);

        if (ack_num > flow_table[flow_id].last_acked) {
          flow_table[flow_id].last_acked = ack_num;

          for (auto it = flow_table[flow_id].packets.begin();
               it != flow_table[flow_id].packets.end();) {
            if (it->first <= ack_num) {
              it = flow_table[flow_id].packets.erase(it);
            } else {
              ++it;
            }
          }
        }

        rte_spinlock_unlock(&flow_table[flow_id].lock);
      }

      rte_pktmbuf_free(pkts[i]);
    }
  }

  printf("Receive thread exiting\n");
  return 0;
}

static int lcore_main(void *arg) {
  int flow_id = *(int *)arg;
  delete (int *)arg;

  while (1) {
    rte_spinlock_lock(&flow_table[flow_id].lock);

    if (flow_table[flow_id].last_acked >= NUM_PING) {
      rte_spinlock_unlock(&flow_table[flow_id].lock);
      break;
    }

    while (flow_table[flow_id].next_seq_num <=
               flow_table[flow_id].last_acked +
                   flow_table[flow_id].window_size &&
           flow_table[flow_id].next_seq_num <= NUM_PING) {
      rte_spinlock_unlock(&flow_table[flow_id].lock);
      send_packet(flow_id, flow_table[flow_id].next_seq_num);
      rte_spinlock_lock(&flow_table[flow_id].lock);
      flow_table[flow_id].next_seq_num++;
    }

    rte_spinlock_unlock(&flow_table[flow_id].lock);

    check_and_retransmit(flow_id);
  }

  printf("Flow %d completed\n", flow_id);
  active_flows--;
  return 0;
}

int main(int argc, char *argv[]) {
  // Initialize EAL, parse arguments, set up port, etc.
  // ...
  unsigned nb_ports;
  uint16_t portid;

  if (argc == 3) {
    flow_num = std::stoull(argv[1]);

    flow_size = std::stoull(argv[2]);
  } else {
    printf("usage: ./lab1-client <flow_num> <flow_size>\n");
    return 1;
  }

  NUM_PING = flow_size / packet_len;
  printf("flow_num is %d, flow_size is %ld\n", flow_num, flow_size);
  printf("NUM_PING is %d\n", NUM_PING);

  int ret = rte_eal_init(argc, argv);
  if (ret < 0)
    rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

  argc -= ret;
  argv += ret;

  nb_ports = rte_eth_dev_count_avail();
  printf("the number of nb_ports is %d\n", nb_ports);

  mbuf_pool = rte_pktmbuf_pool_create(
      "MBUF_POOL", NUM_MBUFS * nb_ports * flow_num, MBUF_CACHE_SIZE, 0,
      RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

  if (mbuf_pool == NULL)
    rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

  RTE_ETH_FOREACH_DEV(portid)
  if (portid == 1 && port_init(portid, mbuf_pool) != 0)
    rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n", portid);
  // if (initialize_flows(1, flow_num) != 0)
  // {
  //     rte_exit(EXIT_FAILURE, "Failed to initialize flows with server\n");
  // }
  // check how many queues on port 1 tx and rx
  rte_eth_dev_info dev_info;
  rte_eth_dev_info_get(1, &dev_info);

  printf("Port 1: RX queues = %u, TX queues = %u\n", dev_info.nb_rx_queues,
         dev_info.nb_tx_queues);

  // Initialize flow states
  flow_table = new flow_state[flow_num];
  for (int i = 0; i < flow_num; i++) {
    flow_table[i].next_seq_num = 1;
    flow_table[i].last_acked = 0;
    flow_table[i].window_size = 10;
    rte_spinlock_init(&flow_table[i].lock);
  }

  active_flows = flow_num;
  auto start_time = get_current_time();
  // launch
  for (int i = 0; i < flow_num; i++) {
    int *arg = new int(i);
    int ret = rte_eal_remote_launch(lcore_main, arg, i + 1);
    if (ret != 0) {
      printf("Error launching thread for flow %d\n", i);
      delete arg;
      active_flows--;
    }
  }

  // Launch receiver thread
  rte_eal_remote_launch(receive_thread, NULL, flow_num + 1);

  // Wait for all threads to complete
  rte_eal_mp_wait_lcore();
  auto end_time = get_current_time();
  auto total_time = (double)(end_time - start_time);
  auto total_data = (double)(flow_size * flow_num);
  printf("Total time: %.3f ms\n", total_time / 1e6);
  printf("Total data: %.3f MB\n", total_data / 1e6);
  printf("Throughput: %.3f Gbps\n", total_data * 8 / total_time);
  rte_eal_cleanup();

  delete[] flow_table;

  return 0;
}
