#include "flow_state.h"
#include "udp_header.h"
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
#include <thread>
#include <vector>

#define RX_RING_SIZE 4096
#define TX_RING_SIZE 4096
#define MAX_FLOWS 8
#define RING_SIZE 1024
#define NUM_MBUFS 40959
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 512
#define MAX_FLOW_NUM 100
#define PORT_NUM 5001
#include <signal.h>
int ack_len = 10;
// use a atomic variable to store the all the packets received
uint64_t received_packets;
struct rte_mempool *mbuf_pool = NULL;
static struct rte_ether_addr my_eth;
struct flow_state_receiver *flow_state;
struct rte_ring *flow_rings[MAX_FLOWS];
std::vector<std::thread> flow_threads;
volatile bool force_quit = false;

static void signal_handler(int signum) {
  if (signum == SIGINT || signum == SIGTERM) {
    printf("\n\nSignal %d received, preparing to exit...\n", signum);
    printf("Total received packets: %lu\n", received_packets);
    exit(0);
  }
}
static void process_packet(struct rte_mbuf *pkt, int flow_id);

static struct rte_mbuf *construct_ack(struct rte_mbuf *pkt, int flow_id);

uint32_t checksum(unsigned char *buf, uint32_t nbytes, uint32_t sum) {
  unsigned int i;

  /* Checksum all the pairs of bytes first. */
  for (i = 0; i < (nbytes & ~1U); i += 2) {
    sum += (uint16_t)ntohs(*((uint16_t *)(buf + i)));
    if (sum > 0xFFFF)
      sum -= 0xFFFF;
  }
  if (i < nbytes) {
    sum += buf[i] << 8;
    if (sum > 0xFFFF)
      sum -= 0xFFFF;
  }

  return sum;
}

uint32_t wrapsum(uint32_t sum) {
  sum = ~sum & 0xFFFF;
  return htons(sum);
}

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */

/* Main functional part of port initialization. 8< */
static inline int port_init(uint16_t port, struct rte_mempool *mbuf_pool) {
  struct rte_eth_conf port_conf;
  const uint16_t rx_rings = 1, tx_rings = 8;
  uint16_t nb_rxd = RX_RING_SIZE;
  uint16_t nb_txd = TX_RING_SIZE;
  int retval;
  uint16_t q;
  struct rte_eth_dev_info dev_info;
  struct rte_eth_txconf txconf;

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

  /* Allocate and set up 1 RX queue per Ethernet port. */
  for (q = 0; q < rx_rings; q++) {
    retval = rte_eth_rx_queue_setup(
        port, q, nb_rxd, rte_eth_dev_socket_id(port), NULL, mbuf_pool);
    if (retval < 0)
      return retval;
  }

  txconf = dev_info.default_txconf;
  txconf.offloads = port_conf.txmode.offloads;
  /* Allocate and set up 1 TX queue per Ethernet port. */
  for (q = 0; q < tx_rings; q++) {
    retval = rte_eth_tx_queue_setup(port, q, nb_txd,
                                    rte_eth_dev_socket_id(port), &txconf);
    if (retval < 0)
      return retval;
  }

  /* Starting Ethernet port. 8< */
  retval = rte_eth_dev_start(port);
  /* >8 End of starting of ethernet port. */
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
  /* End of setting RX port in promiscuous mode. */
  if (retval != 0)
    return retval;

  return 0;
}

/* >8 End of main functional part of port initialization. */

static int get_port(struct sockaddr_in *src, struct sockaddr_in *dst,
                    void **payload, size_t *payload_len, struct rte_mbuf *pkt) {
  // packet layout order is (from outside -> in):
  // ether_hdr
  // ipv4_hdr
  // udp_hdr
  // client timestamp
  uint8_t *p = rte_pktmbuf_mtod(pkt, uint8_t *);
  size_t header = 0;

  // check the ethernet header
  struct rte_ether_hdr *const eth_hdr = (struct rte_ether_hdr *)(p);
  p += sizeof(*eth_hdr);
  header += sizeof(*eth_hdr);
  uint16_t eth_type = ntohs(eth_hdr->ether_type);
  struct rte_ether_addr mac_addr = {};
  rte_eth_macaddr_get(1, &mac_addr);
  if (!rte_is_same_ether_addr(&mac_addr, &eth_hdr->dst_addr)) {
    // printf("Bad MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
    //     " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
    //     eth_hdr->dst_addr.addr_bytes[0], eth_hdr->dst_addr.addr_bytes[1],
    //  eth_hdr->dst_addr.addr_bytes[2], eth_hdr->dst_addr.addr_bytes[3],
    //  eth_hdr->dst_addr.addr_bytes[4], eth_hdr->dst_addr.addr_bytes[5]);
    return -1;
  }
  if (RTE_ETHER_TYPE_IPV4 != eth_type) {
    printf("Bad ether type\n");
    return -2;
  }

  // check the IP header
  struct rte_ipv4_hdr *const ip_hdr = (struct rte_ipv4_hdr *)(p);
  p += sizeof(*ip_hdr);
  header += sizeof(*ip_hdr);

  // In network byte order.
  in_addr_t ipv4_src_addr = ip_hdr->src_addr;
  in_addr_t ipv4_dst_addr = ip_hdr->dst_addr;

  if (IPPROTO_UDP != ip_hdr->next_proto_id) {
    printf("Bad next proto_id\n");
    return -3;
  }

  src->sin_addr.s_addr = ipv4_src_addr;
  dst->sin_addr.s_addr = ipv4_dst_addr;

  // check udp header

  struct udp_header_extra *const udp_hdr_ext = (struct udp_header_extra *)(p);
  p += sizeof(*udp_hdr_ext);
  header += sizeof(*udp_hdr_ext);

  // In network byte order.
  in_port_t udp_src_port = udp_hdr_ext->udp_hdr.src_port;
  in_port_t udp_dst_port = udp_hdr_ext->udp_hdr.dst_port;

  int ret = rte_be_to_cpu_16(udp_hdr_ext->udp_hdr.dst_port) - PORT_NUM;
  if (ret < 0 || ret >= MAX_FLOW_NUM) {
    printf("Bad port number %d\n",
           rte_be_to_cpu_16(udp_hdr_ext->udp_hdr.dst_port));
    return -4;
  }

  src->sin_port = udp_src_port;
  dst->sin_port = udp_dst_port;

  src->sin_family = AF_INET;
  dst->sin_family = AF_INET;

  *payload_len = pkt->pkt_len - header;
  *payload = (void *)p;
  // print the received time stamp in the payload
  // the data is uint64_t
  // print out
  // printf("Received timestamp: %" PRIu64 "\n", payload);
  return ret;
}

// uint16_t get_rx_queue_remaining_space(uint16_t port_id, uint16_t queue_id)
// {
//     struct rte_eth_dev_info dev_info;
//     int ret = rte_eth_dev_info_get(port_id, &dev_info);
//     if (ret != 0)
//     {
//         printf("Error getting device info for port %u: %s\n", port_id,
//         strerror(-ret)); return 0;
//     }
//
//     uint16_t nb_rx_desc = dev_info.rx_desc_lim.nb_max;
//
//     uint16_t current_count = rte_eth_rx_queue_count(port_id, queue_id);
//
//     uint16_t remaining_space = (current_count <= nb_rx_desc) ? (nb_rx_desc -
//     current_count) : 0;
//
//     return remaining_space;
// }

static void process_packet(struct rte_mbuf *pkt, int flow_id) {
  udp_header_extra *udp_hdr_ext = rte_pktmbuf_mtod_offset(
      pkt, struct udp_header_extra *,
      sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
  uint64_t seq = udp_hdr_ext->seq;

  // printf("Debug: Processing packet for flow %d, seq %lu\n", flow_id, seq);

  flow_state->window_packets[flow_id][seq] = pkt;
  flow_state->last_received[flow_id] =
      std::max(flow_state->last_received[flow_id], seq);

  if (seq == flow_state->next_seq_num_expected[flow_id]) {
    flow_state->next_seq_num_expected[flow_id] = seq + 1;
    // printf("Debug: Sequence number as expected. New next_seq_num_expected:
    // %lu\n",flow_state->next_seq_num_expected[flow_id]);
  } else if (seq < flow_state->next_seq_num_expected[flow_id]) {
    // printf("Debug: Received retransmitted packet. seq: %lu, expected: %lu\n",
    //        seq, flow_state->next_seq_num_expected[flow_id]);
    //   } else {
    //     printf("Debug: Out of order packet. seq: %lu, expected: %lu\n", seq,
    //            flow_state->next_seq_num_expected[flow_id]);
    //   }

    flow_state->advertised_window =
        WINDOW_SIZE - (flow_state->next_seq_num_expected[flow_id] -
                       flow_state->last_read[flow_id]);

    // printf("Debug: Updated advertised window: %u\n",
    //   flow_state->advertised_window);
  }
}

static int process_thread(void *arg) {
  int flow_num = *(int *)arg;
  free(arg);

  uint16_t tx_queue = flow_num % 8;
  uint64_t total_processed = 0;
  uint64_t last_print_time = rte_get_timer_cycles();

  printf("Process thread for flow %d running on core %u, using TX queue %u\n",
         flow_num, rte_lcore_id(), tx_queue);

  int total_send = 0;

  while (1) {
    struct rte_mbuf *pkt;
    if (rte_ring_dequeue(flow_rings[flow_num], (void **)&pkt) < 0) {
      continue;
    }

    total_processed++;

    // uint64_t cur_time = rte_get_timer_cycles();
    // if (cur_time - last_print_time > rte_get_timer_hz()) {
    //     printf("Debug: Flow %d processed %lu packets, Current ring count:
    //     %u\n",
    //            flow_num, total_processed,
    //            rte_ring_count(flow_rings[flow_num]));
    //     last_print_time = cur_time;
    // }

    // printf("Debug: Dequeued packet for flow %d\n", flow_num);

    process_packet(pkt, flow_num);

    struct rte_mbuf *ack = construct_ack(pkt, flow_num);
    if (ack != NULL) {
      uint16_t nb_tx = rte_eth_tx_burst(1, tx_queue, &ack, 1);
      if (nb_tx > 0) {
        total_send += nb_tx;
        // printf("Debug: ACK sent for flow %d, total send %u\n", flow_num,
        // total_send);
      } else {
        // printf("Debug: Failed to send ACK for flow %d. TX ring full?\n",
        // flow_num);
        rte_pktmbuf_free(ack);
      }
    } else {
      // printf("Debug: Failed to construct ACK for flow %d\n", flow_num);
    }

    rte_pktmbuf_free(pkt);
  }

  return 0;
}

static struct rte_mbuf *construct_ack(struct rte_mbuf *pkt, int flow_id) {
  auto eth_h = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
  if (eth_h->ether_type != rte_be_to_cpu_16(RTE_ETHER_TYPE_IPV4)) {
    rte_pktmbuf_free(pkt);
    return nullptr;
  }

  auto ip_h = rte_pktmbuf_mtod_offset(pkt, struct rte_ipv4_hdr *,
                                      sizeof(struct rte_ether_hdr));

  auto udp_h = rte_pktmbuf_mtod_offset(pkt, struct udp_header_extra *,
                                       sizeof(struct rte_ether_hdr) +
                                           sizeof(struct rte_ipv4_hdr));

  // update flow state
  auto ack = rte_pktmbuf_alloc(mbuf_pool);
  if (ack == NULL) {
    printf("Error allocating tx mbuf\n");
    return nullptr;
  }
  size_t header_size = 0;

  uint8_t *ptr = rte_pktmbuf_mtod(ack, uint8_t *);
  /* add in an ethernet header */
  auto eth_h_ack = (struct rte_ether_hdr *)ptr;

  rte_ether_addr_copy(&my_eth, &eth_h_ack->src_addr);
  rte_ether_addr_copy(&eth_h->src_addr, &eth_h_ack->dst_addr);
  eth_h_ack->ether_type = rte_be_to_cpu_16(RTE_ETHER_TYPE_IPV4);
  ptr += sizeof(*eth_h_ack);
  header_size += sizeof(*eth_h_ack);

  /* add in ipv4 header*/
  auto ip_h_ack = (struct rte_ipv4_hdr *)ptr;
  ip_h_ack->version_ihl = 0x45;
  ip_h_ack->type_of_service = 0x0;
  ip_h_ack->total_length = rte_cpu_to_be_16(
      sizeof(struct rte_ipv4_hdr) + sizeof(struct udp_header_extra) + ack_len);
  ip_h_ack->packet_id = rte_cpu_to_be_16(1);
  ip_h_ack->fragment_offset = 0;
  ip_h_ack->time_to_live = 64;
  ip_h_ack->next_proto_id = IPPROTO_UDP;
  ip_h_ack->src_addr = ip_h->dst_addr;
  ip_h_ack->dst_addr = ip_h->src_addr;

  uint32_t ipv4_checksum = wrapsum(
      checksum((unsigned char *)ip_h_ack, sizeof(struct rte_ipv4_hdr), 0));
  ip_h_ack->hdr_checksum = rte_cpu_to_be_32(ipv4_checksum);
  header_size += sizeof(*ip_h_ack);
  ptr += sizeof(*ip_h_ack);

  /* add in UDP hdr*/
  auto udp_h_ack_ext = (struct udp_header_extra *)ptr;
  auto udp_h_ack = &udp_h_ack_ext->udp_hdr;
  udp_h_ack->src_port = udp_h->udp_hdr.dst_port;
  udp_h_ack->dst_port = udp_h->udp_hdr.src_port;
  udp_h_ack->dgram_len =
      rte_cpu_to_be_16(sizeof(struct udp_header_extra) + ack_len);
  udp_h_ack_ext->window_size = flow_state->advertised_window;
  udp_h_ack_ext->seq = udp_h->seq;
  udp_h_ack_ext->send_time = udp_h->send_time;
  uint16_t udp_cksum = rte_ipv4_udptcp_cksum(ip_h_ack, (void *)udp_h_ack);

  // printf("Udp checksum is %u\n", (unsigned)udp_cksum);
  udp_h_ack->dgram_cksum = rte_cpu_to_be_16(udp_cksum);

  header_size += sizeof(*udp_h_ack_ext);
  ptr += sizeof(*udp_h_ack_ext);
  /* set the payload */
  memset(ptr, 'a', ack_len);

  ack->l2_len = RTE_ETHER_HDR_LEN;
  ack->l3_len = sizeof(struct rte_ipv4_hdr);
  // pkt->ol_flags = PKT_TX_IP_CKSUM | PKT_TX_IPV4;
  ack->data_len = header_size + ack_len;
  ack->pkt_len = header_size + ack_len;
  ack->nb_segs = 1;

  flow_state->last_read[flow_id] = udp_h_ack_ext->seq;
  flow_state->window_packets[flow_id].erase(udp_h_ack_ext->seq);
  return ack;
}

static int rx_thread(void *arg) {
  unsigned rx_port = 1;
  // unsigned queue_id = *(unsigned *)arg;
  uint64_t total_rx = 0;
  uint64_t last_print_time = rte_get_timer_cycles();

  // printf("RX thread for queue %u running on core %u\n", queue_id,
  // rte_lcore_id());
  while (1) {
    struct rte_mbuf *pkts_burst[BURST_SIZE];
    unsigned nb_rx = rte_eth_rx_burst(rx_port, 0, pkts_burst, BURST_SIZE);

    total_rx += nb_rx;

    // uint64_t cur_time = rte_get_timer_cycles();
    // if (cur_time - last_print_time > rte_get_timer_hz()) {
    //   printf("Debug: Total received packets: %lu, Current free mbufs:
    //              % u\n ",
    //              total_rx,
    //          rte_mempool_avail_count(mbuf_pool));
    //   last_print_time = cur_time;
    // }

    // if (nb_rx > 0) {
    //     printf("Debug: Received %u packets on core %u\n", nb_rx,
    //     rte_lcore_id());
    // }

    for (unsigned i = 0; i < nb_rx; i++) {
      struct rte_mbuf *pkt = pkts_burst[i];

      struct udp_header_extra *udp_hdr = rte_pktmbuf_mtod_offset(
          pkt, struct udp_header_extra *,
          sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
      uint16_t dst_port = rte_be_to_cpu_16(udp_hdr->udp_hdr.dst_port);
      int flow_num = dst_port - PORT_NUM;

      if (flow_num < 0 || flow_num >= MAX_FLOWS) {
        // this is a bad packet
        rte_pktmbuf_free(pkt);
        continue;
      }
      received_packets += nb_rx;

      // printf("Debug: Enqueuing packet for flow %d, seq %lu\n", flow_num,
      // udp_hdr->seq);

      if (rte_ring_enqueue(flow_rings[flow_num], pkt) < 0) {
        // printf("Error: Failed to enqueue packet to flow %d, seq %lu. Ring
        // free space: %u\n",
        //        flow_num, udp_hdr->seq,
        //        rte_ring_free_count(flow_rings[flow_num]));
        rte_pktmbuf_free(pkt);
      }
    }

    // Check RX descriptor status
    // uint16_t nb_rx_desc = rte_eth_rx_queue_count(rx_port, 0);
    // if (nb_rx_desc > RX_RING_SIZE / 2) {
    //     printf("Warning: RX descriptor queue is more than half full. Current
    //     count: %u\n", nb_rx_desc);
    // }
  }

  return 0;
}

void init_flow_state() {
  flow_state = new flow_state_receiver();
  flow_state->advertised_window = WINDOW_SIZE;
  for (int i = 0; i < MAX_FLOWS; i++) {
    flow_state->next_seq_num_expected[i] = 1;
    flow_state->last_read[i] = 0;
    flow_state->last_received[i] = 0;
  }
}

int main(int argc, char *argv[]) {
  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);
  // struct rte_mempool *mbuf_pool;
  unsigned nb_ports = 1;
  uint16_t portid = 1;

  /* Initializion the Environment Abstraction Layer (EAL). 8< */

  int ret = rte_eal_init(argc, argv);
  if (ret < 0)
    rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
  /* >8 End of initialization the Environment Abstraction Layer (EAL). */

  argc -= ret;
  argv += ret;

  nb_ports = rte_eth_dev_count_avail();
  /* Allocates mempool to hold the mbufs. 8< */
  mbuf_pool =
      rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS, MBUF_CACHE_SIZE, 0,
                              RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
  /* >8 End of allocating mempool to hold mbuf. */

  if (mbuf_pool == NULL)
    rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

  /* Initializing all ports. 8< */
  RTE_ETH_FOREACH_DEV(portid)
  if (portid == 1 && port_init(portid, mbuf_pool) != 0)
    rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n", portid);

  // 创建 flow rings
  for (int i = 0; i < MAX_FLOWS; i++) {
    char ring_name[32];
    snprintf(ring_name, sizeof(ring_name), "flow_ring_%d", i);
    flow_rings[i] = rte_ring_create(ring_name, RING_SIZE, rte_socket_id(),
                                    RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (flow_rings[i] == NULL)
      rte_exit(EXIT_FAILURE, "Cannot create ring for flow %d\n", i);
  }
  init_flow_state();

  //
  unsigned lcore_id = rte_get_next_lcore(-1, 1, 0);
  if (lcore_id == RTE_MAX_LCORE)
    rte_exit(EXIT_FAILURE, "Not enough cores\n");
  rte_eal_remote_launch(rx_thread, NULL, lcore_id);
  // unsigned lcore_id;
  // for (unsigned i = 0; i < 2; i++) {
  //         lcore_id = rte_get_next_lcore(-1, 1, 0);
  //         if (lcore_id == RTE_MAX_LCORE)
  //             rte_exit(EXIT_FAILURE, "Not enough cores\n");

  //         unsigned *queue_id = (unsigned *)rte_malloc("queue_id",
  //         sizeof(unsigned), 0); *queue_id = i;
  //         rte_eal_remote_launch(rx_thread, queue_id, lcore_id);
  //     }

  //
  for (int i = 0; i < MAX_FLOWS; i++) {
    lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
    if (lcore_id == RTE_MAX_LCORE)
      rte_exit(EXIT_FAILURE, "Not enough cores\n");
    int *arg = (int *)malloc(sizeof(int));
    *arg = i;
    rte_eal_remote_launch(process_thread, arg, lcore_id);
  }

  //
  rte_eal_mp_wait_lcore();
  rte_eal_cleanup();
  return 0;
}
