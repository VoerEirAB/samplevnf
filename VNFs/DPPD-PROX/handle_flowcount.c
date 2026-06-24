/*
 * handle_flowcount.c - PROX task mode "flowcount"
 *
 * Receiver for both flowgen (flow mode) and burstgen (burst mode).
 * Which mode to use is controlled by the "burst=yes/no" config key.
 *
 * Flow mode (burst=no, default):
 *   Reads seq_no from the payload (at seq_no_offset, default 42).
 *   When seq_no increases, a new interval has started - flush the
 *   previous interval stats (packet count, unique flow count) and
 *   reset the flow hash. Reports per-interval breakdown per sender IP.
 *
 * Burst mode (burst=yes):
 *   Reads the phase marker from the same payload offset.
 *   Value 1 = normal phase packet, value 2 = burst phase packet.
 *   Counts normal_rx and burst_rx separately. No interval logic.
 *
 * Stats are queried live or after stop via the socket:
 *   flowcount stats <core> <task>
 *
 * Registers as: mode=flowcount
 *
 * Licensed under the Apache License, Version 2.0.
 */
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>

#include <rte_mbuf.h>
#include <rte_cycles.h>
#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_hash.h>
#include <rte_hash_crc.h>
#include <rte_malloc.h>

#include "task_base.h"
#include "task_init.h"
#include "lconf.h"
#include "prox_compat.h"
#include "prox_malloc.h"
#include "prox_port_cfg.h"
#include "log.h"
#include "quit.h"
#include "mbuf_utils.h"
#include "etypes.h"
#include "arp.h"
#include "defines.h"
#include "defaults.h"
#include "handle_flowcount.h"

// limits
#define FLOWCOUNT_MAX_SRCS       16
#define FLOWCOUNT_MAX_INTERVALS  8192
#define FLOWCOUNT_DEFAULT_HASH_SIZE 65536

/* Default payload offset for the 8-byte seq_no field */
#define FLOWCOUNT_DEFAULT_SEQ_NO_OFFSET  42

/* Fixed Ethernet frame offsets */
#define ETH_HDR_LEN    14
#define IPV4_HDR_LEN   20
#define UDP_HDR_LEN     8
/* MIN_UDP_PKT: shortest possible untagged IPv4/UDP frame. Used as a
 * quick pre-filter only; actual per-packet offsets are computed
 * dynamically after walking any VLAN tags and reading the IP IHL. */
#define MIN_UDP_PKT    (ETH_HDR_LEN + IPV4_HDR_LEN + UDP_HDR_LEN + 1)

// per-interval stats
struct fc_interval {
	uint64_t seq_no;
	uint64_t pkts;
	uint32_t flows;
};

// per-sender state
struct src_state {
	uint32_t          ip;               /* sender IP, network byte order */
	uint64_t          last_seq_no;
	uint64_t          pkt_count;        /* packets in current interval */
	uint32_t          flow_count;       /* unique flows in current interval */
	struct rte_hash  *flow_hash;        /* key = (src_port<<16|dst_port) u32 */

	struct fc_interval intervals[FLOWCOUNT_MAX_INTERVALS];
	uint32_t           interval_idx;
};

// task struct
struct task_flowcount {
	struct task_base   base;            /* MUST be first */

	struct src_state   srcs[FLOWCOUNT_MAX_SRCS];
	uint8_t            n_srcs;

	/* ARP responder (optional) */
	int                arp_enabled;
	uint32_t           self_ip;         /* network byte order */
	prox_rte_ether_addr self_mac;

	/* seq_no payload offset */
	uint16_t           seq_no_offset;

	/* burst-mode RX counting (enabled when burst=yes in cfg) */
	int                burst_mode;
	uint64_t           normal_rx;   /* packets with phase marker == 1 */
	uint64_t           burst_rx;    /* packets with phase marker == 2 */

	/* discard counter */
	uint64_t           discarded;

	uint32_t           socket_id;
	uint64_t           hz;
} __rte_cache_aligned;

// helper: find src_state by IP (linear, n_srcs <= 16)
static inline struct src_state *
find_src(struct task_flowcount *task, uint32_t ip_net)
{
	for (int i = 0; i < task->n_srcs; i++)
		if (task->srcs[i].ip == ip_net)
			return &task->srcs[i];
	return NULL;
}

// helper: flush current interval into intervals[]
static void flush_interval(struct src_state *s)
{
	if (s->interval_idx >= FLOWCOUNT_MAX_INTERVALS)
		return;
	struct fc_interval *iv = &s->intervals[s->interval_idx++];
	iv->seq_no = s->last_seq_no;
	iv->pkts   = s->pkt_count;
	iv->flows  = s->flow_count;
	s->pkt_count  = 0;
	s->flow_count = 0;
	if (s->flow_hash)
		rte_hash_reset(s->flow_hash);
}

// init
static void init_task_flowcount(struct task_base *tbase,
				struct task_args *targ)
{
	struct task_flowcount *task = (struct task_flowcount *)tbase;

	task->socket_id = rte_lcore_to_socket_id(targ->lconf->id);
	task->hz        = rte_get_tsc_hz();

	// seq_no offset
	task->seq_no_offset = targ->flowgen_seq_no_offset
			    ? targ->flowgen_seq_no_offset
			    : FLOWCOUNT_DEFAULT_SEQ_NO_OFFSET;

	// known sender IPs
	task->n_srcs = targ->flowcount_n_src_ips;
	PROX_PANIC(task->n_srcs == 0,
		   "[flowcount] At least one 'src ip=' entry required\n");

	uint32_t hash_size = targ->flowcount_flow_hash_size
			   ? targ->flowcount_flow_hash_size
			   : FLOWCOUNT_DEFAULT_HASH_SIZE;

	static char hname[64];
	for (int i = 0; i < task->n_srcs; i++) {
		struct src_state *s = &task->srcs[i];
		s->ip          = rte_cpu_to_be_32(targ->flowcount_src_ips[i]);
		s->last_seq_no = 0;
		s->pkt_count   = 0;
		s->flow_count  = 0;
		s->interval_idx = 0;

		snprintf(hname, sizeof(hname),
			 "fc_flow_hash_%d_%d", targ->lconf->id, i);
		struct rte_hash_parameters hp = {
			.name             = hname,
			.entries          = hash_size,
			.key_len          = sizeof(uint32_t),
			.hash_func        = rte_hash_crc,
			.hash_func_init_val = 0,
			.socket_id        = (int)task->socket_id,
		};
		s->flow_hash = rte_hash_create(&hp);
		PROX_PANIC(s->flow_hash == NULL,
			   "[flowcount] Failed to create flow hash for src %d\n", i);
	}

	// ARP / self IP
	task->arp_enabled = targ->flowcount_arp_enabled;
	task->self_ip     = rte_cpu_to_be_32(targ->flowcount_self_ip);

	if (task->arp_enabled) {
		struct prox_port_cfg *port = find_reachable_port(targ);
		if (port)
			memcpy(&task->self_mac, &port->eth_addr,
			       sizeof(prox_rte_ether_addr));
		else
			plog_warn("[flowcount] ARP enabled but no reachable TX "
				  "port found - ARP replies will have zero MAC\n");
	}

	/* burst counting mode *//* burst counting mode */
        task->burst_mode = targ->flowcount_burst_mode;

	plog_info("\t\t[flowcount] Init: n_srcs=%u seq_no_offset=%u "
		  "arp=%s burst_mode=%s\n",
		  task->n_srcs, task->seq_no_offset,
		  task->arp_enabled ? "yes" : "no",
		  task->burst_mode ? "yes" : "no");
}

// hot path
static int handle_flowcount_bulk(struct task_base *tbase,
				 struct rte_mbuf **mbufs,
				 uint16_t n_pkts)
{
	struct task_flowcount *task = (struct task_flowcount *)tbase;

	for (uint16_t i = 0; i < n_pkts; i++) {
		struct rte_mbuf *mbuf = mbufs[i];
		uint32_t pkt_len = rte_pktmbuf_pkt_len(mbuf);
		uint8_t *pkt     = rte_pktmbuf_mtod(mbuf, uint8_t *);

		if (unlikely(pkt_len < ETH_HDR_LEN)) {
			task->discarded++;
			rte_pktmbuf_free(mbuf);
			continue;
		}

		prox_rte_ether_hdr *eth = (prox_rte_ether_hdr *)pkt;

		/* Walk any 802.1Q / 802.1ad VLAN tags to find the real
		 * EtherType and the actual start of the L3 header. */
		uint16_t l2_len = (uint16_t)sizeof(prox_rte_ether_hdr);
		uint16_t etype  = eth->ether_type;

		while ((etype == ETYPE_8021ad || etype == ETYPE_VLAN) &&
		       pkt_len > (uint32_t)(l2_len +
					  sizeof(prox_rte_vlan_hdr))) {
			const prox_rte_vlan_hdr *v =
				(const prox_rte_vlan_hdr *)(pkt + l2_len);
			l2_len += 4;
			etype = v->eth_proto;
		}

		// IPv4 UDP path
		if (etype == ETYPE_IPv4) {

			/* Reject frames that cannot hold even a minimal
			 * IPv4/UDP header after whatever L2 tags were present. */
			if (unlikely(pkt_len < (uint32_t)(l2_len +
						IPV4_HDR_LEN + UDP_HDR_LEN + 1))) {
				task->discarded++;
				rte_pktmbuf_free(mbuf);
				continue;
			}

			prox_rte_ipv4_hdr *ip =
				(prox_rte_ipv4_hdr *)(pkt + l2_len);

			if (ip->next_proto_id != IPPROTO_UDP) {
				task->discarded++;
				rte_pktmbuf_free(mbuf);
				continue;
			}

			/* Read actual IP header length (handles options). */
			uint16_t l3_len = (uint16_t)((ip->version_ihl & 0xF) * 4);
			if (unlikely(l3_len < IPV4_HDR_LEN)) {
				task->discarded++;
				rte_pktmbuf_free(mbuf);
				continue;
			}
			uint16_t l4_off = l2_len + l3_len;

			if (unlikely(pkt_len < (uint32_t)(l4_off + UDP_HDR_LEN + 1))) {
				task->discarded++;
				rte_pktmbuf_free(mbuf);
				continue;
			}

			uint32_t src_ip = ip->src_addr; /* network order */

			struct src_state *s = find_src(task, src_ip);
			if (unlikely(s == NULL)) {
				task->discarded++;
				rte_pktmbuf_free(mbuf);
				continue;
			}

			/* seq_no is stored at fixed offset in the payload */
			if (unlikely(pkt_len <
				     (uint32_t)task->seq_no_offset + 8)) {
				task->discarded++;
				rte_pktmbuf_free(mbuf);
				continue;
			}
			uint64_t seq_no;
			memcpy(&seq_no, pkt + task->seq_no_offset,
			       sizeof(seq_no));

			if (unlikely(seq_no < s->last_seq_no)) {
				/* late / reordered - discard */
				task->discarded++;
				rte_pktmbuf_free(mbuf);
				continue;
			}

			// burst mode: count by phase marker
			if (task->burst_mode) {
				if (seq_no == 1)
					task->normal_rx++;
				else if (seq_no == 2)
					task->burst_rx++;
				else
					task->discarded++;
				s->pkt_count++;
				rte_pktmbuf_free(mbuf);
				continue;
			}

			// flow mode: interval boundary
			if (seq_no > s->last_seq_no) {
				/* last_seq_no == 0: first boundary, skip flush
				 * to avoid phantom {seq_no:0} entry. */
				if (s->last_seq_no > 0)
					flush_interval(s);
				else if (s->flow_hash)
					rte_hash_reset(s->flow_hash);
				s->last_seq_no = seq_no;
			}

			// count unique flow
			prox_rte_udp_hdr *udp =
				(prox_rte_udp_hdr *)(pkt + l4_off);
			uint32_t flow_key =
				((uint32_t)rte_be_to_cpu_16(udp->src_port) << 16)
				| rte_be_to_cpu_16(udp->dst_port);

			int ret = rte_hash_add_key(s->flow_hash, &flow_key);
			if (ret >= 0)
				s->flow_count++; /* newly seen pair */

			s->pkt_count++;
			rte_pktmbuf_free(mbuf);

		// ARP path (untagged only; VLAN-encapsulated ARP not supported)
		} else if (etype == ETYPE_ARP && task->arp_enabled) {

			if (unlikely(pkt_len < sizeof(struct ether_hdr_arp))) {
				task->discarded++;
				rte_pktmbuf_free(mbuf);
				continue;
			}

			struct ether_hdr_arp *ha =
				(struct ether_hdr_arp *)pkt;
			struct my_arp_t *arp = &ha->arp;

			if (arp->oper  == ARP_REQUEST &&
			    arp->data.tpa == task->self_ip) {
				/*
				 * build_arp_reply modifies the packet in-place:
				 * swaps src/dst MACs, sets oper=REPLY,
				 * fills SHA with our MAC.
				 */
				build_arp_reply(&ha->ether_hdr,
						&task->self_mac, arp);
				uint8_t out = 0; /* TX on port/ring 0 */
				tbase->tx_pkt(tbase, &mbuf, 1, &out);
			} else {
				task->discarded++;
				rte_pktmbuf_free(mbuf);
			}

		} else {
			task->discarded++;
			rte_pktmbuf_free(mbuf);
		}
	}

	return 0;
}

// stop callback
static void stop_flowcount(struct task_base *tbase)
{
	struct task_flowcount *task = (struct task_flowcount *)tbase;

	/* flush in-progress interval for each sender */
	for (int si = 0; si < task->n_srcs; si++)
		flush_interval(&task->srcs[si]);

	uint64_t total_packets = 0, total_flows = 0;
	for (int si = 0; si < task->n_srcs; si++) {
		struct src_state *s = &task->srcs[si];
		for (uint32_t iv = 0; iv < s->interval_idx; iv++) {
			total_packets += s->intervals[iv].pkts;
			total_flows   += s->intervals[iv].flows;
		}
	}

	if (task->burst_mode) {
		plog_info("[flowcount] Stopped (burst): "
			  "normal_rx=%" PRIu64 " burst_rx=%" PRIu64
			  " discarded=%" PRIu64
			  "  (use 'flowcount stats' to query)\n",
			  task->normal_rx, task->burst_rx, task->discarded);
	} else {
		plog_info("[flowcount] Stopped (flow): "
			  "total_packets=%" PRIu64 " total_flows=%" PRIu64
			  " discarded=%" PRIu64
			  "  (use 'flowcount stats' to query)\n",
			  total_packets, total_flows, task->discarded);
	}
}

// stats command handler (called from cmd_parser)
void task_flowcount_print_stats(struct task_base *tbase)
{
	struct task_flowcount *task = (struct task_flowcount *)tbase;

	if (task->burst_mode) {
		plogx_info("mode burst\n");
		plogx_info("normal_rx %" PRIu64 "\n", task->normal_rx);
		plogx_info("burst_rx %" PRIu64 "\n",  task->burst_rx);
		plogx_info("total_rx %" PRIu64 "\n",
			   task->normal_rx + task->burst_rx);
		plogx_info("discarded %" PRIu64 "\n", task->discarded);
		return;
	}

	plogx_info("mode flow\n");
	plogx_info("n_srcs %u\n", task->n_srcs);
	for (int si = 0; si < task->n_srcs; si++) {
		struct src_state *s = &task->srcs[si];
		uint8_t *b = (uint8_t *)&s->ip;
		char ip[20];
		snprintf(ip, sizeof(ip), "%u.%u.%u.%u",
			 b[0], b[1], b[2], b[3]);

		uint64_t tp = 0, tf = 0;
		plogx_info("src %s n_intervals %u\n", ip, s->interval_idx);
		for (uint32_t iv = 0; iv < s->interval_idx; iv++) {
			plogx_info("src %s interval %u seq_no %" PRIu64
				   " pkts %" PRIu64 " flows %" PRIu32 "\n",
				   ip, iv,
				   s->intervals[iv].seq_no,
				   s->intervals[iv].pkts,
				   s->intervals[iv].flows);
			tp += s->intervals[iv].pkts;
			tf += s->intervals[iv].flows;
		}
		/* include current in-progress interval */
		plogx_info("src %s current pkts %" PRIu64 " flows %" PRIu32 "\n",
			   ip, s->pkt_count, s->flow_count);
		plogx_info("src %s total_pkts %" PRIu64 " total_flows %" PRIu64 "\n",
			   ip, tp + s->pkt_count, tf + s->flow_count);
	}
	plogx_info("discarded %" PRIu64 "\n", task->discarded);
}

// task registration
static struct task_init task_init_flowcount = {
	.mode_str  = "flowcount",
	.init      = init_task_flowcount,
	.handle    = handle_flowcount_bulk,
	.stop_last = stop_flowcount,
	/* Standard RX task - PROX feeds packets from the NIC RX queue. */
	.size      = sizeof(struct task_flowcount),
};

__attribute__((constructor)) static void reg_task_flowcount(void)
{
	reg_task(&task_init_flowcount);
}
