/*
 * handle_flowgen.c - PROX task mode "flowgen"
 *
 * Generates UDP traffic with a sliding port window. Every interval
 * (flow_interval seconds) the seq_no written into the packet payload
 * increments and the (src_port, dst_port) window advances by regen_rate
 * flows. The receiver (mode=flowcount) detects interval boundaries by
 * reading that value.
 *
 * Packet templates come from a pcap file or are built from config params.
 * In either case, src_port and dst_port are overridden per packet by the
 * window cursor, and seq_no is stamped at seq_no_offset (default 42).
 * The pcap defines MACs, IPs, packet sizes (IMIX) - ports are always
 * overwritten regardless of what the pcap contained.
 *
 * The task runs until stopped externally via the PROX socket:
 *   start <core> <task>              - begin generating
 *   stop  <core> <task>              - stop; stats become available
 *   flowgen stats <core> <task>      - query per-interval TX counts anytime
 *
 * Registers as: mode=flowgen
 *
 * Licensed under the Apache License, Version 2.0.
 */
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>
#include <pcap.h>

#include <rte_mbuf.h>
#include <rte_cycles.h>
#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_mempool.h>

#include "task_base.h"
#include "task_init.h"
#include "lconf.h"
#include "prox_compat.h"
#include "prox_malloc.h"
#include "prox_port_cfg.h"
#include "log.h"
#include "quit.h"
#include "token_time.h"
#include "local_mbuf.h"
#include "mbuf_utils.h"
#include "prox_cksum.h"
#include "etypes.h"
#include "defines.h"
#include "defaults.h"
#include "handle_flowgen.h"

// limits
#define FLOWGEN_MAX_INTERVALS  8192
#define FG_MAX_TEMPLATES       16    /* pcap packets loaded as templates */
#define FG_MAX_PKT             1518  /* max standard Ethernet frame size */

#define FLOWGEN_DEFAULT_SEQ_NO_OFFSET  42

// packet template - loaded from pcap or built from config params
struct fg_template {
	uint8_t  buf[FG_MAX_PKT];
	uint16_t len;
	uint16_t l2_len;     /* bytes before IP header */
	uint16_t l3_len;     /* IP header length */
	uint16_t off_udp_src; /* byte offset of UDP src port */
	uint16_t off_udp_dst; /* byte offset of UDP dst port */
	uint16_t off_ip_dst;  /* byte offset of IPv4 dst addr (0 if n/a) */
};

// task struct
struct task_flowgen {
	struct task_base  base;           /* MUST be first */
	struct local_mbuf local_mbuf;
	struct token_time token_time;
	uint64_t          rate_bps;

	/* packet templates */
	struct fg_template templates[FG_MAX_TEMPLATES];
	uint32_t           n_templates;
	uint32_t           cur_template;

	/* dst IP override (non-pcap path, cycled per packet) */
	uint32_t  dst_ips[16];  /* network byte order */
	uint8_t   n_dst_ips;
	uint8_t   cur_dst_ip_idx;

	/* flow window */
	uint16_t  win_src_start;
	uint16_t  win_dst_start;
	uint16_t  cur_src_port;
	uint16_t  cur_dst_port;
	uint16_t  ports_limit;
	uint16_t  regen_rate;

	/* seqNo */
	uint16_t  seq_no_offset;
	uint64_t  seq_no;

	/* interval timing */
	uint64_t  interval_tsc;
	uint64_t  next_interval_tsc;

	/* per-interval TX stats */
	uint64_t  tx_this_interval;
	uint64_t  interval_tx[FLOWGEN_MAX_INTERVALS];
	uint64_t  interval_seq[FLOWGEN_MAX_INTERVALS];
	uint32_t  interval_idx;

	uint32_t  socket_id;
	uint64_t  hz;
} __rte_cache_aligned;

// l2/l3 length parser (mirrors PROX's parse_l2_l3_len)
static void fg_parse_l2l3_len(const uint8_t *pkt, uint16_t *l2_len,
			       uint16_t *l3_len, uint16_t pkt_len)
{
	*l2_len = sizeof(prox_rte_ether_hdr);
	*l3_len = 0;

	if (pkt_len < *l2_len)
		return;

	const prox_rte_ether_hdr *eth = (const prox_rte_ether_hdr *)pkt;
	uint16_t etype = eth->ether_type;

	while ((etype == ETYPE_8021ad || etype == ETYPE_VLAN) &&
	       pkt_len > *l2_len + (uint16_t)sizeof(prox_rte_vlan_hdr)) {
		const prox_rte_vlan_hdr *v =
			(const prox_rte_vlan_hdr *)(pkt + *l2_len);
		*l2_len += 4;
		etype = v->eth_proto;
	}

	if (etype == ETYPE_IPv4 &&
	    pkt_len >= *l2_len + (uint16_t)sizeof(prox_rte_ipv4_hdr)) {
		const prox_rte_ipv4_hdr *ip =
			(const prox_rte_ipv4_hdr *)(pkt + *l2_len);
		*l3_len = (ip->version_ihl & 0xF) * 4;
	}
}

// TX mempool creation (same pattern as mode=gen)
static struct rte_mempool *flowgen_create_mempool(struct task_args *targ)
{
	char pool_name[32];
	const int sock = rte_lcore_to_socket_id(targ->lconf->id);

	snprintf(pool_name, sizeof(pool_name), "flowgen_pool%u", targ->lconf->id);

	struct rte_mempool *ret =
		rte_mempool_create(pool_name, targ->nb_mbuf - 1,
				   TX_MBUF_SIZE, targ->nb_cache_mbuf,
				   sizeof(struct rte_pktmbuf_pool_private),
				   rte_pktmbuf_pool_init, NULL,
				   rte_pktmbuf_init, NULL, sock, 0);
	PROX_PANIC(ret == NULL,
		   "[flowgen] Failed to create TX mempool on socket %d\n", sock);
	return ret;
}

// init: load templates from pcap
static void flowgen_load_pcap(struct task_flowgen *task, const char *path)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *h = pcap_open_offline(path, errbuf);
	PROX_PANIC(h == NULL, "[flowgen] pcap_open_offline('%s'): %s\n",
		   path, errbuf);

	struct pcap_pkthdr *hdr;
	const uint8_t *data;

	while (task->n_templates < FG_MAX_TEMPLATES &&
	       pcap_next_ex(h, &hdr, (const u_char **)&data) == 1) {
		struct fg_template *t = &task->templates[task->n_templates++];
		uint16_t len = hdr->caplen < FG_MAX_PKT
			     ? (uint16_t)hdr->caplen : FG_MAX_PKT;
		memcpy(t->buf, data, len);
		t->len = len;

		fg_parse_l2l3_len(data, &t->l2_len, &t->l3_len, len);
		t->off_udp_src  = t->l2_len + t->l3_len;
		t->off_udp_dst  = t->l2_len + t->l3_len + 2;
		t->off_ip_dst   = 0; /* not used in pcap mode */
	}
	pcap_close(h);

	PROX_PANIC(task->n_templates == 0,
		   "[flowgen] No packets found in pcap '%s'\n", path);
	plog_info("\t\t[flowgen] Loaded %u template(s) from '%s'\n",
		  task->n_templates, path);
}

// init: build single template from config params
static void flowgen_build_config_template(struct task_flowgen *task,
					  struct task_args *targ)
{
	struct fg_template *t = &task->templates[0];
	task->n_templates = 1;

	uint16_t pkt_size = targ->pkt_size ? targ->pkt_size : 64;
	PROX_PANIC(pkt_size < 42 + 8 || pkt_size > FG_MAX_PKT,
		   "[flowgen] pkt_size=%u out of range\n", pkt_size);

	memset(t->buf, 0, pkt_size);
	t->len    = pkt_size;
	t->l2_len = 14;
	t->l3_len = 20;
	t->off_udp_src = 34;
	t->off_udp_dst = 36;
	t->off_ip_dst  = 30;  /* will be overridden per packet */

	/* Ethernet header */
	prox_rte_ether_hdr *eth = (prox_rte_ether_hdr *)t->buf;
	memcpy(&eth->d_addr, &targ->edaddr, sizeof(prox_rte_ether_addr));
	if (!rte_is_zero_ether_addr(&targ->esaddr)) {
		memcpy(&eth->s_addr, &targ->esaddr, sizeof(prox_rte_ether_addr));
	} else {
		struct prox_port_cfg *port = find_reachable_port(targ);
		if (port)
			memcpy(&eth->s_addr, &port->eth_addr,
			       sizeof(prox_rte_ether_addr));
	}
	eth->ether_type = ETYPE_IPv4;

	/* IPv4 header */
	prox_rte_ipv4_hdr *ip = (prox_rte_ipv4_hdr *)(t->buf + 14);
	ip->version_ihl     = 0x45;
	ip->total_length    = rte_cpu_to_be_16(pkt_size - 14);
	ip->fragment_offset = rte_cpu_to_be_16(0x4000);
	ip->time_to_live    = 64;
	ip->next_proto_id   = IPPROTO_UDP;
	ip->src_addr        = rte_cpu_to_be_32(targ->local_ipv4);
	ip->dst_addr        = 0; /* overridden per packet */
	ip->hdr_checksum    = 0;

	/* UDP header */
	prox_rte_udp_hdr *udp = (prox_rte_udp_hdr *)(t->buf + 34);
	udp->dgram_len  = rte_cpu_to_be_16(pkt_size - 34);
	udp->dgram_cksum = 0;

	/* dst IPs for cycling */
	task->n_dst_ips = targ->flowgen_n_dst_ips;
	for (int i = 0; i < task->n_dst_ips; i++)
		task->dst_ips[i] = rte_cpu_to_be_32(targ->flowgen_dst_ips[i]);

	if (task->n_dst_ips == 0 && targ->remote_ipv4 != 0) {
		task->dst_ips[0] = rte_cpu_to_be_32(targ->remote_ipv4);
		task->n_dst_ips = 1;
	}
	PROX_PANIC(task->n_dst_ips == 0,
		   "[flowgen] No dst IPs configured (use flowgen_n_dst_ips or remote_ipv4)\n");
	plog_info("\t\t[flowgen] Built template from config: pkt_size=%u dst_ips=%u\n",
		  pkt_size, task->n_dst_ips);
}

// init
static void init_task_flowgen(struct task_base *tbase, struct task_args *targ)
{
	struct task_flowgen *task = (struct task_flowgen *)tbase;

	task->socket_id = rte_lcore_to_socket_id(targ->lconf->id);
	task->hz        = rte_get_tsc_hz();

	/* templates */
	if (targ->pcap_file[0])
		flowgen_load_pcap(task, targ->pcap_file);
	else
		flowgen_build_config_template(task, targ);

	/* seq_no offset */
	task->seq_no_offset = targ->flowgen_seq_no_offset
			    ? targ->flowgen_seq_no_offset
			    : FLOWGEN_DEFAULT_SEQ_NO_OFFSET;


	/* sanity checks on templates */
	for (uint32_t i = 0; i < task->n_templates; i++) {
 		struct fg_template *tmpl = &task->templates[i];
 		PROX_PANIC(tmpl->l3_len == 0 ||
 			   tmpl->l2_len + tmpl->l3_len + sizeof(prox_rte_udp_hdr) > tmpl->len ||
 			   task->seq_no_offset + sizeof(task->seq_no) > tmpl->len,
 			   "[flowgen] Template %u not IPv4/UDP or too short for seq_no_offset=%u\n",
 			   i, task->seq_no_offset);
 		prox_rte_ipv4_hdr *ip = (prox_rte_ipv4_hdr *)(tmpl->buf + tmpl->l2_len);
 		PROX_PANIC(ip->next_proto_id != IPPROTO_UDP,
 			   "[flowgen] Template %u is not UDP (proto=%u)\n",
 			   i, ip->next_proto_id);
 	}

	/* flow window */
	task->win_src_start = targ->flowgen_min_src_port
			    ? (uint16_t)targ->flowgen_min_src_port : 1024;
	task->win_dst_start = targ->flowgen_min_dst_port
			    ? (uint16_t)targ->flowgen_min_dst_port : 1024;
	task->ports_limit   = targ->flowgen_flow_rate
			    ? (uint16_t)targ->flowgen_flow_rate  : 1000;
	task->regen_rate    = targ->flowgen_regen_rate
			    ? (uint16_t)targ->flowgen_regen_rate : 100;
	task->cur_src_port  = task->win_src_start;
	task->cur_dst_port  = task->win_dst_start;
	task->seq_no        = 1;

	/* interval timing */
	uint32_t interval_sec = targ->flowgen_flow_interval
			      ? targ->flowgen_flow_interval : 60;
	task->interval_tsc      = (uint64_t)interval_sec * task->hz;
	task->next_interval_tsc = rte_rdtsc() + task->interval_tsc;

	/* rate / token time (base = 10 Gbps, same as mode=gen) */
	task->rate_bps = targ->rate_bps ? targ->rate_bps : 1250000000ULL;
	struct token_time_cfg tt_cfg =
		token_time_cfg_create(1250000000, task->hz, -1);
	token_time_init(&task->token_time, &tt_cfg);
	token_time_set_bpp(&task->token_time, task->rate_bps);
	token_time_reset(&task->token_time, rte_rdtsc(), 0);

	/* TX mempool */
	task->local_mbuf.mempool = flowgen_create_mempool(targ);

	plog_info("\t\t[flowgen] Init: templates=%u flow_rate=%u "
		  "regen=%u interval=%us seq_no_offset=%u rate=%" PRIu64 " bps\n",
		  task->n_templates, task->ports_limit, task->regen_rate,
		  interval_sec, task->seq_no_offset, task->rate_bps);
}

// hot path
static int handle_flowgen_bulk(struct task_base *tbase,
			       __attribute__((unused)) struct rte_mbuf **mbufs,
			       __attribute__((unused)) uint16_t n_pkts)
{
	struct task_flowgen *task = (struct task_flowgen *)tbase;
	const uint64_t now = rte_rdtsc();

	/* interval boundary */
	if (unlikely(now >= task->next_interval_tsc)) {
		if (task->interval_idx < FLOWGEN_MAX_INTERVALS) {
			task->interval_seq[task->interval_idx] = task->seq_no;
			task->interval_tx[task->interval_idx]  = task->tx_this_interval;
			task->interval_idx++;
		}
		task->tx_this_interval = 0;
		task->seq_no++;
		task->win_src_start =
			(uint16_t)(task->win_src_start + task->regen_rate);
		task->cur_src_port = task->win_src_start;
		task->cur_dst_port = task->win_dst_start;
		task->next_interval_tsc += task->interval_tsc;
	}

	token_time_update(&task->token_time, now);

	/* calculate send_bulk: iterate templates to account for IMIX sizes */
	uint32_t send_bulk = 0;
	uint32_t tmpl_idx  = task->cur_template;
	uint64_t avail     = task->token_time.bytes_now;

	for (uint32_t i = 0; i < MAX_PKT_BURST; i++) {
		uint16_t wire =
			pkt_len_to_wire_size(task->templates[tmpl_idx].len);
		if (avail < wire)
			break;
		avail -= wire;
		tmpl_idx = (tmpl_idx + 1) % task->n_templates;
		send_bulk++;
	}
	if (send_bulk == 0)
		return 0;

	struct rte_mbuf **new_pkts =
		local_mbuf_refill_and_take(&task->local_mbuf, send_bulk);
	if (unlikely(new_pkts == NULL))
		return 0;

	uint64_t tokens_used = 0;

	for (uint32_t i = 0; i < send_bulk; i++) {
		struct fg_template *tmpl =
			&task->templates[task->cur_template];
		task->cur_template =
			(task->cur_template + 1) % task->n_templates;

		struct rte_mbuf *mbuf = new_pkts[i];
		rte_pktmbuf_pkt_len(mbuf)  = tmpl->len;
		rte_pktmbuf_data_len(mbuf) = tmpl->len;
		init_mbuf_seg(mbuf);

		uint8_t *pkt = rte_pktmbuf_mtod(mbuf, uint8_t *);
		rte_memcpy(pkt, tmpl->buf, tmpl->len);

		/* override dst IP (config mode only; pcap has it embedded) */
		if (task->n_dst_ips > 0) {
			*(uint32_t *)(pkt + tmpl->off_ip_dst) =
				task->dst_ips[task->cur_dst_ip_idx];
			task->cur_dst_ip_idx =
				(task->cur_dst_ip_idx + 1) % task->n_dst_ips;
		}

		/* stamp src/dst ports */
		*(uint16_t *)(pkt + tmpl->off_udp_src) =
			rte_cpu_to_be_16(task->cur_src_port);
		*(uint16_t *)(pkt + tmpl->off_udp_dst) =
			rte_cpu_to_be_16(task->cur_dst_port);

		/* advance port cursor */
		task->cur_src_port++;
		if (task->cur_src_port >=
		    (uint16_t)(task->win_src_start + task->ports_limit)) {
			task->cur_src_port = task->win_src_start;
			task->cur_dst_port++;
			if (task->cur_dst_port >=
			    (uint16_t)(task->win_dst_start + task->ports_limit))
				task->cur_dst_port = task->win_dst_start;
		}

		/* stamp seq_no */
		memcpy(pkt + task->seq_no_offset, &task->seq_no,
		       sizeof(task->seq_no));

		/* recalculate IP checksum (dst or ports may have changed) */
		prox_rte_ipv4_hdr *ip =
			(prox_rte_ipv4_hdr *)(pkt + tmpl->l2_len);
		ip->hdr_checksum = 0;
		prox_ip_cksum_sw(ip);

		tokens_used += pkt_len_to_wire_size(tmpl->len);
	}

	task->token_time.bytes_now -= tokens_used;
	task->tx_this_interval    += send_bulk;

	uint8_t out[MAX_PKT_BURST] = {0};
	return tbase->tx_pkt(tbase, new_pkts, send_bulk, out);
}

// stop callback
static void stop_flowgen(struct task_base *tbase)
{
	struct task_flowgen *task = (struct task_flowgen *)tbase;

	/* flush in-progress interval */
	if (task->interval_idx < FLOWGEN_MAX_INTERVALS) {
		task->interval_seq[task->interval_idx] = task->seq_no;
		task->interval_tx[task->interval_idx]  = task->tx_this_interval;
		task->interval_idx++;
	}

	uint64_t total = 0;
	for (uint32_t i = 0; i < task->interval_idx; i++)
		total += task->interval_tx[i];

	plog_info("[flowgen] Stopped: %u intervals, total_tx=%" PRIu64
		  "  (use 'flowgen stats' to query per-interval breakdown)\n",
		  task->interval_idx, total);
}

// stats command handler (called from cmd_parser)
void task_flowgen_print_stats(struct task_base *tbase)
{
	struct task_flowgen *task = (struct task_flowgen *)tbase;
	uint64_t total = 0;

	plogx_info("n_intervals %u\n", task->interval_idx);
	for (uint32_t i = 0; i < task->interval_idx; i++) {
		plogx_info("interval %u seq_no %" PRIu64 " tx %" PRIu64 "\n",
			   i, task->interval_seq[i], task->interval_tx[i]);
		total += task->interval_tx[i];
	}
	/* current (in-progress) interval */
	plogx_info("current seq_no %" PRIu64 " tx_in_progress %" PRIu64 "\n",
		   task->seq_no, task->tx_this_interval);
	plogx_info("total_tx %" PRIu64 "\n", total + task->tx_this_interval);
}

// task registration
static struct task_init task_init_flowgen = {
	.mode_str      = "flowgen",
	.init          = init_task_flowgen,
	.handle        = handle_flowgen_bulk,
	.stop_last     = stop_flowgen,
	.flag_features = TASK_FEATURE_NEVER_DISCARDS | TASK_FEATURE_NO_RX,
	.size          = sizeof(struct task_flowgen),
};

__attribute__((constructor)) static void reg_task_flowgen(void)
{
	reg_task(&task_init_flowgen);
}
