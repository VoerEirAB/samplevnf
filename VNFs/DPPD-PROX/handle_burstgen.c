/*
 * handle_burstgen.c - PROX task mode "burstgen"
 *
 * Alternates between two line rates: normal phase at "bps" for
 * "normal_time" seconds, then burst phase at "burst_bps" for
 * "burst_time" seconds. Cycles for the full run.
 *
 * Packet templates are loaded from a pcap file. The pcap defines the
 * complete frame (MACs, IPs, ports, sizes for IMIX). At send time a
 * phase marker is stamped at seq_no_offset (default 42):
 *   value 1 - normal phase packet
 *   value 2 - burst phase packet
 *
 * The receiver (mode=flowcount with burst=yes) reads this to count
 * normal-phase RX vs burst-phase RX, enabling per-phase loss measurement.
 *
 * The task runs until stopped externally via the PROX socket:
 *   start <core> <task>              - begin generating
 *   stop  <core> <task>              - stop
 *   burstgen stats <core> <task>     - query normal/burst TX counts
 *
 * Registers as: mode=burstgen
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
#include "handle_burstgen.h"

// limits
#define BG_MAX_TEMPLATES  16
#define BG_MAX_PKT        1518

/* Phase marker values written into payload (read by flowcount receiver) */
#define BG_PHASE_NORMAL   ((uint64_t)1)
#define BG_PHASE_BURST    ((uint64_t)2)

// packet template
struct bg_template {
	uint8_t  buf[BG_MAX_PKT];
	uint16_t len;
	uint16_t l2_len;
};

// task struct
struct task_burstgen {
	struct task_base  base;           /* MUST be first */
	struct local_mbuf local_mbuf;
	struct token_time token_time;

	/* templates from pcap */
	struct bg_template templates[BG_MAX_TEMPLATES];
	uint32_t           n_templates;
	uint32_t           cur_template;

	/* phase marker offset */
	uint16_t  seq_no_offset;

	/* rate / phase state */
	uint64_t  normal_bps;
	uint64_t  burst_bps;
	uint64_t  normal_time_tsc;
	uint64_t  burst_time_tsc;
	uint64_t  phase_end_tsc;
	int       cur_phase;  /* 1=normal, 2=burst */

	/* stats */
	uint64_t  normal_tx;
	uint64_t  burst_tx;

	uint32_t  socket_id;
	uint64_t  hz;
} __rte_cache_aligned;

// TX mempool
static struct rte_mempool *burstgen_create_mempool(struct task_args *targ)
{
	char pool_name[32];
	const int sock = rte_lcore_to_socket_id(targ->lconf->id);

	snprintf(pool_name, sizeof(pool_name), "burstgen_pool%u", targ->lconf->id);

	struct rte_mempool *ret =
		rte_mempool_create(pool_name, targ->nb_mbuf - 1,
				   TX_MBUF_SIZE, targ->nb_cache_mbuf,
				   sizeof(struct rte_pktmbuf_pool_private),
				   rte_pktmbuf_pool_init, NULL,
				   rte_pktmbuf_init, NULL, sock, 0);
	PROX_PANIC(ret == NULL,
		   "[burstgen] Failed to create TX mempool on socket %d\n", sock);
	return ret;
}

// init
static void init_task_burstgen(struct task_base *tbase, struct task_args *targ)
{
	struct task_burstgen *task = (struct task_burstgen *)tbase;

	task->socket_id = rte_lcore_to_socket_id(targ->lconf->id);
	task->hz        = rte_get_tsc_hz();

	/* load pcap templates */
	PROX_PANIC(targ->pcap_file[0] == '\0',
		   "[burstgen] 'pcap file=' is required\n");

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *h = pcap_open_offline(targ->pcap_file, errbuf);
	PROX_PANIC(h == NULL, "[burstgen] pcap_open_offline('%s'): %s\n",
		   targ->pcap_file, errbuf);

	struct pcap_pkthdr *hdr;
	const uint8_t *data;

	while (task->n_templates < BG_MAX_TEMPLATES &&
	       pcap_next_ex(h, &hdr, (const u_char **)&data) == 1) {
		struct bg_template *t = &task->templates[task->n_templates++];
		uint16_t len = hdr->caplen < BG_MAX_PKT
			     ? (uint16_t)hdr->caplen : BG_MAX_PKT;
		memcpy(t->buf, data, len);
		t->len = len;
		/* l2_len: Ethernet header plus any VLAN/QinQ tags */
		t->l2_len = sizeof(prox_rte_ether_hdr);

		prox_rte_ether_hdr *eth = (prox_rte_ether_hdr *)t->buf;
 		uint16_t etype = eth->ether_type;
 		while (((etype == ETYPE_8021ad) || (etype == ETYPE_VLAN)) &&
 		       (t->l2_len + sizeof(prox_rte_vlan_hdr) < t->len)) {
 			prox_rte_vlan_hdr *vlan = (prox_rte_vlan_hdr *)(t->buf + t->l2_len);
 			t->l2_len += 4;
 			etype = vlan->eth_proto;
		}
	} 
	pcap_close(h);

	PROX_PANIC(task->n_templates == 0,
		   "[burstgen] No packets found in pcap '%s'\n", targ->pcap_file);
	plog_info("\t\t[burstgen] Loaded %u template(s) from '%s'\n",
		  task->n_templates, targ->pcap_file);

	/* phase marker offset */
	task->seq_no_offset = targ->flowgen_seq_no_offset
			    ? targ->flowgen_seq_no_offset : 42;

	/* rates */
	task->normal_bps = targ->rate_bps ? targ->rate_bps : 1250000000ULL;
	task->burst_bps  = targ->burstgen_burst_bps
			 ? targ->burstgen_burst_bps : task->normal_bps * 2;

	/* phase timings */
	uint32_t normal_sec = targ->burstgen_normal_time
			    ? targ->burstgen_normal_time : 30;
	uint32_t burst_sec  = targ->burstgen_burst_time
			    ? targ->burstgen_burst_time  : 10;
	task->normal_time_tsc = (uint64_t)normal_sec * task->hz;
	task->burst_time_tsc  = (uint64_t)burst_sec  * task->hz;

	/* start in normal phase */
	task->cur_phase   = 1;
	task->phase_end_tsc = rte_rdtsc() + task->normal_time_tsc;

	/* token time */
	struct token_time_cfg tt_cfg =
		token_time_cfg_create(1250000000, task->hz, -1);
	token_time_init(&task->token_time, &tt_cfg);
	token_time_set_bpp(&task->token_time, task->normal_bps);
	token_time_reset(&task->token_time, rte_rdtsc(), 0);

	/* TX mempool */
	task->local_mbuf.mempool = burstgen_create_mempool(targ);

	plog_info("\t\t[burstgen] Init: templates=%u normal=%" PRIu64
		  "bps/%us burst=%" PRIu64 "bps/%us seq_no_offset=%u\n",
		  task->n_templates, task->normal_bps, normal_sec,
		  task->burst_bps, burst_sec, task->seq_no_offset);
}

// hot path
static int handle_burstgen_bulk(struct task_base *tbase,
				__attribute__((unused)) struct rte_mbuf **mbufs,
				__attribute__((unused)) uint16_t n_pkts)
{
	struct task_burstgen *task = (struct task_burstgen *)tbase;
	const uint64_t now = rte_rdtsc();

	/* phase toggle */
	if (unlikely(now >= task->phase_end_tsc)) {
		task->cur_phase = (task->cur_phase == 1) ? 2 : 1;
		uint64_t new_bps   = (task->cur_phase == 1)
				   ? task->normal_bps : task->burst_bps;
		uint64_t phase_tsc = (task->cur_phase == 1)
				   ? task->normal_time_tsc : task->burst_time_tsc;
		task->phase_end_tsc = now + phase_tsc;
		token_time_set_bpp(&task->token_time, new_bps);
		token_time_reset(&task->token_time, now, 0);
	}

	token_time_update(&task->token_time, now);

	/* calculate send_bulk (IMIX-aware) */
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
	uint64_t phase_marker = (uint64_t)task->cur_phase;

	for (uint32_t i = 0; i < send_bulk; i++) {
		struct bg_template *tmpl =
			&task->templates[task->cur_template];
		task->cur_template =
			(task->cur_template + 1) % task->n_templates;

		struct rte_mbuf *mbuf = new_pkts[i];
		rte_pktmbuf_pkt_len(mbuf)  = tmpl->len;
		rte_pktmbuf_data_len(mbuf) = tmpl->len;
		init_mbuf_seg(mbuf);

		uint8_t *pkt = rte_pktmbuf_mtod(mbuf, uint8_t *);
		rte_memcpy(pkt, tmpl->buf, tmpl->len);

		/* stamp phase marker at seq_no_offset */
		if (task->seq_no_offset + 8 <= tmpl->len)
			memcpy(pkt + task->seq_no_offset, &phase_marker,
			       sizeof(phase_marker));

		/* recalculate IP checksum (payload bytes changed) */
		if (tmpl->l2_len + (uint16_t)sizeof(prox_rte_ipv4_hdr)
		    <= tmpl->len) {
			prox_rte_ipv4_hdr *ip =
				(prox_rte_ipv4_hdr *)(pkt + tmpl->l2_len);
			if ((ip->version_ihl >> 4) == 4) {
				ip->hdr_checksum = 0;
				prox_ip_cksum_sw(ip);
			}
		}

		tokens_used += pkt_len_to_wire_size(tmpl->len);
	}

	task->token_time.bytes_now -= tokens_used;

	if (task->cur_phase == 1)
		task->normal_tx += send_bulk;
	else
		task->burst_tx  += send_bulk;

	uint8_t out[MAX_PKT_BURST] = {0};
	return tbase->tx_pkt(tbase, new_pkts, send_bulk, out);
}

// stop callback
static void stop_burstgen(struct task_base *tbase)
{
	struct task_burstgen *task = (struct task_burstgen *)tbase;

	plog_info("[burstgen] Stopped: normal_tx=%" PRIu64
		  " burst_tx=%" PRIu64
		  "  (use 'burstgen stats' to query)\n",
		  task->normal_tx, task->burst_tx);
}

// stats command handler
void task_burstgen_print_stats(struct task_base *tbase)
{
	struct task_burstgen *task = (struct task_burstgen *)tbase;

	plogx_info("cur_phase %d\n",      task->cur_phase);
	plogx_info("normal_tx %" PRIu64 "\n", task->normal_tx);
	plogx_info("burst_tx %" PRIu64 "\n",  task->burst_tx);
	plogx_info("total_tx %" PRIu64 "\n",
		   task->normal_tx + task->burst_tx);
}

// task registration
static struct task_init task_init_burstgen = {
	.mode_str      = "burstgen",
	.init          = init_task_burstgen,
	.handle        = handle_burstgen_bulk,
	.stop_last     = stop_burstgen,
	.flag_features = TASK_FEATURE_NEVER_DISCARDS | TASK_FEATURE_NO_RX,
	.size          = sizeof(struct task_burstgen),
};

__attribute__((constructor)) static void reg_task_burstgen(void)
{
	reg_task(&task_init_burstgen);
}
