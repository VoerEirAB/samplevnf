/*
// Copyright (c) 2010-2025 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

/* RFC2544 benchmarking of a layer 2 forwarding device.
 *
 * The 'rfc2544gen' tasks offer traffic to the device under test (DUT)
 * while the 'rfc2544lat' tasks receive the frames forwarded back by the
 * DUT. The first generator of a session also drives the test procedure
 * described in RFC2544 section 26: throughput (26.1), latency (26.2)
 * and frame loss rate (26.3).
 *
 * All tasks of a session communicate through a shared session structure.
 * The controller is the only writer of the control fields and each worker
 * is the only writer of its own slot, so no lock is ever taken and the
 * data path stays free of contention.
 */

#include <string.h>
#include <math.h>
#include <inttypes.h>

#include <rte_cycles.h>
#include <rte_ether.h>
#include <rte_mbuf.h>
#include <rte_byteorder.h>
#include <rte_mempool.h>

#include "handle_rfc2544.h"
#include "task_init.h"
#include "task_base.h"
#include "lconf.h"
#include "log.h"
#include "quit.h"
#include "clock.h"
#include "defaults.h"
#include "mbuf_utils.h"
#include "local_mbuf.h"
#include "token_time.h"
#include "prefetch.h"
#include "prox_port_cfg.h"
#include "prox_malloc.h"
#include "prox_shared.h"
#include "prox_compat.h"
#include "prox_assert.h"

#define RFC2544_MAX_GENERATORS	32
#define RFC2544_MAX_RECEIVERS	32
#define RFC2544_LAT_BUCKETS	1024
#define RFC2544_MAX_LOSS_STEPS	16

/* Preamble (7) + start frame delimiter (1) + inter frame gap (12). The
   frame size as defined by RFC2544 already includes the frame check
   sequence. */
#define RFC2544_FRAME_OVERHEAD	20

/* The token bucket is refilled once per period. Using a fraction of a
   second as period keeps the intermediate results of the token
   accounting far away from a 64 bit overflow, even at line rates of
   several hundred Gbps. */
#define RFC2544_TT_PERIOD_DIV	16

/* Fixed point shift used to convert a number of bytes on the wire into
   a number of cycles without using a division on the data path. */
#define RFC2544_FP_SHIFT	16

/* Give up waiting for a worker to acknowledge a phase change. */
#define RFC2544_SYNC_TIMEOUT_MSEC	1000

/* Payload of a test frame. The fields are written and read by this file
   only and are therefore kept in host byte order. */
struct rfc2544_payload {
	uint32_t signature;
	uint32_t trial_id;
	uint32_t seq;
	uint32_t gen_id;
	uint64_t tx_tsc;
} __attribute__((__packed__));

#define RFC2544_MIN_FRAME_LEN	(PROX_RTE_ETHER_HDR_LEN + \
				 (uint32_t)sizeof(struct rfc2544_payload))

struct rfc2544_counters {
	uint64_t tx_frames;
	uint64_t tx_bytes;
	uint64_t rx_frames;
	uint64_t rx_bytes;
	uint64_t rx_stale;	/* frames belonging to another trial */
	uint64_t rx_other;	/* frames that are not part of the test */
	uint64_t reordered;
	uint64_t lat_samples;
	uint64_t lat_min;
	uint64_t lat_max;
	uint64_t lat_total;
	uint64_t buckets[RFC2544_LAT_BUCKETS];
};

/* Phases of a single trial. The controller moves all workers from one
   phase to the next and waits for every running worker to acknowledge
   the transition before continuing. Arming the receivers before the
   generators start guarantees that no frame of the trial is received
   while the receivers still count for the previous trial. */
enum rfc2544_phase {
	RFC2544_PHASE_IDLE = 0,	/* no traffic, counters can be collected */
	RFC2544_PHASE_LEARN,	/* traffic without measurement (RFC2544 section 7.2) */
	RFC2544_PHASE_ARM,	/* receivers start counting the new trial */
	RFC2544_PHASE_MEASURE,	/* generators offer the trial load */
	RFC2544_PHASE_DRAIN,	/* generators stopped, receivers still counting */
};

struct rfc2544_worker {
	struct rfc2544_counters counters;
	uint64_t phase_seq_ack;
	uint32_t running;
	uint32_t core_id;
} __rte_cache_aligned;

struct rfc2544_session {
	/* Control fields. Written by the controller only, published with a
	   release store on phase_seq. */
	uint64_t phase_seq;
	uint64_t gen_bytes_per_sec;	/* rate offered by a single generator */
	uint64_t line_bytes_per_sec;	/* line rate of the port under test */
	uint32_t phase;
	uint32_t trial_id;
	uint32_t frame_size;
	uint32_t n_gen;
	uint32_t n_lat;
	uint32_t pad[3];

	struct rfc2544_worker gen[RFC2544_MAX_GENERATORS] __rte_cache_aligned;
	struct rfc2544_worker lat[RFC2544_MAX_RECEIVERS];
} __rte_cache_aligned;

/* Result of the tests for one frame size. */
struct rfc2544_result {
	uint32_t frame_size;
	uint32_t throughput_ppm;
	uint32_t throughput_valid;
	uint64_t throughput_fps;
	uint64_t throughput_bps;
	uint32_t latency_valid;
	uint64_t lat_min_nsec;
	uint64_t lat_avg_nsec;
	uint64_t lat_max_nsec;
	uint64_t lat_p50_nsec;
	uint64_t lat_p99_nsec;
	uint64_t lat_samples;
	uint32_t n_loss_steps;
	uint32_t loss_offered_ppm[RFC2544_MAX_LOSS_STEPS];
	uint32_t loss_ratio_ppm[RFC2544_MAX_LOSS_STEPS];
};

enum rfc2544_ctl_state {
	RFC2544_CTL_WAIT_WORKERS,
	RFC2544_CTL_START_TRIAL,
	RFC2544_CTL_LEARN,
	RFC2544_CTL_ARM,
	RFC2544_CTL_MEASURE,
	RFC2544_CTL_DRAIN,
	RFC2544_CTL_EVALUATE,
	RFC2544_CTL_GAP,
	RFC2544_CTL_SYNC,
	RFC2544_CTL_DONE,
};

enum rfc2544_stage {
	RFC2544_STAGE_THROUGHPUT,
	RFC2544_STAGE_LATENCY,
	RFC2544_STAGE_LOSS,
	RFC2544_STAGE_END,
};

struct rfc2544_ctl {
	struct rfc2544_cfg cfg;
	enum rfc2544_ctl_state state;
	enum rfc2544_ctl_state sync_next;
	uint64_t sync_deadline;
	uint64_t deadline;
	uint64_t hz;
	uint64_t line_bytes_per_sec;
	uint64_t measure_start_tsc;
	uint64_t measure_stop_tsc;
	uint32_t trial_id;
	uint32_t lat_bucket_shift;

	/* Position in the test plan */
	uint32_t fs_idx;
	enum rfc2544_stage stage;

	/* Binary search of the throughput (RFC2544 section 26.1) */
	uint32_t lo_ppm;
	uint32_t hi_ppm;
	uint32_t cur_ppm;

	/* Repetitions of the latency trial (RFC2544 section 26.2) */
	uint32_t lat_trial;

	/* Frame loss rate sweep (RFC2544 section 26.3) */
	uint32_t loss_ppm;
	uint32_t loss_zero_streak;

	struct rfc2544_counters agg;
	struct rfc2544_counters lat_agg;
	struct rfc2544_result results[RFC2544_MAX_FRAME_SIZES];
};

struct task_rfc2544_gen {
	struct task_base base;
	struct token_time token_time;
	struct local_mbuf local_mbuf;
	uint64_t phase_seq;
	uint64_t tsc_per_frame;	/* time to put one frame on the wire */
	uint32_t transmitting;
	uint32_t pkt_len;	/* frame size without the frame check sequence */
	uint32_t wire_size;	/* frame size including preamble, SFD and IFG */
	uint32_t frame_size;
	uint32_t seq;
	uint32_t min_bulk_size;
	uint32_t max_bulk_size;
	uint32_t gen_id;
	uint32_t sig;
	uint32_t max_frame_size;
	uint16_t etype_be;
	uint8_t  src_dst_mac[12];
	uint8_t  *frame_template;
	struct rfc2544_session *session;
	struct rfc2544_worker *slot;
	struct rfc2544_ctl *ctl;
	struct rfc2544_counters counters;
};

struct task_rfc2544_lat {
	struct task_base base;
	uint64_t phase_seq;
	uint64_t tsc_per_byte_fp;
	uint32_t counting;
	uint32_t trial_id;
	uint32_t sig;
	uint32_t lat_bucket_shift;
	uint16_t etype_be;
	uint32_t last_seq[RFC2544_MAX_GENERATORS];
	struct rfc2544_session *session;
	struct rfc2544_worker *slot;
	struct rfc2544_counters counters;
};

/*
 * Configuration helpers
 */

void rfc2544_cfg_set_defaults(struct rfc2544_cfg *cfg)
{
	static const uint32_t default_frame_sizes[] = {64, 128, 256, 512, 1024, 1280, 1518};

	memset(cfg, 0, sizeof(*cfg));
	prox_strncpy(cfg->session, "rfc2544", sizeof(cfg->session));
	for (uint32_t i = 0; i < RTE_DIM(default_frame_sizes); ++i)
		cfg->frame_size[i] = default_frame_sizes[i];
	cfg->n_frame_sizes = RTE_DIM(default_frame_sizes);
	cfg->tests = RFC2544_TEST_ALL;
	cfg->trial_duration_msec = 60000;	/* RFC2544 section 24 */
	cfg->warm_up_duration_msec = 2000;
	cfg->settle_duration_msec = 2000;	/* RFC2544 section 23 */
	cfg->inter_trial_gap_msec = 2000;	/* RFC2544 section 23 */
	cfg->start_rate_ppm = RFC2544_FULL_RATE;
	cfg->resolution_ppm = 1000;		/* 0.1% of the line rate */
	cfg->max_loss_ppm = 0;			/* no loss allowed */
	cfg->loss_step_ppm = 100000;		/* 10% steps, RFC2544 section 26.3 */
	cfg->lat_bucket_nsec = 100;
	cfg->latency_trials = 1;
	cfg->line_rate_mbps = 0;		/* taken from the port */
	cfg->etype = RFC2544_DEFAULT_ETYPE;
	cfg->signature = RFC2544_DEFAULT_SIGNATURE;
}

int rfc2544_parse_tests(uint32_t *tests, const char *str)
{
	const char *cur = str;
	uint32_t mask = 0;

	while (*cur) {
		size_t len;
		const char *comma = strchr(cur, ',');

		len = comma ? (size_t)(comma - cur) : strlen(cur);
		while (len && (*cur == ' ' || *cur == '\t')) {
			cur++;
			len--;
		}
		while (len && (cur[len - 1] == ' ' || cur[len - 1] == '\t'))
			len--;

		if (len == 3 && !strncmp(cur, "all", len))
			mask |= RFC2544_TEST_ALL;
		else if (len == 10 && !strncmp(cur, "throughput", len))
			mask |= RFC2544_TEST_THROUGHPUT;
		else if (len == 7 && !strncmp(cur, "latency", len))
			mask |= RFC2544_TEST_LATENCY;
		else if (len == 4 && !strncmp(cur, "loss", len))
			mask |= RFC2544_TEST_LOSS_RATE;
		else
			return -1;

		if (!comma)
			break;
		cur = comma + 1;
	}

	if (mask == 0)
		return -1;

	*tests = mask;
	return 0;
}

/*
 * Shared session
 */

static struct rfc2544_session *rfc2544_session_get(struct task_args *targ)
{
	char name[RFC2544_SESSION_NAME_LEN + 16];
	struct rfc2544_session *session;

	snprintf(name, sizeof(name), "rfc2544:%s", targ->rfc2544.session);
	session = prox_sh_find_system(name);
	if (session != NULL)
		return session;

	session = prox_zmalloc(sizeof(*session), rte_lcore_to_socket_id(targ->lconf->id));
	PROX_PANIC(session == NULL, "Failed to allocate rfc2544 session '%s'\n", targ->rfc2544.session);
	prox_sh_add_system(name, session);
	plog_info("\t\tCreated rfc2544 session '%s'\n", targ->rfc2544.session);

	return session;
}

static void rfc2544_publish(struct rfc2544_worker *slot, const struct rfc2544_counters *counters,
			    uint64_t phase_seq)
{
	rte_memcpy(&slot->counters, counters, sizeof(*counters));
	__atomic_store_n(&slot->phase_seq_ack, phase_seq, __ATOMIC_RELEASE);
}

static void rfc2544_counters_reset(struct rfc2544_counters *counters)
{
	memset(counters, 0, sizeof(*counters));
	counters->lat_min = UINT64_MAX;
}

static void rfc2544_counters_add(struct rfc2544_counters *dst, const struct rfc2544_counters *src)
{
	dst->tx_frames += src->tx_frames;
	dst->tx_bytes += src->tx_bytes;
	dst->rx_frames += src->rx_frames;
	dst->rx_bytes += src->rx_bytes;
	dst->rx_stale += src->rx_stale;
	dst->rx_other += src->rx_other;
	dst->reordered += src->reordered;
	dst->lat_samples += src->lat_samples;
	dst->lat_total += src->lat_total;
	if (src->lat_samples) {
		if (src->lat_min < dst->lat_min)
			dst->lat_min = src->lat_min;
		if (src->lat_max > dst->lat_max)
			dst->lat_max = src->lat_max;
	}
	for (uint32_t i = 0; i < RFC2544_LAT_BUCKETS; ++i)
		dst->buckets[i] += src->buckets[i];
}

/*
 * Generator
 */

static uint64_t rfc2544_rate_to_bytes_per_sec(uint64_t line_bytes_per_sec, uint32_t rate_ppm)
{
	/* line_bytes_per_sec is at most a few tens of GB/s so the
	   multiplication cannot overflow. */
	return line_bytes_per_sec / RFC2544_FULL_RATE * rate_ppm +
		(line_bytes_per_sec % RFC2544_FULL_RATE) * rate_ppm / RFC2544_FULL_RATE;
}

static void task_rfc2544_gen_build_template(struct task_rfc2544_gen *task)
{
	prox_rte_ether_hdr *hdr = (prox_rte_ether_hdr *)task->frame_template;
	struct rfc2544_payload *payload;

	memset(task->frame_template, 0, task->max_frame_size);
	rte_memcpy(hdr, task->src_dst_mac, sizeof(task->src_dst_mac));
	hdr->ether_type = task->etype_be;

	payload = (struct rfc2544_payload *)(task->frame_template + PROX_RTE_ETHER_HDR_LEN);
	payload->signature = task->sig;
	payload->gen_id = task->gen_id;
	payload->trial_id = 0;
	payload->seq = 0;
	payload->tx_tsc = 0;
}

static void task_rfc2544_gen_set_frame_size(struct task_rfc2544_gen *task, uint32_t frame_size,
					    uint64_t line_bytes_per_sec)
{
	if (frame_size < RFC2544_MIN_FRAME_SIZE)
		frame_size = RFC2544_MIN_FRAME_SIZE;
	if (frame_size > task->max_frame_size)
		frame_size = task->max_frame_size;

	task->frame_size = frame_size;
	task->pkt_len = frame_size - PROX_RTE_ETHER_CRC_LEN;
	task->wire_size = frame_size + RFC2544_FRAME_OVERHEAD;

	/* Frames of a burst leave the port back to back at line rate. The
	   transmit time stamps are spread accordingly so that the latency
	   reported by the receivers is not biased by the burst size. */
	if (line_bytes_per_sec)
		task->tsc_per_frame = rte_get_tsc_hz() * task->wire_size / line_bytes_per_sec;
	else
		task->tsc_per_frame = 0;
}

static void task_rfc2544_gen_apply_phase(struct task_rfc2544_gen *task, uint64_t tsc)
{
	struct rfc2544_session *session = task->session;
	uint64_t phase_seq = __atomic_load_n(&session->phase_seq, __ATOMIC_ACQUIRE);
	uint32_t phase = __atomic_load_n(&session->phase, __ATOMIC_RELAXED);
	uint32_t trial_id = __atomic_load_n(&session->trial_id, __ATOMIC_RELAXED);
	uint32_t frame_size = __atomic_load_n(&session->frame_size, __ATOMIC_RELAXED);
	uint64_t gen_bps = __atomic_load_n(&session->gen_bytes_per_sec, __ATOMIC_RELAXED);
	uint64_t line_bps = __atomic_load_n(&session->line_bytes_per_sec, __ATOMIC_RELAXED);
	struct rfc2544_payload *payload =
		(struct rfc2544_payload *)(task->frame_template + PROX_RTE_ETHER_HDR_LEN);

	if (phase == RFC2544_PHASE_ARM)
		rfc2544_counters_reset(&task->counters);

	switch (phase) {
	case RFC2544_PHASE_LEARN:
	case RFC2544_PHASE_ARM:
	case RFC2544_PHASE_MEASURE:
		task_rfc2544_gen_set_frame_size(task, frame_size, line_bps);
		token_time_set_bpp(&task->token_time, gen_bps / RFC2544_TT_PERIOD_DIV);
		token_time_reset(&task->token_time, tsc, 0);
		payload->trial_id = (phase == RFC2544_PHASE_LEARN) ? 0 : trial_id;
		if (phase == RFC2544_PHASE_ARM)
			task->seq = 0;
		task->transmitting = (phase != RFC2544_PHASE_ARM);
		break;
	default:
		task->transmitting = 0;
		break;
	}

	task->phase_seq = phase_seq;
	rfc2544_publish(task->slot, &task->counters, phase_seq);
}

static void rfc2544_ctl_run(struct rfc2544_ctl *ctl, struct rfc2544_session *session, uint64_t tsc);

static int handle_rfc2544_gen_bulk(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
	struct task_rfc2544_gen *task = (struct task_rfc2544_gen *)tbase;
	uint8_t out[MAX_PKT_BURST];
	uint64_t tsc = rte_rdtsc();
	uint32_t send_bulk = 0;
	uint64_t would_send_bytes = 0;
	struct rte_mbuf **new_pkts;
	int ret;

	if (task->ctl != NULL)
		rfc2544_ctl_run(task->ctl, task->session, tsc);

	if (unlikely(__atomic_load_n(&task->session->phase_seq, __ATOMIC_ACQUIRE) != task->phase_seq))
		task_rfc2544_gen_apply_phase(task, tsc);

	if (!task->transmitting)
		return 0;

	token_time_update(&task->token_time, tsc);

	while (send_bulk < task->max_bulk_size &&
	       would_send_bytes + task->wire_size <= task->token_time.bytes_now) {
		would_send_bytes += task->wire_size;
		send_bulk++;
	}

	if (send_bulk < task->min_bulk_size)
		return 0;

	new_pkts = local_mbuf_refill_and_take(&task->local_mbuf, send_bulk);
	if (unlikely(new_pkts == NULL))
		return 0;

	/* Consume the tokens. The depth of the bucket is limited to a
	   single burst so that a generator that cannot keep up with the
	   configured rate does not try to catch up by sending a long
	   burst at line rate afterwards. */
	task->token_time.bytes_now -= would_send_bytes;

	prefetch_pkts(new_pkts, send_bulk);

	for (uint32_t i = 0; i < send_bulk; ++i) {
		struct rte_mbuf *mbuf = new_pkts[i];
		uint8_t *pkt;
		struct rfc2544_payload *payload;

		rte_pktmbuf_pkt_len(mbuf) = task->pkt_len;
		rte_pktmbuf_data_len(mbuf) = task->pkt_len;
		init_mbuf_seg(mbuf);

		pkt = rte_pktmbuf_mtod(mbuf, uint8_t *);
		rte_memcpy(pkt, task->frame_template, task->pkt_len);

		payload = (struct rfc2544_payload *)(pkt + PROX_RTE_ETHER_HDR_LEN);
		payload->seq = task->seq++;
		payload->tx_tsc = tsc + i * task->tsc_per_frame;
		out[i] = 0;
	}

	task->counters.tx_frames += send_bulk;
	task->counters.tx_bytes += (uint64_t)send_bulk * task->frame_size;

	ret = task->base.tx_pkt(&task->base, new_pkts, send_bulk, out);
	if (unlikely(ret)) {
		/* Frames that could not be sent must not be reported as
		   transmitted, otherwise they would be accounted as lost. */
		task->counters.tx_frames -= ret;
		task->counters.tx_bytes -= (uint64_t)ret * task->frame_size;
		task->seq -= ret;
	}

	return ret;
}

/*
 * Receiver
 */

static void task_rfc2544_lat_apply_phase(struct task_rfc2544_lat *task)
{
	struct rfc2544_session *session = task->session;
	uint64_t phase_seq = __atomic_load_n(&session->phase_seq, __ATOMIC_ACQUIRE);
	uint32_t phase = __atomic_load_n(&session->phase, __ATOMIC_RELAXED);
	uint64_t line_bps = __atomic_load_n(&session->line_bytes_per_sec, __ATOMIC_RELAXED);

	if (phase == RFC2544_PHASE_ARM) {
		rfc2544_counters_reset(&task->counters);
		task->trial_id = __atomic_load_n(&session->trial_id, __ATOMIC_RELAXED);
		for (uint32_t i = 0; i < RFC2544_MAX_GENERATORS; ++i)
			task->last_seq[i] = 0;
		task->tsc_per_byte_fp = line_bps ?
			((rte_get_tsc_hz() << RFC2544_FP_SHIFT) / line_bps) : 0;
	}

	task->counting = (phase == RFC2544_PHASE_ARM) || (phase == RFC2544_PHASE_MEASURE) ||
		(phase == RFC2544_PHASE_DRAIN);

	task->phase_seq = phase_seq;
	rfc2544_publish(task->slot, &task->counters, phase_seq);
}

static int handle_rfc2544_lat_bulk(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
	struct task_rfc2544_lat *task = (struct task_rfc2544_lat *)tbase;
	struct rfc2544_counters *counters = &task->counters;
	uint64_t bytes_after = 0;
	uint64_t rx_tsc;

	if (unlikely(__atomic_load_n(&task->session->phase_seq, __ATOMIC_ACQUIRE) != task->phase_seq))
		task_rfc2544_lat_apply_phase(task);

	if (n_pkts == 0)
		return 0;

	if (unlikely(!task->counting))
		return task->base.tx_pkt(&task->base, mbufs, n_pkts, NULL);

	rx_tsc = tbase->aux->tsc_rx.after;
	prefetch_pkts(mbufs, n_pkts);

	/* The frames of the burst are walked in reverse order: the last
	   frame of the burst was received at rx_tsc and the previous ones
	   earlier by the time the frames behind them needed on the wire.
	   Without this correction, the latency of a frame would include
	   the time needed to receive the rest of the burst. */
	for (uint16_t i = n_pkts; i > 0; --i) {
		struct rte_mbuf *mbuf = mbufs[i - 1];
		prox_rte_ether_hdr *hdr = rte_pktmbuf_mtod(mbuf, prox_rte_ether_hdr *);
		const struct rfc2544_payload *payload;
		uint32_t gen_id;
		uint64_t rx_time;
		uint64_t lat;
		uint64_t bucket;
		uint64_t wire_size = mbuf_wire_size(mbuf);
		uint64_t bytes_before_me = bytes_after;

		bytes_after += wire_size;

		if (unlikely(rte_pktmbuf_data_len(mbuf) < RFC2544_MIN_FRAME_LEN ||
			     hdr->ether_type != task->etype_be)) {
			counters->rx_other++;
			continue;
		}

		payload = (const struct rfc2544_payload *)((const uint8_t *)hdr + PROX_RTE_ETHER_HDR_LEN);
		if (unlikely(payload->signature != task->sig)) {
			counters->rx_other++;
			continue;
		}
		if (unlikely(payload->trial_id != task->trial_id)) {
			counters->rx_stale++;
			continue;
		}

		gen_id = payload->gen_id;
		if (unlikely(gen_id >= RFC2544_MAX_GENERATORS)) {
			counters->rx_other++;
			continue;
		}

		counters->rx_frames++;
		counters->rx_bytes += rte_pktmbuf_pkt_len(mbuf) + PROX_RTE_ETHER_CRC_LEN;

		if (payload->seq < task->last_seq[gen_id])
			counters->reordered++;
		else
			task->last_seq[gen_id] = payload->seq;

		rx_time = rx_tsc - ((bytes_before_me * task->tsc_per_byte_fp) >> RFC2544_FP_SHIFT);

		if (unlikely(rx_time <= payload->tx_tsc))
			lat = 0;
		else
			lat = rx_time - payload->tx_tsc;

		counters->lat_samples++;
		counters->lat_total += lat;
		if (lat < counters->lat_min)
			counters->lat_min = lat;
		if (lat > counters->lat_max)
			counters->lat_max = lat;

		bucket = lat >> task->lat_bucket_shift;
		if (unlikely(bucket >= RFC2544_LAT_BUCKETS))
			bucket = RFC2544_LAT_BUCKETS - 1;
		counters->buckets[bucket]++;
	}

	return task->base.tx_pkt(&task->base, mbufs, n_pkts, NULL);
}

/*
 * Test controller
 */

static uint64_t rfc2544_bucket_to_nsec(const struct rfc2544_ctl *ctl, uint64_t bucket)
{
	return tsc_to_nsec((bucket + 1) << ctl->lat_bucket_shift);
}

static uint64_t rfc2544_percentile_nsec(const struct rfc2544_ctl *ctl,
					const struct rfc2544_counters *counters,
					uint64_t percentile_ppm)
{
	uint64_t target = counters->lat_samples * percentile_ppm / RFC2544_FULL_RATE;
	uint64_t cum = 0;

	if (counters->lat_samples == 0)
		return 0;

	for (uint64_t i = 0; i < RFC2544_LAT_BUCKETS; ++i) {
		cum += counters->buckets[i];
		if (cum >= target)
			return rfc2544_bucket_to_nsec(ctl, i);
	}
	return rfc2544_bucket_to_nsec(ctl, RFC2544_LAT_BUCKETS - 1);
}

static void rfc2544_ctl_publish_phase(struct rfc2544_ctl *ctl, struct rfc2544_session *session,
				      uint32_t phase, uint32_t rate_ppm,
				      enum rfc2544_ctl_state next)
{
	uint64_t gen_bps = 0;
	uint32_t n_gen = session->n_gen ? session->n_gen : 1;

	if (rate_ppm)
		gen_bps = rfc2544_rate_to_bytes_per_sec(ctl->line_bytes_per_sec, rate_ppm) / n_gen;

	__atomic_store_n(&session->phase, phase, __ATOMIC_RELAXED);
	__atomic_store_n(&session->trial_id, ctl->trial_id, __ATOMIC_RELAXED);
	__atomic_store_n(&session->frame_size, ctl->cfg.frame_size[ctl->fs_idx], __ATOMIC_RELAXED);
	__atomic_store_n(&session->gen_bytes_per_sec, gen_bps, __ATOMIC_RELAXED);
	__atomic_store_n(&session->line_bytes_per_sec, ctl->line_bytes_per_sec, __ATOMIC_RELAXED);
	__atomic_store_n(&session->phase_seq, session->phase_seq + 1, __ATOMIC_RELEASE);

	ctl->sync_next = next;
	ctl->sync_deadline = rte_rdtsc() + msec_to_tsc(RFC2544_SYNC_TIMEOUT_MSEC);
	ctl->state = RFC2544_CTL_SYNC;
}

static int rfc2544_ctl_all_running(struct rfc2544_session *session)
{
	for (uint32_t i = 0; i < session->n_gen; ++i) {
		if (!__atomic_load_n(&session->gen[i].running, __ATOMIC_ACQUIRE))
			return 0;
	}
	for (uint32_t i = 0; i < session->n_lat; ++i) {
		if (!__atomic_load_n(&session->lat[i].running, __ATOMIC_ACQUIRE))
			return 0;
	}
	return 1;
}

static int rfc2544_ctl_all_acked(struct rfc2544_session *session)
{
	uint64_t seq = __atomic_load_n(&session->phase_seq, __ATOMIC_RELAXED);

	for (uint32_t i = 0; i < session->n_gen; ++i) {
		if (!__atomic_load_n(&session->gen[i].running, __ATOMIC_RELAXED))
			continue;
		if (__atomic_load_n(&session->gen[i].phase_seq_ack, __ATOMIC_ACQUIRE) != seq)
			return 0;
	}
	for (uint32_t i = 0; i < session->n_lat; ++i) {
		if (!__atomic_load_n(&session->lat[i].running, __ATOMIC_RELAXED))
			continue;
		if (__atomic_load_n(&session->lat[i].phase_seq_ack, __ATOMIC_ACQUIRE) != seq)
			return 0;
	}
	return 1;
}

static void rfc2544_ctl_collect(struct rfc2544_ctl *ctl, struct rfc2544_session *session)
{
	rfc2544_counters_reset(&ctl->agg);

	for (uint32_t i = 0; i < session->n_gen; ++i) {
		if (__atomic_load_n(&session->gen[i].running, __ATOMIC_RELAXED))
			rfc2544_counters_add(&ctl->agg, &session->gen[i].counters);
	}
	for (uint32_t i = 0; i < session->n_lat; ++i) {
		if (__atomic_load_n(&session->lat[i].running, __ATOMIC_RELAXED))
			rfc2544_counters_add(&ctl->agg, &session->lat[i].counters);
	}
}

static uint64_t rfc2544_ctl_loss_ppm(const struct rfc2544_ctl *ctl)
{
	uint64_t tx = ctl->agg.tx_frames;
	uint64_t rx = ctl->agg.rx_frames;

	if (tx == 0)
		return RFC2544_FULL_RATE;
	if (rx >= tx)
		return 0;
	return (tx - rx) * RFC2544_FULL_RATE / tx;
}

static int rfc2544_ctl_trial_passed(const struct rfc2544_ctl *ctl)
{
	uint64_t tx = ctl->agg.tx_frames;
	uint64_t lost;

	if (tx == 0)
		return 0;
	if (ctl->agg.rx_frames >= tx)
		return 1;

	lost = tx - ctl->agg.rx_frames;
	return lost * RFC2544_FULL_RATE <= (uint64_t)ctl->cfg.max_loss_ppm * tx;
}

static uint64_t rfc2544_ctl_measured_fps(const struct rfc2544_ctl *ctl)
{
	uint64_t duration = ctl->measure_stop_tsc - ctl->measure_start_tsc;
	uint64_t msec = duration * 1000 / ctl->hz;

	/* Multiplying the number of frames with the tsc frequency would
	   overflow for long trials at high frame rates. */
	if (msec == 0)
		return 0;
	return ctl->agg.tx_frames * 1000 / msec;
}

static void rfc2544_ctl_log_trial(struct rfc2544_ctl *ctl, const char *what)
{
	uint64_t loss_ppm = rfc2544_ctl_loss_ppm(ctl);

	plog_info("RFC2544 %s: frame size %u, offered %.4f%% (%" PRIu64 " fps), "
		  "tx %" PRIu64 ", rx %" PRIu64 ", loss %.6f%%, reordered %" PRIu64 "\n",
		  what, ctl->cfg.frame_size[ctl->fs_idx],
		  ctl->cur_ppm / 10000.0, rfc2544_ctl_measured_fps(ctl),
		  ctl->agg.tx_frames, ctl->agg.rx_frames,
		  loss_ppm / 10000.0, ctl->agg.reordered);
}

/* RFC2544 section 26.2 asks for the latency trial to be repeated. The
   samples of all the repetitions are aggregated into a single result. */
static void rfc2544_ctl_store_latency(struct rfc2544_ctl *ctl)
{
	struct rfc2544_result *res = &ctl->results[ctl->fs_idx];

	rfc2544_counters_add(&ctl->lat_agg, &ctl->agg);

	if (ctl->lat_agg.lat_samples == 0)
		return;

	res->latency_valid = 1;
	res->lat_samples = ctl->lat_agg.lat_samples;
	res->lat_min_nsec = tsc_to_nsec(ctl->lat_agg.lat_min);
	res->lat_max_nsec = tsc_to_nsec(ctl->lat_agg.lat_max);
	res->lat_avg_nsec = tsc_to_nsec(ctl->lat_agg.lat_total / ctl->lat_agg.lat_samples);
	res->lat_p50_nsec = rfc2544_percentile_nsec(ctl, &ctl->lat_agg, 500000);
	res->lat_p99_nsec = rfc2544_percentile_nsec(ctl, &ctl->lat_agg, 990000);
}

static void rfc2544_ctl_report(struct rfc2544_ctl *ctl)
{
	plog_info("=== RFC2544 results ===\n");
	for (uint32_t i = 0; i < ctl->cfg.n_frame_sizes; ++i) {
		struct rfc2544_result *res = &ctl->results[i];

		if (ctl->cfg.tests & RFC2544_TEST_THROUGHPUT) {
			if (res->throughput_valid)
				plog_info("Throughput: frame size %u: %.4f%% of line rate, "
					  "%" PRIu64 " fps, %" PRIu64 " Mbps on the wire\n",
					  res->frame_size, res->throughput_ppm / 10000.0,
					  res->throughput_fps, res->throughput_bps / 1000000);
			else
				plog_info("Throughput: frame size %u: no rate without acceptable loss\n",
					  res->frame_size);
		}
		if ((ctl->cfg.tests & RFC2544_TEST_LATENCY) && res->latency_valid)
			plog_info("Latency:    frame size %u: min %" PRIu64 " ns, avg %" PRIu64
				  " ns, p50 %" PRIu64 " ns, p99 %" PRIu64 " ns, max %" PRIu64
				  " ns (%" PRIu64 " samples)\n",
				  res->frame_size, res->lat_min_nsec, res->lat_avg_nsec,
				  res->lat_p50_nsec, res->lat_p99_nsec, res->lat_max_nsec,
				  res->lat_samples);
		for (uint32_t s = 0; s < res->n_loss_steps; ++s)
			plog_info("Frame loss: frame size %u: offered %.4f%% => loss %.6f%%\n",
				  res->frame_size, res->loss_offered_ppm[s] / 10000.0,
				  res->loss_ratio_ppm[s] / 10000.0);
	}
	plog_info("=== RFC2544 done ===\n");
}

/* Prepare the next trial. Returns 0 when the whole test plan is done. */
static int rfc2544_ctl_next_trial(struct rfc2544_ctl *ctl)
{
	while (ctl->fs_idx < ctl->cfg.n_frame_sizes) {
		struct rfc2544_result *res = &ctl->results[ctl->fs_idx];

		switch (ctl->stage) {
		case RFC2544_STAGE_THROUGHPUT:
			if (!(ctl->cfg.tests & RFC2544_TEST_THROUGHPUT)) {
				ctl->stage = RFC2544_STAGE_LATENCY;
				continue;
			}
			/* cur_ppm is the next rate of the binary search, it is
			   computed by rfc2544_ctl_evaluate(). */
			return 1;
		case RFC2544_STAGE_LATENCY:
			if (!(ctl->cfg.tests & RFC2544_TEST_LATENCY) ||
			    ctl->lat_trial >= ctl->cfg.latency_trials) {
				ctl->stage = RFC2544_STAGE_LOSS;
				ctl->loss_ppm = ctl->cfg.start_rate_ppm;
				ctl->loss_zero_streak = 0;
				continue;
			}
			/* RFC2544 section 26.2: latency is measured at the
			   throughput rate found for this frame size. */
			ctl->cur_ppm = (ctl->cfg.tests & RFC2544_TEST_THROUGHPUT) ?
				res->throughput_ppm : ctl->cfg.start_rate_ppm;
			if (ctl->cur_ppm == 0) {
				plog_warn("RFC2544: skipping latency for frame size %u, "
					  "no throughput was found\n", res->frame_size);
				ctl->stage = RFC2544_STAGE_LOSS;
				ctl->loss_ppm = ctl->cfg.start_rate_ppm;
				ctl->loss_zero_streak = 0;
				continue;
			}
			return 1;
		case RFC2544_STAGE_LOSS:
			if (!(ctl->cfg.tests & RFC2544_TEST_LOSS_RATE) ||
			    ctl->loss_ppm == 0 || ctl->loss_zero_streak >= 2 ||
			    res->n_loss_steps >= RFC2544_MAX_LOSS_STEPS) {
				ctl->stage = RFC2544_STAGE_END;
				continue;
			}
			ctl->cur_ppm = ctl->loss_ppm;
			return 1;
		case RFC2544_STAGE_END:
		default:
			ctl->fs_idx++;
			ctl->stage = RFC2544_STAGE_THROUGHPUT;
			ctl->lo_ppm = 0;
			ctl->hi_ppm = ctl->cfg.start_rate_ppm;
			ctl->cur_ppm = ctl->cfg.start_rate_ppm;
			ctl->lat_trial = 0;
			rfc2544_counters_reset(&ctl->lat_agg);
			if (ctl->fs_idx < ctl->cfg.n_frame_sizes)
				ctl->results[ctl->fs_idx].frame_size = ctl->cfg.frame_size[ctl->fs_idx];
			continue;
		}
	}

	return 0;
}

/* Take the result of the trial that just finished into account. */
static void rfc2544_ctl_evaluate(struct rfc2544_ctl *ctl)
{
	struct rfc2544_result *res = &ctl->results[ctl->fs_idx];
	int passed = rfc2544_ctl_trial_passed(ctl);

	switch (ctl->stage) {
	case RFC2544_STAGE_THROUGHPUT:
		rfc2544_ctl_log_trial(ctl, passed ? "throughput trial passed" : "throughput trial failed");
		if (passed) {
			ctl->lo_ppm = ctl->cur_ppm;
			res->throughput_valid = 1;
			res->throughput_ppm = ctl->cur_ppm;
			res->throughput_fps = rfc2544_ctl_measured_fps(ctl);
			res->throughput_bps = res->throughput_fps *
				(ctl->cfg.frame_size[ctl->fs_idx] + RFC2544_FRAME_OVERHEAD) * 8;
		} else {
			ctl->hi_ppm = ctl->cur_ppm;
		}
		/* Stop once the interval that still needs to be explored is
		   smaller than the requested resolution. */
		if (ctl->hi_ppm - ctl->lo_ppm <= ctl->cfg.resolution_ppm)
			ctl->stage = RFC2544_STAGE_LATENCY;
		else
			ctl->cur_ppm = ctl->lo_ppm + (ctl->hi_ppm - ctl->lo_ppm) / 2;
		break;
	case RFC2544_STAGE_LATENCY:
		rfc2544_ctl_log_trial(ctl, "latency trial");
		rfc2544_ctl_store_latency(ctl);
		ctl->lat_trial++;
		break;
	case RFC2544_STAGE_LOSS:
		rfc2544_ctl_log_trial(ctl, "frame loss trial");
		if (res->n_loss_steps < RFC2544_MAX_LOSS_STEPS) {
			res->loss_offered_ppm[res->n_loss_steps] = ctl->cur_ppm;
			res->loss_ratio_ppm[res->n_loss_steps] = rfc2544_ctl_loss_ppm(ctl);
			res->n_loss_steps++;
		}
		/* RFC2544 section 26.3: the sweep stops after two successive
		   trials without any loss. */
		if (rfc2544_ctl_loss_ppm(ctl) == 0)
			ctl->loss_zero_streak++;
		else
			ctl->loss_zero_streak = 0;
		ctl->loss_ppm = (ctl->loss_ppm > ctl->cfg.loss_step_ppm) ?
			ctl->loss_ppm - ctl->cfg.loss_step_ppm : 0;
		break;
	default:
		break;
	}
}

static void rfc2544_ctl_run(struct rfc2544_ctl *ctl, struct rfc2544_session *session, uint64_t tsc)
{
	switch (ctl->state) {
	case RFC2544_CTL_WAIT_WORKERS:
		/* Do not start before every task of the session is running,
		   otherwise the frames of the first trial would be missed. */
		if (!rfc2544_ctl_all_running(session) && tsc < ctl->deadline)
			return;
		if (session->n_lat == 0) {
			plog_err("RFC2544: no 'rfc2544lat' task configured, cannot measure\n");
			ctl->state = RFC2544_CTL_DONE;
			return;
		}
		plog_info("RFC2544: starting test with %u generator(s) and %u receiver(s), "
			  "line rate %" PRIu64 " Mbps\n",
			  session->n_gen, session->n_lat, ctl->line_bytes_per_sec * 8 / 1000000);
		ctl->results[0].frame_size = ctl->cfg.frame_size[0];
		ctl->state = RFC2544_CTL_START_TRIAL;
		return;

	case RFC2544_CTL_START_TRIAL:
		if (!rfc2544_ctl_next_trial(ctl)) {
			rfc2544_ctl_report(ctl);
			ctl->state = RFC2544_CTL_DONE;
			return;
		}
		ctl->trial_id++;
		if (ctl->cfg.warm_up_duration_msec) {
			rfc2544_ctl_publish_phase(ctl, session, RFC2544_PHASE_LEARN,
						  ctl->cur_ppm, RFC2544_CTL_LEARN);
			ctl->deadline = tsc + msec_to_tsc(ctl->cfg.warm_up_duration_msec);
		} else {
			ctl->state = RFC2544_CTL_LEARN;
			ctl->deadline = tsc;
		}
		return;

	case RFC2544_CTL_LEARN:
		if (tsc < ctl->deadline)
			return;
		rfc2544_ctl_publish_phase(ctl, session, RFC2544_PHASE_ARM,
					  ctl->cur_ppm, RFC2544_CTL_ARM);
		return;

	case RFC2544_CTL_ARM:
		rfc2544_ctl_publish_phase(ctl, session, RFC2544_PHASE_MEASURE,
					  ctl->cur_ppm, RFC2544_CTL_MEASURE);
		ctl->measure_start_tsc = tsc;
		ctl->deadline = tsc + msec_to_tsc(ctl->cfg.trial_duration_msec);
		return;

	case RFC2544_CTL_MEASURE:
		if (tsc < ctl->deadline)
			return;
		ctl->measure_stop_tsc = tsc;
		rfc2544_ctl_publish_phase(ctl, session, RFC2544_PHASE_DRAIN, 0, RFC2544_CTL_DRAIN);
		ctl->deadline = tsc + msec_to_tsc(ctl->cfg.settle_duration_msec);
		return;

	case RFC2544_CTL_DRAIN:
		if (tsc < ctl->deadline)
			return;
		rfc2544_ctl_publish_phase(ctl, session, RFC2544_PHASE_IDLE, 0, RFC2544_CTL_EVALUATE);
		return;

	case RFC2544_CTL_EVALUATE:
		rfc2544_ctl_collect(ctl, session);
		rfc2544_ctl_evaluate(ctl);
		ctl->deadline = tsc + msec_to_tsc(ctl->cfg.inter_trial_gap_msec);
		ctl->state = RFC2544_CTL_GAP;
		return;

	case RFC2544_CTL_GAP:
		if (tsc < ctl->deadline)
			return;
		ctl->state = RFC2544_CTL_START_TRIAL;
		return;

	case RFC2544_CTL_SYNC:
		if (rfc2544_ctl_all_acked(session)) {
			ctl->state = ctl->sync_next;
			return;
		}
		if (tsc > ctl->sync_deadline) {
			plog_warn("RFC2544: timeout while waiting for all tasks to "
				  "acknowledge a phase change\n");
			ctl->state = ctl->sync_next;
		}
		return;

	case RFC2544_CTL_DONE:
	default:
		return;
	}
}

/*
 * Initialization
 */

static uint64_t rfc2544_line_bytes_per_sec(struct task_args *targ, struct prox_port_cfg *port)
{
	if (targ->rfc2544.line_rate_mbps)
		return (uint64_t)targ->rfc2544.line_rate_mbps * 125000;

	/* max_link_speed reports the maximum, non negotiated link speed in
	   Mbps, e.g. 40000 for a 40 Gbps NIC. */
	if (port == NULL || port->max_link_speed == 0 || port->max_link_speed == UINT32_MAX)
		return 0;

	return (uint64_t)port->max_link_speed * 125000;
}

static uint32_t rfc2544_lat_bucket_shift(uint32_t bucket_nsec)
{
	uint64_t bucket_tsc = nsec_to_tsc(bucket_nsec ? bucket_nsec : 1);
	uint32_t shift = 0;

	if (bucket_tsc == 0)
		bucket_tsc = 1;
	while ((1ULL << shift) < bucket_tsc && shift < 63)
		shift++;

	return shift;
}

static void rfc2544_check_cfg(struct task_args *targ, uint32_t max_frame_size)
{
	struct rfc2544_cfg *cfg = &targ->rfc2544;

	PROX_PANIC(cfg->n_frame_sizes == 0, "No rfc2544 frame size configured\n");
	PROX_PANIC(cfg->n_frame_sizes > RFC2544_MAX_FRAME_SIZES,
		   "Too many rfc2544 frame sizes configured\n");
	PROX_PANIC(cfg->start_rate_ppm == 0 || cfg->start_rate_ppm > RFC2544_FULL_RATE,
		   "rfc2544 start rate must be in ]0, 100] %%\n");
	PROX_PANIC(cfg->loss_step_ppm == 0, "rfc2544 loss step must be > 0\n");
	PROX_PANIC(cfg->latency_trials == 0, "rfc2544 latency trials must be > 0\n");

	for (uint32_t i = 0; i < cfg->n_frame_sizes; ++i) {
		PROX_PANIC(cfg->frame_size[i] < RFC2544_MIN_FRAME_SIZE,
			   "rfc2544 frame size %u is smaller than the minimum Ethernet frame size\n",
			   cfg->frame_size[i]);
		PROX_PANIC(cfg->frame_size[i] > max_frame_size,
			   "rfc2544 frame size %u does not fit in the mtu of the port (max %u)\n",
			   cfg->frame_size[i], max_frame_size);
	}
}

static struct rte_mempool *rfc2544_create_mempool(struct task_args *targ, uint32_t max_frame_size)
{
	const int sock_id = rte_lcore_to_socket_id(targ->lconf->id);
	uint32_t mbuf_size = TX_MBUF_SIZE;
	struct rte_mempool *ret;
	char name[MAX_NAME_SIZE];

	if (max_frame_size + (unsigned)sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM > mbuf_size)
		mbuf_size = max_frame_size + (unsigned)sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM;

	snprintf(name, sizeof(name), "rfc2544_pool_%u_%u", targ->lconf->id, targ->id);
	ret = rte_mempool_create(name, targ->nb_mbuf - 1, mbuf_size,
				 targ->nb_cache_mbuf, sizeof(struct rte_pktmbuf_pool_private),
				 rte_pktmbuf_pool_init, NULL, rte_pktmbuf_init, 0,
				 sock_id, 0);
	PROX_PANIC(ret == NULL, "Failed to allocate memory pool '%s' on socket %u with %u elements\n",
		   name, sock_id, targ->nb_mbuf - 1);

	return ret;
}

static void init_task_rfc2544_gen(struct task_base *tbase, struct task_args *targ)
{
	struct task_rfc2544_gen *task = (struct task_rfc2544_gen *)tbase;
	struct rfc2544_session *session = rfc2544_session_get(targ);
	const int socket_id = rte_lcore_to_socket_id(targ->lconf->id);
	struct prox_port_cfg *port = find_reachable_port(targ);
	uint32_t max_frame_size = PROX_RTE_ETHER_MAX_LEN;
	uint64_t line_bytes_per_sec;
	struct token_time_cfg tt_cfg;

	PROX_PANIC(session->n_gen >= RFC2544_MAX_GENERATORS,
		   "Too many rfc2544 generators in session '%s' (max %u)\n",
		   targ->rfc2544.session, RFC2544_MAX_GENERATORS);
	PROX_PANIC(targ->nb_txports == 0 && targ->nb_txrings == 0,
		   "rfc2544gen requires a tx port or a tx ring\n");

	if (port)
		max_frame_size = port->mtu + PROX_RTE_ETHER_HDR_LEN + PROX_RTE_ETHER_CRC_LEN;
	rfc2544_check_cfg(targ, max_frame_size);
	line_bytes_per_sec = rfc2544_line_bytes_per_sec(targ, port);

	task->session = session;
	task->gen_id = session->n_gen++;
	task->slot = &session->gen[task->gen_id];
	task->slot->core_id = targ->lconf->id;
	task->sig = targ->rfc2544.signature;
	task->etype_be = rte_cpu_to_be_16((uint16_t)targ->rfc2544.etype);
	task->max_frame_size = max_frame_size;
	task->min_bulk_size = targ->min_bulk_size ? targ->min_bulk_size : 1;
	task->max_bulk_size = targ->max_bulk_size ? targ->max_bulk_size : MAX_PKT_BURST;
	PROX_PANIC(task->max_bulk_size > MAX_PKT_BURST, "max bulk size higher than %u\n", MAX_PKT_BURST);
	PROX_PANIC(task->max_bulk_size < task->min_bulk_size,
		   "max bulk size must be >= min bulk size\n");

	/* The destination mac defaults to broadcast so that the frames are
	   forwarded by any layer 2 device, the source mac defaults to the
	   mac of the transmitting port. */
	if (targ->flags & TASK_ARG_DST_MAC_SET)
		memcpy(&task->src_dst_mac[0], &targ->edaddr, sizeof(targ->edaddr));
	else
		memset(&task->src_dst_mac[0], 0xff, 6);

	if (targ->flags & TASK_ARG_SRC_MAC_SET)
		memcpy(&task->src_dst_mac[6], &targ->esaddr, sizeof(targ->esaddr));
	else if (port)
		memcpy(&task->src_dst_mac[6], &port->eth_addr, sizeof(port->eth_addr));

	task->frame_template = prox_zmalloc(max_frame_size, socket_id);
	PROX_PANIC(task->frame_template == NULL, "Failed to allocate the rfc2544 frame template\n");
	task_rfc2544_gen_build_template(task);

	task->local_mbuf.mempool = rfc2544_create_mempool(targ, max_frame_size);
	task_rfc2544_gen_set_frame_size(task, targ->rfc2544.frame_size[0], line_bytes_per_sec);
	rfc2544_counters_reset(&task->counters);

	/* The token bucket is refilled once per period. A period shorter
	   than a second keeps the intermediate results of the token
	   accounting far away from a 64 bit overflow, even for line rates
	   of several hundred Gbps. */
	tt_cfg.bpp = 0;
	tt_cfg.period = rte_get_tsc_hz() / RFC2544_TT_PERIOD_DIV;
	tt_cfg.bytes_max = (uint64_t)task->max_bulk_size *
		(max_frame_size + RFC2544_FRAME_OVERHEAD);
	token_time_init(&task->token_time, &tt_cfg);
	token_time_reset(&task->token_time, rte_rdtsc(), 0);

	/* The first generator of the session runs the test procedure. */
	if (task->gen_id == 0) {
		struct rfc2544_ctl *ctl = prox_zmalloc(sizeof(*ctl), socket_id);

		PROX_PANIC(ctl == NULL, "Failed to allocate the rfc2544 controller\n");
		PROX_PANIC(line_bytes_per_sec == 0,
			   "Unable to determine the line rate of the port, "
			   "use 'rfc2544 line rate' to configure it\n");
		ctl->cfg = targ->rfc2544;
		ctl->hz = rte_get_tsc_hz();
		ctl->line_bytes_per_sec = line_bytes_per_sec;
		ctl->lat_bucket_shift = rfc2544_lat_bucket_shift(targ->rfc2544.lat_bucket_nsec);
		ctl->state = RFC2544_CTL_WAIT_WORKERS;
		ctl->lo_ppm = 0;
		ctl->hi_ppm = ctl->cfg.start_rate_ppm;
		ctl->cur_ppm = ctl->cfg.start_rate_ppm;
		rfc2544_counters_reset(&ctl->agg);
		task->ctl = ctl;
		plog_info("\t\tCore %u is the rfc2544 controller of session '%s'\n",
			  targ->lconf->id, targ->rfc2544.session);
	}

	plog_info("\t\trfc2544 generator %u, session '%s'\n", task->gen_id, targ->rfc2544.session);
}

static void init_task_rfc2544_lat(struct task_base *tbase, struct task_args *targ)
{
	struct task_rfc2544_lat *task = (struct task_rfc2544_lat *)tbase;
	struct rfc2544_session *session = rfc2544_session_get(targ);

	PROX_PANIC(session->n_lat >= RFC2544_MAX_RECEIVERS,
		   "Too many rfc2544 receivers in session '%s' (max %u)\n",
		   targ->rfc2544.session, RFC2544_MAX_RECEIVERS);
	PROX_PANIC(targ->nb_rxports == 0 && targ->nb_rxrings == 0,
		   "rfc2544lat requires an rx port or an rx ring\n");
	PROX_PANIC(targ->nb_txports > 1 || targ->nb_txrings > 1,
		   "rfc2544lat supports at most one tx port or tx ring\n");

	task->session = session;
	task->slot = &session->lat[session->n_lat++];
	task->slot->core_id = targ->lconf->id;
	task->sig = targ->rfc2544.signature;
	task->etype_be = rte_cpu_to_be_16((uint16_t)targ->rfc2544.etype);
	task->lat_bucket_shift = rfc2544_lat_bucket_shift(targ->rfc2544.lat_bucket_nsec);
	rfc2544_counters_reset(&task->counters);

	plog_info("\t\trfc2544 receiver, session '%s', latency bucket %" PRIu64 " nsec\n",
		  targ->rfc2544.session, tsc_to_nsec(1ULL << task->lat_bucket_shift));
}

static void start_rfc2544_gen(struct task_base *tbase)
{
	struct task_rfc2544_gen *task = (struct task_rfc2544_gen *)tbase;

	rfc2544_counters_reset(&task->counters);
	task->transmitting = 0;
	task->phase_seq = __atomic_load_n(&task->session->phase_seq, __ATOMIC_ACQUIRE);
	rfc2544_publish(task->slot, &task->counters, task->phase_seq);
	__atomic_store_n(&task->slot->running, 1, __ATOMIC_RELEASE);

	if (task->ctl != NULL && task->ctl->state == RFC2544_CTL_WAIT_WORKERS) {
		/* Give the other tasks of the session the time to start. */
		task->ctl->deadline = rte_rdtsc() + msec_to_tsc(5000);
	}
}

static void stop_rfc2544_gen(struct task_base *tbase)
{
	struct task_rfc2544_gen *task = (struct task_rfc2544_gen *)tbase;

	task->transmitting = 0;
	__atomic_store_n(&task->slot->running, 0, __ATOMIC_RELEASE);
}

static void start_rfc2544_lat(struct task_base *tbase)
{
	struct task_rfc2544_lat *task = (struct task_rfc2544_lat *)tbase;

	rfc2544_counters_reset(&task->counters);
	task->counting = 0;
	task->phase_seq = __atomic_load_n(&task->session->phase_seq, __ATOMIC_ACQUIRE);
	rfc2544_publish(task->slot, &task->counters, task->phase_seq);
	__atomic_store_n(&task->slot->running, 1, __ATOMIC_RELEASE);
}

static void stop_rfc2544_lat(struct task_base *tbase)
{
	struct task_rfc2544_lat *task = (struct task_rfc2544_lat *)tbase;

	task->counting = 0;
	__atomic_store_n(&task->slot->running, 0, __ATOMIC_RELEASE);
}

static struct task_init task_init_rfc2544_gen = {
	.mode_str = "rfc2544gen",
	.init = init_task_rfc2544_gen,
	.handle = handle_rfc2544_gen_bulk,
	.start = start_rfc2544_gen,
	.stop = stop_rfc2544_gen,
	.flag_features = TASK_FEATURE_NEVER_DISCARDS | TASK_FEATURE_NO_RX |
			 TASK_FEATURE_TXQ_FLAGS_NOOFFLOADS,
	.size = sizeof(struct task_rfc2544_gen),
};

static struct task_init task_init_rfc2544_lat = {
	.mode_str = "rfc2544lat",
	.init = init_task_rfc2544_lat,
	.handle = handle_rfc2544_lat_bulk,
	.start = start_rfc2544_lat,
	.stop = stop_rfc2544_lat,
	.flag_features = TASK_FEATURE_TSC_RX | TASK_FEATURE_ZERO_RX | TASK_FEATURE_NEVER_DISCARDS,
	.size = sizeof(struct task_rfc2544_lat),
};

__attribute__((constructor)) static void reg_task_rfc2544(void)
{
	reg_task(&task_init_rfc2544_gen);
	reg_task(&task_init_rfc2544_lat);
}
