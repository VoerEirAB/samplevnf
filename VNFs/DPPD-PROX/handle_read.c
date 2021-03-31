/*
// Copyright (c) 2010-2017 Intel Corporation
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

#include <rte_ip.h>
#include <stdio.h>
#include <string.h>
#include <rte_version.h>

#include "prox_lua.h"
#include "prox_lua_types.h"
#include "lconf.h"
#include "prox_cfg.h"
#include "prox_shared.h"
#include "mbuf_utils.h"
#include "task_base.h"
#include "task_init.h"
#include "defines.h"
#include "prefetch.h"
#include "log.h"

struct task_read {
	struct task_base    base;
};

static inline uint8_t handle_port_range(struct task_read *task, struct rte_mbuf *mbuf)
{
    uint64_t *first;
    first = rte_pktmbuf_mtod(mbuf, uint64_t *);
    if (*first == 0) return OUT_DISCARD;

	prox_rte_ether_hdr *peth = rte_pktmbuf_mtod(mbuf, prox_rte_ether_hdr *);
	const prox_rte_ipv4_hdr *ipv4_hdr;
	const uint16_t eth_type = peth->ether_type;
	ipv4_hdr = (const prox_rte_ipv4_hdr *)(peth+1);
	if (ipv4_hdr->next_proto_id == IPPROTO_UDP) {
	    const prox_rte_udp_hdr *udp = (const prox_rte_udp_hdr *)((const uint8_t *)ipv4_hdr + sizeof(prox_rte_ipv4_hdr));
	    if (((udp->src_port == 0xD304) && (udp->dst_port == 0x2e16))) {
            TASK_STATS_ADD_DROP_DISCARD(&task->base.aux->stats, 1);
	        return OUT_DISCARD;
		}
	}
	return 0;
}

static int handle_read_bulk(struct task_base *tbase, struct rte_mbuf **mbufs, uint16_t n_pkts)
{
	struct task_read *task = (struct task_read *)tbase;
	uint8_t out[MAX_PKT_BURST];
	uint16_t j;

#ifdef PROX_PREFETCH_OFFSET
	for (j = 0; j < PROX_PREFETCH_OFFSET && j < n_pkts; ++j) {
		PREFETCH0(mbufs[j]);
	}
	for (j = 1; j < PROX_PREFETCH_OFFSET && j < n_pkts; ++j) {
		PREFETCH0(rte_pktmbuf_mtod(mbufs[j - 1], void *));
	}
#endif
	for (j = 0; j + PREFETCH_OFFSET < n_pkts; ++j) {
#ifdef PROX_PREFETCH_OFFSET
		PREFETCH0(mbufs[j + PREFETCH_OFFSET]);
		PREFETCH0(rte_pktmbuf_mtod(mbufs[j + PREFETCH_OFFSET - 1], void *));
#endif
		out[j] = handle_port_range(task, mbufs[j]);
	}
#ifdef PROX_PREFETCH_OFFSET
	prefetch_nta(rte_pktmbuf_mtod(mbufs[n_pkts - 1], void *));
	for (; j < n_pkts; ++j) {
		out[j] = handle_port_range(task, mbufs[j]);
	}
#endif

	return task->base.tx_pkt(&task->base, mbufs, n_pkts, out);
}

static void init_task_read(__attribute__((unused)) struct task_base *tbase,
			   __attribute__((unused)) struct task_args *targ)
{
}

static struct task_init task_init_read = {
	.mode_str = "read",
	.init = init_task_read,
	.handle = handle_read_bulk,
	.size = sizeof(struct task_read)
};

__attribute__((constructor)) static void reg_task_read(void)
{
	reg_task(&task_init_read);
}