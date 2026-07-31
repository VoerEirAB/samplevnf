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

#ifndef _HANDLE_RFC2544_H_
#define _HANDLE_RFC2544_H_

#include <inttypes.h>

/* Benchmarking of an L2 forwarding device according to RFC2544
   ("Benchmarking Methodology for Network Interconnect Devices").

   Two task modes implement the test:
     - 'rfc2544gen': transmits the test streams and, for the first
        generator of a session, also runs the test procedure itself.
     - 'rfc2544lat': receives the frames looped back by the device
        under test and measures frame loss, latency and re-ordering.

   Generators and receivers of the same session exchange data through a
   lock free shared session structure, so that the test can be scaled
   over as many cores as needed without introducing contention on the
   data path. */

/* Frame sizes to be used on Ethernet, see RFC2544 appendix C.2.1. The
   sizes include the frame check sequence but exclude preamble, start
   frame delimiter and inter frame gap. */
#define RFC2544_MAX_FRAME_SIZES		16
#define RFC2544_MIN_FRAME_SIZE		64
#define RFC2544_MAX_STD_FRAME_SIZE	1518

/* Tests described in RFC2544 section 26. */
#define RFC2544_TEST_THROUGHPUT		0x01	/* section 26.1 */
#define RFC2544_TEST_LATENCY		0x02	/* section 26.2 */
#define RFC2544_TEST_LOSS_RATE		0x04	/* section 26.3 */
#define RFC2544_TEST_ALL		(RFC2544_TEST_THROUGHPUT | \
					 RFC2544_TEST_LATENCY | \
					 RFC2544_TEST_LOSS_RATE)

/* Rates are expressed in parts per million of the line rate to avoid
   floating point arithmetic outside of the configuration parsing. */
#define RFC2544_FULL_RATE		1000000

#define RFC2544_SESSION_NAME_LEN	32

/* IEEE Std 802 local experimental Ethertype 1. Used by default since
   RFC2544 does not mandate any specific frame content for a layer 2
   forwarding device. */
#define RFC2544_DEFAULT_ETYPE		0x88B5
#define RFC2544_DEFAULT_SIGNATURE	0x52464332	/* "RFC2" */

struct rfc2544_cfg {
	char     session[RFC2544_SESSION_NAME_LEN];
	uint32_t frame_size[RFC2544_MAX_FRAME_SIZES];
	uint32_t n_frame_sizes;
	uint32_t tests;
	uint32_t trial_duration_msec;
	uint32_t warm_up_duration_msec;
	uint32_t settle_duration_msec;	/* RFC2544 section 23: wait for residual frames */
	uint32_t inter_trial_gap_msec;	/* RFC2544 section 23: wait before next trial */
	uint32_t start_rate_ppm;	/* highest rate offered to the device */
	uint32_t resolution_ppm;	/* stop condition of the binary search */
	uint32_t max_loss_ppm;		/* loss ratio still considered a success */
	uint32_t loss_step_ppm;		/* rate decrement of the frame loss rate test */
	uint32_t lat_bucket_nsec;	/* width of a latency histogram bucket */
	uint32_t latency_trials;	/* RFC2544 section 26.2 recommends 20 */
	uint32_t line_rate_mbps;	/* 0 means "take it from the port" */
	uint32_t etype;			/* Ethertype of the test frames, host order */
	uint32_t signature;		/* payload signature of the test frames */
};

/* Fill cfg with the values recommended by RFC2544. */
void rfc2544_cfg_set_defaults(struct rfc2544_cfg *cfg);

/* Parse a comma separated list of test names ("throughput", "latency",
   "loss" or "all") into a mask of RFC2544_TEST_* values. Returns 0 on
   success and -1 if an unknown test name is found. */
int rfc2544_parse_tests(uint32_t *tests, const char *str);

#endif /* _HANDLE_RFC2544_H_ */
