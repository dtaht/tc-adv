/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause) */
/*
 * Common Applications Kept Enhanced  --  CAKE
 *
 *  Copyright (C) 2014-2018 Jonathan Morton <chromatix99@gmail.com>
 *  Copyright (C) 2017-2018 Toke Høiland-Jørgensen <toke@toke.dk>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer,
 *    without modification.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The names of the authors may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * Alternatively, provided that this notice is retained in full, this
 * software may be distributed under the terms of the GNU General
 * Public License ("GPL") version 2, in which case the provisions of the
 * GPL apply INSTEAD OF those given above.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 *
 */

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <inttypes.h>

#include "utils.h"
#include "tc_util.h"

static void explain(void)
{
	fprintf(stderr,
"Usage: ... cake [ bandwidth RATE | unlimited* | autorate_ingress ]\n"
"                [ rtt TIME | datacentre | lan | metro | regional |\n"
"                  internet* | oceanic | satellite | interplanetary ]\n"
"                [ besteffort | diffserv8 | diffserv4 | diffserv3* ]\n"
"                [ flowblind | srchost | dsthost | hosts | flows |\n"
"                  dual-srchost | dual-dsthost | triple-isolate* ]\n"
"                [ nat | nonat* ]\n"
"                [ wash | nowash* ]\n"
"                [ ack-filter | ack-filter-aggressive | no-ack-filter* ]\n"
"                [ memlimit LIMIT ]\n"
"                [ ptm | atm | noatm* ] [ overhead N | conservative | raw* ]\n"
"                [ mpu N ] [ ingress | egress* ]\n"
"                (* marks defaults)\n");
}

static int cake_parse_opt(struct qdisc_util *qu, int argc, char **argv,
			  struct nlmsghdr *n, const char *dev)
{
	int unlimited = 0;
	unsigned bandwidth = 0;
	unsigned interval = 0;
	unsigned target = 0;
	unsigned diffserv = 0;
	unsigned memlimit = 0;
	int  overhead = 0;
	bool overhead_set = false;
	bool overhead_override = false;
	int mpu = 0;
	int flowmode = -1;
	int nat = -1;
	int atm = -1;
	int autorate = -1;
	int wash = -1;
	int ingress = -1;
	int ack_filter = -1;
	struct rtattr *tail;

	while (argc > 0) {
		if (strcmp(*argv, "bandwidth") == 0) {
			NEXT_ARG();
			if (get_rate(&bandwidth, *argv)) {
				fprintf(stderr, "Illegal \"bandwidth\"\n");
				return -1;
			}
			unlimited = 0;
			autorate = 0;
		} else if (strcmp(*argv, "unlimited") == 0) {
			bandwidth = 0;
			unlimited = 1;
			autorate = 0;
		} else if (strcmp(*argv, "autorate_ingress") == 0) {
			autorate = 1;

		} else if (strcmp(*argv, "rtt") == 0) {
			NEXT_ARG();
			if (get_time(&interval, *argv)) {
				fprintf(stderr, "Illegal \"rtt\"\n");
				return -1;
			}
			target = interval / 20;
			if(!target)
				target = 1;
		} else if (strcmp(*argv, "datacentre") == 0) {
			interval = 100;
			target   =   5;
		} else if (strcmp(*argv, "lan") == 0) {
			interval = 1000;
			target   =   50;
		} else if (strcmp(*argv, "metro") == 0) {
			interval = 10000;
			target   =   500;
		} else if (strcmp(*argv, "regional") == 0) {
			interval = 30000;
			target    = 1500;
		} else if (strcmp(*argv, "internet") == 0) {
			interval = 100000;
			target   =   5000;
		} else if (strcmp(*argv, "oceanic") == 0) {
			interval = 300000;
			target   =  15000;
		} else if (strcmp(*argv, "satellite") == 0) {
			interval = 1000000;
			target   =   50000;
		} else if (strcmp(*argv, "interplanetary") == 0) {
			interval = 1000000000;
			target   =   50000000;

		} else if (strcmp(*argv, "besteffort") == 0) {
			diffserv = CAKE_DIFFSERV_BESTEFFORT;
		} else if (strcmp(*argv, "precedence") == 0) {
			diffserv = CAKE_DIFFSERV_PRECEDENCE;
		} else if (strcmp(*argv, "diffserv8") == 0) {
			diffserv = CAKE_DIFFSERV_DIFFSERV8;
		} else if (strcmp(*argv, "diffserv4") == 0) {
			diffserv = CAKE_DIFFSERV_DIFFSERV4;
		} else if (strcmp(*argv, "diffserv") == 0) {
			diffserv = CAKE_DIFFSERV_DIFFSERV4;
		} else if (strcmp(*argv, "diffserv3") == 0) {
			diffserv = CAKE_DIFFSERV_DIFFSERV3;

		} else if (strcmp(*argv, "nowash") == 0) {
			wash = 0;
		} else if (strcmp(*argv, "wash") == 0) {
			wash = 1;

		} else if (strcmp(*argv, "flowblind") == 0) {
			flowmode = CAKE_FLOW_NONE;
		} else if (strcmp(*argv, "srchost") == 0) {
			flowmode = CAKE_FLOW_SRC_IP;
		} else if (strcmp(*argv, "dsthost") == 0) {
			flowmode = CAKE_FLOW_DST_IP;
		} else if (strcmp(*argv, "hosts") == 0) {
			flowmode = CAKE_FLOW_HOSTS;
		} else if (strcmp(*argv, "flows") == 0) {
			flowmode = CAKE_FLOW_FLOWS;
		} else if (strcmp(*argv, "dual-srchost") == 0) {
			flowmode = CAKE_FLOW_DUAL_SRC;
		} else if (strcmp(*argv, "dual-dsthost") == 0) {
			flowmode = CAKE_FLOW_DUAL_DST;
		} else if (strcmp(*argv, "triple-isolate") == 0) {
			flowmode = CAKE_FLOW_TRIPLE;

		} else if (strcmp(*argv, "nat") == 0) {
			nat = 1;
		} else if (strcmp(*argv, "nonat") == 0) {
			nat = 0;

		} else if (strcmp(*argv, "ptm") == 0) {
			atm = CAKE_ATM_PTM;
		} else if (strcmp(*argv, "atm") == 0) {
			atm = CAKE_ATM_ATM;
		} else if (strcmp(*argv, "noatm") == 0) {
			atm = CAKE_ATM_NONE;

		} else if (strcmp(*argv, "raw") == 0) {
			atm = CAKE_ATM_NONE;
			overhead = 0;
			overhead_set = true;
			overhead_override = true;
		} else if (strcmp(*argv, "conservative") == 0) {
			/*
			 * Deliberately over-estimate overhead:
			 * one whole ATM cell plus ATM framing.
			 * A safe choice if the actual overhead is unknown.
			 */
			atm = CAKE_ATM_ATM;
			overhead = 48;
			overhead_set = true;

		/* Various ADSL framing schemes, all over ATM cells */
		} else if (strcmp(*argv, "ipoa-vcmux") == 0) {
			atm = CAKE_ATM_ATM;
			overhead += 8;
			overhead_set = true;
		} else if (strcmp(*argv, "ipoa-llcsnap") == 0) {
			atm = CAKE_ATM_ATM;
			overhead += 16;
			overhead_set = true;
		} else if (strcmp(*argv, "bridged-vcmux") == 0) {
			atm = CAKE_ATM_ATM;
			overhead += 24;
			overhead_set = true;
		} else if (strcmp(*argv, "bridged-llcsnap") == 0) {
			atm = CAKE_ATM_ATM;
			overhead += 32;
			overhead_set = true;
		} else if (strcmp(*argv, "pppoa-vcmux") == 0) {
			atm = CAKE_ATM_ATM;
			overhead += 10;
			overhead_set = true;
		} else if (strcmp(*argv, "pppoa-llc") == 0) {
			atm = CAKE_ATM_ATM;
			overhead += 14;
			overhead_set = true;
		} else if (strcmp(*argv, "pppoe-vcmux") == 0) {
			atm = CAKE_ATM_ATM;
			overhead += 32;
			overhead_set = true;
		} else if (strcmp(*argv, "pppoe-llcsnap") == 0) {
			atm = CAKE_ATM_ATM;
			overhead += 40;
			overhead_set = true;

		/* Typical VDSL2 framing schemes, both over PTM */
		/* PTM has 64b/65b coding which absorbs some bandwidth */
		} else if (strcmp(*argv, "pppoe-ptm") == 0) {
			/* 2B PPP + 6B PPPoE + 6B dest MAC + 6B src MAC
			 * + 2B ethertype + 4B Frame Check Sequence
			 * + 1B Start of Frame (S) + 1B End of Frame (Ck)
			 * + 2B TC-CRC (PTM-FCS) = 30B
			 */
			atm = CAKE_ATM_PTM;
			overhead += 30;
			overhead_set = true;
		} else if (strcmp(*argv, "bridged-ptm") == 0) {
			/* 6B dest MAC + 6B src MAC + 2B ethertype
			 * + 4B Frame Check Sequence
			 * + 1B Start of Frame (S) + 1B End of Frame (Ck)
			 * + 2B TC-CRC (PTM-FCS) = 22B
			 */
			atm = CAKE_ATM_PTM;
			overhead += 22;
			overhead_set = true;

		} else if (strcmp(*argv, "via-ethernet") == 0) {
			/*
			 * We used to use this flag to manually compensate for
			 * Linux including the Ethernet header on Ethernet-type
			 * interfaces, but not on IP-type interfaces.
			 *
			 * It is no longer needed, because Cake now adjusts for
			 * that automatically, and is thus ignored.
			 *
			 * It would be deleted entirely, but it appears in the
			 * stats output when the automatic compensation is
			 * active.
			 */

		} else if (strcmp(*argv, "ethernet") == 0) {
			/* ethernet pre-amble & interframe gap & FCS
			 * you may need to add vlan tag */
			overhead += 38;
			overhead_set = true;
			mpu = 84;

		/* Additional Ethernet-related overhead used by some ISPs */
		} else if (strcmp(*argv, "ether-vlan") == 0) {
			/* 802.1q VLAN tag - may be repeated */
			overhead += 4;
			overhead_set = true;

		/*
		 * DOCSIS cable shapers account for Ethernet frame with FCS,
		 * but not interframe gap or preamble.
		 */
		} else if (strcmp(*argv, "docsis") == 0) {
			atm = CAKE_ATM_NONE;
			overhead += 18;
			overhead_set = true;
			mpu = 64;

		} else if (strcmp(*argv, "overhead") == 0) {
			char* p = NULL;
			NEXT_ARG();
			overhead = strtol(*argv, &p, 10);
			if(!p || *p || !*argv || overhead < -64 || overhead > 256) {
				fprintf(stderr, "Illegal \"overhead\", valid range is -64 to 256\\n");
				return -1;
			}
			overhead_set = true;

		} else if (strcmp(*argv, "mpu") == 0) {
			char* p = NULL;
			NEXT_ARG();
			mpu = strtol(*argv, &p, 10);
			if(!p || *p || !*argv || mpu < 0 || mpu > 256) {
				fprintf(stderr, "Illegal \"mpu\", valid range is 0 to 256\\n");
				return -1;
			}

		} else if (strcmp(*argv, "ingress") == 0) {
			ingress = 1;
		} else if (strcmp(*argv, "egress") == 0) {
			ingress = 0;

		} else if (strcmp(*argv, "no-ack-filter") == 0) {
			ack_filter = CAKE_ACK_NONE;
		} else if (strcmp(*argv, "ack-filter") == 0) {
			ack_filter = CAKE_ACK_FILTER;
		} else if (strcmp(*argv, "ack-filter-aggressive") == 0) {
			ack_filter = CAKE_ACK_AGGRESSIVE;

		} else if (strcmp(*argv, "memlimit") == 0) {
			NEXT_ARG();
			if(get_size(&memlimit, *argv)) {
				fprintf(stderr, "Illegal value for \"memlimit\": \"%s\"\n", *argv);
				return -1;
			}

		} else if (strcmp(*argv, "help") == 0) {
			explain();
			return -1;
		} else {
			fprintf(stderr, "What is \"%s\"?\n", *argv);
			explain();
			return -1;
		}
		argc--; argv++;
	}

	tail = NLMSG_TAIL(n);
	addattr_l(n, 1024, TCA_OPTIONS, NULL, 0);
	if (bandwidth || unlimited)
		addattr_l(n, 1024, TCA_CAKE_BASE_RATE, &bandwidth, sizeof(bandwidth));
	if (diffserv)
		addattr_l(n, 1024, TCA_CAKE_DIFFSERV_MODE, &diffserv, sizeof(diffserv));
	if (atm != -1)
		addattr_l(n, 1024, TCA_CAKE_ATM, &atm, sizeof(atm));
	if (flowmode != -1)
		addattr_l(n, 1024, TCA_CAKE_FLOW_MODE, &flowmode, sizeof(flowmode));
	if (overhead_set)
		addattr_l(n, 1024, TCA_CAKE_OVERHEAD, &overhead, sizeof(overhead));
	if (overhead_override) {
		unsigned zero = 0;
		addattr_l(n, 1024, TCA_CAKE_RAW, &zero, sizeof(zero));
	}
	if (mpu > 0)
		addattr_l(n, 1024, TCA_CAKE_MPU, &mpu, sizeof(mpu));
	if (interval)
		addattr_l(n, 1024, TCA_CAKE_RTT, &interval, sizeof(interval));
	if (target)
		addattr_l(n, 1024, TCA_CAKE_TARGET, &target, sizeof(target));
	if (autorate != -1)
		addattr_l(n, 1024, TCA_CAKE_AUTORATE, &autorate, sizeof(autorate));
	if (memlimit)
		addattr_l(n, 1024, TCA_CAKE_MEMORY, &memlimit, sizeof(memlimit));
	if (nat != -1)
		addattr_l(n, 1024, TCA_CAKE_NAT, &nat, sizeof(nat));
	if (wash != -1)
		addattr_l(n, 1024, TCA_CAKE_WASH, &wash, sizeof(wash));
	if (ingress != -1)
		addattr_l(n, 1024, TCA_CAKE_INGRESS, &ingress, sizeof(ingress));
	if (ack_filter != -1)
		addattr_l(n, 1024, TCA_CAKE_ACK_FILTER, &ack_filter, sizeof(ack_filter));

	tail->rta_len = (void *) NLMSG_TAIL(n) - (void *) tail;
	return 0;
}


static int cake_print_opt(struct qdisc_util *qu, FILE *f, struct rtattr *opt)
{
	struct rtattr *tb[TCA_CAKE_MAX + 1];
	unsigned bandwidth = 0;
	unsigned diffserv = 0;
	unsigned flowmode = 0;
	unsigned interval = 0;
	unsigned memlimit = 0;
	int overhead = 0;
	int raw = 0;
	int mpu = 0;
	int atm = 0;
	int nat = 0;
	int autorate = 0;
	int wash = 0;
	int ingress = 0;
	int ack_filter = 0;
	int split_gso = 0;
	SPRINT_BUF(b1);
	SPRINT_BUF(b2);

	if (opt == NULL)
		return 0;

	parse_rtattr_nested(tb, TCA_CAKE_MAX, opt);

	if (tb[TCA_CAKE_BASE_RATE] &&
	    RTA_PAYLOAD(tb[TCA_CAKE_BASE_RATE]) >= sizeof(__u32)) {
		bandwidth = rta_getattr_u32(tb[TCA_CAKE_BASE_RATE]);
		if(bandwidth) {
			print_uint(PRINT_JSON, "bandwidth", NULL, bandwidth);
			print_string(PRINT_FP, NULL, "bandwidth %s ", sprint_rate(bandwidth, b1));
		} else
			print_string(PRINT_ANY, "bandwidth", "bandwidth %s ", "unlimited");
	}
	if (tb[TCA_CAKE_AUTORATE] &&
		RTA_PAYLOAD(tb[TCA_CAKE_AUTORATE]) >= sizeof(__u32)) {
		autorate = rta_getattr_u32(tb[TCA_CAKE_AUTORATE]);
		if(autorate == 1)
			print_string(PRINT_ANY, "autorate", "autorate_%s ", "ingress");
		else if(autorate)
			print_string(PRINT_ANY, "autorate", "(?autorate?) ", "unknown");
	}
	if (tb[TCA_CAKE_DIFFSERV_MODE] &&
	    RTA_PAYLOAD(tb[TCA_CAKE_DIFFSERV_MODE]) >= sizeof(__u32)) {
		diffserv = rta_getattr_u32(tb[TCA_CAKE_DIFFSERV_MODE]);
		switch(diffserv) {
		case CAKE_DIFFSERV_DIFFSERV3:
			print_string(PRINT_ANY, "diffserv", "%s ", "diffserv3");
			break;
		case CAKE_DIFFSERV_DIFFSERV4:
			print_string(PRINT_ANY, "diffserv", "%s ", "diffserv4");
			break;
		case CAKE_DIFFSERV_DIFFSERV8:
			print_string(PRINT_ANY, "diffserv", "%s ", "diffserv8");
			break;
		case CAKE_DIFFSERV_BESTEFFORT:
			print_string(PRINT_ANY, "diffserv", "%s ", "besteffort");
			break;
		case CAKE_DIFFSERV_PRECEDENCE:
			print_string(PRINT_ANY, "diffserv", "%s ", "precedence");
			break;
		default:
			print_string(PRINT_ANY, "diffserv", "(?diffserv?) ", "unknown");
			break;
		};
	}
	if (tb[TCA_CAKE_FLOW_MODE] &&
	    RTA_PAYLOAD(tb[TCA_CAKE_FLOW_MODE]) >= sizeof(__u32)) {
		flowmode = rta_getattr_u32(tb[TCA_CAKE_FLOW_MODE]);
		switch(flowmode) {
		case CAKE_FLOW_NONE:
			print_string(PRINT_ANY, "flowmode", "%s ", "flowblind");
			break;
		case CAKE_FLOW_SRC_IP:
			print_string(PRINT_ANY, "flowmode", "%s ", "srchost");
			break;
		case CAKE_FLOW_DST_IP:
			print_string(PRINT_ANY, "flowmode", "%s ", "dsthost");
			break;
		case CAKE_FLOW_HOSTS:
			print_string(PRINT_ANY, "flowmode", "%s ", "hosts");
			break;
		case CAKE_FLOW_FLOWS:
			print_string(PRINT_ANY, "flowmode", "%s ", "flows");
			break;
		case CAKE_FLOW_DUAL_SRC:
			print_string(PRINT_ANY, "flowmode", "%s ", "dual-srchost");
			break;
		case CAKE_FLOW_DUAL_DST:
			print_string(PRINT_ANY, "flowmode", "%s ", "dual-dsthost");
			break;
		case CAKE_FLOW_TRIPLE:
			print_string(PRINT_ANY, "flowmode", "%s ", "triple-isolate");
			break;
		default:
			print_string(PRINT_ANY, "flowmode", "(?flowmode?) ", "unknown");
			break;
		};

	}

	if (tb[TCA_CAKE_NAT] &&
	    RTA_PAYLOAD(tb[TCA_CAKE_NAT]) >= sizeof(__u32)) {
	    nat = rta_getattr_u32(tb[TCA_CAKE_NAT]);
	}

	if(nat)
		print_string(PRINT_FP, NULL, "nat ", NULL);
	print_bool(PRINT_JSON, "nat", NULL, nat);

	if (tb[TCA_CAKE_WASH] &&
	    RTA_PAYLOAD(tb[TCA_CAKE_WASH]) >= sizeof(__u32)) {
		wash = rta_getattr_u32(tb[TCA_CAKE_WASH]);
	}
	if (tb[TCA_CAKE_ATM] &&
	    RTA_PAYLOAD(tb[TCA_CAKE_ATM]) >= sizeof(__u32)) {
		atm = rta_getattr_u32(tb[TCA_CAKE_ATM]);
	}
	if (tb[TCA_CAKE_OVERHEAD] &&
	    RTA_PAYLOAD(tb[TCA_CAKE_OVERHEAD]) >= sizeof(__s32)) {
		overhead = *(__s32 *) RTA_DATA(tb[TCA_CAKE_OVERHEAD]);
	}
	if (tb[TCA_CAKE_MPU] &&
	    RTA_PAYLOAD(tb[TCA_CAKE_MPU]) >= sizeof(__u32)) {
		mpu = rta_getattr_u32(tb[TCA_CAKE_MPU]);
	}
	if (tb[TCA_CAKE_INGRESS] &&
	    RTA_PAYLOAD(tb[TCA_CAKE_INGRESS]) >= sizeof(__u32)) {
		ingress = rta_getattr_u32(tb[TCA_CAKE_INGRESS]);
	}
	if (tb[TCA_CAKE_ACK_FILTER] &&
	    RTA_PAYLOAD(tb[TCA_CAKE_ACK_FILTER]) >= sizeof(__u32)) {
		ack_filter = rta_getattr_u32(tb[TCA_CAKE_ACK_FILTER]);
	}
	if (tb[TCA_CAKE_SPLIT_GSO] &&
	    RTA_PAYLOAD(tb[TCA_CAKE_SPLIT_GSO]) >= sizeof(__u32)) {
		split_gso = rta_getattr_u32(tb[TCA_CAKE_SPLIT_GSO]);
	}
	if (tb[TCA_CAKE_RAW]) {
		raw = 1;
	}
	if (tb[TCA_CAKE_RTT] &&
	    RTA_PAYLOAD(tb[TCA_CAKE_RTT]) >= sizeof(__u32)) {
		interval = rta_getattr_u32(tb[TCA_CAKE_RTT]);
	}

	if (wash)
		print_string(PRINT_FP, NULL, "wash ", NULL);
	print_bool(PRINT_JSON, "wash", NULL, wash);

	if (ingress)
		print_string(PRINT_FP, NULL, "ingress ", NULL);
	print_bool(PRINT_JSON, "ingress", NULL, ingress);

	if (ack_filter == CAKE_ACK_AGGRESSIVE)
		print_string(PRINT_ANY, "ack-filter", "ack-filter-%s ", "aggressive");
	else if (ack_filter == CAKE_ACK_FILTER)
		print_string(PRINT_ANY, "ack-filter", "ack-filter ", "enabled");
	else
		print_string(PRINT_JSON, "ack-filter", NULL, "disabled");

	if (split_gso)
		print_string(PRINT_FP, NULL, "split-gso ", NULL);
	print_bool(PRINT_JSON, "split_gso", NULL, split_gso);

	if (interval)
		print_string(PRINT_FP, NULL, "rtt %s ", sprint_time(interval, b2));
	print_uint(PRINT_JSON, "rtt", NULL, interval);

	if (raw)
		print_string(PRINT_FP, NULL, "raw ", NULL);
	print_bool(PRINT_JSON, "raw", NULL, raw);

	if (atm == CAKE_ATM_ATM)
		print_string(PRINT_ANY, "atm", "%s ", "atm");
	else if (atm == CAKE_ATM_PTM)
		print_string(PRINT_ANY, "atm", "%s ", "ptm");
	else if (!raw)
		print_string(PRINT_ANY, "atm", "%s ", "noatm");

	print_int(PRINT_ANY, "overhead", "overhead %d ", overhead);

	if (mpu)
		print_uint(PRINT_ANY, "mpu", "mpu %u ", mpu);

	if (memlimit) {
		print_uint(PRINT_JSON, "memlimit", NULL, memlimit);
		print_string(PRINT_FP, NULL, "memlimit %s", sprint_size(memlimit, b1));
	}

	return 0;
}

static void cake_print_json_tin(struct rtattr **tstat)
{
#define PRINT_TSTAT_JSON(type, name, attr) if (tstat[TCA_CAKE_TIN_STATS_ ## attr]) \
		print_u64(PRINT_JSON, name, NULL,			\
			rta_getattr_ ## type((struct rtattr *)tstat[TCA_CAKE_TIN_STATS_ ## attr]))

	open_json_object(NULL);
	PRINT_TSTAT_JSON(u32, "threshold_rate", THRESHOLD_RATE);
	PRINT_TSTAT_JSON(u32, "target_us", TARGET_US);
	PRINT_TSTAT_JSON(u32, "interval_us", INTERVAL_US);
	PRINT_TSTAT_JSON(u32, "peak_delay_us", PEAK_DELAY_US);
	PRINT_TSTAT_JSON(u32, "avg_delay_us", AVG_DELAY_US);
	PRINT_TSTAT_JSON(u32, "base_delay_us", BASE_DELAY_US);
	PRINT_TSTAT_JSON(u32, "sent_packets", SENT_PACKETS);
	PRINT_TSTAT_JSON(u64, "sent_bytes", SENT_BYTES64);
	PRINT_TSTAT_JSON(u32, "way_indirect_hits", WAY_INDIRECT_HITS);
	PRINT_TSTAT_JSON(u32, "way_misses", WAY_MISSES);
	PRINT_TSTAT_JSON(u32, "way_collisions", WAY_COLLISIONS);
	PRINT_TSTAT_JSON(u32, "drops", DROPPED_PACKETS);
	PRINT_TSTAT_JSON(u32, "ecn_mark", ECN_MARKED_PACKETS);
	PRINT_TSTAT_JSON(u32, "ack_drops", ACKS_DROPPED_PACKETS);
	PRINT_TSTAT_JSON(u32, "sparse_flows", SPARSE_FLOWS);
	PRINT_TSTAT_JSON(u32, "bulk_flows", BULK_FLOWS);
	PRINT_TSTAT_JSON(u32, "unresponsive_flows", UNRESPONSIVE_FLOWS);
	PRINT_TSTAT_JSON(u32, "max_pkt_len", MAX_SKBLEN);
	PRINT_TSTAT_JSON(u32, "flow_quantum", FLOW_QUANTUM);
	close_json_object();

#undef PRINT_TSTAT_JSON
}

static int cake_print_xstats(struct qdisc_util *qu, FILE *f,
			     struct rtattr *xstats)
{
	SPRINT_BUF(b1);
	struct rtattr *st[TCA_CAKE_STATS_MAX + 1];
	int i;

	if (xstats == NULL)
		return 0;

#define GET_STAT_U32(attr) rta_getattr_u32(st[TCA_CAKE_STATS_ ## attr])

	parse_rtattr_nested(st, TCA_CAKE_STATS_MAX, xstats);

	if (st[TCA_CAKE_STATS_MEMORY_USED] &&
	    st[TCA_CAKE_STATS_MEMORY_LIMIT]) {
		print_string(PRINT_FP, NULL, " memory used: %s",
			sprint_size(GET_STAT_U32(MEMORY_USED), b1));

		print_string(PRINT_FP, NULL, " of %s\n",
			sprint_size(GET_STAT_U32(MEMORY_LIMIT), b1));

		print_uint(PRINT_JSON, "memory_used", NULL,
			GET_STAT_U32(MEMORY_USED));
		print_uint(PRINT_JSON, "memory_limit", NULL,
			GET_STAT_U32(MEMORY_LIMIT));
	}

	if (st[TCA_CAKE_STATS_CAPACITY_ESTIMATE]) {
		print_string(PRINT_FP, NULL, " capacity estimate: %s\n",
			sprint_rate(GET_STAT_U32(CAPACITY_ESTIMATE), b1));
		print_uint(PRINT_JSON, "capacity_estimate", NULL,
			GET_STAT_U32(CAPACITY_ESTIMATE));
	}

	if (st[TCA_CAKE_STATS_MIN_NETLEN] &&
	    st[TCA_CAKE_STATS_MAX_NETLEN]) {
		print_uint(PRINT_ANY, "min_network_size",
			   " min/max network layer size: %12u",
			   GET_STAT_U32(MIN_NETLEN));
		print_uint(PRINT_ANY, "max_network_size",
			   " /%8u\n", GET_STAT_U32(MAX_NETLEN));
	}

	if (st[TCA_CAKE_STATS_MIN_ADJLEN] &&
	    st[TCA_CAKE_STATS_MAX_ADJLEN]) {
		print_uint(PRINT_ANY, "min_adj_size",
			   " min/max overhead-adjusted size: %8u",
			   GET_STAT_U32(MIN_ADJLEN));
		print_uint(PRINT_ANY, "max_adj_size",
			   " /%8u\n", GET_STAT_U32(MAX_ADJLEN));
	}

	if (st[TCA_CAKE_STATS_AVG_NETOFF])
		print_uint(PRINT_ANY, "avg_hdr_offset",
			   " average network hdr offset: %12u\n\n",
			   GET_STAT_U32(AVG_NETOFF));

#undef GET_STAT_U32

	if (st[TCA_CAKE_STATS_TIN_STATS]) {
		struct rtattr *tins[TC_CAKE_MAX_TINS + 1];
		struct rtattr *tstat[TC_CAKE_MAX_TINS][TCA_CAKE_TIN_STATS_MAX + 1];
		int num_tins = 0;

		parse_rtattr_nested(tins, TC_CAKE_MAX_TINS, st[TCA_CAKE_STATS_TIN_STATS]);

		for (i = 1; i <= TC_CAKE_MAX_TINS && tins[i]; i++) {
			parse_rtattr_nested(tstat[i-1], TCA_CAKE_TIN_STATS_MAX, tins[i]);
			num_tins++;
		}

		if (!num_tins)
			return 0;

		if (is_json_context()) {
			open_json_array(PRINT_JSON, "tins");
			for (i = 0; i < num_tins; i++)
				cake_print_json_tin(tstat[i]);
			close_json_array(PRINT_JSON, NULL);

			return 0;
		}


		switch(num_tins) {
		case 3:
			fprintf(f, "                   Bulk  Best Effort        Voice\n");
			break;

		case 4:
			fprintf(f, "                   Bulk  Best Effort        Video        Voice\n");
			break;

		default:
			fprintf(f, "          ");
			for(i=0; i < num_tins; i++)
				fprintf(f, "        Tin %u", i);
			fprintf(f, "\n");
		};

#define GET_TSTAT(i, attr) (tstat[i][TCA_CAKE_TIN_STATS_ ## attr])
#define PRINT_TSTAT(name, attr, fmts, val)	do {		\
			if (GET_TSTAT(0, attr)) {		\
				fprintf(f, name);		\
				for (i = 0; i < num_tins; i++)	\
					fprintf(f, " %12" fmts,	val);	\
				fprintf(f, "\n");			\
			}						\
		} while (0)

#define SPRINT_TSTAT(pfunc, name, attr) PRINT_TSTAT(		\
			name, attr, "s", sprint_ ## pfunc(		\
				rta_getattr_u32(GET_TSTAT(i, attr)), b1))

#define PRINT_TSTAT_U32(name, attr)	PRINT_TSTAT(			\
			name, attr, "u", rta_getattr_u32(GET_TSTAT(i, attr)))

#define PRINT_TSTAT_U64(name, attr)	PRINT_TSTAT(			\
			name, attr, "llu", rta_getattr_u64(GET_TSTAT(i, attr)))

		SPRINT_TSTAT(rate, "  thresh  ", THRESHOLD_RATE);
		SPRINT_TSTAT(time, "  target  ", TARGET_US);
		SPRINT_TSTAT(time, "  interval", INTERVAL_US);
		SPRINT_TSTAT(time, "  pk_delay", PEAK_DELAY_US);
		SPRINT_TSTAT(time, "  av_delay", AVG_DELAY_US);
		SPRINT_TSTAT(time, "  sp_delay", BASE_DELAY_US);

		PRINT_TSTAT_U32("  pkts    ", SENT_PACKETS);
		PRINT_TSTAT_U64("  bytes   ", SENT_BYTES64);

		PRINT_TSTAT_U32("  way_inds", WAY_INDIRECT_HITS);
		PRINT_TSTAT_U32("  way_miss", WAY_MISSES);
		PRINT_TSTAT_U32("  way_cols", WAY_COLLISIONS);
		PRINT_TSTAT_U32("  drops   ", DROPPED_PACKETS);
		PRINT_TSTAT_U32("  marks   ", ECN_MARKED_PACKETS);
		PRINT_TSTAT_U32("  ack_drop", ACKS_DROPPED_PACKETS);
		PRINT_TSTAT_U32("  sp_flows", SPARSE_FLOWS);
		PRINT_TSTAT_U32("  bk_flows", BULK_FLOWS);
		PRINT_TSTAT_U32("  un_flows", UNRESPONSIVE_FLOWS);
		PRINT_TSTAT_U32("  max_len ", MAX_SKBLEN);
		PRINT_TSTAT_U32("  quantum ", FLOW_QUANTUM);

#undef GET_STAT
#undef PRINT_TSTAT
#undef SPRINT_TSTAT
#undef PRINT_TSTAT_U32
#undef PRINT_TSTAT_U64
	}
	return 0;
}

struct qdisc_util cake_qdisc_util = {
	.id		= "cake",
	.parse_qopt	= cake_parse_opt,
	.print_qopt	= cake_print_opt,
	.print_xstats	= cake_print_xstats,
};
