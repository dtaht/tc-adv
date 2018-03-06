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

#include "utils.h"
#include "tc_util.h"

static void explain(void)
{
	fprintf(stderr,
"Usage: ... cake [ bandwidth RATE | unlimited* | autorate_ingress ]\n"
"                [ rtt TIME | datacentre | lan | metro | regional |\n"
"                  internet* | oceanic | satellite | interplanetary ]\n"
"                [ besteffort | diffserv8 | diffserv4 | diffserv-llt |\n"
"                  diffserv3* ]\n"
"                [ flowblind | srchost | dsthost | hosts | flows |\n"
"                  dual-srchost | dual-dsthost | triple-isolate* ]\n"
"                [ nat | nonat* ]\n"
"                [ wash | nowash * ]\n"
"                [ ack-filter | ack-filter-aggressive | no-ack-filter * ]\n"
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
			diffserv = 1;
		} else if (strcmp(*argv, "precedence") == 0) {
			diffserv = 2;
		} else if (strcmp(*argv, "diffserv8") == 0) {
			diffserv = 3;
		} else if (strcmp(*argv, "diffserv4") == 0) {
			diffserv = 4;
		} else if (strcmp(*argv, "diffserv") == 0) {
			diffserv = 4;
		} else if (strcmp(*argv, "diffserv-llt") == 0) {
			diffserv = 5;
		} else if (strcmp(*argv, "diffserv3") == 0) {
			diffserv = 6;

		} else if (strcmp(*argv, "nowash") == 0) {
			wash = 0;
		} else if (strcmp(*argv, "wash") == 0) {
			wash = 1;

		} else if (strcmp(*argv, "flowblind") == 0) {
			flowmode = 0;
		} else if (strcmp(*argv, "srchost") == 0) {
			flowmode = 1;
		} else if (strcmp(*argv, "dsthost") == 0) {
			flowmode = 2;
		} else if (strcmp(*argv, "hosts") == 0) {
			flowmode = 3;
		} else if (strcmp(*argv, "flows") == 0) {
			flowmode = 4;
		} else if (strcmp(*argv, "dual-srchost") == 0) {
			flowmode = 5;
		} else if (strcmp(*argv, "dual-dsthost") == 0) {
			flowmode = 6;
		} else if (strcmp(*argv, "triple-isolate") == 0) {
			flowmode = 7;

		} else if (strcmp(*argv, "nat") == 0) {
			nat = 1;
		} else if (strcmp(*argv, "nonat") == 0) {
			nat = 0;

		} else if (strcmp(*argv, "ptm") == 0) {
			atm = 2;
		} else if (strcmp(*argv, "atm") == 0) {
			atm = 1;
		} else if (strcmp(*argv, "noatm") == 0) {
			atm = 0;

		} else if (strcmp(*argv, "raw") == 0) {
			atm = 0;
			overhead = 0;
			overhead_set = true;
			overhead_override = true;
		} else if (strcmp(*argv, "conservative") == 0) {
			/*
			 * Deliberately over-estimate overhead:
			 * one whole ATM cell plus ATM framing.
			 * A safe choice if the actual overhead is unknown.
			 */
			atm = 1;
			overhead = 48;
			overhead_set = true;

		/* Various ADSL framing schemes, all over ATM cells */
		} else if (strcmp(*argv, "ipoa-vcmux") == 0) {
			atm = 1;
			overhead += 8;
			overhead_set = true;
		} else if (strcmp(*argv, "ipoa-llcsnap") == 0) {
			atm = 1;
			overhead += 16;
			overhead_set = true;
		} else if (strcmp(*argv, "bridged-vcmux") == 0) {
			atm = 1;
			overhead += 24;
			overhead_set = true;
		} else if (strcmp(*argv, "bridged-llcsnap") == 0) {
			atm = 1;
			overhead += 32;
			overhead_set = true;
		} else if (strcmp(*argv, "pppoa-vcmux") == 0) {
			atm = 1;
			overhead += 10;
			overhead_set = true;
		} else if (strcmp(*argv, "pppoa-llc") == 0) {
			atm = 1;
			overhead += 14;
			overhead_set = true;
		} else if (strcmp(*argv, "pppoe-vcmux") == 0) {
			atm = 1;
			overhead += 32;
			overhead_set = true;
		} else if (strcmp(*argv, "pppoe-llcsnap") == 0) {
			atm = 1;
			overhead += 40;
			overhead_set = true;

		/* Typical VDSL2 framing schemes, both over PTM */
		/* PTM has 64b/65b coding which absorbs some bandwidth */
		} else if (strcmp(*argv, "pppoe-ptm") == 0) {
			atm = 2;
			overhead += 27;
			overhead_set = true;
		} else if (strcmp(*argv, "bridged-ptm") == 0) {
			atm = 2;
			overhead += 19;
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
			 * stats output when the automatic compensation is active.
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
		 * but not interframe gap nor preamble.
		 */
		} else if (strcmp(*argv, "docsis") == 0) {
			atm = 0;
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
			ack_filter = 0;
		} else if (strcmp(*argv, "ack-filter") == 0) {
			ack_filter = 0x0200;
		} else if (strcmp(*argv, "ack-filter-aggressive") == 0) {
			ack_filter = 0x0600;

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
		case 1:
			print_string(PRINT_ANY, "diffserv", "%s ", "besteffort");
			break;
		case 2:
			print_string(PRINT_ANY, "diffserv", "%s ", "precedence");
			break;
		case 3:
			print_string(PRINT_ANY, "diffserv", "%s ", "diffserv8");
			break;
		case 4:
			print_string(PRINT_ANY, "diffserv", "%s ", "diffserv4");
			break;
		case 5:
			print_string(PRINT_ANY, "diffserv", "%s ", "diffserv-llt");
			break;
		case 6:
			print_string(PRINT_ANY, "diffserv", "%s ", "diffserv3");
			break;
		default:
			print_string(PRINT_ANY, "diffserv", "(?diffserv?) ", "unknown");
			break;
		};
	}
	if (tb[TCA_CAKE_FLOW_MODE] &&
	    RTA_PAYLOAD(tb[TCA_CAKE_FLOW_MODE]) >= sizeof(__u32)) {
		flowmode = rta_getattr_u32(tb[TCA_CAKE_FLOW_MODE]);
		nat = !!(flowmode & 64);
		flowmode &= ~64;
		switch(flowmode) {
		case 0:
			print_string(PRINT_ANY, "flowmode", "%s ", "flowblind");
			break;
		case 1:
			print_string(PRINT_ANY, "flowmode", "%s ", "srchost");
			break;
		case 2:
			print_string(PRINT_ANY, "flowmode", "%s ", "dsthost");
			break;
		case 3:
			print_string(PRINT_ANY, "flowmode", "%s ", "hosts");
			break;
		case 4:
			print_string(PRINT_ANY, "flowmode", "%s ", "flows");
			break;
		case 5:
			print_string(PRINT_ANY, "flowmode", "%s ", "dual-srchost");
			break;
		case 6:
			print_string(PRINT_ANY, "flowmode", "%s ", "dual-dsthost");
			break;
		case 7:
			print_string(PRINT_ANY, "flowmode", "%s ", "triple-isolate");
			break;
		default:
			print_string(PRINT_ANY, "flowmode", "(?flowmode?) ", "unknown");
			break;
		};

		if(nat)
			print_string(PRINT_FP, NULL, "nat ", NULL);
		print_bool(PRINT_JSON, "nat", NULL, nat);
	}
	if (tb[TCA_CAKE_WASH] &&
	    RTA_PAYLOAD(tb[TCA_CAKE_WASH]) >= sizeof(__u32)) {
		wash = rta_getattr_u32(tb[TCA_CAKE_WASH]);
	}
	if (tb[TCA_CAKE_ATM] &&
	    RTA_PAYLOAD(tb[TCA_CAKE_ATM]) >= sizeof(__u32)) {
		atm = rta_getattr_u32(tb[TCA_CAKE_ATM]);
	}
	if (tb[TCA_CAKE_OVERHEAD] &&
	    RTA_PAYLOAD(tb[TCA_CAKE_OVERHEAD]) >= sizeof(__u32)) {
		overhead = rta_getattr_u32(tb[TCA_CAKE_OVERHEAD]);
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

	if (ack_filter == 0x0600)
		print_string(PRINT_ANY, "ack-filter", "ack-filter-%s ", "aggressive");
	else if (ack_filter)
		print_string(PRINT_ANY, "ack-filter", "ack-filter ", "enabled");
	else
		print_string(PRINT_JSON, "ack-filter", NULL, "disabled");

	if (interval)
		print_string(PRINT_FP, NULL, "rtt %s ", sprint_time(interval, b2));
	print_uint(PRINT_JSON, "rtt", NULL, interval);

	if (raw)
		print_string(PRINT_FP, NULL, "raw ", NULL);
	print_bool(PRINT_JSON, "raw", NULL, raw);

	if (atm == 1)
		print_string(PRINT_ANY, "atm", "%s ", "atm");
	else if (atm == 2)
		print_string(PRINT_ANY, "atm", "%s ", "ptm");
	else if (!raw)
		print_string(PRINT_ANY, "atm", "%s ", "noatm");

	print_uint(PRINT_ANY, "overhead", "overhead %d", overhead);

	if (mpu)
		print_uint(PRINT_ANY, "mpu", "mpu %d ", mpu);

	if (memlimit) {
		print_uint(PRINT_JSON, "memlimit", NULL, memlimit);
		print_string(PRINT_FP, NULL, "memlimit %s", sprint_size(memlimit, b1));
	}

	return 0;
}

#define FOR_EACH_TIN(xstats, tst, i)				\
	for(tst = xstats->tin_stats, i = 0;			\
	i < xstats->tin_cnt;						\
	    i++, tst = ((void *) xstats->tin_stats) + xstats->tin_stats_size * i)

static int cake_print_xstats(struct qdisc_util *qu, FILE *f,
				 struct rtattr *xstats)
{
	/* fq_codel stats format borrowed */
	struct tc_fq_codel_xstats *st;
	struct tc_cake_xstats     *stnc;
	SPRINT_BUF(b1);
	SPRINT_BUF(b2);

	if (xstats == NULL)
		return 0;

	if (RTA_PAYLOAD(xstats) < sizeof(st->type))
		return -1;

	st   = RTA_DATA(xstats);
	stnc = RTA_DATA(xstats);

	if (st->type == TCA_FQ_CODEL_XSTATS_QDISC && RTA_PAYLOAD(xstats) >= sizeof(*st)) {
		fprintf(f, "  maxpacket %u drop_overlimit %u new_flow_count %u ecn_mark %u",
			st->qdisc_stats.maxpacket,
			st->qdisc_stats.drop_overlimit,
			st->qdisc_stats.new_flow_count,
			st->qdisc_stats.ecn_mark);
		fprintf(f, "\n  new_flows_len %u old_flows_len %u",
			st->qdisc_stats.new_flows_len,
			st->qdisc_stats.old_flows_len);
	} else if (st->type == TCA_FQ_CODEL_XSTATS_CLASS && RTA_PAYLOAD(xstats) >= sizeof(*st)) {
		fprintf(f, "  deficit %d count %u lastcount %u ldelay %s",
			st->class_stats.deficit,
			st->class_stats.count,
			st->class_stats.lastcount,
			sprint_time(st->class_stats.ldelay, b1));
		if (st->class_stats.dropping) {
			fprintf(f, " dropping");
			if (st->class_stats.drop_next < 0)
				fprintf(f, " drop_next -%s",
					sprint_time(-st->class_stats.drop_next, b1));
			else
				fprintf(f, " drop_next %s",
					sprint_time(st->class_stats.drop_next, b1));
		}
	} else if (stnc->version > 0x100
		&& RTA_PAYLOAD(xstats) >= (sizeof(struct tc_cake_xstats) +
					stnc->tin_stats_size * stnc->tin_cnt))
	{
		struct tc_cake_tin_stats  *tst;
		int i;

		fprintf(f, " memory used: %s of %s\n", sprint_size(stnc->memory_used, b1), sprint_size(stnc->memory_limit, b2));
		fprintf(f, " capacity estimate: %s\n", sprint_rate(stnc->capacity_estimate, b1));

		switch(stnc->tin_cnt) {
		case 3:
			fprintf(f, "                 Bulk   Best Effort      Voice\n");
			break;

		case 4:
			fprintf(f, "                 Bulk   Best Effort      Video       Voice\n");
			break;

		case 5:
			fprintf(f, "              Low Loss  Best Effort   Low Delay       Bulk  Net Control\n");
			break;

		default:
			fprintf(f, "          ");
			for(i=0; i < stnc->tin_cnt; i++)
				fprintf(f, "       Tin %u", i);
			fprintf(f, "\n");
		};

		fprintf(f, "  thresh  ");
		FOR_EACH_TIN(stnc, tst, i)
			fprintf(f, "%12s", sprint_rate(tst->threshold_rate, b1));
		fprintf(f, "\n");

		fprintf(f, "  target  ");
		FOR_EACH_TIN(stnc, tst, i)
			fprintf(f, "%12s", sprint_time(tst->target_us, b1));
		fprintf(f, "\n");

		fprintf(f, "  interval");
		FOR_EACH_TIN(stnc, tst, i)
			fprintf(f, "%12s", sprint_time(tst->interval_us, b1));
		fprintf(f, "\n");

		fprintf(f, "  pk_delay");
		FOR_EACH_TIN(stnc, tst, i)
			fprintf(f, "%12s", sprint_time(tst->peak_delay_us, b1));
		fprintf(f, "\n");

		fprintf(f, "  av_delay");
		FOR_EACH_TIN(stnc, tst, i)
			fprintf(f, "%12s", sprint_time(tst->avge_delay_us, b1));
		fprintf(f, "\n");

		fprintf(f, "  sp_delay");
		FOR_EACH_TIN(stnc, tst, i)
			fprintf(f, "%12s", sprint_time(tst->base_delay_us, b1));
		fprintf(f, "\n");

		fprintf(f, "  pkts    ");
		FOR_EACH_TIN(stnc, tst, i)
			fprintf(f, "%12u", tst->sent.packets);
		fprintf(f, "\n");

		fprintf(f, "  bytes   ");
		FOR_EACH_TIN(stnc, tst, i)
			fprintf(f, "%12llu", tst->sent.bytes);
		fprintf(f, "\n");

		fprintf(f, "  way_inds");
		FOR_EACH_TIN(stnc, tst, i)
			fprintf(f, "%12u", tst->way_indirect_hits);
		fprintf(f, "\n");

		fprintf(f, "  way_miss");
		FOR_EACH_TIN(stnc, tst, i)
			fprintf(f, "%12u", tst->way_misses);
		fprintf(f, "\n");

		fprintf(f, "  way_cols");
		FOR_EACH_TIN(stnc, tst, i)
			fprintf(f, "%12u", tst->way_collisions);
		fprintf(f, "\n");

		fprintf(f, "  drops   ");
		FOR_EACH_TIN(stnc, tst, i)
			fprintf(f, "%12u", tst->dropped.packets);
		fprintf(f, "\n");

		fprintf(f, "  marks   ");
		FOR_EACH_TIN(stnc, tst, i)
			fprintf(f, "%12u", tst->ecn_marked.packets);
		fprintf(f, "\n");

		fprintf(f, "  ack_drop");
		FOR_EACH_TIN(stnc, tst, i)
			fprintf(f, "%12u", tst->ack_drops.packets);
		fprintf(f, "\n");

		fprintf(f, "  sp_flows");
		FOR_EACH_TIN(stnc, tst, i)
			fprintf(f, "%12u", tst->sparse_flows);
		fprintf(f, "\n");

		fprintf(f, "  bk_flows");
		FOR_EACH_TIN(stnc, tst, i)
			fprintf(f, "%12u", tst->bulk_flows);
		fprintf(f, "\n");

		fprintf(f, "  un_flows");
		FOR_EACH_TIN(stnc, tst, i)
			fprintf(f, "%12u", tst->unresponse_flows);
		fprintf(f, "\n");

		fprintf(f, "  max_len ");
		FOR_EACH_TIN(stnc, tst, i)
			fprintf(f, "%12u", tst->max_skblen);
		fprintf(f, "\n");

		fprintf(f, "  max_tran");
		fprintf(f, "%12u", stnc->max_trnlen);
		fprintf(f, "\n");

		fprintf(f, "  max_adj ");
		fprintf(f, "%12u", stnc->max_adjlen);
		fprintf(f, "\n");

		fprintf(f, "  min_tran");
		fprintf(f, "%12u", stnc->min_trnlen);
		fprintf(f, "\n");

		fprintf(f, "  min_adj ");
		fprintf(f, "%12u", stnc->min_adjlen);
		fprintf(f, "\n");

		fprintf(f, "  avg_off ");
		fprintf(f, "%12u", stnc->avg_trnoff);
		fprintf(f, "\n");
	} else {
		return -1;
	}
	return 0;
}

struct qdisc_util cake_qdisc_util = {
	.id		= "cake",
	.parse_qopt	= cake_parse_opt,
	.print_qopt	= cake_print_opt,
	.print_xstats	= cake_print_xstats,
};
