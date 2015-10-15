/*
 * Common Applications Kept Enhanced  --  CAKE
 *
 *  Copyright (C) 2014 Jonathan Morton <chromatix99@gmail.com>
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
	fprintf(stderr, "Usage: ... cake0 [ bandwidth RATE | unlimited ]\n"
	                "                 [ besteffort | precedence | diffserv ]\n"
	                "                 [ flowblind | srchost | dsthost | hosts | flows ]\n"
	                "                 [ atm ]\n");
}

static int cake_parse_opt(struct qdisc_util *qu, int argc, char **argv,
			      struct nlmsghdr *n)
{
	int unlimited = 0;
	unsigned bandwidth = 0;
	unsigned diffserv = 0;
	int flowmode = -1;
	int atm = -1;
	struct rtattr *tail;

	while (argc > 0) {
		if (strcmp(*argv, "bandwidth") == 0) {
			NEXT_ARG();
			if (get_rate(&bandwidth, *argv)) {
				fprintf(stderr, "Illegal \"bandwidth\"\n");
				return -1;
			}
			unlimited = 0;
		} else if (strcmp(*argv, "unlimited") == 0) {
			bandwidth = 0;
			unlimited = 1;

		} else if (strcmp(*argv, "besteffort") == 0) {
			diffserv = 1;
		} else if (strcmp(*argv, "precedence") == 0) {
			diffserv = 2;
		} else if (strcmp(*argv, "diffserv") == 0) {
			diffserv = 3;

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

		} else if (strcmp(*argv, "atm") == 0) {
			atm = 1;
		} else if (strcmp(*argv, "noatm") == 0) {
			atm = 0;

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
	tail->rta_len = (void *) NLMSG_TAIL(n) - (void *) tail;
	return 0;
}

static int cake_print_opt(struct qdisc_util *qu, FILE *f, struct rtattr *opt)
{
	struct rtattr *tb[TCA_CAKE_MAX + 1];
	unsigned bandwidth = 0;
	unsigned diffserv = 0;
	unsigned flowmode = 0;
	int atm = -1;
	SPRINT_BUF(b1);

	if (opt == NULL)
		return 0;

	parse_rtattr_nested(tb, TCA_CAKE_MAX, opt);

	if (tb[TCA_CAKE_BASE_RATE] &&
	    RTA_PAYLOAD(tb[TCA_CAKE_BASE_RATE]) >= sizeof(__u32)) {
		bandwidth = rta_getattr_u32(tb[TCA_CAKE_BASE_RATE]);
		if(bandwidth)
			fprintf(f, "bandwidth %s ", sprint_rate(bandwidth, b1));
		else
			fprintf(f, "unlimited");
	}
	if (tb[TCA_CAKE_DIFFSERV_MODE] &&
	    RTA_PAYLOAD(tb[TCA_CAKE_DIFFSERV_MODE]) >= sizeof(__u32)) {
		diffserv = rta_getattr_u32(tb[TCA_CAKE_DIFFSERV_MODE]);
		switch(diffserv) {
		case 1:
			fprintf(f, "besteffort ");
			break;
		case 2:
			fprintf(f, "precedence ");
			break;
		case 3:
			fprintf(f, "diffserv ");
			break;
		default:
			fprintf(f, "(?diffserv?) ");
			break;
		};
	}
	if (tb[TCA_CAKE_FLOW_MODE] &&
	    RTA_PAYLOAD(tb[TCA_CAKE_FLOW_MODE]) >= sizeof(__u32)) {
		flowmode = rta_getattr_u32(tb[TCA_CAKE_FLOW_MODE]);
		switch(flowmode) {
		case 0:
			fprintf(f, "flowblind ");
			break;
		case 1:
			fprintf(f, "srchost ");
			break;
		case 2:
			fprintf(f, "dsthost ");
			break;
		case 3:
			fprintf(f, "hosts ");
			break;
		case 4:
			fprintf(f, "flows ");
			break;
		default:
			fprintf(f, "(?flowmode?) ");
			break;
		};
	}
	if (tb[TCA_CAKE_ATM] &&
	    RTA_PAYLOAD(tb[TCA_CAKE_ATM]) >= sizeof(__u32)) {
		atm = rta_getattr_u32(tb[TCA_CAKE_ATM]);
		if (atm)
			fprintf(f, "atm ");
	}

	return 0;
}

static int cake_print_xstats(struct qdisc_util *qu, FILE *f,
				 struct rtattr *xstats)
{
	/* fq_codel stats format borrowed */
	struct tc_fq_codel_xstats *st;
	struct tc_cake_old_xstats     *stc;
	SPRINT_BUF(b1);

	if (xstats == NULL)
		return 0;

	if (RTA_PAYLOAD(xstats) < sizeof(st->type))
		return -1;

	st  = RTA_DATA(xstats);
	stc = RTA_DATA(xstats);

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
	} else if (stc->type == 0xCAFE && RTA_PAYLOAD(xstats) >= sizeof(*stc)) {
		int i;

		fprintf(f, "        ");
		for(i=0; i < stc->class_cnt; i++)
			fprintf(f, "  Class %u ", i);
		fprintf(f, "\n");

		fprintf(f, "  rate  ");
		for(i=0; i < stc->class_cnt; i++)
			fprintf(f, "%10s", sprint_rate(stc->cls[i].rate, b1));
		fprintf(f, "\n");

		fprintf(f, "  target");
		for(i=0; i < stc->class_cnt; i++)
			fprintf(f, "%10s", sprint_time(stc->cls[i].target_us, b1));
		fprintf(f, "\n");

		fprintf(f, "interval");
		for(i=0; i < stc->class_cnt; i++)
			fprintf(f, "%10s", sprint_time(stc->cls[i].interval_us, b1));
		fprintf(f, "\n");

		fprintf(f, "  delay ");
		for(i=0; i < stc->class_cnt; i++)
			fprintf(f, "%10s", sprint_time(stc->cls[i].peak_delay, b1));
		fprintf(f, "\n");

		fprintf(f, "  pkts  ");
		for(i=0; i < stc->class_cnt; i++)
			fprintf(f, "%10u", stc->cls[i].packets);
		fprintf(f, "\n");

		fprintf(f, "  bytes ");
		for(i=0; i < stc->class_cnt; i++)
			fprintf(f, "%10llu", stc->cls[i].bytes);
		fprintf(f, "\n");

		fprintf(f, "  drops ");
		for(i=0; i < stc->class_cnt; i++)
			fprintf(f, "%10u", stc->cls[i].dropped);
		fprintf(f, "\n");

		fprintf(f, "  marks ");
		for(i=0; i < stc->class_cnt; i++)
			fprintf(f, "%10u", stc->cls[i].ecn_marked);
	} else {
		return -1;
	}
	return 0;
}

struct qdisc_util cake0_qdisc_util = {
	.id		= "cake0",
	.parse_qopt	= cake_parse_opt,
	.print_qopt	= cake_print_opt,
	.print_xstats	= cake_print_xstats,
};
