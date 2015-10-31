/*
 * Common Applications Kept Enhanced  --  CAKE
 *
 *  Copyright (C) 2014-2015 Jonathan Morton <chromatix99@gmail.com>
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
	fprintf(stderr, "Usage: ... cake [ bandwidth RATE | unlimited* | autorate_ingress ]\n"
	                "                [ rtt TIME | datacentre | lan | metro | regional | internet* | oceanic | satellite | interplanetary ]\n"
	                "                [ besteffort | squash | precedence | diffserv8 | diffserv4* ]\n"
	                "                [ flowblind | srchost | dsthost | hosts | flows* ]\n"
	                "                [ atm | noatm* ] [ overhead N | conservative | raw* ]\n"
	                "    (* marks defaults)\n");
}

static int cake_parse_opt(struct qdisc_util *qu, int argc, char **argv,
			      struct nlmsghdr *n)
{
	int unlimited = 0;
	unsigned bandwidth = 0;
	unsigned interval = 0;
	unsigned target = 0;
	unsigned diffserv = 0;
	int overhead = -99999;
	int flowmode = -1;
	int atm = -1;
	int autorate = -1;
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
			target = interval / 16;
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
			target   =   5000;
		} else if (strcmp(*argv, "satellite") == 0) {
			interval = 1000000;
			target   =    5000;
		} else if (strcmp(*argv, "interplanetary") == 0) {
			interval = 3600000000U;
			target   =       5000;

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
		} else if (strcmp(*argv, "squash") == 0) {
			diffserv = 5;

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

		} else if (strcmp(*argv, "raw") == 0) {
			atm = 0;
			overhead = 0;
		} else if (strcmp(*argv, "conservative") == 0) {
			/*
			 * Deliberately over-estimate overhead:
			 * one whole ATM cell plus ATM framing.
			 * A safe choice if the actual overhead is unknown.
			 */
			atm = 1;
			overhead = 48;

		/* Various ADSL framing schemes */
		} else if (strcmp(*argv, "ipoa-vcmux") == 0) {
			atm = 1;
			overhead = 8;
		} else if (strcmp(*argv, "ipoa-llcsnap") == 0) {
			atm = 1;
			overhead = 16;
		} else if (strcmp(*argv, "bridged-vcmux") == 0) {
			atm = 1;
			overhead = 24;
		} else if (strcmp(*argv, "bridged-llcsnap") == 0) {
			atm = 1;
			overhead = 32;
		} else if (strcmp(*argv, "pppoa-vcmux") == 0) {
			atm = 1;
			overhead = 10;
		} else if (strcmp(*argv, "pppoa-llc") == 0) {
			atm = 1;
			overhead = 14;
		} else if (strcmp(*argv, "pppoe-vcmux") == 0) {
			atm = 1;
			overhead = 32;
		} else if (strcmp(*argv, "pppoe-llcsnap") == 0) {
			atm = 1;
			overhead = 40;

		/* Typical VDSL2 framing schemes */
		/* NB: PTM includes HDLC's 0x7D/7E expansion, adds extra 1/128 */
		} else if (strcmp(*argv, "pppoe-ptm") == 0) {
			atm = 0;
			overhead = 27;
		} else if (strcmp(*argv, "bridged-ptm") == 0) {
			atm = 0;
			overhead = 19;

		} else if (strcmp(*argv, "via-ethernet") == 0) {
			/*
			 * The above overheads are relative to an IP packet,
			 * but if the physical interface is Ethernet, Linux
			 * includes Ethernet framing overhead already.
			 */
			overhead -= 14;

		/* Additional Ethernet-related overheads used by some ISPs */
		} else if (strcmp(*argv, "ether-phy") == 0) {
			/* ethernet pre-amble & interframe gap 20 bytes
			 * Linux will have already accounted for MACs & frame type 14 bytes
			 * you probably want to add an FCS as well*/
			overhead = 20;
		} else if (strcmp(*argv, "ether-all") == 0) {
			/* ethernet pre-amble & interframe gap & FCS
			 * Linux will have already accounted for MACs & frame type 14 bytes
			 * you may need to add vlan tag*/
			overhead = 24;

		} else if (strcmp(*argv, "ether-fcs") == 0) {
			/* Frame Check Sequence */
			/* we ignore the minimum frame size, because IP packets usually meet it */
			overhead += 4;
		} else if (strcmp(*argv, "ether-vlan") == 0) {
			/* 802.1q VLAN tag - may be repeated */
			overhead += 4;

		} else if (strcmp(*argv, "overhead") == 0) {
			char* p = NULL;
			NEXT_ARG();
			overhead = strtol(*argv, &p, 10);
			if(!p || *p || !*argv || overhead < -64 || overhead > 256) {
				fprintf(stderr, "Illegal \"overhead\"\n");
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
	if (overhead > -999)
		addattr_l(n, 1024, TCA_CAKE_OVERHEAD, &overhead, sizeof(overhead));
	if (interval)
		addattr_l(n, 1024, TCA_CAKE_RTT, &interval, sizeof(interval));
	if (target)
		addattr_l(n, 1024, TCA_CAKE_TARGET, &target, sizeof(target));
	if (autorate != -1)
		addattr_l(n, 1024, TCA_CAKE_AUTORATE, &autorate, sizeof(autorate));
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
	int overhead = 0;
	int atm = 0;
	int autorate = 0;
	SPRINT_BUF(b1);
	SPRINT_BUF(b2);

	if (opt == NULL)
		return 0;

	parse_rtattr_nested(tb, TCA_CAKE_MAX, opt);

	if (tb[TCA_CAKE_BASE_RATE] &&
	    RTA_PAYLOAD(tb[TCA_CAKE_BASE_RATE]) >= sizeof(__u32)) {
		bandwidth = rta_getattr_u32(tb[TCA_CAKE_BASE_RATE]);
		if(bandwidth)
			fprintf(f, "bandwidth %s ", sprint_rate(bandwidth, b1));
		else
			fprintf(f, "unlimited ");
	}
	if (tb[TCA_CAKE_AUTORATE] &&
		RTA_PAYLOAD(tb[TCA_CAKE_AUTORATE]) >= sizeof(__u32)) {
		autorate = rta_getattr_u32(tb[TCA_CAKE_AUTORATE]);
		if(autorate == 1)
			fprintf(f, "autorate_ingress ");
		else if(autorate)
			fprintf(f, "(?autorate?) ");
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
			fprintf(f, "diffserv8 ");
			break;
		case 4:
			fprintf(f, "diffserv4 ");
			break;
		case 5:
			fprintf(f, "squash ");
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
	}
	if (tb[TCA_CAKE_OVERHEAD] &&
	    RTA_PAYLOAD(tb[TCA_CAKE_OVERHEAD]) >= sizeof(__u32)) {
		overhead = rta_getattr_u32(tb[TCA_CAKE_OVERHEAD]);
	}
	if (tb[TCA_CAKE_RTT] &&
	    RTA_PAYLOAD(tb[TCA_CAKE_RTT]) >= sizeof(__u32)) {
		interval = rta_getattr_u32(tb[TCA_CAKE_RTT]);
	}

	if (interval)
		fprintf(f, "rtt %s ", sprint_time(interval, b2));

	if (atm)
		fprintf(f, "atm ");
	else if (overhead)
		fprintf(f, "noatm ");

	if (overhead || atm)
		fprintf(f, "overhead %d ", overhead);

	if (!atm && !overhead)
		fprintf(f, "raw ");

	return 0;
}

static int cake_print_xstats(struct qdisc_util *qu, FILE *f,
				 struct rtattr *xstats)
{
	/* fq_codel stats format borrowed */
	struct tc_fq_codel_xstats *st;
	struct tc_cake_old_xstats *stc;
	struct tc_cake_xstats     *stnc;
	SPRINT_BUF(b1);

	if (xstats == NULL)
		return 0;

	if (RTA_PAYLOAD(xstats) < sizeof(st->type))
		return -1;

	st   = RTA_DATA(xstats);
	stc  = RTA_DATA(xstats);
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
	} else if (stc->type == 0xCAFE && RTA_PAYLOAD(xstats) >= sizeof(*stc)) {
		int i;

		fprintf(f, "        ");
		for(i=0; i < stc->class_cnt; i++)
			fprintf(f, "     Bin %u  ", i);
		fprintf(f, "\n");

		fprintf(f, "  rate  ");
		for(i=0; i < stc->class_cnt; i++)
			fprintf(f, "%12s", sprint_rate(stc->cls[i].rate, b1));
		fprintf(f, "\n");

		fprintf(f, "  target");
		for(i=0; i < stc->class_cnt; i++)
			fprintf(f, "%12s", sprint_time(stc->cls[i].target_us, b1));
		fprintf(f, "\n");

		fprintf(f, "interval");
		for(i=0; i < stc->class_cnt; i++)
			fprintf(f, "%12s", sprint_time(stc->cls[i].interval_us, b1));
		fprintf(f, "\n");

		fprintf(f, "Pk-delay");
		for(i=0; i < stc->class_cnt; i++)
			fprintf(f, "%12s", sprint_time(stc->cls[i].peak_delay, b1));
		fprintf(f, "\n");

		fprintf(f, "Av-delay");
		for(i=0; i < stc->class_cnt; i++)
			fprintf(f, "%12s", sprint_time(stc->cls[i].avge_delay, b1));
		fprintf(f, "\n");

		fprintf(f, "Sp-delay");
		for(i=0; i < stc->class_cnt; i++)
			fprintf(f, "%12s", sprint_time(stc->cls[i].base_delay, b1));
		fprintf(f, "\n");

		fprintf(f, "  pkts  ");
		for(i=0; i < stc->class_cnt; i++)
			fprintf(f, "%12u", stc->cls[i].packets);
		fprintf(f, "\n");

		fprintf(f, "way-inds");
		for(i=0; i < stc->class_cnt; i++)
			fprintf(f, "%12u", stc->cls[i].way_indirect_hits);
		fprintf(f, "\n");

		fprintf(f, "way-miss");
		for(i=0; i < stc->class_cnt; i++)
			fprintf(f, "%12u", stc->cls[i].way_misses);
		fprintf(f, "\n");

		fprintf(f, "way-cols");
		for(i=0; i < stc->class_cnt; i++)
			fprintf(f, "%12u", stc->cls[i].way_collisions);
		fprintf(f, "\n");

		fprintf(f, "  bytes ");
		for(i=0; i < stc->class_cnt; i++)
			fprintf(f, "%12llu", stc->cls[i].bytes);
		fprintf(f, "\n");

		fprintf(f, "  drops ");
		for(i=0; i < stc->class_cnt; i++)
			fprintf(f, "%12u", stc->cls[i].dropped);
		fprintf(f, "\n");

		fprintf(f, "  marks ");
		for(i=0; i < stc->class_cnt; i++)
			fprintf(f, "%12u", stc->cls[i].ecn_marked);
		fprintf(f, "\n");

		fprintf(f, "Sp-flows");
		for(i=0; i < stc->class_cnt; i++)
			fprintf(f, "%12u", stc->cls[i].sparse_flows);
		fprintf(f, "\n");

		fprintf(f, "Bk-flows");
		for(i=0; i < stc->class_cnt; i++)
			fprintf(f, "%12u", stc->cls[i].bulk_flows);
		fprintf(f, "\n");

	} else if (stnc->version >= 1 && stnc->version < 0xFF
				&& stnc->max_tins == TC_CAKE_MAX_TINS
				&& RTA_PAYLOAD(xstats) >= offsetof(struct tc_cake_xstats, capacity_estimate))
	{
		int i;

		if(stnc->version >= 2)
			fprintf(f, "capacity estimate: %s\n", sprint_rate(stnc->capacity_estimate, b1));

		fprintf(f, "        ");
		for(i=0; i < stnc->tin_cnt; i++)
			fprintf(f, "     Tin %u  ", i);
		fprintf(f, "\n");

		fprintf(f, "  thresh");
		for(i=0; i < stnc->tin_cnt; i++)
			fprintf(f, "%12s", sprint_rate(stnc->threshold_rate[i], b1));
		fprintf(f, "\n");

		fprintf(f, "  target");
		for(i=0; i < stnc->tin_cnt; i++)
			fprintf(f, "%12s", sprint_time(stnc->target_us[i], b1));
		fprintf(f, "\n");

		fprintf(f, "interval");
		for(i=0; i < stnc->tin_cnt; i++)
			fprintf(f, "%12s", sprint_time(stnc->interval_us[i], b1));
		fprintf(f, "\n");

		fprintf(f, "Pk-delay");
		for(i=0; i < stnc->tin_cnt; i++)
			fprintf(f, "%12s", sprint_time(stnc->peak_delay_us[i], b1));
		fprintf(f, "\n");

		fprintf(f, "Av-delay");
		for(i=0; i < stnc->tin_cnt; i++)
			fprintf(f, "%12s", sprint_time(stnc->avge_delay_us[i], b1));
		fprintf(f, "\n");

		fprintf(f, "Sp-delay");
		for(i=0; i < stnc->tin_cnt; i++)
			fprintf(f, "%12s", sprint_time(stnc->base_delay_us[i], b1));
		fprintf(f, "\n");

		fprintf(f, "  pkts  ");
		for(i=0; i < stnc->tin_cnt; i++)
			fprintf(f, "%12u", stnc->sent[i].packets);
		fprintf(f, "\n");

		fprintf(f, "  bytes ");
		for(i=0; i < stnc->tin_cnt; i++)
			fprintf(f, "%12llu", stnc->sent[i].bytes);
		fprintf(f, "\n");

		fprintf(f, "way-inds");
		for(i=0; i < stnc->tin_cnt; i++)
			fprintf(f, "%12u", stnc->way_indirect_hits[i]);
		fprintf(f, "\n");

		fprintf(f, "way-miss");
		for(i=0; i < stnc->tin_cnt; i++)
			fprintf(f, "%12u", stnc->way_misses[i]);
		fprintf(f, "\n");

		fprintf(f, "way-cols");
		for(i=0; i < stnc->tin_cnt; i++)
			fprintf(f, "%12u", stnc->way_collisions[i]);
		fprintf(f, "\n");

		fprintf(f, "  drops ");
		for(i=0; i < stnc->tin_cnt; i++)
			fprintf(f, "%12u", stnc->dropped[i].packets);
		fprintf(f, "\n");

		fprintf(f, "  marks ");
		for(i=0; i < stnc->tin_cnt; i++)
			fprintf(f, "%12u", stnc->ecn_marked[i].packets);
		fprintf(f, "\n");

		fprintf(f, "Sp-flows");
		for(i=0; i < stnc->tin_cnt; i++)
			fprintf(f, "%12u", stnc->sparse_flows[i]);
		fprintf(f, "\n");

		fprintf(f, "Bk-flows");
		for(i=0; i < stnc->tin_cnt; i++)
			fprintf(f, "%12u", stnc->bulk_flows[i]);
		fprintf(f, "\n");

		fprintf(f, "last-len");
		for(i=0; i < stnc->tin_cnt; i++)
			fprintf(f, "%12u", stnc->last_skblen[i]);
		fprintf(f, "\n");

		fprintf(f, "max-len ");
		for(i=0; i < stnc->tin_cnt; i++)
			fprintf(f, "%12u", stnc->max_skblen[i]);
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
