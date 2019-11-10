// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

/*
 * Cheap Nasty Queuing with Codel-BLUE Alternate - CNQ-COBALT
 *
 *  Copyright (C) 2014-2019 Jonathan Morton <chromatix99@gmail.com>
 *  Copyright (C) 2017-2018 Toke Høiland-Jørgensen <toke@toke.dk>
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

struct cnq_preset {
	char *name;
	unsigned int target;
	unsigned int interval;
};

static struct cnq_preset presets[] = {
	{"datacentre",		5,		100},
	{"lan",			50,		1000},
	{"metro",		500,		10000},
	{"regional",		1500,		30000},
	{"internet",		5000,		100000},
	{"oceanic",		15000,		300000},
	{"satellite",		50000,		1000000},
	{"interplanetary",	50000000,	1000000000},
};

static struct cnq_preset *find_preset(char *argv)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(presets); i++)
		if (!strcmp(argv, presets[i].name))
			return &presets[i];
	return NULL;
}

static void explain(void)
{
	fprintf(stderr,
"Usage: ... cnq_cobalt [ bandwidth RATE | unlimited* ]\n"
"                [ rtt TIME | datacentre | lan | metro | regional |\n"
"                  internet* | oceanic | satellite | interplanetary ]\n"
"                [ ptm | atm | noatm* ] [ overhead N | conservative | raw* ]\n"
"                [ mpu N ] [sce | no-sce* | sce-thresh N]\n"
"                (* marks defaults)\n");
}

static int cnq_parse_opt(struct qdisc_util *qu, int argc, char **argv,
			  struct nlmsghdr *n, const char *dev)
{
	struct cnq_preset *preset, *preset_set = NULL;
	bool overhead_override = false;
	bool overhead_set = false;
	unsigned int interval = 0;
	unsigned int target = 0;
	__u64 bandwidth = 0;
	struct rtattr *tail;
	int unlimited = 0;
	int overhead = 0;
	int atm = -1;
	int sce = -1;
	int mpu = 0;

	while (argc > 0) {
		if (strcmp(*argv, "bandwidth") == 0) {
			NEXT_ARG();
			if (get_rate64(&bandwidth, *argv)) {
				fprintf(stderr, "Illegal \"bandwidth\"\n");
				return -1;
			}
			unlimited = 0;
		} else if (strcmp(*argv, "unlimited") == 0) {
			bandwidth = 0;
			unlimited = 1;
		} else if (strcmp(*argv, "rtt") == 0) {
			NEXT_ARG();
			if (get_time(&interval, *argv)) {
				fprintf(stderr, "Illegal \"rtt\"\n");
				return -1;
			}
			target = interval / 20;
			if (!target)
				target = 1;
		} else if ((preset = find_preset(*argv))) {
			if (preset_set)
				duparg(*argv, preset_set->name);
			preset_set = preset;
			target = preset->target;
			interval = preset->interval;
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
			 * you may need to add vlan tag
			 */
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
			char *p = NULL;

			NEXT_ARG();
			overhead = strtol(*argv, &p, 10);
			if (!p || *p || !*argv ||
			    overhead < -64 || overhead > 256) {
				fprintf(stderr,
					"Illegal \"overhead\", valid range is -64 to 256\\n");
				return -1;
			}
			overhead_set = true;

		} else if (strcmp(*argv, "mpu") == 0) {
			char *p = NULL;

			NEXT_ARG();
			mpu = strtol(*argv, &p, 10);
			if (!p || *p || !*argv || mpu < 0 || mpu > 256) {
				fprintf(stderr,
					"Illegal \"mpu\", valid range is 0 to 256\\n");
				return -1;
			}
		} else if (strcmp(*argv, "sce-thresh") == 0) {
			NEXT_ARG();
			if (get_u32(&sce, *argv, 0) || sce < 1 || sce > 1024) {
				fprintf(stderr,
					"Illegal value for \"sce-thresh\": \"%s\"\n", *argv);
				return -1;
			}
		} else if (strcmp(*argv, "sce") == 0) {
			sce = 1;
		} else if (strcmp(*argv, "no-sce") == 0) {
			sce = 0;
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
		addattr_l(n, 1024, TCA_CAKE_BASE_RATE64, &bandwidth,
			  sizeof(bandwidth));
	if (atm != -1)
		addattr_l(n, 1024, TCA_CAKE_ATM, &atm, sizeof(atm));
	if (overhead_set)
		addattr_l(n, 1024, TCA_CAKE_OVERHEAD, &overhead,
			  sizeof(overhead));
	if (overhead_override) {
		unsigned int zero = 0;

		addattr_l(n, 1024, TCA_CAKE_RAW, &zero, sizeof(zero));
	}
	if (mpu > 0)
		addattr_l(n, 1024, TCA_CAKE_MPU, &mpu, sizeof(mpu));
	if (interval)
		addattr_l(n, 1024, TCA_CAKE_RTT, &interval, sizeof(interval));
	if (target)
		addattr_l(n, 1024, TCA_CAKE_TARGET, &target, sizeof(target));
	if (sce != -1)
		addattr_l(n, 1024, TCA_CAKE_SCE, &sce, sizeof(sce));

	tail->rta_len = (void *) NLMSG_TAIL(n) - (void *) tail;
	return 0;
}

static void cnq_print_mode(unsigned int value, unsigned int max,
			    const char *key, const char **table)
{
	if (value < max && table[value]) {
		print_string(PRINT_ANY, key, "%s ", table[value]);
	} else {
		print_string(PRINT_JSON, key, NULL, "unknown");
		print_string(PRINT_FP, NULL, "(?%s?)", key);
	}
}

static int cnq_print_opt(struct qdisc_util *qu, FILE *f, struct rtattr *opt)
{
	struct rtattr *tb[TCA_CAKE_MAX + 1];
	unsigned int interval = 0;
	__u64 bandwidth = 0;
	int overhead = 0;
	int raw = 0;
	int mpu = 0;
	int atm = 0;
	int sce = 0;

	SPRINT_BUF(b1);
	SPRINT_BUF(b2);

	if (opt == NULL)
		return 0;

	parse_rtattr_nested(tb, TCA_CAKE_MAX, opt);

	if (tb[TCA_CAKE_BASE_RATE64] &&
	    RTA_PAYLOAD(tb[TCA_CAKE_BASE_RATE64]) >= sizeof(bandwidth)) {
		bandwidth = rta_getattr_u64(tb[TCA_CAKE_BASE_RATE64]);
		if (bandwidth) {
			print_uint(PRINT_JSON, "bandwidth", NULL, bandwidth);
			print_string(PRINT_FP, NULL, "bandwidth %s ",
				     sprint_rate(bandwidth, b1));
		} else
			print_string(PRINT_ANY, "bandwidth", "bandwidth %s ",
				     "unlimited");
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
	if (tb[TCA_CAKE_RAW]) {
		raw = 1;
	}
	if (tb[TCA_CAKE_RTT] &&
	    RTA_PAYLOAD(tb[TCA_CAKE_RTT]) >= sizeof(__u32)) {
		interval = rta_getattr_u32(tb[TCA_CAKE_RTT]);
	}
	if (tb[TCA_CAKE_SCE] &&
	    RTA_PAYLOAD(tb[TCA_CAKE_SCE]) >= sizeof(__u32)) {
		sce = rta_getattr_u32(tb[TCA_CAKE_SCE]);
	}

	if (interval)
		print_string(PRINT_FP, NULL, "rtt %s ",
			     sprint_time(interval, b2));
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

	if (sce == 1)
		print_string(PRINT_FP, NULL, "sce ", NULL);
	else if(!sce)
		print_string(PRINT_FP, NULL, "no-sce ", NULL);
	else
		print_uint(PRINT_FP, NULL, "sce-thresh %u ", sce);
	print_uint(PRINT_JSON, "sce", NULL, sce);

	return 0;
}

static int cnq_print_xstats(struct qdisc_util *qu, FILE *f,
			     struct rtattr *xstats)
{
	return 0;
}

struct qdisc_util cnq_qdisc_util = {
	.id		= "cnq_cobalt",
	.parse_qopt	= cnq_parse_opt,
	.print_qopt	= cnq_print_opt,
	.print_xstats	= cnq_print_xstats,
};
