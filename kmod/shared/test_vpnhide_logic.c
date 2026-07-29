/*
 * Host unit test for shared/vpnhide_logic.h (the backend-agnostic filtering
 * logic shared by the .ko and the KPM).
 *
 * Build: gcc -O2 -Wall -Wextra -Werror -I.. -o test_vpnhide_logic test_vpnhide_logic.c
 * Run:   ./test_vpnhide_logic   (exit 0 on success)
 */
#include <stdio.h>
#include <string.h>

#include "generated/iface_lists.h"
#include "shared/vpnhide_logic.h"

static int failures;

/* int-returning adapter for the bool matcher (function-pointer-type safe). */
static int match_vpn(const char *name)
{
	return vpnhide_iface_is_vpn(name) ? 1 : 0;
}

static void expect_str(const char *what, const char *got, const char *want)
{
	if (strcmp(got, want) != 0) {
		fprintf(stderr, "FAIL %s:\n  got : %s\n  want: %s\n", what, got,
			want);
		failures++;
	}
}

static void test_route_first_field(void)
{
	/* /proc/net/route: iface is the first tab-separated field. */
	char buf[512] = "Iface\tDestination\tGateway\n"
			"wlan0\t00000000\t0101A8C0\n"
			"tun0\t00000000\t010010AC\n"
			"rmnet0\tFEFFFFFF\t00000000\n"
			"wg0\t00000000\t00000000\n";
	unsigned long count = strlen(buf);
	/* keep the header line (start=0) — matcher rejects "Iface". */
	unsigned long n = vpnhide_compact_seq_lines(
		buf, 0, count, VPNHIDE_FIELD_FIRST, match_vpn);
	buf[n] = '\0';
	expect_str("route: tun0+wg0 removed", buf,
		   "Iface\tDestination\tGateway\n"
		   "wlan0\t00000000\t0101A8C0\n"
		   "rmnet0\tFEFFFFFF\t00000000\n");
}

static void test_ipv6_route_last_field(void)
{
	/* /proc/net/ipv6_route: iface is the last whitespace field. */
	char buf[512] = "00000000000000000000000000000000 00 ... wlan0\n"
			"fe800000000000000000000000000000 40 ... tun0\n"
			"00000000000000000000000000000000 00 ... rmnet_data0\n";
	unsigned long count = strlen(buf);
	unsigned long n = vpnhide_compact_seq_lines(
		buf, 0, count, VPNHIDE_FIELD_LAST, match_vpn);
	buf[n] = '\0';
	expect_str("ipv6_route: tun0 removed", buf,
		   "00000000000000000000000000000000 00 ... wlan0\n"
		   "00000000000000000000000000000000 00 ... rmnet_data0\n");
}

static void test_start_offset_preserved(void)
{
	/* Bytes before `start` belong to earlier show() calls — never touched,
	 * even if they name a VPN iface. */
	char buf[256] = "tun9\tearlier-entry\nwlan0\tkeep\ntun0\tdrop\n";
	unsigned long start = strlen("tun9\tearlier-entry\n");
	unsigned long count = strlen(buf);
	unsigned long n = vpnhide_compact_seq_lines(
		buf, start, count, VPNHIDE_FIELD_FIRST, match_vpn);
	buf[n] = '\0';
	expect_str("start offset preserved", buf,
		   "tun9\tearlier-entry\nwlan0\tkeep\n");
}

static void expect_int(const char *what, int got, int want)
{
	if (got != want) {
		fprintf(stderr, "FAIL %s: got %d want %d\n", what, got, want);
		failures++;
	}
}

static int pub4(unsigned char a, unsigned char b, unsigned char c,
		unsigned char d)
{
	const unsigned char be[4] = { a, b, c, d };

	return vpnhide_is_public_ipv4(be);
}

static void test_is_public_ipv4(void)
{
	/* Public. */
	expect_int("ipv4 8.8.8.8", pub4(8, 8, 8, 8), 1);
	expect_int("ipv4 1.2.3.4", pub4(1, 2, 3, 4), 1);
	expect_int("ipv4 203.0.114.1", pub4(203, 0, 114, 1), 1);
	/* Private / reserved / special — all rejected. */
	expect_int("ipv4 0.x", pub4(0, 1, 2, 3), 0);
	expect_int("ipv4 10/8", pub4(10, 0, 0, 1), 0);
	expect_int("ipv4 127/8", pub4(127, 0, 0, 1), 0);
	expect_int("ipv4 224/4", pub4(239, 0, 0, 1), 0);
	expect_int("ipv4 100.64/10", pub4(100, 64, 0, 1), 0);
	expect_int("ipv4 169.254/16", pub4(169, 254, 0, 1), 0);
	expect_int("ipv4 172.16/12", pub4(172, 16, 0, 1), 0);
	expect_int("ipv4 192.168/16", pub4(192, 168, 0, 1), 0);
	expect_int("ipv4 192.0.2/24", pub4(192, 0, 2, 1), 0);
	expect_int("ipv4 198.18/15", pub4(198, 19, 0, 1), 0);
	expect_int("ipv4 198.51.100/24", pub4(198, 51, 100, 1), 0);
	expect_int("ipv4 203.0.113/24", pub4(203, 0, 113, 1), 0);
}

static void test_is_public_ipv6(void)
{
	unsigned char gua[16] = { 0x26, 0x06, 0x47, 0 }; /* 2606:4700::  */
	unsigned char ll[16] = { 0xfe, 0x80, 0 }; /* fe80::          */
	unsigned char ula[16] = { 0xfc, 0, 0 }; /* fc00::            */
	unsigned char loop[16] = { 0 }; /* ::                          */
	unsigned char doc[16] = { 0x20, 0x01, 0x0d, 0xb8, 0 }; /* 2001:db8:: */

	loop[15] = 1; /* ::1 */
	expect_int("ipv6 2606:4700::", vpnhide_is_public_ipv6(gua), 1);
	expect_int("ipv6 fe80::", vpnhide_is_public_ipv6(ll), 0);
	expect_int("ipv6 fc00::", vpnhide_is_public_ipv6(ula), 0);
	expect_int("ipv6 ::1", vpnhide_is_public_ipv6(loop), 0);
	expect_int("ipv6 2001:db8::", vpnhide_is_public_ipv6(doc), 0);
}

static void test_is_physical_iface(void)
{
	expect_int("phys eth0", vpnhide_iface_is_physical("eth0"), 1);
	expect_int("phys rmnet_data0", vpnhide_iface_is_physical("rmnet_data0"),
		   1);
	expect_int("phys WLAN0 (ci)", vpnhide_iface_is_physical("WLAN0"), 1);
	expect_int("phys seth1", vpnhide_iface_is_physical("seth1"), 1);
	expect_int("phys tun0 (no)", vpnhide_iface_is_physical("tun0"), 0);
	expect_int("phys wg0 (no)", vpnhide_iface_is_physical("wg0"), 0);
	expect_int("phys NULL", vpnhide_iface_is_physical((const char *)0), 0);
}

static void test_parse_uids(void)
{
	const char *in = "10010\n  10020 \n# a comment\n\n10030\nbad\n10040";
	unsigned int out[8];
	int n = vpnhide_parse_target_uids(in, strlen(in), out, 8);
	if (n != 4 || out[0] != 10010 || out[1] != 10020 || out[2] != 10030 ||
	    out[3] != 10040) {
		fprintf(stderr, "FAIL parse_uids: n=%d [%u %u %u %u]\n", n,
			out[0], out[1], out[2], out[3]);
		failures++;
	}
}

static void test_prefix_match(void)
{
	struct vpnhide_prefix_rule r;
	unsigned char a[16];

	/* 2401:4900::/32 */
	memset(&r, 0, sizeof(r));
	r.prefix_len = 32;
	r.addr[0] = 0x24;
	r.addr[1] = 0x01;
	r.addr[2] = 0x49;
	r.addr[3] = 0x00;

	memset(a, 0, sizeof(a));
	a[0] = 0x24;
	a[1] = 0x01;
	a[2] = 0x49;
	a[3] = 0x00;
	a[4] = 0xa3;
	a[5] = 0xf1; /* 2401:4900:a3f1:: — in-prefix */
	expect_int("prefix /32 in", vpnhide_prefix_match(a, &r), 1);

	a[3] = 0x01; /* 2401:4901:: — out at /32 */
	expect_int("prefix /32 out", vpnhide_prefix_match(a, &r), 0);

	r.prefix_len = 0; /* /0 matches anything */
	expect_int("prefix /0 any", vpnhide_prefix_match(a, &r), 1);

	/* /33: bit 33 must match (byte 4, top bit) */
	memset(&r, 0, sizeof(r));
	r.prefix_len = 33;
	r.addr[4] = 0x80;
	memset(a, 0, sizeof(a));
	a[4] = 0x80;
	expect_int("prefix /33 in", vpnhide_prefix_match(a, &r), 1);
	a[4] = 0x00;
	expect_int("prefix /33 out", vpnhide_prefix_match(a, &r), 0);

	/* /128 exact */
	memset(&r, 0, sizeof(r));
	r.prefix_len = 128;
	r.addr[15] = 0x01;
	memset(a, 0, sizeof(a));
	a[15] = 0x01;
	expect_int("prefix /128 eq", vpnhide_prefix_match(a, &r), 1);
	a[15] = 0x02;
	expect_int("prefix /128 ne", vpnhide_prefix_match(a, &r), 0);

	/* out-of-range plen rejects */
	r.prefix_len = 129;
	expect_int("prefix /129 reject", vpnhide_prefix_match(a, &r), 0);
}

static void test_uid_prefix_filtered(void)
{
	/* System readers are NOT filtered — they must see real addresses. */
	expect_int("uid 0 (root)", vpnhide_uid_prefix_filtered(0), 0);
	expect_int("uid 1", vpnhide_uid_prefix_filtered(1), 0);
	expect_int("uid 1000 (system_server)",
		   vpnhide_uid_prefix_filtered(1000), 0);
	expect_int("uid 1073 (networkstack)", vpnhide_uid_prefix_filtered(1073),
		   0);
	expect_int("uid 1999", vpnhide_uid_prefix_filtered(1999), 0);
	expect_int("uid 9999", vpnhide_uid_prefix_filtered(9999), 0);

	/* The adb shell and every app uid (incl. isolated) ARE filtered. */
	expect_int("uid 2000 (shell)", vpnhide_uid_prefix_filtered(2000), 1);
	expect_int("uid 10000 (first app)", vpnhide_uid_prefix_filtered(10000),
		   1);
	expect_int("uid 10123", vpnhide_uid_prefix_filtered(10123), 1);
	expect_int("uid 99000 (isolated start)",
		   vpnhide_uid_prefix_filtered(99000), 1);
	expect_int("uid 99999", vpnhide_uid_prefix_filtered(99999), 1);
	expect_int("uid 0xffffffff", vpnhide_uid_prefix_filtered(0xffffffffu),
		   1);
}

static void test_compact_if_inet6(void)
{
	/* /proc/net/if_inet6: "<32hex addr> <ifindex> <plen> <scope> <flags> <name>" */
	char buf[512] =
		"24014900a3f1e04d54fdd7fffeb173bf 1e 40 00 00 rmnet_data1\n"
		"24014900a41fb57cf4d296fffecd4b63 20 40 00 00 rmnet_data3\n"
		"fe800000000000005042d7fffe000001 1e 40 20 80 rmnet_data1\n";
	/* rule: hide 2401:4900::/32 on rmnet_data1 only */
	struct vpnhide_prefix_rule rules[1];
	unsigned long n;

	memset(&rules[0], 0, sizeof(rules[0]));
	rules[0].ifname[0] = 'r';
	rules[0].ifname[1] = 'm';
	rules[0].ifname[2] = 'n';
	rules[0].ifname[3] = 'e';
	rules[0].ifname[4] = 't';
	rules[0].ifname[5] = '_';
	rules[0].ifname[6] = 'd';
	rules[0].ifname[7] = 'a';
	rules[0].ifname[8] = 't';
	rules[0].ifname[9] = 'a';
	rules[0].ifname[10] = '1';
	rules[0].ifname[11] = '\0';
	rules[0].addr[0] = 0x24;
	rules[0].addr[1] = 0x01;
	rules[0].addr[2] = 0x49;
	rules[0].addr[3] = 0x00;
	rules[0].prefix_len = 32;

	/* vpn_match NULL (per-uid VPN path inactive) -> only the prefix rule fires:
	 * the global v6 on rmnet_data1 goes; rmnet_data3 (same prefix, other iface)
	 * and the fe80 link-local on rmnet_data1 (not in 2401:4900::/32) stay. */
	n = vpnhide_compact_if_inet6_lines(buf, 0, strlen(buf),
					   (vpnhide_match_fn)0, rules, 1, 0);
	buf[n] = '\0';
	expect_str(
		"if_inet6: rmnet_data1 global v6 removed", buf,
		"24014900a41fb57cf4d296fffecd4b63 20 40 00 00 rmnet_data3\n"
		"fe800000000000005042d7fffe000001 1e 40 20 80 rmnet_data1\n");
}

static void test_compact_if_inet6_vpn_and_edges(void)
{
	/* Case A: vpn_match removes the tun0 line, the prefix rule removes the
	 * rmnet_data1 global v6, and the LAST line has NO trailing newline. */
	char buf[512] =
		"fe800000000000005042d7fffe000001 05 40 20 80 tun0\n"
		"24014900a3f1e04d54fdd7fffeb173bf 1e 40 00 00 rmnet_data1\n"
		"24014900a41fb57cf4d296fffecd4b63 20 40 00 00 rmnet_data3";
	struct vpnhide_prefix_rule rules[1];
	unsigned long n;

	memset(&rules[0], 0, sizeof(rules[0]));
	strcpy(rules[0].ifname, "rmnet_data1");
	rules[0].addr[0] = 0x24;
	rules[0].addr[1] = 0x01;
	rules[0].addr[2] = 0x49;
	rules[0].addr[3] = 0x00;
	rules[0].prefix_len = 32;

	n = vpnhide_compact_if_inet6_lines(buf, 0, strlen(buf), match_vpn,
					   rules, 1, 0);
	buf[n] = '\0';
	expect_str(
		"if_inet6: vpn tun0 + prefix removed, no-trailing-newline kept",
		buf,
		"24014900a41fb57cf4d296fffecd4b63 20 40 00 00 rmnet_data3");

	/* Case B: bytes before `start` are never touched (the pre-start
	 * rmnet_data1 line is kept verbatim); the tun0 line after start is
	 * removed by vpn_match (rules unused here). */
	{
		char buf2[256] =
			"24014900a3f1e04d54fdd7fffeb173bf 1e 40 00 00 rmnet_data1\n"
			"fe800000000000005042d7fffe000001 05 40 20 80 tun0\n";
		unsigned long start = strlen(
			"24014900a3f1e04d54fdd7fffeb173bf 1e 40 00 00 rmnet_data1\n");
		unsigned long m = vpnhide_compact_if_inet6_lines(
			buf2, start, strlen(buf2), match_vpn,
			(const struct vpnhide_prefix_rule *)0, 0, 0);

		buf2[m] = '\0';
		expect_str(
			"if_inet6: start offset preserved (pre-start line kept)",
			buf2,
			"24014900a3f1e04d54fdd7fffeb173bf 1e 40 00 00 rmnet_data1\n");
	}
}

static void test_compact_ipv6_route_prefix(void)
{
	/* /proc/net/ipv6_route: "<dst32> <plen> <src32> <srcplen> <nh32>
	 * <metric> <ref> <use> <flags> <name>" — the compactor reads only the
	 * FIRST (dst) and LAST (ifname) fields, exactly like if_inet6. */
	char buf[640] =
		"24014900a3f1e04d0000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 100 0 0 1 rmnet_data1\n"
		"fe800000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 100 0 0 1 rmnet_data1\n"
		"24014900a41fb57c0000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 100 0 0 1 rmnet_data3\n"
		"ff000000000000000000000000000000 08 00000000000000000000000000000000 00 00000000000000000000000000000000 100 0 0 1 rmnet_data1\n"
		"24014900a3f1e04d54fdd7fffeb173bf 80 00000000000000000000000000000000 00 00000000000000000000000000000000 100 0 0 1 rmnet_data1";
	/* rule: hide 2401:4900::/32 on rmnet_data1 only */
	struct vpnhide_prefix_rule rules[1];
	unsigned long n;

	memset(&rules[0], 0, sizeof(rules[0]));
	strcpy(rules[0].ifname, "rmnet_data1");
	rules[0].addr[0] = 0x24;
	rules[0].addr[1] = 0x01;
	rules[0].addr[2] = 0x49;
	rules[0].addr[3] = 0x00;
	rules[0].prefix_len = 32;

	/* vpn_match NULL -> only prefix rules fire: the rmnet_data1 /64 subnet
	 * route and the /128 host route inside 2401:4900::/32 go (the route's
	 * own plen field is never consulted); the fe80 link route (outside
	 * the rule), the rmnet_data3 /64 (other iface), and the ff00::/8
	 * multicast route (outside the rule) stay. The last input line has
	 * NO trailing newline and is dropped, so the kept lines' original
	 * bytes (with their newlines) survive verbatim. */
	n = vpnhide_compact_if_inet6_lines(buf, 0, strlen(buf),
					   (vpnhide_match_fn)0, rules, 1, 1);
	buf[n] = '\0';
	expect_str(
		"ipv6_route: prefix-dest routes removed, link/mcast/other-iface kept",
		buf,
		"fe800000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 100 0 0 1 rmnet_data1\n"
		"24014900a41fb57c0000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 100 0 0 1 rmnet_data3\n"
		"ff000000000000000000000000000000 08 00000000000000000000000000000000 00 00000000000000000000000000000000 100 0 0 1 rmnet_data1\n");
}

/* Fill a rule with the stock 2401:4900::/32 fixture (mode + fake set by the
 * caller). */
static void fill_prefix_fixture(struct vpnhide_prefix_rule *r,
				const char *ifname)
{
	memset(r, 0, sizeof(*r));
	strcpy(r->ifname, ifname);
	r->addr[0] = 0x24;
	r->addr[1] = 0x01;
	r->addr[2] = 0x49;
	r->addr[3] = 0x00;
	r->prefix_len = 32;
}

/* 2401:4900:7f3a:9c21:5e88:1b4d:a2f0:6c19 — the fixture fake. */
static void fill_fake_fixture(unsigned char fake[16])
{
	static const unsigned char f[16] = { 0x24, 0x01, 0x49, 0x00, 0x7f, 0x3a,
					     0x9c, 0x21, 0x5e, 0x88, 0x1b, 0x4d,
					     0xa2, 0xf0, 0x6c, 0x19 };

	memcpy(fake, f, 16);
}

static void test_hex32_render(void)
{
	unsigned char addr[16];
	char out[33];

	fill_fake_fixture(addr);
	vpnhide_hex32_render(out, addr);
	out[32] = '\0';
	expect_str("hex32_render lowercase 32 chars", out,
		   "240149007f3a9c215e881b4da2f06c19");
}

static void test_prefix4_match(void)
{
	struct vpnhide_prefix4_rule r;
	unsigned char a[4];

	/* 100.64.0.0/10 (CGNAT) */
	memset(&r, 0, sizeof(r));
	strcpy(r.ifname, "ccmni1");
	r.addr[0] = 100;
	r.addr[1] = 64;
	r.prefix_len = 10;

	a[0] = 100;
	a[1] = 124;
	a[2] = 146;
	a[3] = 11; /* 100.124.146.11 — in /10 */
	expect_int("prefix4 /10 in", vpnhide_prefix4_match(a, &r), 1);
	a[1] = 127; /* 100.127.x — top of /10 */
	expect_int("prefix4 /10 top", vpnhide_prefix4_match(a, &r), 1);
	a[1] = 128; /* 100.128.x — just outside /10 */
	expect_int("prefix4 /10 out", vpnhide_prefix4_match(a, &r), 0);
	a[0] = 192;
	a[1] = 168; /* 192.168.x — far outside */
	expect_int("prefix4 192.168 out", vpnhide_prefix4_match(a, &r), 0);
	r.prefix_len = 33; /* out-of-range rejects */
	expect_int("prefix4 /33 reject", vpnhide_prefix4_match(a, &r), 0);
}

static void test_compact_if_inet6_rewrite(void)
{
	/* REWRITE mode: the matched line is KEPT and its 32-hex address field
	 * overwritten with the fake — same length, so the return value equals
	 * the input length. Other-iface and out-of-prefix lines stay verbatim. */
	char buf[512] =
		"24014900a3f1e04d54fdd7fffeb173bf 1e 40 00 00 rmnet_data1\n"
		"24014900a41fb57cf4d296fffecd4b63 20 40 00 00 rmnet_data3\n"
		"fe800000000000005042d7fffe000001 1e 40 20 80 rmnet_data1\n";
	struct vpnhide_prefix_rule rules[1];
	unsigned long n;

	fill_prefix_fixture(&rules[0], "rmnet_data1");
	rules[0].mode = VPNHIDE_RULE_REWRITE;
	fill_fake_fixture(rules[0].fake);

	n = vpnhide_compact_if_inet6_lines(buf, 0, strlen(buf),
					   (vpnhide_match_fn)0, rules, 1, 0);
	buf[n] = '\0';
	expect_str(
		"if_inet6 rewrite: addr substituted, all lines kept", buf,
		"240149007f3a9c215e881b4da2f06c19 1e 40 00 00 rmnet_data1\n"
		"24014900a41fb57cf4d296fffecd4b63 20 40 00 00 rmnet_data3\n"
		"fe800000000000005042d7fffe000001 1e 40 20 80 rmnet_data1\n");
	expect_int("if_inet6 rewrite: length unchanged", (int)n,
		   (int)strlen(
			   "240149007f3a9c215e881b4da2f06c19 1e 40 00 00 rmnet_data1\n"
			   "24014900a41fb57cf4d296fffecd4b63 20 40 00 00 rmnet_data3\n"
			   "fe800000000000005042d7fffe000001 1e 40 20 80 rmnet_data1\n"));
}

static void test_compact_ipv6_route_rewrite(void)
{
	/* REWRITE with route_compose=1: the destination's top 64 bits become
	 * the fake's; the original low 64 survive. */
	char buf[640] =
		"24014900a3f1e04d0000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 100 0 0 1 rmnet_data1\n"
		"fe800000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 100 0 0 1 rmnet_data1\n"
		"24014900a41fb57c0000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 100 0 0 1 rmnet_data3\n";
	struct vpnhide_prefix_rule rules[1];
	unsigned long n;

	fill_prefix_fixture(&rules[0], "rmnet_data1");
	rules[0].mode = VPNHIDE_RULE_REWRITE;
	fill_fake_fixture(rules[0].fake);

	n = vpnhide_compact_if_inet6_lines(buf, 0, strlen(buf),
					   (vpnhide_match_fn)0, rules, 1, 1);
	buf[n] = '\0';
	expect_str(
		"ipv6_route rewrite: top-64 compose, other lines kept", buf,
		"240149007f3a9c210000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 100 0 0 1 rmnet_data1\n"
		"fe800000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 100 0 0 1 rmnet_data1\n"
		"24014900a41fb57c0000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 100 0 0 1 rmnet_data3\n");
}

static void expect_mem(const char *what, const unsigned char *got,
		       const unsigned char *want, unsigned long n)
{
	if (memcmp(got, want, n) != 0) {
		fprintf(stderr, "FAIL %s: %d bytes differ\n", what, (int)n);
		failures++;
	}
}

static void test_rtattr_replace(void)
{
	/* Synthetic ifaddrmsg region: 8 header bytes, then
	 *   A: IFA_LOCAL(2)  len=20 payload=real16
	 *   B: IFA_ADDRESS(1) len=20 payload=real16
	 *   C: IFA_ADDRESS(1) len=20 payload=peer16 (must survive)
	 *   D: malformed (rta_len=2) — the walker must stop here. */
	unsigned char buf[96];
	unsigned char real[16], fake[16], peer[16];
	unsigned long off;
	int n;

	memset(buf, 0, sizeof(buf));
	fill_fake_fixture(fake);
	memcpy(real, fake, 16);
	real[15] ^= 0xff; /* real != fake */
	memcpy(peer, fake, 16);
	peer[15] ^= 0x01; /* peer != real */

	/* A */
	off = 8;
	buf[off] = 20;
	buf[off + 2] = 2; /* IFA_LOCAL */
	memcpy(buf + off + 4, real, 16);
	/* B */
	off += 20;
	buf[off] = 20;
	buf[off + 2] = 1; /* IFA_ADDRESS */
	memcpy(buf + off + 4, real, 16);
	/* C */
	off += 20;
	buf[off] = 20;
	buf[off + 2] = 1; /* IFA_ADDRESS (peer) */
	memcpy(buf + off + 4, peer, 16);
	/* D */
	off += 20;
	buf[off] = 2; /* malformed: rta_len < 4 */

	/* IFA_LOCAL pass: replaces A only. */
	n = vpnhide_rtattr_replace(buf, sizeof(buf), 8, 2, real, fake, 16);
	expect_int("rtattr IFA_LOCAL count", n, 1);
	expect_mem("rtattr IFA_LOCAL bytes", buf + 8 + 4, fake, 16);
	expect_mem("rtattr IFA_ADDRESS still real", buf + 28 + 4, real, 16);
	/* IFA_ADDRESS pass: replaces B, leaves peer C. */
	n = vpnhide_rtattr_replace(buf, sizeof(buf), 8, 1, real, fake, 16);
	expect_int("rtattr IFA_ADDRESS count", n, 1);
	expect_mem("rtattr IFA_ADDRESS bytes", buf + 28 + 4, fake, 16);
	expect_mem("rtattr peer preserved", buf + 48 + 4, peer, 16);

	/* v4 sub-case: a 4-byte needle inside a DIFFERENT attr type
	 * (IFA_CACHEINFO-shaped) must not be touched; the same needle in an
	 * IFA_LOCAL-shaped attr is replaced. A trailing malformed attr stops
	 * the walk. */
	{
		unsigned char b4[64];
		unsigned char real4[4] = { 100, 124, 146, 11 };
		unsigned char fake4[4] = { 100, 87, 23, 45 };

		memset(b4, 0, sizeof(b4));
		/* IFA_LOCAL(2), len=8, payload=real4 */
		b4[8] = 8;
		b4[10] = 2;
		memcpy(b4 + 12, real4, 4);
		/* IFA_CACHEINFO(6), len=20, payload starts with the needle */
		b4[16] = 20;
		b4[18] = 6;
		memcpy(b4 + 20, real4, 4);
		/* malformed terminator */
		b4[36] = 1;

		n = vpnhide_rtattr_replace(b4, sizeof(b4), 8, 2, real4, fake4,
					   4);
		expect_int("rtattr v4 count", n, 1);
		expect_mem("rtattr v4 replaced", b4 + 12, fake4, 4);
		expect_mem("rtattr cacheinfo untouched", b4 + 20, real4, 4);
	}
}

static void test_route4_column_rewrite(void)
{
	/* /proc/net/route: Destination/Gateway are fixed 8-char UPPERCASE
	 * little-endian %08X columns. 100.110.255.23 (bytes 64 6E FF 17)
	 * prints as "17FF6E64"; the fake 100.118.64.203 (64 76 40 CB) must
	 * replace covered columns as "CB407664" — width- and case-exact. */
	char buf[640] =
		"Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"
		"ccmni0\t00000000\t17FF6E64\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"
		"ccmni0\t17FF6E64\t00000000\t0001\t0\t0\t0\tFFFFFFFF\t0\t0\t0\n"
		"ccmni1\t00000000\t17FF6E64\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"
		"wlan0\t00000000\t0101A8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0\n";
	struct vpnhide_prefix4_rule rules[1];
	unsigned long count = strlen(buf);
	int rw;

	memset(&rules[0], 0, sizeof(rules[0]));
	strcpy(rules[0].ifname, "ccmni0");
	rules[0].addr[0] = 100;
	rules[0].addr[1] = 64;
	rules[0].prefix_len = 10;
	rules[0].fake[0] = 100;
	rules[0].fake[1] = 118;
	rules[0].fake[2] = 64;
	rules[0].fake[3] = 203;

	rw = vpnhide_rewrite_route4_lines(buf, 0, count, rules, 1);
	expect_int("route4: gateway + host-dst rewritten", rw, 2);
	expect_str(
		"route4: covered columns faked, rest verbatim", buf,
		"Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"
		"ccmni0\t00000000\tCB407664\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"
		"ccmni0\tCB407664\t00000000\t0001\t0\t0\t0\tFFFFFFFF\t0\t0\t0\n"
		"ccmni1\t00000000\t17FF6E64\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"
		"wlan0\t00000000\t0101A8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0\n");
	/* In-place only: length never changes. */
	expect_int("route4: length unchanged", (int)count,
		   (int)strlen(
			   "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"
			   "ccmni0\t00000000\tCB407664\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"
			   "ccmni0\tCB407664\t00000000\t0001\t0\t0\t0\tFFFFFFFF\t0\t0\t0\n"
			   "ccmni1\t00000000\t17FF6E64\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"
			   "wlan0\t00000000\t0101A8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"));
}

int main(void)
{
	test_route_first_field();
	test_ipv6_route_last_field();
	test_start_offset_preserved();
	test_is_public_ipv4();
	test_is_public_ipv6();
	test_is_physical_iface();
	test_parse_uids();
	test_prefix_match();
	test_uid_prefix_filtered();
	test_compact_if_inet6();
	test_compact_if_inet6_vpn_and_edges();
	test_compact_ipv6_route_prefix();
	test_hex32_render();
	test_prefix4_match();
	test_compact_if_inet6_rewrite();
	test_compact_ipv6_route_rewrite();
	test_rtattr_replace();
	test_route4_column_rewrite();

	if (failures) {
		fprintf(stderr, "%d test(s) failed\n", failures);
		return 1;
	}
	printf("all shared-logic tests passed\n");
	return 0;
}
