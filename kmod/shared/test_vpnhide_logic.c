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
					   (vpnhide_match_fn)0, rules, 1);
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

	n = vpnhide_compact_if_inet6_lines(buf, 0, strlen(buf), match_vpn, rules,
					   1);
	buf[n] = '\0';
	expect_str(
		"if_inet6: vpn tun0 + prefix removed, no-trailing-newline kept",
		buf, "24014900a41fb57cf4d296fffecd4b63 20 40 00 00 rmnet_data3");

	/* Case B: bytes before `start` are never touched (even a VPN line); the
	 * tun0 line after start is removed by vpn_match (rules unused here). */
	{
		char buf2[256] =
			"24014900a3f1e04d54fdd7fffeb173bf 1e 40 00 00 rmnet_data1\n"
			"fe800000000000005042d7fffe000001 05 40 20 80 tun0\n";
		unsigned long start = strlen(
			"24014900a3f1e04d54fdd7fffeb173bf 1e 40 00 00 rmnet_data1\n");
		unsigned long m = vpnhide_compact_if_inet6_lines(
			buf2, start, strlen(buf2), match_vpn,
			(const struct vpnhide_prefix_rule *)0, 0);

		buf2[m] = '\0';
		expect_str(
			"if_inet6: start offset preserved (pre-start line kept)",
			buf2,
			"24014900a3f1e04d54fdd7fffeb173bf 1e 40 00 00 rmnet_data1\n");
	}
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
	test_compact_if_inet6();
	test_compact_if_inet6_vpn_and_edges();

	if (failures) {
		fprintf(stderr, "%d test(s) failed\n", failures);
		return 1;
	}
	printf("all shared-logic tests passed\n");
	return 0;
}
