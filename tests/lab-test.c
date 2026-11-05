#include "harness/unity.h"
#include "../src/lab.h"

#include <stdio.h>
#include <string.h>

void setUp(void) {
}

void tearDown(void) {
}

void test_ip_parse_valid_addresses(void) {
  uint32_t addr = 0;

  TEST_ASSERT_TRUE(ip_parse("0.0.0.0", &addr));
  TEST_ASSERT_EQUAL_UINT32(0x00000000U, addr);
  TEST_ASSERT_TRUE(ip_parse("192.168.1.10", &addr));
  TEST_ASSERT_EQUAL_UINT32(0xC0A8010AU, addr);
  TEST_ASSERT_TRUE(ip_parse("255.255.255.255", &addr));
  TEST_ASSERT_EQUAL_UINT32(0xFFFFFFFFU, addr);
}

void test_ip_parse_rejects_malformed_addresses(void) {
  const char *invalid[] = {
    "1.2.3", "1.2.3.4.5", "1..2.3", "256.1.1.1",
    "010.0.0.1", "1.2.3.4x", "+1.2.3.4", "1.2.3.4 ",
    NULL
  };
  uint32_t addr = 0xA5A5A5A5U;

  for (size_t i = 0; invalid[i] != NULL; i++) {
    TEST_ASSERT_FALSE(ip_parse(invalid[i], &addr));
    TEST_ASSERT_EQUAL_UINT32(0xA5A5A5A5U, addr);
  }
  TEST_ASSERT_FALSE(ip_parse(NULL, &addr));
  TEST_ASSERT_FALSE(ip_parse("1.2.3.4", NULL));
}

void test_ip_format(void) {
  char out[IP_STR_LEN];

  ip_format(0x00000000U, out);
  TEST_ASSERT_EQUAL_STRING("0.0.0.0", out);
  ip_format(0xC0A8010AU, out);
  TEST_ASSERT_EQUAL_STRING("192.168.1.10", out);
  ip_format(0xFFFFFFFFU, out);
  TEST_ASSERT_EQUAL_STRING("255.255.255.255", out);
}

void test_cidr_parse_and_format(void) {
  cidr_t block = {0};
  char out[CIDR_STR_LEN];

  TEST_ASSERT_TRUE(cidr_parse("132.178.227.11/25", &block));
  TEST_ASSERT_EQUAL_UINT32(0x84B2E30BU, block.addr);
  TEST_ASSERT_EQUAL_UINT8(25U, block.prefix);
  cidr_format(block, out);
  TEST_ASSERT_EQUAL_STRING("132.178.227.11/25", out);

  TEST_ASSERT_TRUE(cidr_parse("0.0.0.0/0", &block));
  TEST_ASSERT_EQUAL_UINT8(0U, block.prefix);
  TEST_ASSERT_TRUE(cidr_parse("255.255.255.255/32", &block));
  TEST_ASSERT_EQUAL_UINT8(32U, block.prefix);
  block.prefix = 33U;
  cidr_format(block, out);
  TEST_ASSERT_EQUAL_STRING("255.255.255.255/32", out);
}

void test_cidr_parse_rejects_malformed_blocks(void) {
  const char *invalid[] = {
    "1.2.3.4/33", "1.2.3.4/024", "1.2.3.4/",
    "1.2.3/24", "1.2.3.4", "1.2.3.4/1x", "1.2.3.4/1/2",
    "1234567890123456/24",
    NULL
  };
  cidr_t block = {0xA5A5A5A5U, 17U};

  for (size_t i = 0; invalid[i] != NULL; i++) {
    TEST_ASSERT_FALSE(cidr_parse(invalid[i], &block));
    TEST_ASSERT_EQUAL_UINT32(0xA5A5A5A5U, block.addr);
    TEST_ASSERT_EQUAL_UINT8(17U, block.prefix);
  }
  TEST_ASSERT_FALSE(cidr_parse(NULL, &block));
  TEST_ASSERT_FALSE(cidr_parse("1.2.3.4/24", NULL));
}

void test_cidr_mask_and_boundaries(void) {
  TEST_ASSERT_EQUAL_UINT32(0x00000000U, cidr_mask(0U));
  TEST_ASSERT_EQUAL_UINT32(0xFFFFFF80U, cidr_mask(25U));
  TEST_ASSERT_EQUAL_UINT32(0xFFFFFFFFU, cidr_mask(32U));
  TEST_ASSERT_EQUAL_UINT32(0xFFFFFFFFU, cidr_mask(33U));
}

void test_cidr_network_and_broadcast(void) {
  cidr_t block = {0x84B2E30BU, 25U};

  TEST_ASSERT_EQUAL_UINT32(0x84B2E300U, cidr_network(block));
  TEST_ASSERT_EQUAL_UINT32(0x84B2E37FU, cidr_broadcast(block));

  block.addr = 0xFFFFFFFFU;
  block.prefix = 32U;
  TEST_ASSERT_EQUAL_UINT32(0xFFFFFFFFU, cidr_network(block));
  TEST_ASSERT_EQUAL_UINT32(0xFFFFFFFFU, cidr_broadcast(block));
}

void test_cidr_hosts_and_counts(void) {
  cidr_t block = {0x84B2E30BU, 25U};

  TEST_ASSERT_EQUAL_UINT32(0x84B2E301U, cidr_first_host(block));
  TEST_ASSERT_EQUAL_UINT32(0x84B2E37EU, cidr_last_host(block));
  TEST_ASSERT_EQUAL_UINT64(126U, cidr_host_count(block));

  block.addr = 0U;
  block.prefix = 0U;
  TEST_ASSERT_EQUAL_UINT32(1U, cidr_first_host(block));
  TEST_ASSERT_EQUAL_UINT32(0xFFFFFFFEU, cidr_last_host(block));
  TEST_ASSERT_EQUAL_UINT64(UINT64_C(4294967294), cidr_host_count(block));

  block.addr = 0xC0A80102U;
  block.prefix = 31U;
  TEST_ASSERT_EQUAL_UINT32(0xC0A80102U, cidr_first_host(block));
  TEST_ASSERT_EQUAL_UINT32(0xC0A80103U, cidr_last_host(block));
  TEST_ASSERT_EQUAL_UINT64(2U, cidr_host_count(block));

  block.prefix = 32U;
  TEST_ASSERT_EQUAL_UINT32(0xC0A80102U, cidr_first_host(block));
  TEST_ASSERT_EQUAL_UINT32(0xC0A80102U, cidr_last_host(block));
  TEST_ASSERT_EQUAL_UINT64(1U, cidr_host_count(block));
}

void test_cidr_contains_and_network_status(void) {
  cidr_t block = {0x84B2E300U, 25U};

  TEST_ASSERT_TRUE(cidr_contains(block, 0x84B2E30BU));
  TEST_ASSERT_TRUE(cidr_contains(block, 0x84B2E37FU));
  TEST_ASSERT_FALSE(cidr_contains(block, 0x84B2E380U));
  TEST_ASSERT_TRUE(cidr_is_network(block));

  block.addr = 0x84B2E30BU;
  TEST_ASSERT_FALSE(cidr_is_network(block));
}

void test_cidr_subnet(void) {
  cidr_t block = {0xC0A80100U, 24U};
  cidr_t subnet = {0xA5A5A5A5U, 17U};

  TEST_ASSERT_TRUE(cidr_subnet(block, 4U, 0U, &subnet));
  TEST_ASSERT_EQUAL_UINT32(0xC0A80100U, subnet.addr);
  TEST_ASSERT_EQUAL_UINT8(26U, subnet.prefix);
  TEST_ASSERT_TRUE(cidr_subnet(block, 4U, 3U, &subnet));
  TEST_ASSERT_EQUAL_UINT32(0xC0A801C0U, subnet.addr);
  TEST_ASSERT_EQUAL_UINT8(26U, subnet.prefix);

  TEST_ASSERT_FALSE(cidr_subnet(block, 3U, 0U, &subnet));
  TEST_ASSERT_FALSE(cidr_subnet(block, 4U, 4U, &subnet));
  TEST_ASSERT_FALSE(cidr_subnet(block, 0U, 0U, &subnet));
  TEST_ASSERT_FALSE(cidr_subnet(block, 4U, 0U, NULL));
  TEST_ASSERT_EQUAL_UINT32(0xC0A801C0U, subnet.addr);
  TEST_ASSERT_EQUAL_UINT8(26U, subnet.prefix);

  block.addr = 0xC0A80101U;
  TEST_ASSERT_FALSE(cidr_subnet(block, 2U, 0U, &subnet));
  block.addr = 0xC0A80000U;
  block.prefix = 31U;
  TEST_ASSERT_FALSE(cidr_subnet(block, 4U, 0U, &subnet));

  block.addr = 0U;
  block.prefix = 0U;
  TEST_ASSERT_TRUE(cidr_subnet(block, 1U, 0U, &subnet));
  TEST_ASSERT_EQUAL_UINT32(0U, subnet.addr);
  TEST_ASSERT_EQUAL_UINT8(0U, subnet.prefix);
  TEST_ASSERT_TRUE(cidr_subnet(block, 2U, 1U, &subnet));
  TEST_ASSERT_EQUAL_UINT32(0x80000000U, subnet.addr);
  TEST_ASSERT_EQUAL_UINT8(1U, subnet.prefix);
}

void test_route_parse(void) {
  route_t route = {0};
  route_t original = route;

  TEST_ASSERT_TRUE(route_parse("default 132.178.227.1 eno1\n", &route));
  TEST_ASSERT_EQUAL_UINT32(0U, route.dest.addr);
  TEST_ASSERT_EQUAL_UINT8(0U, route.dest.prefix);
  TEST_ASSERT_EQUAL_UINT32(0x84B2E301U, route.gateway);
  TEST_ASSERT_EQUAL_STRING("eno1", route.dev);

  TEST_ASSERT_TRUE(route_parse("10.1.0.0/16 direct eth1", &route));
  TEST_ASSERT_EQUAL_UINT32(0x0A010000U, route.dest.addr);
  TEST_ASSERT_EQUAL_UINT8(16U, route.dest.prefix);
  TEST_ASSERT_EQUAL_UINT32(0U, route.gateway);

  route = original;
  TEST_ASSERT_FALSE(route_parse("10.1.2.5/24 direct eth1", &route));
  TEST_ASSERT_EQUAL_MEMORY(&original, &route, sizeof(route));
  TEST_ASSERT_FALSE(route_parse("10.1.0.0/16 direct eth1 extra", &route));
  TEST_ASSERT_FALSE(route_parse("10.1.0.0/16 010.1.0.1 eth1", &route));
  TEST_ASSERT_FALSE(route_parse("10.1.0.0/16 direct ", &route));
  TEST_ASSERT_FALSE(route_parse("10.1.0.0/16 direct 1234567890123456", &route));
  TEST_ASSERT_FALSE(route_parse("10.1.2.5/24 direct eth1", &route));
  TEST_ASSERT_FALSE(route_parse("10.1.0.0/16 not-an-address eth1", &route));
  TEST_ASSERT_FALSE(route_parse(NULL, &route));
  TEST_ASSERT_FALSE(route_parse("default direct eth1", NULL));
}

void test_table_operations_and_lookup(void) {
  fwd_table_t *table = table_create();
  fwd_table_t *reordered = table_create();
  route_t routes[4];
  const route_t *match;

  TEST_ASSERT_NOT_NULL(table);
  TEST_ASSERT_NOT_NULL(reordered);
  TEST_ASSERT_EQUAL_UINT(0U, table_count(table));
  TEST_ASSERT_EQUAL_UINT(0U, table_count(NULL));
  TEST_ASSERT_TRUE(route_parse("10.0.0.0/8 10.1.0.1 eth1", &routes[0]));
  TEST_ASSERT_TRUE(route_parse("10.1.2.128/25 10.1.2.1 eth2", &routes[1]));
  TEST_ASSERT_TRUE(route_parse("10.1.0.0/16 direct eth1", &routes[2]));
  TEST_ASSERT_TRUE(route_parse("default 132.178.227.1 eno1", &routes[3]));

  TEST_ASSERT_TRUE(table_add(table, &routes[3]));
  TEST_ASSERT_TRUE(table_add(table, &routes[0]));
  TEST_ASSERT_TRUE(table_add(table, &routes[2]));
  TEST_ASSERT_TRUE(table_add(table, &routes[1]));
  TEST_ASSERT_EQUAL_UINT(4U, table_count(table));
  TEST_ASSERT_FALSE(table_add(table, &routes[0]));
  TEST_ASSERT_FALSE(table_add(table, NULL));
  TEST_ASSERT_FALSE(table_add(NULL, &routes[0]));
  routes[0].dest.addr = 0x0A000001U;
  TEST_ASSERT_FALSE(table_add(table, &routes[0]));
  routes[0].dest.addr = 0x0A000000U;
  routes[0].dest.prefix = 33U;
  TEST_ASSERT_FALSE(table_add(table, &routes[0]));
  routes[0].dest.prefix = 8U;

  match = table_lookup(table, 0x0A0102C8U);
  TEST_ASSERT_NOT_NULL(match);
  TEST_ASSERT_EQUAL_UINT8(25U, match->dest.prefix);
  TEST_ASSERT_EQUAL_STRING("eth2", match->dev);
  match = table_lookup(table, 0x08080808U);
  TEST_ASSERT_NOT_NULL(match);
  TEST_ASSERT_EQUAL_UINT8(0U, match->dest.prefix);
  match = table_lookup(table, 0xC0A80101U);
  TEST_ASSERT_NOT_NULL(match);
  TEST_ASSERT_EQUAL_UINT8(0U, match->dest.prefix);
  TEST_ASSERT_NULL(table_lookup(NULL, 0U));
  table_destroy(table);
  table_destroy(NULL);

  TEST_ASSERT_TRUE(table_add(reordered, &routes[1]));
  TEST_ASSERT_TRUE(table_add(reordered, &routes[2]));
  TEST_ASSERT_TRUE(table_add(reordered, &routes[0]));
  match = table_lookup(reordered, 0x0A0102C8U);
  TEST_ASSERT_NOT_NULL(match);
  TEST_ASSERT_EQUAL_UINT8(25U, match->dest.prefix);
  match = table_lookup(reordered, 0xC0A80101U);
  TEST_ASSERT_NULL(match);
  table_destroy(reordered);
}

void test_table_load(void) {
  fwd_table_t *table = table_create();
  FILE *in = tmpfile();
  size_t bad_line = 99U;
  const route_t *match;

  TEST_ASSERT_NOT_NULL(table);
  TEST_ASSERT_NOT_NULL(in);
  fputs("# comment\n\n10.0.0.0/8 direct eth0\n10.1.0.0/16 direct eth1 # inline\n", in);
  rewind(in);
  TEST_ASSERT_TRUE(table_load(table, in, &bad_line));
  TEST_ASSERT_EQUAL_UINT(2U, table_count(table));
  TEST_ASSERT_EQUAL_UINT(0U, bad_line);
  match = table_lookup(table, 0x0A010001U);
  TEST_ASSERT_NOT_NULL(match);
  TEST_ASSERT_EQUAL_STRING("eth1", match->dev);
  fclose(in);
  table_destroy(table);

  table = table_create();
  in = tmpfile();
  fputs("10.0.0.0/8 direct eth0\nbad route\n10.1.0.0/16 direct eth1\n", in);
  rewind(in);
  TEST_ASSERT_FALSE(table_load(table, in, &bad_line));
  TEST_ASSERT_EQUAL_UINT(2U, bad_line);
  TEST_ASSERT_EQUAL_UINT(1U, table_count(table));
  fclose(in);
  table_destroy(table);

  table = table_create();
  in = tmpfile();
  TEST_ASSERT_FALSE(table_load(NULL, in, &bad_line));
  rewind(in);
  TEST_ASSERT_FALSE(table_load(table, NULL, &bad_line));
  rewind(in);
  TEST_ASSERT_TRUE(table_load(table, in, NULL));
  fclose(in);
  table_destroy(table);

  table = table_create();
  in = tmpfile();
  fputs("10.0.0.0/8 direct eth0\n10.0.0.0/8 direct eth1\n", in);
  rewind(in);
  TEST_ASSERT_FALSE(table_load(table, in, &bad_line));
  TEST_ASSERT_EQUAL_UINT(2U, bad_line);
  TEST_ASSERT_EQUAL_UINT(1U, table_count(table));
  fclose(in);
  table_destroy(table);

  table = table_create();
  for (uint32_t i = 0U; i < 5U; i++) {
    route_t route;
    char line[64];
    (void)snprintf(line, sizeof(line), "192.168.%u.0/24 direct eth0",
                   (unsigned)i);
    TEST_ASSERT_TRUE(route_parse(line, &route));
    TEST_ASSERT_TRUE(table_add(table, &route));
  }
  TEST_ASSERT_EQUAL_UINT(5U, table_count(table));
  table_destroy(table);
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_ip_parse_valid_addresses);
  RUN_TEST(test_ip_parse_rejects_malformed_addresses);
  RUN_TEST(test_ip_format);
  RUN_TEST(test_cidr_parse_and_format);
  RUN_TEST(test_cidr_parse_rejects_malformed_blocks);
  RUN_TEST(test_cidr_mask_and_boundaries);
  RUN_TEST(test_cidr_network_and_broadcast);
  RUN_TEST(test_cidr_hosts_and_counts);
  RUN_TEST(test_cidr_contains_and_network_status);
  RUN_TEST(test_cidr_subnet);
  RUN_TEST(test_route_parse);
  RUN_TEST(test_table_operations_and_lookup);
  RUN_TEST(test_table_load);
  return UNITY_END();
}
