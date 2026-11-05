#include "lab.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef TEST
#define main main_exclude
#endif

static void print_usage(void)
{
  printf("Usage: myapp info <address>/<prefix>\n"
         "       myapp split <network>/<prefix> <count>\n"
         "       myapp lookup <table-file> <address>...\n");
}

static bool parse_count(const char *text, uint32_t *count)
{
  char *end;
  unsigned long value;

  if (text == NULL || *text == '\0') {
    return false;
  }
  for (const char *p = text; *p != '\0'; p++) {
    if (*p < '0' || *p > '9') {
      return false;
    }
  }
  errno = 0;
  value = strtoul(text, &end, 10);
  if (errno == ERANGE || *end != '\0' || value > UINT32_MAX) {
    return false;
  }
  *count = (uint32_t)value;
  return true;
}

static int run_info(const char *text)
{
  cidr_t block;
  char address[IP_STR_LEN];
  char mask[IP_STR_LEN];
  char network[IP_STR_LEN];
  char broadcast[IP_STR_LEN];
  char first_host[IP_STR_LEN];
  char last_host[IP_STR_LEN];

  if (text == NULL || !cidr_parse(text, &block)) {
    fprintf(stderr, "myapp: %s: not a valid CIDR block\n",
            text == NULL ? "(null)" : text);
    return 1;
  }
  ip_format(block.addr, address);
  ip_format(cidr_mask(block.prefix), mask);
  ip_format(cidr_network(block), network);
  ip_format(cidr_broadcast(block), broadcast);
  ip_format(cidr_first_host(block), first_host);
  ip_format(cidr_last_host(block), last_host);
  printf("address    %s\n"
         "prefix     /%u\n"
         "netmask    %s\n"
         "network    %s\n"
         "broadcast  %s\n"
         "first host %s\n"
         "last host  %s\n"
         "hosts      %llu\n",
         address, (unsigned)block.prefix, mask, network, broadcast,
         first_host, last_host, (unsigned long long)cidr_host_count(block));
  return 0;
}

static int run_split(const char *text, const char *count_text)
{
  cidr_t block;
  uint32_t count;
  char output[CIDR_STR_LEN];

  if (text == NULL || !cidr_parse(text, &block) ||
      !cidr_is_network(block) || !parse_count(count_text, &count) ||
      count == 0U || (count & (count - 1U)) != 0U) {
    fprintf(stderr, "myapp: invalid network or subnet count\n");
    return 1;
  }
  for (uint32_t i = 0U; i < count; i++) {
    cidr_t subnet;
    if (!cidr_subnet(block, count, i, &subnet)) {
      fprintf(stderr, "myapp: cannot split %s into %u subnets\n",
              text, (unsigned)count);
      return 1;
    }
    cidr_format(subnet, output);
    puts(output);
  }
  return 0;
}

static int run_lookup(const char *filename, int address_count,
                      char *const addresses[])
{
  FILE *in;
  fwd_table_t *table;
  size_t bad_line;
  bool malformed = false;
  bool unreachable = false;

  in = fopen(filename, "r");
  if (in == NULL) {
    fprintf(stderr, "myapp: %s: cannot open table file\n", filename);
    return 2;
  }
  table = table_create();
  if (table == NULL) {
    (void)fclose(in);
    fprintf(stderr, "myapp: could not allocate forwarding table\n");
    return 2;
  }
  if (!table_load(table, in, &bad_line)) {
    if (bad_line != 0U) {
      fprintf(stderr, "myapp: %s:%zu: not a valid route\n",
              filename, bad_line);
    } else {
      fprintf(stderr, "myapp: %s: could not read table file\n", filename);
    }
    (void)fclose(in);
    table_destroy(table);
    return 2;
  }
  (void)fclose(in);

  for (int i = 0; i < address_count; i++) {
    uint32_t address;
    const route_t *route;
    char formatted[IP_STR_LEN];
    if (!ip_parse(addresses[i], &address)) {
      fprintf(stderr, "myapp: %s: not a valid address\n", addresses[i]);
      malformed = true;
      continue;
    }
    ip_format(address, formatted);
    route = table_lookup(table, address);
    if (route == NULL) {
      printf("%s unreachable\n", formatted);
      unreachable = true;
    } else if (route->gateway == 0U) {
      printf("%s dev %s\n", formatted, route->dev);
    } else {
      char gateway[IP_STR_LEN];
      ip_format(route->gateway, gateway);
      printf("%s via %s dev %s\n", formatted, gateway, route->dev);
    }
  }
  table_destroy(table);
  if (malformed) {
    return 1;
  }
  return unreachable ? 3 : 0;
}

int main(int argc, char *argv[])
{
  if (argc == 1) {
    print_usage();
    return 0;
  }
  if (strcmp(argv[1], "info") == 0 && argc == 3) {
    return run_info(argv[2]);
  }
  if (strcmp(argv[1], "split") == 0 && argc == 4) {
    return run_split(argv[2], argv[3]);
  }
  if (strcmp(argv[1], "lookup") == 0 && argc >= 4) {
    return run_lookup(argv[2], argc - 3, &argv[3]);
  }
  fprintf(stderr, "myapp: invalid command line\n");
  print_usage();
  return 1;
}