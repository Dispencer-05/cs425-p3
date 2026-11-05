#include "lab.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

struct fwd_table {
  route_t *routes;
  size_t count;
  size_t capacity;
};

static bool parse_octet(const char **cursor, uint32_t *value)
{
  const char *p = *cursor;
  uint32_t number = 0;
  size_t digits = 0;

  if (*p == '0') {
    p++;
    digits = 1;
    if (*p >= '0' && *p <= '9') {
      return false;
    }
  } else {
    while (*p >= '0' && *p <= '9') {
      number = number * 10U + (uint32_t)(*p - '0');
      if (number > 255U) {
        return false;
      }
      p++;
      digits++;
    }
  }

  if (digits == 0) {
    return false;
  }

  *cursor = p;
  *value = number;
  return true;
}

bool ip_parse(const char *text, uint32_t *addr)
{
  const char *p = text;
  uint32_t parsed = 0;

  if (text == NULL || addr == NULL) {
    return false;
  }

  for (size_t i = 0; i < 4; i++) {
    uint32_t octet = 0;
    if (!parse_octet(&p, &octet)) {
      return false;
    }
    parsed = (parsed << 8) | octet;
    if (i < 3) {
      if (*p != '.') {
        return false;
      }
      p++;
    }
  }

  if (*p != '\0') {
    return false;
  }

  *addr = parsed;
  return true;
}

void ip_format(uint32_t addr, char out[IP_STR_LEN])
{
  (void)snprintf(out, IP_STR_LEN, "%u.%u.%u.%u",
                 (unsigned)((addr >> 24) & 0xffU),
                 (unsigned)((addr >> 16) & 0xffU),
                 (unsigned)((addr >> 8) & 0xffU),
                 (unsigned)(addr & 0xffU));
}

bool cidr_parse(const char *text, cidr_t *block)
{
  const char *slash;
  const char *p;
  char address[IP_STR_LEN];
  uint32_t addr;
  uint32_t prefix = 0;
  size_t address_length;

  if (text == NULL || block == NULL) {
    return false;
  }

  slash = strchr(text, '/');
  if (slash == NULL || strchr(slash + 1, '/') != NULL) {
    return false;
  }

  address_length = (size_t)(slash - text);
  if (address_length == 0 || address_length >= sizeof(address)) {
    return false;
  }
  (void)memcpy(address, text, address_length);
  address[address_length] = '\0';
  if (!ip_parse(address, &addr)) {
    return false;
  }

  p = slash + 1;
  if (*p == '\0' || (*p == '0' && p[1] != '\0')) {
    return false;
  }
  while (*p >= '0' && *p <= '9') {
    prefix = prefix * 10U + (uint32_t)(*p - '0');
    if (prefix > 32U) {
      return false;
    }
    p++;
  }
  if (*p != '\0') {
    return false;
  }

  block->addr = addr;
  block->prefix = (uint8_t)prefix;
  return true;
}

void cidr_format(cidr_t block, char out[CIDR_STR_LEN])
{
  char address[IP_STR_LEN];
  ip_format(block.addr, address);
  (void)snprintf(out, CIDR_STR_LEN, "%s/%u", address,
                 (unsigned)(block.prefix > 32U ? 32U : block.prefix));
}

/**
 * @brief Computes the subnet mask for an IPv4 prefix length.
 * @param prefix Prefix length; values above 32 are treated as 32.
 * @return The subnet mask in host byte order.
 */
uint32_t cidr_mask(uint8_t prefix)
{
  if (prefix == 0U) {
    return 0U;
  }
  if (prefix >= 32U) {
    return UINT32_MAX;
  }
  return UINT32_MAX << (32U - prefix);
}

/**
 * @brief Computes the lowest address in a CIDR block.
 * @param block The CIDR block.
 * @return The network address in host byte order.
 */
uint32_t cidr_network(cidr_t block)
{
  return block.addr & cidr_mask(block.prefix);
}

/**
 * @brief Computes the highest address in a CIDR block.
 * @param block The CIDR block.
 * @return The broadcast address in host byte order.
 */
uint32_t cidr_broadcast(cidr_t block)
{
  return cidr_network(block) | ~cidr_mask(block.prefix);
}

/**
 * @brief Computes the first usable host address in a CIDR block.
 * @param block The CIDR block.
 * @return The first usable address, including RFC 3021 handling for /31 and /32.
 */
uint32_t cidr_first_host(cidr_t block)
{
  uint8_t prefix = block.prefix > 32U ? 32U : block.prefix;
  if (prefix >= 31U) {
    return cidr_network(block);
  }
  return cidr_network(block) + 1U;
}

/**
 * @brief Computes the last usable host address in a CIDR block.
 * @param block The CIDR block.
 * @return The last usable address, including RFC 3021 handling for /31 and /32.
 */
uint32_t cidr_last_host(cidr_t block)
{
  uint8_t prefix = block.prefix > 32U ? 32U : block.prefix;
  uint32_t broadcast = cidr_broadcast(block);
  if (prefix >= 31U) {
    return broadcast;
  }
  return broadcast - 1U;
}

/**
 * @brief Counts the addresses available for hosts in a CIDR block.
 * @param block The CIDR block.
 * @return The number of usable host addresses.
 */
uint64_t cidr_host_count(cidr_t block)
{
  uint8_t prefix = block.prefix > 32U ? 32U : block.prefix;
  if (prefix == 31U) {
    return 2U;
  }
  if (prefix == 32U) {
    return 1U;
  }
  return (UINT64_C(1) << (32U - prefix)) - 2U;
}

/**
 * @brief Checks whether an address belongs to a CIDR block.
 * @param block The CIDR block.
 * @param addr The address to test, in host byte order.
 * @return true if addr is contained in block; otherwise false.
 */
bool cidr_contains(cidr_t block, uint32_t addr)
{
  uint32_t mask = cidr_mask(block.prefix);
  return (addr & mask) == (block.addr & mask);
}

/**
 * @brief Checks whether a CIDR address has all host bits cleared.
 * @param block The CIDR block to test.
 * @return true if block names a network address; otherwise false.
 */
bool cidr_is_network(cidr_t block)
{
  return block.addr == cidr_network(block);
}

/**
 * @brief Computes one of n equally sized subnets within a CIDR block.
 * @param block The network block to split.
 * @param n Number of subnets; must be a nonzero power of two.
 * @param i Zero-based index of the requested subnet.
 * @param out Destination for the subnet; unchanged when the operation fails.
 * @return true on success; false for invalid input or an impossible split.
 */
bool cidr_subnet(cidr_t block, uint32_t n, uint32_t i, cidr_t *out)
{
  uint32_t bits = 0;
  uint32_t pieces = n;
  uint32_t new_prefix;
  uint32_t subnet_size;
  cidr_t result;

  if (out == NULL || block.prefix > 32U || !cidr_is_network(block) ||
      n == 0U || (n & (n - 1U)) != 0U || i >= n) {
    return false;
  }

  while (pieces > 1U) {
    pieces >>= 1;
    bits++;
  }
  new_prefix = (uint32_t)block.prefix + bits;
  if (new_prefix > 32U) {
    return false;
  }

  subnet_size = new_prefix == 0U ? 0U : UINT32_C(1) << (32U - new_prefix);
  result.addr = block.addr + i * subnet_size;
  result.prefix = (uint8_t)new_prefix;
  *out = result;
  return true;
}

/**
 * @brief Parses one forwarding-table route line.
 * @param line A route line without comment processing.
 * @param route Destination for the parsed route; unchanged on failure.
 * @return true if line contains one valid route; otherwise false.
 */
bool route_parse(const char *line, route_t *route)
{
  char destination[CIDR_STR_LEN];
  char gateway[IP_STR_LEN];
  char device[DEV_NAME_LEN];
  char extra[2];
  route_t parsed;
  cidr_t block;

  if (line == NULL || route == NULL ||
      sscanf(line, " %18s %15s %15s %1s", destination, gateway, device, extra) != 3) {
    return false;
  }

  if (strcmp(destination, "default") == 0) {
    block.addr = 0U;
    block.prefix = 0U;
  } else if (!cidr_parse(destination, &block) || !cidr_is_network(block)) {
    return false;
  }

  parsed.dest = block;
  if (strcmp(gateway, "direct") == 0) {
    parsed.gateway = 0U;
  } else if (!ip_parse(gateway, &parsed.gateway)) {
    return false;
  }
  (void)memcpy(parsed.dev, device, sizeof(parsed.dev));
  parsed.dev[DEV_NAME_LEN - 1U] = '\0';
  *route = parsed;
  return true;
}

/**
 * @brief Creates an empty dynamically sized forwarding table.
 * @return A new table, or NULL if memory allocation fails.
 */
fwd_table_t *table_create(void)
{
  return calloc(1U, sizeof(fwd_table_t));
}

/**
 * @brief Destroys a forwarding table and releases its route storage.
 * @param table The table to destroy; NULL is allowed.
 */
void table_destroy(fwd_table_t *table)
{
  if (table != NULL) {
    free(table->routes);
    free(table);
  }
}

/**
 * @brief Gets the number of routes in a forwarding table.
 * @param table The table to inspect.
 * @return The route count, or zero for NULL.
 */
size_t table_count(const fwd_table_t *table)
{
  return table == NULL ? 0U : table->count;
}

/**
 * @brief Adds a route if its destination is valid and unique.
 * @param table The table to modify.
 * @param route The route to copy into the table.
 * @return true on success; false for invalid, duplicate, or unallocatable input.
 */
bool table_add(fwd_table_t *table, const route_t *route)
{
  route_t *expanded;
  size_t new_capacity;

  if (table == NULL || route == NULL || route->dest.prefix > 32U ||
      !cidr_is_network(route->dest)) {
    return false;
  }
  for (size_t i = 0; i < table->count; i++) {
    if (table->routes[i].dest.addr == route->dest.addr &&
        table->routes[i].dest.prefix == route->dest.prefix) {
      return false;
    }
  }
  if (table->count == table->capacity) {
    new_capacity = table->capacity == 0U ? 4U : table->capacity * 2U;
    expanded = realloc(table->routes, new_capacity * sizeof(*expanded));
    if (expanded == NULL) {
      return false;
    }
    table->routes = expanded;
    table->capacity = new_capacity;
  }
  table->routes[table->count++] = *route;
  return true;
}

/**
 * @brief Loads routes from a forwarding-table file.
 * @param table The table to modify.
 * @param in An open route file.
 * @param bad_line Receives the first invalid line number, or zero for invalid
 *                 arguments or a file-read error.
 * @return true if every non-comment line was loaded; otherwise false.
 */
bool table_load(fwd_table_t *table, FILE *in, size_t *bad_line)
{
  char *line = NULL;
  size_t line_capacity = 0U;
  size_t line_number = 0U;
  bool success = true;

  if (bad_line != NULL) {
    *bad_line = 0U;
  }
  if (table == NULL || in == NULL) {
    return false;
  }

  while (getline(&line, &line_capacity, in) >= 0) {
    route_t route;
    char *comment = strchr(line, '#');
    line_number++;
    if (comment != NULL) {
      *comment = '\0';
    }
    if (line[strspn(line, " \t\r\n")] == '\0') {
      continue;
    }
    if (!route_parse(line, &route) || !table_add(table, &route)) {
      if (bad_line != NULL) {
        *bad_line = line_number;
      }
      success = false;
      break;
    }
  }
  if (success && ferror(in) && bad_line != NULL) {
    *bad_line = 0U;
  }
  free(line);
  return success && !ferror(in);
}

/**
 * @brief Finds the most specific route containing an address.
 * @param table The table to search.
 * @param dest Destination address in host byte order.
 * @return A table-owned longest-prefix match, or NULL if none exists.
 */
const route_t *table_lookup(const fwd_table_t *table, uint32_t dest)
{
  const route_t *best = NULL;

  if (table == NULL) {
    return NULL;
  }
  for (size_t i = 0; i < table->count; i++) {
    const route_t *candidate = &table->routes[i];
    if (cidr_contains(candidate->dest, dest) &&
        (best == NULL || candidate->dest.prefix > best->dest.prefix)) {
      best = candidate;
    }
  }
  return best;
}
