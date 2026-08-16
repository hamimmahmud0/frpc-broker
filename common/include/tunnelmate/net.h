#ifndef TM_NET_H
#define TM_NET_H

#include "tunnelmate/common.h"
#include <uv.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* Parse "host:port" into a sockaddr. host may be IPv4, IPv6 (bracketed) or
   hostname. Returns TM_OK. */
tm_status tm_addr_parse(const char *host, uint16_t port,
                        struct sockaddr_storage *out);

/* Format sockaddr into "host:port" (IPv6 bracketed). Returns buffer (static,
   per-call; not thread-safe by design). */
const char *tm_addr_str(const struct sockaddr *sa);

/* Best-effort sockaddr comparison. */
bool tm_addr_eq(const struct sockaddr *a, const struct sockaddr *b);

#endif