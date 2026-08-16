#include "tunnelmate/net.h"
#include "tunnelmate/common.h"
#include <netdb.h>
#include <stdio.h>

tm_status tm_addr_parse(const char *host, uint16_t port,
                        struct sockaddr_storage *out) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    char portstr[8];
    snprintf(portstr, sizeof(portstr), "%u", (unsigned)port);
    struct addrinfo *res = NULL;
    if (getaddrinfo(host, portstr, &hints, &res) != 0 || !res) return TM_ERR_INVALID;
    /* prefer IPv4 when both available? No: honor order; take first */
    memset(out, 0, sizeof(*out));
    memcpy(out, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);
    return TM_OK;
}

const char *tm_addr_str(const struct sockaddr *sa) {
    static __thread char buf[2][128];
    static __thread int idx = 0;
    idx ^= 1;
    char host[64] = {0};
    char port[8] = {0};
    if (!sa) return "unknown";
    int r = getnameinfo(sa, (socklen_t)(sa->sa_family == AF_INET ? sizeof(struct sockaddr_in)
                                                                 : sizeof(struct sockaddr_in6)),
                        host, sizeof(host), port, sizeof(port),
                        NI_NUMERICHOST | NI_NUMERICSERV);
    if (r != 0) return "unknown";
    if (strchr(host, ':'))
        snprintf(buf[idx], sizeof(buf[idx]), "[%s]:%s", host, port);
    else
        snprintf(buf[idx], sizeof(buf[idx]), "%s:%s", host, port);
    return buf[idx];
}

bool tm_addr_eq(const struct sockaddr *a, const struct sockaddr *b) {
    if (!a || !b || a->sa_family != b->sa_family) return false;
    if (a->sa_family == AF_INET) {
        const struct sockaddr_in *x = (const struct sockaddr_in *)a;
        const struct sockaddr_in *y = (const struct sockaddr_in *)b;
        return x->sin_port == y->sin_port && x->sin_addr.s_addr == y->sin_addr.s_addr;
    }
    if (a->sa_family == AF_INET6) {
        const struct sockaddr_in6 *x = (const struct sockaddr_in6 *)a;
        const struct sockaddr_in6 *y = (const struct sockaddr_in6 *)b;
        return x->sin6_port == y->sin6_port &&
               memcmp(&x->sin6_addr, &y->sin6_addr, sizeof(x->sin6_addr)) == 0;
    }
    return false;
}