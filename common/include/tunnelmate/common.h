#ifndef TM_COMMON_H
#define TM_COMMON_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define TM_PROTO_VERSION      1
#define TM_PROTO_STRING       "TunnelMate/1"
#define TM_PROTO_STRING_LEN   11

#define TM_MAX_FRAME_PAYLOAD  (256u * 1024u)
#define TM_MAX_TUNNEL_ID      128
#define TM_MAX_SECRET         256
#define TM_MAX_ERRSTR         256
#define TM_MAX_AGENT_NAME     64
#define TM_MAX_DATAGRAM       65507
#define TM_DEFAULT_DATAGRAM   1400
#define TM_MAX_ENVELOPE_HDR   16

#define TM_PORT_START_DEFAULT 20000
#define TM_PORT_END_DEFAULT   40000

typedef enum {
    TM_MSG_HELLO = 1,
    TM_MSG_HELLO_ACK,
    TM_MSG_REGISTER,
    TM_MSG_REGISTER_OK,
    TM_MSG_REGISTER_ERROR,
    TM_MSG_PING,
    TM_MSG_PONG,
    TM_MSG_OPEN_STREAM,
    TM_MSG_OPEN_STREAM_ACK,
    TM_MSG_OPEN_STREAM_ERROR,
    TM_MSG_DATA_BIND,
    TM_MSG_DATA_BIND_OK,
    TM_MSG_DATA_BIND_ERROR,
    TM_MSG_CLOSE_STREAM,
    TM_MSG_GOING_AWAY,
    TM_MSG_ERROR,
    TM_MSG_KILL_STREAM,
    TM_MSG_REGISTER_ACK = 18,
    TM_MSG_AUTH = 19,
    TM_MSG_AUTH_OK = 20,
    TM_MSG_AUTH_ERROR = 21,
    TM_MSG_MAX
} tm_msg_type;

#define TM_ENV_FLAG_DIR_P2S    0x01u
#define TM_ENV_FLAG_AUTH_REQ   0x02u
#define TM_ENV_FLAG_AUTH_OK    0x04u
#define TM_ENV_FLAG_AUTH_ERR   0x08u
#define TM_ENV_FLAG_ALL        (TM_ENV_FLAG_DIR_P2S | TM_ENV_FLAG_AUTH_REQ | \
                                TM_ENV_FLAG_AUTH_OK | TM_ENV_FLAG_AUTH_ERR)

/* IP protocol selector shared by C and control plane */
typedef enum {
    TM_PROTO_TCP = 0,
    TM_PROTO_UDP = 1
} tm_proto;

typedef enum {
    TM_OK = 0,
    TM_ERR = -1,
    TM_ERR_AGAIN = -2,
    TM_ERR_EOF = -3,
    TM_ERR_PROTO = -4,
    TM_ERR_TLS = -5,
    TM_ERR_OOM = -6,
    TM_ERR_BUSY = -7,
    TM_ERR_NOTFOUND = -8,
    TM_ERR_FULL = -9,
    TM_ERR_INVALID = -10,
    TM_ERR_IO = -11
} tm_status;

/* Wire frame. payload is malloc'd, owned by the frame. */
typedef struct {
    uint8_t version;
    uint8_t type;
    uint32_t stream_id;
    uint32_t payload_len;
    uint8_t *payload;
} tm_frame;

static inline uint16_t rd_u16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}
static inline uint32_t rd_u32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}
static inline uint64_t rd_u64(const uint8_t *p) {
    return ((uint64_t)rd_u32(p) << 32) | rd_u32(p + 4);
}
static inline void wr_u16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v;
}
static inline void wr_u32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
}
static inline void wr_u64(uint8_t *p, uint64_t v) {
    wr_u32(p, (uint32_t)(v >> 32)); wr_u32(p + 4, (uint32_t)v);
}

/* UTF-8: returns true if s is well-formed UTF-8, len bytes. */
bool tm_utf8_valid(const uint8_t *s, size_t len);

/* Constant-time compare; returns true if equal. */
bool tm_ct_eq(const uint8_t *a, const uint8_t *b, size_t len);

/* Allocate zeroed memory or die (broker/agent are fail-fast on OOM). */
void *tm_xcalloc(size_t n, size_t sz);
void *tm_xmalloc(size_t sz);
char *tm_xstrdup(const char *s);
void *tm_xrealloc(void *p, size_t sz);

/* Time helpers (monotonic ms). */
uint64_t tm_now_ms(void);

#endif