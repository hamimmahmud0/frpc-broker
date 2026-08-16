#include "tunnelmate/frame.h"

#define FRAME_STATE_HDR 0
#define FRAME_STATE_PAY 1

struct tm_frame_reader {
    int state;
    uint8_t hdr[TM_FRAME_HDR_LEN];
    size_t hdr_fill;
    uint8_t *pay;
    size_t pay_fill;
    uint32_t pay_len;
};

tm_frame_reader *tm_frame_reader_new(void) {
    return tm_xcalloc(1, sizeof(tm_frame_reader));
}

void tm_frame_reader_free(tm_frame_reader *r) {
    if (!r) return;
    free(r->pay);
    free(r);
}

size_t tm_frame_reader_buffered(const tm_frame_reader *r) {
    if (r->state == FRAME_STATE_HDR) return r->hdr_fill;
    return TM_FRAME_HDR_LEN + r->pay_fill;
}

uint8_t *tm_frame_reader_drain(tm_frame_reader *r, size_t *out_len) {
    size_t n = tm_frame_reader_buffered(r);
    if (n == 0) { *out_len = 0; return NULL; }
    uint8_t *buf = tm_xmalloc(n);
    size_t off = 0;
    if (r->hdr_fill) { memcpy(buf + off, r->hdr, r->hdr_fill); off += r->hdr_fill; }
    if (r->state == FRAME_STATE_PAY && r->pay_fill) {
        memcpy(buf + off, r->pay, r->pay_fill);
        off += r->pay_fill;
    }
    free(r->pay);
    r->pay = NULL;
    r->state = FRAME_STATE_HDR;
    r->hdr_fill = 0;
    r->pay_fill = 0;
    r->pay_len = 0;
    *out_len = off;
    return buf;
}

tm_frame *tm_frame_reader_feed(tm_frame_reader *r, const uint8_t *data,
                               size_t len, bool *errored) {
    *errored = false;
    size_t i = 0;
    while (i < len) {
        if (r->state == FRAME_STATE_HDR) {
            size_t want = TM_FRAME_HDR_LEN - r->hdr_fill;
            size_t take = len - i < want ? len - i : want;
            memcpy(r->hdr + r->hdr_fill, data + i, take);
            r->hdr_fill += take;
            i += take;
            if (r->hdr_fill < TM_FRAME_HDR_LEN) return NULL;
            if (r->hdr[0] != TM_PROTO_VERSION) { *errored = true; return NULL; }
            r->pay_len = rd_u32(r->hdr + 2);
            if (r->pay_len > TM_MAX_FRAME_PAYLOAD) { *errored = true; return NULL; }
            r->state = FRAME_STATE_PAY;
            if (r->pay_len == 0) {
                tm_frame *f = tm_frame_make(r->hdr[1], rd_u32(r->hdr + 6), NULL, 0);
                r->state = FRAME_STATE_HDR;
                r->hdr_fill = 0;
                return f;
            }
            r->pay = tm_xmalloc(r->pay_len);
            r->pay_fill = 0;
        }
        if (r->state == FRAME_STATE_PAY) {
            size_t want = r->pay_len - r->pay_fill;
            size_t take = len - i < want ? len - i : want;
            memcpy(r->pay + r->pay_fill, data + i, take);
            r->pay_fill += take;
            i += take;
            if (r->pay_fill == r->pay_len) {
                tm_frame *f = tm_frame_make(r->hdr[1], rd_u32(r->hdr + 6),
                                            r->pay, r->pay_len);
                r->pay = NULL;
                r->state = FRAME_STATE_HDR;
                r->hdr_fill = 0;
                return f;
            }
        }
    }
    return NULL;
}

void tm_frame_free(tm_frame *f) {
    if (!f) return;
    free(f->payload);
    free(f);
}

uint8_t *tm_frame_encode(const tm_frame *f, size_t *out_len) {
    if (f->payload_len > TM_MAX_FRAME_PAYLOAD) return NULL;
    size_t len = TM_FRAME_HDR_LEN + f->payload_len;
    uint8_t *buf = tm_xmalloc(len);
    buf[0] = TM_PROTO_VERSION;
    buf[1] = f->type;
    wr_u32(buf + 2, f->payload_len);
    wr_u32(buf + 6, f->stream_id);
    if (f->payload_len) memcpy(buf + TM_FRAME_HDR_LEN, f->payload, f->payload_len);
    *out_len = len;
    return buf;
}

tm_frame *tm_frame_make(uint8_t type, uint32_t stream_id,
                        const uint8_t *payload, uint32_t payload_len) {
    if (payload_len > TM_MAX_FRAME_PAYLOAD) return NULL;
    tm_frame *f = tm_xcalloc(1, sizeof(*f));
    f->version = TM_PROTO_VERSION;
    f->type = type;
    f->stream_id = stream_id;
    f->payload_len = payload_len;
    if (payload_len) {
        f->payload = tm_xmalloc(payload_len);
        memcpy(f->payload, payload, payload_len);
    }
    return f;
}

uint8_t *tm_env_encode(uint64_t flow_id, uint8_t flags,
                       const uint8_t *payload, uint32_t payload_len,
                       size_t *out_len) {
    size_t len = 11u + payload_len;
    uint8_t *buf = tm_xmalloc(len);
    wr_u16(buf, 11u);
    wr_u64(buf + 2, flow_id);
    buf[10] = flags;
    if (payload_len) memcpy(buf + 11, payload, payload_len);
    *out_len = len;
    return buf;
}

tm_status tm_env_decode(const uint8_t *buf, size_t len, uint64_t *flow_id,
                        uint8_t *flags, const uint8_t **payload,
                        uint32_t *payload_len) {
    if (len < 11u) return TM_ERR_PROTO;
    uint16_t hdr = rd_u16(buf);
    if (hdr != 11u) return TM_ERR_PROTO;
    uint8_t fl = buf[10];
    if (fl & ~TM_ENV_FLAG_ALL) return TM_ERR_PROTO;
    *flow_id = rd_u64(buf + 2);
    *flags = fl;
    *payload = buf + 11;
    *payload_len = (uint32_t)(len - 11u);
    return TM_OK;
}