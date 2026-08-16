#include "tunnelmate/frame.h"

struct tm_frame_reader {
    uint8_t *buf;
    size_t len;
    size_t cap;
};

tm_frame_reader *tm_frame_reader_new(void) {
    return tm_xcalloc(1, sizeof(tm_frame_reader));
}

void tm_frame_reader_free(tm_frame_reader *r) {
    if (!r) return;
    free(r->buf);
    free(r);
}

size_t tm_frame_reader_buffered(const tm_frame_reader *r) {
    return r ? r->len : 0;
}

uint8_t *tm_frame_reader_drain(tm_frame_reader *r, size_t *out_len) {
    size_t n = tm_frame_reader_buffered(r);
    if (n == 0) { *out_len = 0; return NULL; }
    uint8_t *buf = tm_xmalloc(n);
    memcpy(buf, r->buf, n);
    r->len = 0;
    *out_len = n;
    return buf;
}

tm_frame *tm_frame_reader_feed(tm_frame_reader *r, const uint8_t *data,
                               size_t len, bool *errored) {
    *errored = false;
    if (len) {
        if (!data || len > SIZE_MAX - r->len ||
            r->len + len > (size_t)TM_MAX_FRAME_PAYLOAD + TM_FRAME_HDR_LEN) {
            *errored = true;
            return NULL;
        }
        if (r->len + len > r->cap) {
            size_t ncap = r->cap ? r->cap : 1024;
            while (ncap < r->len + len) ncap *= 2;
            r->buf = tm_xrealloc(r->buf, ncap);
            r->cap = ncap;
        }
        memcpy(r->buf + r->len, data, len);
        r->len += len;
    }
    if (r->len < TM_FRAME_HDR_LEN) return NULL;
    if (r->buf[0] != TM_PROTO_VERSION) { *errored = true; return NULL; }
    uint32_t pay_len = rd_u32(r->buf + 2);
    if (pay_len > TM_MAX_FRAME_PAYLOAD) { *errored = true; return NULL; }
    size_t frame_len = TM_FRAME_HDR_LEN + (size_t)pay_len;
    if (r->len < frame_len) return NULL;

    tm_frame *f = tm_frame_make(r->buf[1], rd_u32(r->buf + 6),
                                r->buf + TM_FRAME_HDR_LEN, pay_len);
    size_t remain = r->len - frame_len;
    if (remain) memmove(r->buf, r->buf + frame_len, remain);
    r->len = remain;
    return f;
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
