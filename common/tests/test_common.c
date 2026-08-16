#include "tunnelmate/frame.h"
#include "tunnelmate/config.h"
#include "tunnelmate/crypto.h"
#include "tunnelmate/net.h"
#include <assert.h>
#include <stdio.h>

static int failures = 0;
#define CHECK(cond) do { \
    if (!(cond)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); failures++; } \
} while (0)

static void test_frame_roundtrip(void) {
    tm_frame f = { .version = TM_PROTO_VERSION, .type = TM_MSG_REGISTER,
                   .stream_id = 42, .payload_len = 0, .payload = NULL };
    size_t len;
    uint8_t *buf = tm_frame_encode(&f, &len);
    CHECK(buf && len == TM_FRAME_HDR_LEN);
    tm_frame_reader *r = tm_frame_reader_new();
    bool err = false;
    tm_frame *out = tm_frame_reader_feed(r, buf, len, &err);
    CHECK(out && !err);
    CHECK(out->type == TM_MSG_REGISTER && out->stream_id == 42);
    tm_frame_free(out);
    free(buf);
    tm_frame_reader_free(r);
}

static void test_frame_payload(void) {
    uint8_t payload[] = "hello tunnel";
    tm_frame *f = tm_frame_make(TM_MSG_ERROR, 7, payload, sizeof(payload) - 1);
    size_t len;
    uint8_t *buf = tm_frame_encode(f, &len);
    tm_frame_reader *r = tm_frame_reader_new();
    bool err = false;
    /* feed byte by byte to exercise incremental parsing */
    tm_frame *out = NULL;
    for (size_t i = 0; i < len; i++) {
        out = tm_frame_reader_feed(r, buf + i, 1, &err);
        if (out) break;
    }
    CHECK(out && !err);
    CHECK(out->payload_len == sizeof(payload) - 1);
    CHECK(memcmp(out->payload, payload, sizeof(payload) - 1) == 0);
    tm_frame_free(out);
    tm_frame_free(f);
    free(buf);
    tm_frame_reader_free(r);
}

static void test_frame_oversize_rejected(void) {
    uint8_t hdr[TM_FRAME_HDR_LEN];
    hdr[0] = TM_PROTO_VERSION;
    hdr[1] = TM_MSG_PING;
    wr_u32(hdr + 2, TM_MAX_FRAME_PAYLOAD + 1); /* oversized */
    wr_u32(hdr + 6, 0);
    tm_frame_reader *r = tm_frame_reader_new();
    bool err = false;
    tm_frame *out = tm_frame_reader_feed(r, hdr, sizeof(hdr), &err);
    CHECK(out == NULL && err); /* rejected before allocation */
    tm_frame_reader_free(r);
}

static void test_frame_bad_version(void) {
    uint8_t hdr[TM_FRAME_HDR_LEN] = {0};
    hdr[1] = TM_MSG_PING;
    tm_frame_reader *r = tm_frame_reader_new();
    bool err = false;
    tm_frame *out = tm_frame_reader_feed(r, hdr, sizeof(hdr), &err);
    CHECK(out == NULL && err);
    tm_frame_reader_free(r);
}

static void test_frame_truncated(void) {
    uint8_t hdr[TM_FRAME_HDR_LEN];
    hdr[0] = TM_PROTO_VERSION;
    hdr[1] = TM_MSG_ERROR;
    wr_u32(hdr + 2, 10);
    wr_u32(hdr + 6, 0);
    tm_frame_reader *r = tm_frame_reader_new();
    bool err = false;
    tm_frame *out = tm_frame_reader_feed(r, hdr, sizeof(hdr), &err);
    CHECK(out == NULL && !err); /* waiting for payload */
    tm_frame_reader_free(r);
}

static void test_env_roundtrip(void) {
    uint8_t payload[] = {1, 2, 3, 4, 5};
    size_t len;
    uint8_t *buf = tm_env_encode(0xdeadbeef, TM_ENV_FLAG_DIR_P2S, payload, 5, &len);
    CHECK(len == 16);
    uint64_t flow;
    uint8_t flags;
    const uint8_t *pl;
    uint32_t plen;
    CHECK(tm_env_decode(buf, len, &flow, &flags, &pl, &plen) == TM_OK);
    CHECK(flow == 0xdeadbeef && flags == TM_ENV_FLAG_DIR_P2S && plen == 5);
    CHECK(memcmp(pl, payload, 5) == 0);
    /* malformed: bad header len */
    uint8_t bad[16];
    memcpy(bad, buf, 16);
    free(buf);
    wr_u16(bad, 99);
    CHECK(tm_env_decode(bad, 16, &flow, &flags, &pl, &plen) != TM_OK);
    /* truncated */
    CHECK(tm_env_decode(bad, 5, &flow, &flags, &pl, &plen) != TM_OK);
}

static void test_config(void) {
    tm_config *c = tm_config_new();
    char err[256];
    const char *text =
        "listen_host = \"0.0.0.0\"\n"
        "control_port = 7000\n"
        "public_port_start = 20000\n"
        "public_port_end = 40000\n"
        "tls_verify = false\n"
        "ratio = 1.5\n"
        "# comment\n"
        "[limits]\n"
        "max_tunnels = 100\n"
        "max_streams = 500\n";
    CHECK(tm_config_parse(c, text, err, sizeof(err)) == TM_OK);
    const char *h;
    tm_config_get_str(c, "listen_host", "?", &h);
    CHECK(strcmp(h, "0.0.0.0") == 0);
    long long v;
    tm_config_get_int(c, "control_port", 0, &v);
    CHECK(v == 7000);
    tm_config_get_int(c, "limits.max_tunnels", 0, &v);
    CHECK(v == 100);
    bool b;
    tm_config_get_bool(c, "tls_verify", true, &b);
    CHECK(b == false);
    double d;
    tm_config_get_double(c, "ratio", 0, &d);
    CHECK(d > 1.49 && d < 1.51);
    /* unknown key -> default */
    tm_config_get_int(c, "nope", 42, &v);
    CHECK(v == 42);
    tm_config_free(c);
    /* malformed line */
    c = tm_config_new();
    CHECK(tm_config_parse(c, "bad line no equals\n", err, sizeof(err)) != TM_OK);
    tm_config_free(c);
}

static void test_crypto(void) {
    char a[33], b[33];
    tm_rand_token(a, 32);
    tm_rand_token(b, 32);
    CHECK(strlen(a) == 32 && strlen(b) == 32);
    CHECK(strcmp(a, b) != 0); /* astronomically unlikely to collide */
    for (int i = 0; i < 32; i++) {
        CHECK(a[i] >= 'a' && a[i] <= 'z' || a[i] >= 'A' && a[i] <= 'Z' || a[i] >= '0' && a[i] <= '9');
    }
    uint8_t k[16] = {0}, msg[8] = {0};
    uint8_t d1[32], d2[32];
    tm_hmac_sha256(k, 16, msg, 8, d1);
    tm_hmac_sha256(k, 16, msg, 8, d2);
    CHECK(memcmp(d1, d2, 32) == 0);
    char hex1[65], hex2[65];
    tm_sha256_hex(msg, 8, hex1);
    tm_sha256_hex(msg, 8, hex2);
    CHECK(tm_ct_eq_hex(hex1, hex2));
    hex2[10] = 'f';
    CHECK(!tm_ct_eq_hex(hex1, hex2));
    CHECK(!tm_ct_eq_hex(hex1, "short"));
}

static void test_net(void) {
    struct sockaddr_storage sa;
    CHECK(tm_addr_parse("127.0.0.1", 7000, &sa) == TM_OK);
    CHECK(sa.ss_family == AF_INET);
    CHECK(tm_addr_parse("::1", 7000, &sa) == TM_OK);
    CHECK(sa.ss_family == AF_INET6);
    CHECK(tm_addr_parse("localhost", 7000, &sa) == TM_OK);
    CHECK(tm_addr_parse("not a host!!!", 7000, &sa) != TM_OK);
    const char *s = tm_addr_str((struct sockaddr *)&sa);
    CHECK(s && s[0]);
}

static void test_utf8(void) {
    CHECK(tm_utf8_valid((const uint8_t *)"ascii", 5));
    CHECK(tm_utf8_valid((const uint8_t *)"h\xc3\xa9llo", 6)); /* é */
    CHECK(!tm_utf8_valid((const uint8_t *)"h\xc3llo", 5));    /* truncated */
    CHECK(!tm_utf8_valid((const uint8_t *)"\xff\xfe", 2));
    CHECK(!tm_utf8_valid((const uint8_t *)"\xed\xa0\x80", 3)); /* surrogate */
    CHECK(!tm_utf8_valid((const uint8_t *)"\xf4\x90\x80\x80", 4)); /* > U+10FFFF */
}

int main(void) {
    test_frame_roundtrip();
    test_frame_payload();
    test_frame_oversize_rejected();
    test_frame_bad_version();
    test_frame_truncated();
    test_env_roundtrip();
    test_config();
    test_crypto();
    test_net();
    test_utf8();
    if (failures) {
        fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    printf("all common tests passed\n");
    return 0;
}