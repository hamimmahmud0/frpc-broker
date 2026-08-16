#include "broker.h"

/* The relay pairs a consumer-side socket (raw public TCP, or a closed
   peer's TLS connection) with the agent's TLS data connection and moves
   bytes with bounded queues and explicit pause/resume backpressure.
   Half-close is honored in both directions. */

void tm_broker_tls_free_handle_cb(uv_handle_t *h) { free(h); }

tm_stream *tm_stream_find(tm_broker *b, tm_tunnel *tun, uint32_t id) {
    (void)b;
    for (tm_stream *st = tun->streams; st; st = st->next) {
        if (st->id == id) return st;
    }
    return NULL;
}

static void stream_unlink(tm_stream *st) {
    tm_stream **pp = &st->tun->streams;
    while (*pp) {
        if (*pp == st) { *pp = st->next; break; }
        pp = &(*pp)->next;
    }
    if (st->tun->streams_active > 0) st->tun->streams_active--;
    st->tun->b->stream_count--;
}

/* fully close both legs and free */
void tm_stream_close(tm_broker *b, tm_stream *st) {
    if (st->closing) return;
    st->closing = true;
    uv_timer_stop(&st->bind_timer);
    if (st->io_a) { tm_io_close(st->io_a); st->io_a = NULL; }
    if (st->io_b) { tm_io_close(st->io_b); st->io_b = NULL; }
    if (st->sock_a && !uv_is_closing(st->sock_a))
        uv_close(st->sock_a, tm_broker_tls_free_handle_cb);
    if (st->sock_b && !uv_is_closing(st->sock_b))
        uv_close(st->sock_b, tm_broker_tls_free_handle_cb);
    if (!uv_is_closing((uv_handle_t *)&st->bind_timer))
        uv_close((uv_handle_t *)&st->bind_timer, NULL);
    stream_unlink(st);
    b->stream_errors++;
    tm_log_debug(b->log, "stream_closed",
                 "sid=%u up=%llu down=%llu a_eof=%d b_eof=%d",
                 st->id, (unsigned long long)st->up_bytes,
                 (unsigned long long)st->down_bytes, st->a_eof, st->b_eof);
    free(st->preq);
    free(st->pend_a);
    free(st->pend_b);
    free(st);
}

/* close only once both sides have EOF'd AND every queued byte has been
   handed to the sockets; dropping a leg with unsent data loses the tail */
static void stream_maybe_close(tm_stream *st) {
    if (st->closing || !st->a_eof || !st->b_eof) return;
    if (st->io_a && !tm_io_drained(st->io_a)) return;
    if (st->io_b && !tm_io_drained(st->io_b)) return;
    if (st->pend_a_len || st->pend_b_len || st->preq_len) return;
    tm_stream_close(st->tun->b, st);
}

static void flush_pend(tm_io *io, uint8_t **buf, size_t *len, size_t *cap);

/* ---------------------- consumer-side (leg A) callbacks ------------- */

static void relay_a_read(tm_io *io, const uint8_t *data, size_t len, void *arg) {
    tm_stream *st = (tm_stream *)arg;
    (void)io;
    if (st->closing) return;
    st->tun->rx_bytes += len;
    st->tun->b->rx_bytes_total += len;
    st->up_bytes += len;
    if (!st->io_b) {
        /* closed-tunnel stream: agent leg not bound yet. Queue the bytes;
           relay_start flushes them once the agent attaches. */
        if (st->preq_len + len > TM_IO_HIGH_WATER) {
            tm_io_pause_read(st->io_a);
            st->a_paused = true;
            return;
        }
        if (st->preq_len + len > st->preq_cap) {
            size_t ncap = st->preq_cap ? st->preq_cap * 2 : 16384;
            while (ncap < st->preq_len + len) ncap *= 2;
            st->preq = tm_xrealloc(st->preq, ncap);
            st->preq_cap = ncap;
        }
        memcpy(st->preq + st->preq_len, data, len);
        st->preq_len += len;
        return;
    }
    fprintf(stderr, "DBG a_read +%zu up=%llu\n", len, (unsigned long long)st->up_bytes);
    int r = tm_io_write(st->io_b, data, len);
    if (r == TM_ERR_BUSY) {
        fprintf(stderr, "DBG a_read BUSY pend_b=%zu\n", st->pend_b_len);
        if (st->pend_b_len + len > st->pend_b_cap) {
            size_t ncap = st->pend_b_cap ? st->pend_b_cap * 2 : 16384;
            while (ncap < st->pend_b_len + len) ncap *= 2;
            st->pend_b = tm_xrealloc(st->pend_b, ncap);
            st->pend_b_cap = ncap;
        }
        memcpy(st->pend_b + st->pend_b_len, data, len);
        st->pend_b_len += len;
        tm_io_pause_read(st->io_a);
        st->a_paused = true;
    } else if (r != TM_OK) {
        tm_stream_close(st->tun->b, st);
    }
}

static void relay_a_eof(tm_io *io, void *arg) {
    tm_stream *st = (tm_stream *)arg;
    (void)io;
    if (st->closing) return;
    st->a_eof = true;
    if (!st->io_b) { stream_maybe_close(st); return; }
    flush_pend(st->io_b, &st->pend_b, &st->pend_b_len, &st->pend_b_cap);
    if (st->pend_b_len) { stream_maybe_close(st); return; }
    st->a_fin = true;
    tm_io_shutdown_send(st->io_b);
    stream_maybe_close(st);
}

static void relay_a_error(tm_io *io, int err, void *arg) {
    tm_stream *st = (tm_stream *)arg;
    (void)io;
    (void)err;
    if (st->closing) return;
    /* the consumer leg is dead: close it now, keep relaying what the
       agent leg still has queued, then close once it drains */
    if (st->io_a) { tm_io_close(st->io_a); st->io_a = NULL; }
    st->a_eof = true;
    if (!st->io_b) { stream_maybe_close(st); return; }
    flush_pend(st->io_b, &st->pend_b, &st->pend_b_len, &st->pend_b_cap);
    if (st->pend_b_len) { stream_maybe_close(st); return; }
    st->a_fin = true;
    tm_io_shutdown_send(st->io_b);
    stream_maybe_close(st);
}

/* feed pend into io in pieces so progress is made even when a piece
   exceeds the io's high-water mark; BUSY leaves the rest for the next
   low callback (the partial write keeps the FIN from firing early) */
static void flush_pend(tm_io *io, uint8_t **buf, size_t *len, size_t *cap) {
    while (*len) {
        size_t n = *len < 65536 ? *len : 65536;
        int r = tm_io_write(io, *buf, n);
        if (r == TM_ERR_BUSY) return;
        if (r != TM_OK) {
            free(*buf);
            *buf = NULL;
            *len = *cap = 0;
            return;
        }
        memmove(*buf, *buf + n, *len - n);
        *len -= n;
        if (!*len) { free(*buf); *buf = NULL; *cap = 0; }
    }
}

static void relay_a_low(tm_io *io, void *arg) {
    /* io_a's write side drained: push queued leg-B data to the client */
    tm_stream *st = (tm_stream *)arg;
    (void)io;
    if (st->closing) return;
    fprintf(stderr, "DBG a_low fired pend_a=%zu b_paused=%d\n", st->pend_a_len, st->b_paused);
    flush_pend(st->io_a, &st->pend_a, &st->pend_a_len, &st->pend_a_cap);
    if (st->pend_a_len) { stream_maybe_close(st); return; }
    if (st->b_eof && !st->b_fin) { st->b_fin = true; tm_io_shutdown_send(st->io_a); }
    if (st->b_paused) {
        st->b_paused = false;
        tm_io_resume_read(st->io_b);
    }
    stream_maybe_close(st);
}

/* ---------------------- agent-side (leg B) callbacks ---------------- */

static void relay_b_read(tm_io *io, const uint8_t *data, size_t len, void *arg) {
    tm_stream *st = (tm_stream *)arg;
    (void)io;
    if (st->closing) return;
    st->tun->tx_bytes += len;
    st->tun->b->tx_bytes_total += len;
    st->down_bytes += len;
    fprintf(stderr, "DBG b_read +%zu down=%llu\n", len, (unsigned long long)st->down_bytes);
    int r = tm_io_write(st->io_a, data, len);
    if (r == TM_ERR_BUSY) {
        fprintf(stderr, "DBG b_read BUSY pend_a=%zu\n", st->pend_a_len);
        if (st->pend_a_len + len > st->pend_a_cap) {
            size_t ncap = st->pend_a_cap ? st->pend_a_cap * 2 : 16384;
            while (ncap < st->pend_a_len + len) ncap *= 2;
            st->pend_a = tm_xrealloc(st->pend_a, ncap);
            st->pend_a_cap = ncap;
        }
        memcpy(st->pend_a + st->pend_a_len, data, len);
        st->pend_a_len += len;
        tm_io_pause_read(st->io_b);
        st->b_paused = true;
    } else if (r != TM_OK) {
        tm_stream_close(st->tun->b, st);
    }
}

static void relay_b_eof(tm_io *io, void *arg) {
    tm_stream *st = (tm_stream *)arg;
    (void)io;
    if (st->closing) return;
    st->b_eof = true;
    if (!st->io_a) { stream_maybe_close(st); return; }
    flush_pend(st->io_a, &st->pend_a, &st->pend_a_len, &st->pend_a_cap);
    if (st->pend_a_len) { stream_maybe_close(st); return; }
    st->b_fin = true;
    tm_io_shutdown_send(st->io_a);
    stream_maybe_close(st);
}

static void relay_b_error(tm_io *io, int err, void *arg) {
    tm_stream *st = (tm_stream *)arg;
    (void)io;
    (void)err;
    if (st->closing) return;
    /* the agent leg is dead: close it now, keep relaying what the
       consumer leg still has queued, then close once it drains */
    if (st->io_b) { tm_io_close(st->io_b); st->io_b = NULL; }
    st->b_eof = true;
    if (!st->io_a) { stream_maybe_close(st); return; }
    flush_pend(st->io_a, &st->pend_a, &st->pend_a_len, &st->pend_a_cap);
    if (st->pend_a_len) { stream_maybe_close(st); return; }
    st->b_fin = true;
    tm_io_shutdown_send(st->io_a);
    stream_maybe_close(st);
}

static void relay_b_low(tm_io *io, void *arg) {
    /* io_b's write side drained: push queued leg-A data to the agent */
    tm_stream *st = (tm_stream *)arg;
    (void)io;
    if (st->closing) return;
    fprintf(stderr, "DBG b_low fired pend_b=%zu a_paused=%d\n", st->pend_b_len, st->a_paused);
    flush_pend(st->io_b, &st->pend_b, &st->pend_b_len, &st->pend_b_cap);
    if (st->pend_b_len) { stream_maybe_close(st); return; }
    if (st->a_eof && !st->a_fin) { st->a_fin = true; tm_io_shutdown_send(st->io_b); }
    if (st->a_paused) {
        st->a_paused = false;
        tm_io_resume_read(st->io_a);
    }
    stream_maybe_close(st);
}

/* Deliver bytes that arrived in the same chunk as the role-deciding frame
   (they were consumed by the frame reader, not the io). */
void tm_stream_ingest(tm_stream *st, const uint8_t *data, size_t len) {
    if (st->closing || len == 0) return;
    relay_b_read(st->io_b, data, len, st);
}

/* Deliver bytes that arrived in the same chunk as the peer's DATA_BIND(0)
   frame; leg A plaintext, queued until the agent leg attaches. */
void tm_stream_ingest_a(tm_stream *st, const uint8_t *data, size_t len) {
    if (st->closing || len == 0) return;
    relay_a_read(st->io_a, data, len, st);
}

/* ---------------------- lifecycle ----------------------------------- */

static void stream_bind_timer_cb(uv_timer_t *t) {
    tm_stream *st = (tm_stream *)t->data;
    if (!st || st->bound) return;
    tm_broker *b = st->tun->b;
    tm_log_warn(b->log, "bind_timeout",
                "stream_id", NULL, "%u tunnel=%s", st->id, st->tun->id);
    tm_stream_close(b, st);
}

/* begin relaying: create the raw consumer io if missing, start both legs */
void tm_stream_relay_start(tm_broker *b, tm_stream *st) {
    if (st->bound) return;
    st->bound = true;
    uv_timer_stop(&st->bind_timer);
    if (!st->io_a) {
        st->io_a = tm_io_tcp_new(b->loop, (uv_tcp_t *)st->sock_a, &(tm_io_cbs){
            .read_cb = relay_a_read,
            .eof_cb = relay_a_eof,
            .error_cb = relay_a_error,
            .low_cb = relay_a_low,
            .arg = st,
        });
        tm_io_start(st->io_a);
    }
    if (st->io_b) tm_io_start(st->io_b);
    if (st->preq_len) {
        uint8_t *p = st->preq;
        size_t n = st->preq_len;
        st->preq = NULL;
        st->preq_len = 0;
        st->preq_cap = 0;
        relay_a_read(st->io_a, p, n, st);
        free(p);
    }
    if (st->a_paused) {
        st->a_paused = false;
        tm_io_resume_read(st->io_a);
    }
}

/* attach the agent's TLS data connection io (and its socket) to a pending
   stream. For closed-tunnel streams leg A is the peer's TLS connection. */
void tm_stream_relay_attach_agent(tm_broker *b, tm_stream *st, tm_io *io,
                                  uv_handle_t *sock_b) {
    if (!st || st->closing || st->bound) return;
    st->io_b = io;
    st->sock_b = sock_b;
    tm_io_set_cbs(io, &(tm_io_cbs){
        .read_cb = relay_b_read,
        .eof_cb = relay_b_eof,
        .error_cb = relay_b_error,
        .low_cb = relay_b_low,
        .arg = st,
    });
    tm_stream_relay_start(b, st);
}

/* create a pending stream for an open public connection */
tm_stream *tm_stream_create_open(tm_broker *b, tm_tunnel *tun,
                                 uv_tcp_t *public_sock) {
    if (b->stream_count >= b->cfg.max_streams) return NULL;
    if (tun->streams_active >= b->cfg.max_streams_per_tunnel) return NULL;
    tm_stream *st = tm_xcalloc(1, sizeof(*st));
    static uint64_t sid_counter = 1;
    st->id = (uint32_t)(sid_counter++ & 0x7FFFFFFFu);
    if (st->id == 0) st->id = 1;
    st->tun = tun;
    st->sock_a = (uv_handle_t *)public_sock;
    st->b = b;
    st->start_ms = tm_now_ms();
    uv_timer_init(b->loop, &st->bind_timer);
    st->bind_timer.data = st;
    uv_timer_start(&st->bind_timer, stream_bind_timer_cb,
                   (uint64_t)b->cfg.bind_timeout_ms, 0);
    st->next = tun->streams;
    tun->streams = st;
    tun->streams_active++;
    tun->streams_total++;
    b->stream_count++;
    b->streams_total++;
    return st;
}

/* create a pending stream for a closed-tunnel peer connection; the peer's
   TLS io becomes leg A immediately (frames stop, raw bytes begin). */
tm_stream *tm_stream_create_closed(tm_broker *b, tm_tunnel *tun, tm_io *peer_io,
                                   uv_handle_t *peer_sock) {
    if (b->stream_count >= b->cfg.max_streams) return NULL;
    if (tun->streams_active >= b->cfg.max_streams_per_tunnel) return NULL;
    tm_stream *st = tm_xcalloc(1, sizeof(*st));
    static uint64_t sid_counter2 = 1;
    st->id = (uint32_t)(sid_counter2++ & 0x7FFFFFFFu);
    if (st->id == 0) st->id = 1;
    st->tun = tun;
    st->sock_a = peer_sock;
    st->io_a = peer_io;
    st->b = b;
    st->start_ms = tm_now_ms();
    uv_timer_init(b->loop, &st->bind_timer);
    st->bind_timer.data = st;
    uv_timer_start(&st->bind_timer, stream_bind_timer_cb,
                   (uint64_t)b->cfg.bind_timeout_ms, 0);
    tm_io_set_cbs(peer_io, &(tm_io_cbs){
        .read_cb = relay_a_read,
        .eof_cb = relay_a_eof,
        .error_cb = relay_a_error,
        .low_cb = relay_a_low,
        .arg = st,
    });
    st->next = tun->streams;
    tun->streams = st;
    tun->streams_active++;
    tun->streams_total++;
    b->stream_count++;
    b->streams_total++;
    return st;
}