#ifndef TM_IO_H
#define TM_IO_H

#include "tunnelmate/common.h"
#include <uv.h>
#include <openssl/ssl.h>
#include <stdint.h>

/* Generic byte-pump used by every relay leg (raw TCP socket or TLS/DTLS
   stream). Provides bounded write queues and half-close support. */

typedef struct tm_io tm_io;

struct tm_io {
    int kind;
    void *impl;
};

typedef void (*tm_io_read_cb)(tm_io *io, const uint8_t *data, size_t len,
                              void *arg);
typedef void (*tm_io_eof_cb)(tm_io *io, void *arg);
typedef void (*tm_io_error_cb)(tm_io *io, int err, void *arg);
typedef void (*tm_io_ready_cb)(tm_io *io, void *arg);

typedef void (*tm_io_low_cb)(tm_io *io, void *arg); /* pending <= LOW_WATER */

typedef struct {
    tm_io_ready_cb ready_cb;  /* after handshake completes (TLS legs) */
    tm_io_read_cb read_cb;
    tm_io_eof_cb eof_cb;
    tm_io_error_cb error_cb;
    tm_io_low_cb low_cb;      /* output queue drained below low watermark */
    void *arg;
} tm_io_cbs;

#define TM_IO_HIGH_WATER (256u * 1024u)
#define TM_IO_LOW_WATER  (128u * 1024u)

/* Raw TCP leg (public sockets, local service sockets, peer local sockets). */
tm_io *tm_io_tcp_new(uv_loop_t *loop, uv_tcp_t *tcp, const tm_io_cbs *cbs);

/* TLS leg. is_server: role. tls13: true = TLS 1.3 (control conns),
   false = TLS 1.2 (data conns, preserves half-close). */
tm_io *tm_io_ssl_new(uv_loop_t *loop, uv_stream_t *sock, SSL *ssl,
                     bool is_server, bool tls13, const tm_io_cbs *cbs);

/* DTLS leg for UDP tunnels. Client role: agent/peer; server: broker. */
tm_io *tm_io_dtls_new(uv_loop_t *loop, uv_udp_t *udp, SSL *ssl,
                      bool is_server, const tm_io_cbs *cbs);

void tm_io_start(tm_io *io);                 /* begin reading */
void tm_io_handshake(tm_io *io);             /* TLS legs only */
void tm_io_set_cbs(tm_io *io, const tm_io_cbs *cbs); /* rewire callbacks (role handoff) */

/* Queue bytes. TM_OK queued; TM_ERR_BUSY when over high watermark (caller
   must pause its source); TM_ERR when closed/half-closed. */
int tm_io_write(tm_io *io, const uint8_t *data, size_t len);

/* Half-close: FIN (raw) or close_notify (TLS). Further writes are refused. */
void tm_io_shutdown_send(tm_io *io);
void tm_io_pause_read(tm_io *io);
void tm_io_resume_read(tm_io *io);

bool tm_io_write_available(tm_io *io);
size_t tm_io_pending(tm_io *io);
bool tm_io_drained(tm_io *io); /* no queued writes remain unsent */
bool tm_io_is_open(tm_io *io);
bool tm_io_is_tls(tm_io *io);

/* Close and free the io object (not the socket handle; caller closes it). */
void tm_io_close(tm_io *io);
uint64_t tm_io_write_total(tm_io *io);

/* Bounded, secret-free description of the last transport failure. */
const char *tm_io_error_detail(tm_io *io);

/* Create a connected TCP client (used by agent/peer). */
tm_status tm_tcp_connect(uv_loop_t *loop, uv_tcp_t *tcp, const char *host,
                         uint16_t port, uv_connect_cb cb, void *arg);

#endif