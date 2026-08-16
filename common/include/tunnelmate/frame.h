#ifndef TM_FRAME_H
#define TM_FRAME_H

#include "tunnelmate/common.h"

#define TM_FRAME_HDR_LEN 10u

typedef struct tm_frame_reader tm_frame_reader;

/* Streaming control-frame parser. Rejects malformed/oversized frames before
   any allocation; never trusts client-controlled lengths. */
tm_frame_reader *tm_frame_reader_new(void);
void tm_frame_reader_free(tm_frame_reader *r);

/* Feed bytes. On success returns a malloc'd frame (or NULL if incomplete).
   Set *errored on protocol violation (caller must close connection). */
tm_frame *tm_frame_reader_feed(tm_frame_reader *r, const uint8_t *data,
                               size_t len, bool *errored);

/* Bytes buffered inside the reader that have not yet formed a complete
   frame (used to hand off mid-stream application data). */
size_t tm_frame_reader_buffered(const tm_frame_reader *r);

/* Drain remaining buffered bytes into a malloc'd buffer (caller frees);
   resets the reader to a clean state. Returns 0 when empty. */
uint8_t *tm_frame_reader_drain(tm_frame_reader *r, size_t *out_len);

void tm_frame_free(tm_frame *f);

/* Encode a frame into a malloc'd buffer; *out_len set. */
uint8_t *tm_frame_encode(const tm_frame *f, size_t *out_len);

/* Build common frames. payload is copied. */
tm_frame *tm_frame_make(uint8_t type, uint32_t stream_id,
                        const uint8_t *payload, uint32_t payload_len);

/* Envelope for the UDP datagram path (DTLS records). Returns malloc'd
   envelope buffer, sets *out_len. */
uint8_t *tm_env_encode(uint64_t flow_id, uint8_t flags,
                       const uint8_t *payload, uint32_t payload_len,
                       size_t *out_len);

/* Parse an envelope; returns TM_OK and sets *flow_id,*flags and payload
   pointer/size into buf (no copy). */
tm_status tm_env_decode(const uint8_t *buf, size_t len, uint64_t *flow_id,
                        uint8_t *flags, const uint8_t **payload,
                        uint32_t *payload_len);

#endif