#include "broker.h"
#include "tunnelmate/cJSON.h"
#include "tunnelmate/crypto.h"
#include <sys/un.h>
#include <unistd.h>

/* IPC: newline-delimited JSON over a unix socket. Ops:
   create_tunnel, delete_tunnel, disable_tunnel, enable_tunnel,
   rotate_agent_secret, rotate_shared_token, kill_stream,
   get_status, get_tunnels, health, reload. */

typedef struct {
    uv_pipe_t pipe;
    uv_write_t wreq;
    uv_buf_t wbuf;
    char *data;
    bool writing;
    bool close_pending;
    bool handle_closing;
    tm_broker *b;
    char rbuf[16384];
    size_t rbuf_len;
} tm_ipc_conn;

static void ipc_conn_free(tm_ipc_conn *pc) {
    free(pc->data);
    free(pc);
}

static void ipc_conn_close_cb(uv_handle_t *h) {
    tm_ipc_conn *pc = (tm_ipc_conn *)h->data;
    ipc_conn_free(pc);
}

static void ipc_conn_close_handle(tm_ipc_conn *pc) {
    if (pc->handle_closing) return;
    pc->handle_closing = true;
    uv_close((uv_handle_t *)&pc->pipe, ipc_conn_close_cb);
}

static void ipc_conn_close(tm_ipc_conn *pc) {
    if (pc->handle_closing || pc->close_pending) return;
    if (pc->writing) {
        pc->close_pending = true;
        uv_read_stop((uv_stream_t *)&pc->pipe);
        return;
    }
    ipc_conn_close_handle(pc);
}

static void ipc_write_done(uv_write_t *req, int status) {
    (void)status;
    tm_ipc_conn *pc = (tm_ipc_conn *)req->data;
    pc->writing = false;
    free(pc->data);
    pc->data = NULL;
    if (pc->close_pending) ipc_conn_close_handle(pc);
}

static void ipc_send(tm_ipc_conn *pc, const char *json) {
    if (pc->writing || pc->close_pending || pc->handle_closing) return;
    size_t len = strlen(json);
    pc->data = tm_xmalloc(len + 2);
    memcpy(pc->data, json, len);
    pc->data[len] = '\n';
    pc->data[len + 1] = 0;
    pc->wbuf = uv_buf_init(pc->data, (unsigned)(len + 1));
    pc->writing = true;
    pc->wreq.data = pc;
    uv_write(&pc->wreq, (uv_stream_t *)&pc->pipe, &pc->wbuf, 1, ipc_write_done);
}

/* ------------------------------------------------------------------ */
/* handlers                                                            */
/* ------------------------------------------------------------------ */

static void reply_ok(tm_ipc_conn *pc, cJSON *extra) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "status", "ok");
    if (extra) {
        cJSON *it = extra->child;
        while (it) {
            cJSON *nxt = it->next;
            cJSON_DetachItemFromObject(extra, it->string);
            cJSON_AddItemToObject(o, it->string, it);
            it = nxt;
        }
        cJSON_Delete(extra);
    }
    char *s = cJSON_PrintUnformatted(o);
    ipc_send(pc, s);
    free(s);
    cJSON_Delete(o);
}

static void reply_err(tm_ipc_conn *pc, const char *msg) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "status", "error");
    cJSON_AddStringToObject(o, "error", msg);
    char *s = cJSON_PrintUnformatted(o);
    ipc_send(pc, s);
    free(s);
    cJSON_Delete(o);
}

static void ipc_handle_op(tm_ipc_conn *pc, cJSON *req) {
    tm_broker *b = pc->b;
    cJSON *opj = cJSON_GetObjectItemCaseSensitive(req, "op");
    if (!cJSON_IsString(opj)) { reply_err(pc, "missing op"); return; }
    const char *op = opj->valuestring;

    if (strcmp(op, "health") == 0) {
        cJSON *x = cJSON_CreateObject();
        cJSON_AddStringToObject(x, "status", "ok");
        reply_ok(pc, x);
        return;
    }
    if (strcmp(op, "get_status") == 0) {
        char *s = tm_metrics_json(b, false);
        cJSON *x = cJSON_Parse(s);
        free(s);
        reply_ok(pc, x);
        return;
    }
    if (strcmp(op, "get_tunnels") == 0) {
        char *s = tm_metrics_json(b, true);
        cJSON *x = cJSON_Parse(s);
        free(s);
        reply_ok(pc, x);
        return;
    }
    if (strcmp(op, "create_tunnel") == 0) {
        cJSON *idj = cJSON_GetObjectItemCaseSensitive(req, "tunnel_id");
        cJSON *protoj = cJSON_GetObjectItemCaseSensitive(req, "proto");
        cJSON *closedj = cJSON_GetObjectItemCaseSensitive(req, "closed");
        cJSON *agent_secretj = cJSON_GetObjectItemCaseSensitive(req, "agent_secret");
        cJSON *tokenj = cJSON_GetObjectItemCaseSensitive(req, "shared_token");
        cJSON *agent_hmacj = cJSON_GetObjectItemCaseSensitive(req, "agent_secret_hmac");
        cJSON *token_hmacj = cJSON_GetObjectItemCaseSensitive(req, "shared_token_hmac");
        cJSON *preferj = cJSON_GetObjectItemCaseSensitive(req, "prefer_port");
        if (!cJSON_IsString(idj) || !cJSON_IsString(protoj)) {
            reply_err(pc, "tunnel_id and proto required");
            return;
        }
        size_t idlen = strlen(idj->valuestring);
        if (idlen == 0 || idlen > TM_TUNNEL_ID_LEN) {
            reply_err(pc, "bad tunnel_id length");
            return;
        }
        tm_proto proto = strcmp(protoj->valuestring, "udp") == 0 ? TM_PROTO_UDP
                                                                 : TM_PROTO_TCP;
        bool closed = cJSON_IsTrue(closedj);
        if (tm_tunnel_find(b, idj->valuestring)) {
            reply_err(pc, "tunnel already exists");
            return;
        }
        /* accept provided secrets or generate */
        char agent_secret[TM_MAX_SECRET + 1];
        char token[TM_MAX_SECRET + 1];
        if (cJSON_IsString(agent_secretj) && agent_secretj->valuestring[0]) {
            snprintf(agent_secret, sizeof(agent_secret), "%s", agent_secretj->valuestring);
        } else {
            tm_rand_token(agent_secret, 48);
        }
        if (closed) {
            if (cJSON_IsString(tokenj) && tokenj->valuestring[0])
                snprintf(token, sizeof(token), "%s", tokenj->valuestring);
            else
                tm_rand_token(token, 48);
        } else {
            token[0] = 0;
        }
        uint8_t hmac[32];
        char agent_hmac[65], token_hmac[65];
        if (cJSON_IsString(agent_hmacj) && strlen(agent_hmacj->valuestring) == 64) {
            snprintf(agent_hmac, sizeof(agent_hmac), "%s", agent_hmacj->valuestring);
            agent_secret[0] = 0; /* restore path: no plaintext capability */
        } else {
            tm_hmac_sha256(b->hmac_key, sizeof(b->hmac_key),
                           (const uint8_t *)agent_secret, strlen(agent_secret), hmac);
            tm_sha256_hex(hmac, 32, agent_hmac);
        }
        if (cJSON_IsString(token_hmacj) && strlen(token_hmacj->valuestring) == 64) {
            snprintf(token_hmac, sizeof(token_hmac), "%s", token_hmacj->valuestring);
            token[0] = 0;
        } else if (token[0]) {
            tm_hmac_sha256(b->hmac_key, sizeof(b->hmac_key),
                           (const uint8_t *)token, strlen(token), hmac);
            tm_sha256_hex(hmac, 32, token_hmac);
        } else {
            token_hmac[0] = 0;
        }
        uint16_t prefer = 0;
        if (cJSON_IsNumber(preferj)) prefer = (uint16_t)preferj->valuedouble;
        uint16_t allocated = 0;
        tm_tunnel *tun = tm_tunnel_create(b, idj->valuestring, proto, closed,
                                          agent_hmac, token_hmac, prefer,
                                          &allocated);
        if (!tun) {
            reply_err(pc, "create failed");
            return;
        }
        cJSON *x = cJSON_CreateObject();
        cJSON_AddStringToObject(x, "tunnel_id", tun->id);
        cJSON_AddNumberToObject(x, "public_port", tun->public_port);
        if (agent_secret[0]) cJSON_AddStringToObject(x, "agent_secret", agent_secret);
        cJSON_AddStringToObject(x, "agent_secret_hmac", agent_hmac);
        if (token[0]) cJSON_AddStringToObject(x, "shared_token", token);
        if (token_hmac[0]) cJSON_AddStringToObject(x, "shared_token_hmac", token_hmac);
        reply_ok(pc, x);
        return;
    }
    if (strcmp(op, "delete_tunnel") == 0 ||
        strcmp(op, "disable_tunnel") == 0 ||
        strcmp(op, "enable_tunnel") == 0) {
        cJSON *idj = cJSON_GetObjectItemCaseSensitive(req, "tunnel_id");
        if (!cJSON_IsString(idj)) { reply_err(pc, "tunnel_id required"); return; }
        tm_tunnel *tun = tm_tunnel_find(b, idj->valuestring);
        if (!tun) { reply_err(pc, "tunnel not found"); return; }
        if (strcmp(op, "delete_tunnel") == 0) {
            char err[128];
            if (tm_tunnel_delete(b, idj->valuestring, err, sizeof(err)) != TM_OK) {
                reply_err(pc, err);
                return;
            }
            reply_ok(pc, NULL);
            return;
        }
        if (strcmp(op, "disable_tunnel") == 0) {
            if (!tun->enabled) { reply_err(pc, "already disabled"); return; }
            tun->enabled = false;
            if (tun->agent) tm_agent_drop(b, tun->agent, "tunnel disabled");
            tm_tunnel_listener_stop(b, tun);
            tm_udp_stop(b, tun);
            reply_ok(pc, NULL);
            return;
        }
        if (strcmp(op, "enable_tunnel") == 0) {
            if (tun->enabled) { reply_err(pc, "already enabled"); return; }
            tun->enabled = true;
            if (tun->proto == TM_PROTO_TCP) tm_tunnel_listener_start(b, tun);
            else tm_udp_start(b, tun);
            reply_ok(pc, NULL);
            return;
        }
    }
    if (strcmp(op, "rotate_agent_secret") == 0 ||
        strcmp(op, "rotate_shared_token") == 0) {
        cJSON *idj = cJSON_GetObjectItemCaseSensitive(req, "tunnel_id");
        cJSON *secretj = cJSON_GetObjectItemCaseSensitive(req, "secret");
        if (!cJSON_IsString(idj)) { reply_err(pc, "tunnel_id required"); return; }
        tm_tunnel *tun = tm_tunnel_find(b, idj->valuestring);
        if (!tun) { reply_err(pc, "tunnel not found"); return; }
        char secret[TM_MAX_SECRET + 1];
        if (cJSON_IsString(secretj) && secretj->valuestring[0])
            snprintf(secret, sizeof(secret), "%s", secretj->valuestring);
        else
            tm_rand_token(secret, 48);
        uint8_t hmac[32];
        tm_hmac_sha256(b->hmac_key, sizeof(b->hmac_key),
                       (const uint8_t *)secret, strlen(secret), hmac);
        char hex[65];
        tm_sha256_hex(hmac, 32, hex);
        if (strcmp(op, "rotate_agent_secret") == 0) {
            memcpy(tun->agent_secret_hmac, hex, 65);
            /* force the agent to re-authenticate */
            if (tun->agent) tm_agent_drop(b, tun->agent, "secret rotated");
        } else {
            memcpy(tun->shared_token_hmac, hex, 65);
        }
        cJSON *x = cJSON_CreateObject();
        cJSON_AddStringToObject(x, "secret", secret);
        cJSON_AddStringToObject(x, "secret_hmac", hex);
        reply_ok(pc, x);
        return;
    }
    if (strcmp(op, "kill_stream") == 0) {
        cJSON *idj = cJSON_GetObjectItemCaseSensitive(req, "tunnel_id");
        cJSON *sidj = cJSON_GetObjectItemCaseSensitive(req, "stream_id");
        if (!cJSON_IsString(idj) || !cJSON_IsNumber(sidj)) {
            reply_err(pc, "tunnel_id and stream_id required");
            return;
        }
        tm_tunnel *tun = tm_tunnel_find(b, idj->valuestring);
        if (!tun) { reply_err(pc, "tunnel not found"); return; }
        tm_stream *st = tm_stream_find(b, tun, (uint32_t)sidj->valuedouble);
        if (!st) { reply_err(pc, "stream not found"); return; }
        tm_stream_close(b, st);
        reply_ok(pc, NULL);
        return;
    }
    if (strcmp(op, "reload") == 0) {
        /* cfg reload is applied on next startup; acknowledge */
        reply_ok(pc, NULL);
        return;
    }
    reply_err(pc, "unknown op");
}

/* ------------------------------------------------------------------ */
/* connection handling                                                 */
/* ------------------------------------------------------------------ */

static void ipc_conn_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    tm_ipc_conn *pc = (tm_ipc_conn *)stream->data;
    if (nread <= 0) {
        free(buf->base);
        if (nread < 0) ipc_conn_close(pc);
        return;
    }
    if (pc->rbuf_len + (size_t)nread > sizeof(pc->rbuf) - 1) {
        free(buf->base);
        ipc_conn_close(pc);
        return;
    }
    memcpy(pc->rbuf + pc->rbuf_len, buf->base, (size_t)nread);
    pc->rbuf_len += (size_t)nread;
    free(buf->base);
    /* process complete lines */
    char *line_start = pc->rbuf;
    for (;;) {
        char *nl = memchr(line_start, '\n',
                          pc->rbuf + pc->rbuf_len - line_start);
        if (!nl) break;
        *nl = 0;
        cJSON *req = cJSON_Parse(line_start);
        if (req) {
            ipc_handle_op(pc, req);
            cJSON_Delete(req);
        } else {
            reply_err(pc, "bad json");
        }
        line_start = nl + 1;
    }
    size_t remaining = pc->rbuf + pc->rbuf_len - line_start;
    memmove(pc->rbuf, line_start, remaining);
    pc->rbuf_len = remaining;
}

static void ipc_conn_alloc(uv_handle_t *handle, size_t suggested, uv_buf_t *buf) {
    (void)handle; (void)suggested;
    buf->base = tm_xmalloc(16384);
    buf->len = 16384;
}

static void ipc_on_conn(uv_stream_t *server, int status) {
    tm_broker *b = (tm_broker *)server->data;
    if (status != 0) return;
    tm_ipc_conn *pc = tm_xcalloc(1, sizeof(*pc));
    pc->b = b;
    uv_pipe_init(b->loop, &pc->pipe, 0);
    pc->pipe.data = pc;
    if (uv_accept(server, (uv_stream_t *)&pc->pipe) != 0) {
        uv_close((uv_handle_t *)&pc->pipe, ipc_conn_close_cb);
        return;
    }
    uv_read_start((uv_stream_t *)&pc->pipe, ipc_conn_alloc, ipc_conn_read);
}

tm_status tm_ipc_start(tm_broker *b) {
    /* sun_path is a fixed-size field; a longer path would be silently
       truncated and bind somewhere the control plane will never find. */
    size_t path_len = strlen(b->cfg.broker_socket);
    if (path_len >= sizeof(((struct sockaddr_un *)0)->sun_path)) {
        tm_log_error(b->log, "ipc_path_too_long", "socket", NULL,
                     "%zu bytes, maximum %zu", path_len,
                     sizeof(((struct sockaddr_un *)0)->sun_path) - 1);
        return TM_ERR;
    }
    unlink(b->cfg.broker_socket);
    uv_pipe_init(b->loop, &b->ipc_pipe, 0);
    b->ipc_pipe.data = b;
    int r = uv_pipe_bind(&b->ipc_pipe, b->cfg.broker_socket);
    if (r != 0) {
        tm_log_error(b->log, "ipc_bind_failed", "socket", NULL, "%s: %s",
                     b->cfg.broker_socket, uv_strerror(r));
        return TM_ERR;
    }
    r = uv_listen((uv_stream_t *)&b->ipc_pipe, 16, ipc_on_conn);
    if (r != 0) {
        tm_log_error(b->log, "ipc_listen_failed", "socket", NULL, "%s: %s",
                     b->cfg.broker_socket, uv_strerror(r));
        return TM_ERR;
    }
    b->ipc_open = true;
    chmod(b->cfg.broker_socket, 0660);
    tm_log_info(b->log, "ipc_listening", "socket", NULL, "%s", b->cfg.broker_socket);
    return TM_OK;
}
