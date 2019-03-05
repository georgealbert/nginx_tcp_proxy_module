
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_tcp.h>


typedef struct {
    ngx_str_t       text;
} ngx_tcp_return_srv_conf_t;

typedef struct {
    ngx_chain_t    *out;
} ngx_tcp_return_ctx_t;

static void ngx_tcp_return_init_session(ngx_tcp_session_t *s);
static void ngx_tcp_return_read_handler(ngx_event_t *rev);
static void ngx_tcp_return_write_handler(ngx_event_t *wev);

static void *ngx_tcp_return_create_srv_conf(ngx_conf_t *cf);
static char *ngx_tcp_return(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
/* static void ngx_tcp_return_send(ngx_tcp_session_t *s, ngx_buf_t *b); */

static ngx_tcp_protocol_t  ngx_tcp_return_protocol = {

    ngx_string("tcp_return"),
    { 0, 0, 0, 0 },
    NGX_TCP_GENERIC_PROTOCOL,
    /* NGX_TCP_RETURN_PROTOCOL, */
    ngx_tcp_return_init_session,
    NULL,
    NULL,
    ngx_string("500 Internal server error" CRLF)

};


static ngx_command_t  ngx_tcp_return_commands[] = {

    { ngx_string("return"),
      NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_tcp_return,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_tcp_return_srv_conf_t, text),
      NULL },

      ngx_null_command
};


static ngx_tcp_module_t  ngx_tcp_return_module_ctx = {
    &ngx_tcp_return_protocol,              /* protocol */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_tcp_return_create_srv_conf,        /* create server configuration */
    NULL                                   /* merge server configuration */
};


ngx_module_t  ngx_tcp_return_module = {
    NGX_MODULE_V1,
    &ngx_tcp_return_module_ctx,            /* module context */
    ngx_tcp_return_commands,               /* module directives */
    NGX_TCP_MODULE,                        /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static void 
ngx_tcp_return_init_session(ngx_tcp_session_t *s) 
{
    ngx_connection_t  *c;

    c = s->connection;
    s->buffer = ngx_create_temp_buf(s->connection->pool, ngx_pagesize);

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, c->log, 0, "tcp return init session");

    c->read->handler = ngx_tcp_return_read_handler;

    ngx_tcp_return_read_handler(c->read);
}


static void
ngx_tcp_return_read_handler(ngx_event_t *rev)
{
    u_char                      return_string[256] = {0};
    size_t                      size;
    ssize_t                     n;
    ngx_buf_t                  *b, *recv_buf;
    /* ngx_err_t                   err; */
    ngx_uint_t                  len = 0;
    ngx_connection_t           *c;
    ngx_tcp_session_t          *s;
    ngx_tcp_return_ctx_t       *ctx;
    ngx_tcp_return_srv_conf_t  *rscf;

    c = rev->data;
    s = c->data;

    /* if (rev->timedout) { */

    /*     ngx_connection_error(c, NGX_ETIMEDOUT, "return read timed out"); */
    /*     c->timedout = 1; */

    /*     ngx_tcp_finalize_session(s); */
    /*     return; */
    /* } */

    c->log->action = "reading text";

    recv_buf = s->buffer;
    recv_buf->last = recv_buf->start;
    size = recv_buf->end - recv_buf->start;

    /* TODO: cannot recv all data if recv() return NGX_AGAIN */
    for ( ;; ) {
        /* if (!c->read->ready) { */
        /*     break; */
        /* } */

        /* n = recv(c->fd, recv_buf->last, 1, MSG_PEEK); */
        /* ngx_log_debug1(NGX_LOG_DEBUG_TCP, rev->log, 0, */
        /*                "tcp return module peek: %d", n); */

        n = c->recv(c, recv_buf->last, size);
        /* err = ngx_socket_errno; */

        ngx_log_debug1(NGX_LOG_DEBUG_TCP, rev->log, 0,
                       "tcp return module recv: %d", n);

        if (n > 0) {
            /* recv_buf->last += n; */
            s->bytes_read += n;
            continue;
        }

        /* if (n == NGX_AGAIN || n == 0) { */
        if (n == NGX_AGAIN) {
            /* ngx_log_debug(NGX_LOG_DEBUG_TCP, rev->log, 0, */
            /*               "tcp return module recv NGX_AGAIN"); */
            break;
        }

        if (n == NGX_ERROR || n == 0) {
            /* c->read->eof = 1; */
            break;
        }
    }

    /* ngx_log_debug2(NGX_LOG_DEBUG_TCP, rev->log, 0, */
    /*                "tcp return read handler fd: %d, rev->available: %d", */
    /*                c->fd, rev->available); */

    /* if (c->read->eof) { */

    rscf = ngx_tcp_get_module_srv_conf(s, ngx_tcp_return_module);

    ngx_sprintf(return_string, "%s", rscf->text.data);
    len = ngx_strlen(return_string);

    ctx = ngx_pcalloc(c->pool, sizeof(ngx_tcp_return_ctx_t));
    if (ctx == NULL) {
        ngx_tcp_session_internal_server_error(s);
        return;
    }

    ngx_tcp_set_ctx(s, ctx, ngx_tcp_return_module);

    b = ngx_calloc_buf(c->pool);
    if (b == NULL) {
        ngx_tcp_session_internal_server_error(s);
        return;
    }

    b->memory = 1;
    b->pos = return_string;
    b->last = return_string + len;
    b->last_buf = 1;

    ctx->out = ngx_alloc_chain_link(c->pool);
    if (ctx->out == NULL) {
        ngx_tcp_session_internal_server_error(s);
        return;
    }

    ctx->out->buf = b;
    ctx->out->next = NULL;

    c->write->handler = ngx_tcp_return_write_handler;
    ngx_tcp_return_write_handler(c->write);

    /* b = ngx_create_temp_buf(s->connection->pool, NGX_PAGE_SIZE); */
    /* if (b == NULL) { */
    /* 	ngx_tcp_session_internal_server_error(s); */
    /*     return; */
    /* } */

    /* b->last = ngx_snprintf(b->last, b->end - b->last, */
    /*                        "%s", rscf->text.data); */

    /* ngx_tcp_return_send(s, b); */
    /* ngx_tcp_finalize_session(s); */
    /* } */

    /* if (c->read->timer_set) { */
    /*     ngx_del_timer(c->read); */
    /* } */

    /* if (ngx_handle_read_event(c->read, 0) != NGX_OK) { */
    /* 	ngx_tcp_session_internal_server_error(s); */
    /*     return; */
    /* } */

    /* ngx_add_timer(c->read, 2000); */
}


static void
ngx_tcp_return_write_handler(ngx_event_t *wev)
{
    ssize_t                n;
    ngx_buf_t             *b;
    ngx_uint_t             len;
    ngx_connection_t      *c;
    ngx_tcp_session_t     *s;
    ngx_tcp_return_ctx_t  *ctx;

    c = wev->data;
    s = c->data;

    c->log->action = "returning text";

    if (wev->timedout) {

        ngx_connection_error(c, NGX_ETIMEDOUT, "connection timed out");
        c->timedout = 1;

        ngx_tcp_finalize_session(s);
        return;
    }

    ctx = ngx_tcp_get_module_ctx(s, ngx_tcp_return_module);

    b = ctx->out->buf;
    len = b->last - b->pos;
    n = c->send(c, b->pos, len);

    ngx_log_debug1(NGX_LOG_DEBUG_TCP, c->log, 0,
                   "ngx_tcp_return_write_handler n: %d", n);

    ctx->out = NULL;
    if (n == NGX_ERROR || n == 0) {
        ngx_log_debug1(NGX_LOG_DEBUG_TCP, c->log, 0,
                       "ngx_tcp_return_write_handler send error: %d", n);
        ngx_tcp_finalize_session(s);
        return;
    }

    s->bytes_write += n;

    if (ngx_handle_write_event(wev, 0) != NGX_OK) {
    	ngx_tcp_session_internal_server_error(s);
        return;
    }

    ngx_add_timer(wev, 1234);
}


static void *
ngx_tcp_return_create_srv_conf(ngx_conf_t *cf)
{
    ngx_tcp_return_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_tcp_return_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}


static char *
ngx_tcp_return(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                             *rv;
    ngx_tcp_core_srv_conf_t          *cscf;
    ngx_tcp_return_srv_conf_t        *rscf;

    rscf = conf;
    rv = ngx_conf_set_str_slot(cf, cmd, conf);

    cscf = ngx_tcp_conf_get_module_srv_conf(cf, ngx_tcp_core_module);

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "return_string: %s", rscf->text.data);

    if (cscf->protocol == NULL) {
        cscf->protocol = &ngx_tcp_return_protocol;
    }

    return rv;
    /* return NGX_CONF_OK; */
}


/* static void */
/* ngx_tcp_return_send(ngx_tcp_session_t *s, ngx_buf_t *b) */
/* { */
/*     u_char                  *data; */
/*     ssize_t                  temp_send = 0, send_num = 0, len; */
/*     ngx_connection_t        *c; */

/*     c = s->connection; */
/*     data = b->pos; */
/*     len = b->last - b->pos; */

/*     ngx_log_debug0(NGX_LOG_DEBUG, c->log, 0, "upstream_show_send"); */

/*     while (send_num < len) { */

/*         temp_send = c->send(c, data + temp_send, len - send_num); */

/* #if (NGX_DEBUG) */
/*         { */
/*             ngx_err_t  err; */

/*             err = (temp_send >=0) ? 0 : ngx_socket_errno; */
/*             ngx_log_debug2(NGX_LOG_DEBUG, c->log, err, */
/*                            "tcp return send size: %z, total: %z", */
/*                            temp_send, len); */

/*             if (temp_send > 0) { */
/*                 ngx_log_debug2(NGX_LOG_DEBUG, c->log, err, */
/*                                "tcp return send content: %*s ", temp_send, data); */
/*             } */
/*         } */
/* #endif */

/*         if (temp_send > 0) { */
/*             send_num += temp_send; */

/*         } else if (temp_send == 0 || temp_send == NGX_AGAIN) { */
/*             continue; */

/*         } else { */
/*             c->error = 1; */
/*             break; */
/*         } */
/*     } */

/*     if (send_num == len) { */
/*         ngx_log_debug0(NGX_LOG_DEBUG, c->log, 0, "tcp return send done."); */
/*     } */

/*     return; */
/* } */
