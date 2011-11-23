
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_tcp.h>


#define NGX_DEFAULT_CIPHERS  "HIGH:!aNULL:!MD5"
#if defined(nginx_version) && nginx_version >= 1000006
#define NGX_DEFAULT_ECDH_CURVE  "prime256v1" 
#endif


static void *ngx_tcp_ssl_create_srv_conf(ngx_conf_t *cf);
static char *ngx_tcp_ssl_merge_srv_conf(ngx_conf_t *cf,
    void *parent, void *child);

static char *ngx_tcp_ssl_enable(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_tcp_ssl_session_cache(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_conf_bitmask_t  ngx_tcp_ssl_protocols[] = {
    { ngx_string("SSLv2"), NGX_SSL_SSLv2 },
    { ngx_string("SSLv3"), NGX_SSL_SSLv3 },
    { ngx_string("TLSv1"), NGX_SSL_TLSv1 },
    { ngx_null_string, 0 }
};


static ngx_conf_enum_t  ngx_tcp_ssl_verify[] = {
    { ngx_string("off"), 0 },
    { ngx_string("on"), 1 },
    { ngx_string("optional"), 2 },
    { ngx_null_string, 0 }
};


static ngx_command_t  ngx_tcp_ssl_commands[] = {

    { ngx_string("ssl"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_FLAG,
      ngx_tcp_ssl_enable,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_tcp_ssl_srv_conf_t, enable),
      NULL },

    { ngx_string("ssl_certificate"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_tcp_ssl_srv_conf_t, certificate),
      NULL },

    { ngx_string("ssl_certificate_key"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_tcp_ssl_srv_conf_t, certificate_key),
      NULL },

    { ngx_string("ssl_dhparam"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_tcp_ssl_srv_conf_t, dhparam),
      NULL },

#if defined(nginx_version) && nginx_version >= 1000006
    { ngx_string("ssl_ecdh_curve"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_tcp_ssl_srv_conf_t, ecdh_curve),
      NULL },

#endif
    { ngx_string("ssl_protocols"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_1MORE,
      ngx_conf_set_bitmask_slot,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_tcp_ssl_srv_conf_t, protocols),
      &ngx_tcp_ssl_protocols },

    { ngx_string("ssl_ciphers"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_tcp_ssl_srv_conf_t, ciphers),
      NULL },

    { ngx_string("ssl_verify_client"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_enum_slot,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_tcp_ssl_srv_conf_t, verify),
      &ngx_tcp_ssl_verify },

    { ngx_string("ssl_verify_depth"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_1MORE,
      ngx_conf_set_num_slot,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_tcp_ssl_srv_conf_t, verify_depth),
      NULL },

    { ngx_string("ssl_client_certificate"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_tcp_ssl_srv_conf_t, client_certificate),
      NULL },

    { ngx_string("ssl_prefer_server_ciphers"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_tcp_ssl_srv_conf_t, prefer_server_ciphers),
      NULL },

    { ngx_string("ssl_session_cache"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE12,
      ngx_tcp_ssl_session_cache,
      NGX_TCP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("ssl_session_timeout"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_tcp_ssl_srv_conf_t, session_timeout),
      NULL },

    { ngx_string("ssl_crl"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_tcp_ssl_srv_conf_t, crl),
      NULL },

      ngx_null_command
};


static ngx_tcp_module_t  ngx_tcp_ssl_module_ctx = {
    NULL,                                  /* */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_tcp_ssl_create_srv_conf,           /* create server configuration */
    ngx_tcp_ssl_merge_srv_conf,            /* merge server configuration */
};


ngx_module_t  ngx_tcp_ssl_module = {
    NGX_MODULE_V1,
    &ngx_tcp_ssl_module_ctx,               /* module context */
    ngx_tcp_ssl_commands,                  /* module directives */
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


static ngx_str_t ngx_tcp_ssl_sess_id_ctx = ngx_string("TCP");


static void *
ngx_tcp_ssl_create_srv_conf(ngx_conf_t *cf)
{
    ngx_tcp_ssl_srv_conf_t  *sscf;

    sscf = ngx_pcalloc(cf->pool, sizeof(ngx_tcp_ssl_srv_conf_t));
    if (sscf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     sscf->protocols = 0;
     *     sscf->certificate = { 0, NULL };
     *     sscf->certificate_key = { 0, NULL };
     *     sscf->dhparam = { 0, NULL };
     *     sscf->ecdh_curve = { 0, NULL };
     *     sscf->client_certificate = { 0, NULL };
     *     sscf->crl = { 0, NULL };
     *     sscf->ciphers.len = 0;
     *     sscf->ciphers.data = NULL;
     *     sscf->shm_zone = NULL;
     */

    sscf->enable = NGX_CONF_UNSET;
    sscf->prefer_server_ciphers = NGX_CONF_UNSET;
    sscf->verify = NGX_CONF_UNSET_UINT;
    sscf->verify_depth = NGX_CONF_UNSET_UINT;
    sscf->builtin_session_cache = NGX_CONF_UNSET;
    sscf->session_timeout = NGX_CONF_UNSET;

    return sscf;
}


static char *
ngx_tcp_ssl_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_tcp_ssl_srv_conf_t *prev = parent;
    ngx_tcp_ssl_srv_conf_t *conf = child;

    ngx_pool_cleanup_t  *cln;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);

    ngx_conf_merge_value(conf->session_timeout,
                         prev->session_timeout, 300);

    ngx_conf_merge_value(conf->prefer_server_ciphers,
                         prev->prefer_server_ciphers, 0);

    ngx_conf_merge_bitmask_value(conf->protocols, prev->protocols,
                         (NGX_CONF_BITMASK_SET|NGX_SSL_SSLv3|NGX_SSL_TLSv1));

    ngx_conf_merge_uint_value(conf->verify, prev->verify, 0);
    ngx_conf_merge_uint_value(conf->verify_depth, prev->verify_depth, 1);

    ngx_conf_merge_str_value(conf->certificate, prev->certificate, "");
    ngx_conf_merge_str_value(conf->certificate_key, prev->certificate_key, "");

    ngx_conf_merge_str_value(conf->dhparam, prev->dhparam, "");

#if defined(nginx_version) && nginx_version >= 1000006
    ngx_conf_merge_str_value(conf->ecdh_curve, prev->ecdh_curve, 
                         NGX_DEFAULT_ECDH_CURVE); 

#endif
    ngx_conf_merge_str_value(conf->client_certificate, prev->client_certificate,
                         "");
    ngx_conf_merge_str_value(conf->crl, prev->crl, "");

    ngx_conf_merge_str_value(conf->ciphers, prev->ciphers, NGX_DEFAULT_CIPHERS);


    conf->ssl.log = cf->log;

    if (conf->enable) {

        if (conf->certificate.len == 0) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "no \"ssl_certificate\" is defined for "
                          "the \"ssl\" directive in %s:%ui",
                          conf->file, conf->line);
            return NGX_CONF_ERROR;
        }

        if (conf->certificate_key.len == 0) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "no \"ssl_certificate_key\" is defined for "
                          "the \"ssl\" directive in %s:%ui",
                          conf->file, conf->line);
            return NGX_CONF_ERROR;
        }

    } else {

        if (conf->certificate.len == 0) {
            return NGX_CONF_OK;
        }

        if (conf->certificate_key.len == 0) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "no \"ssl_certificate_key\" is defined "
                          "for certificate \"%V\"", &conf->certificate);
            return NGX_CONF_ERROR;
        }
    }

    if (ngx_ssl_create(&conf->ssl, conf->protocols, conf) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NGX_CONF_ERROR;
    }

    cln->handler = ngx_ssl_cleanup_ctx;
    cln->data = &conf->ssl;

    if (ngx_ssl_certificate(cf, &conf->ssl, &conf->certificate,
                            &conf->certificate_key)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (SSL_CTX_set_cipher_list(conf->ssl.ctx,
                                (const char *) conf->ciphers.data)
        == 0)
    {
        ngx_ssl_error(NGX_LOG_EMERG, cf->log, 0,
                      "SSL_CTX_set_cipher_list(\"%V\") failed",
                      &conf->ciphers);
    }

    if (conf->verify) {

        if (conf->client_certificate.len == 0) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "no ssl_client_certificate for ssl_client_verify");
            return NGX_CONF_ERROR;
        }

        if (ngx_ssl_client_certificate(cf, &conf->ssl,
                                       &conf->client_certificate,
                                       conf->verify_depth)
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }

        if (ngx_ssl_crl(cf, &conf->ssl, &conf->crl) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    if (conf->prefer_server_ciphers) {
        SSL_CTX_set_options(conf->ssl.ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
    }

    /* a temporary 512-bit RSA key is required for export versions of MSIE */
#if defined(nginx_version) && nginx_version >= 1000006
    SSL_CTX_set_tmp_rsa_callback(conf->ssl.ctx, ngx_ssl_rsa512_key_callback); 
#else
    if (ngx_ssl_generate_rsa512_key(&conf->ssl) != NGX_OK) {
        return NGX_CONF_ERROR;
    }
#endif

    if (ngx_ssl_dhparam(cf, &conf->ssl, &conf->dhparam) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    ngx_conf_merge_value(conf->builtin_session_cache,
                         prev->builtin_session_cache, NGX_SSL_NONE_SCACHE);

    if (conf->shm_zone == NULL) {
        conf->shm_zone = prev->shm_zone;
    }

    if (ngx_ssl_session_cache(&conf->ssl, &ngx_tcp_ssl_sess_id_ctx,
                              conf->builtin_session_cache,
                              conf->shm_zone, conf->session_timeout)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_tcp_ssl_enable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_tcp_ssl_srv_conf_t *sscf = conf;

    char  *rv;

    rv = ngx_conf_set_flag_slot(cf, cmd, conf);

    if (rv != NGX_CONF_OK) {
        return rv;
    }

    sscf->file = cf->conf_file->file.name.data;
    sscf->line = cf->conf_file->line;

    return NGX_CONF_OK;
}


static char *
ngx_tcp_ssl_session_cache(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_tcp_ssl_srv_conf_t *sscf = conf;

    size_t       len;
    ngx_str_t   *value, name, size;
    ngx_int_t    n;
    ngx_uint_t   i, j;

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_strcmp(value[i].data, "off") == 0) {
            sscf->builtin_session_cache = NGX_SSL_NO_SCACHE;
            continue;
        }

        if (ngx_strcmp(value[i].data, "none") == 0) {
            sscf->builtin_session_cache = NGX_SSL_NONE_SCACHE;
            continue;
        }

        if (ngx_strcmp(value[i].data, "builtin") == 0) {
            sscf->builtin_session_cache = NGX_SSL_DFLT_BUILTIN_SCACHE;
            continue;
        }

        if (value[i].len > sizeof("builtin:") - 1
            && ngx_strncmp(value[i].data, "builtin:", sizeof("builtin:") - 1)
               == 0)
        {
            n = ngx_atoi(value[i].data + sizeof("builtin:") - 1,
                         value[i].len - (sizeof("builtin:") - 1));

            if (n == NGX_ERROR) {
                goto invalid;
            }

            sscf->builtin_session_cache = n;

            continue;
        }

        if (value[i].len > sizeof("shared:") - 1
            && ngx_strncmp(value[i].data, "shared:", sizeof("shared:") - 1)
               == 0)
        {
            len = 0;

            for (j = sizeof("shared:") - 1; j < value[i].len; j++) {
                if (value[i].data[j] == ':') {
                    value[i].data[j] = '\0';
                    break;
                }

                len++;
            }

            if (len == 0) {
                goto invalid;
            }

            name.len = len;
            name.data = value[i].data + sizeof("shared:") - 1;

            size.len = value[i].len - j - 1;
            size.data = name.data + len + 1;

            n = ngx_parse_size(&size);

            if (n == NGX_ERROR) {
                goto invalid;
            }

            if (n < (ngx_int_t) (8 * ngx_pagesize)) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "session cache \"%V\" is too small",
                                   &value[i]);

                return NGX_CONF_ERROR;
            }

            sscf->shm_zone = ngx_shared_memory_add(cf, &name, n,
                                                   &ngx_tcp_ssl_module);
            if (sscf->shm_zone == NULL) {
                return NGX_CONF_ERROR;
            }

            continue;
        }

        goto invalid;
    }

    if (sscf->shm_zone && sscf->builtin_session_cache == NGX_CONF_UNSET) {
        sscf->builtin_session_cache = NGX_SSL_NO_BUILTIN_SCACHE;
    }

    return NGX_CONF_OK;

invalid:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid session cache \"%V\"", &value[i]);

    return NGX_CONF_ERROR;
}