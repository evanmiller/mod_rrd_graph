/*
 * mod_rrd_graph - Graph data in a Round Robin Database (RRD).
 * 
 * Copyright (C) Evan Miller
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <rrd.h>

typedef struct {
    ngx_str_t      root;
} ngx_http_rrd_graph_conf_t;

static void * ngx_http_rrd_graph_create_conf(ngx_conf_t *cf);
static char * ngx_http_rrd_graph_merge_conf(ngx_conf_t *cf, void *parent, void *child);
static char* ngx_http_rrd_graph(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_rrd_graph_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_rrd_graph_send_image(ngx_http_request_t *r, u_char *image, size_t image_size);
static ngx_int_t ngx_http_rrd_graph_parse_uri(ngx_http_request_t *r, int *argc_ptr, 
        char ***argv_ptr, size_t **argv_len_ptr);

static u_char ngx_http_png_header[] = { '\x89', 'P', 'N', 'G' };
static u_char ngx_http_pdf_header[] = { '%', 'P', 'D', 'F' };
static u_char ngx_http_svg_header[] = { '<', '?', 'x', 'm', 'l' };
static u_char ngx_http_eps_header[] = { '%', '!', 'P', 'S' };

static ngx_command_t  ngx_http_rrd_graph_commands[] = {
    { ngx_string("rrd_graph"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_rrd_graph,
      0,
      0,
      NULL },

/* the root directory that will be prefixed to file names */
    { ngx_string("rrd_graph_root"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_rrd_graph_conf_t, root),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_rrd_graph_module_ctx = {
    NULL,                          /* preconfiguration */
    NULL,                          /* postconfiguration */

    NULL,                          /* create main configuration */
    NULL,                          /* init main configuration */

    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */

    ngx_http_rrd_graph_create_conf,/* create location configuration */
    ngx_http_rrd_graph_merge_conf  /* merge location configuration */
};


ngx_module_t  ngx_http_rrd_graph_module = {
    NGX_MODULE_V1,
    &ngx_http_rrd_graph_module_ctx, /* module context */
    ngx_http_rrd_graph_commands,   /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    NULL,                          /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_rrd_graph_handler(ngx_http_request_t *r)
{
    ngx_int_t     rc;
    /* image metadata */
    rrd_info_t   *image_info = NULL, *walker;
    u_char       *image = NULL, *tmp;
    size_t        image_size = 0;

    int           argc = 3; /* two dummies + at least one real */
    char        **argv;
    size_t       *argv_len;

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD)))
        return NGX_HTTP_NOT_ALLOWED;

    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK && rc != NGX_AGAIN)
        return rc;

    if ((rc = ngx_http_rrd_graph_parse_uri(r, &argc, &argv, &argv_len)) != NGX_OK)
        return rc;

    image_info = rrd_graph_v(argc, argv);

    if (rrd_test_error()) {
	ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "mod_rrd_graph: RRD graph failed: %s", rrd_get_error());
        rrd_clear_error();
        rrd_info_free(image_info);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    for (walker = image_info; walker; walker = walker->next) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "mod_rrd_graph: found key '%s'", walker->key);
        if (ngx_strcmp(walker->key, "image") == 0) {
            image = walker->value.u_blo.ptr;
            image_size = walker->value.u_blo.size;
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "mod_rrd_graph: image size is %d bytes", image_size);
        }
    }

    if (image_size) {
        if ((tmp = ngx_palloc(r->pool, image_size)) == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
                    "mod_rrd_graph: Failed to allocate response buffer.");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        ngx_memcpy(tmp, image, image_size);
        rrd_info_free(image_info); 
        return ngx_http_rrd_graph_send_image(r, tmp, image_size);
    }

    rrd_info_free(image_info); 

    return NGX_HTTP_NOT_FOUND;
}

static char *
ngx_http_rrd_graph(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_rrd_graph_handler;

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_rrd_graph_parse_uri(ngx_http_request_t *r, int *argc_ptr, 
    char ***argv_ptr, size_t **argv_len_ptr)
{
    int i,   argc = 3, in_quote = 0;
    char   **argv;
    size_t  *argv_len;
    char *tmp, *p;
    u_char *uri_copy;
    ngx_http_core_loc_conf_t  *clcf;
    ngx_http_rrd_graph_conf_t *conf;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (r->uri.len == clcf->name.len)
        return NGX_HTTP_NOT_FOUND;

    /* tokenize */
    if ((uri_copy = ngx_palloc(r->pool, (r->uri.len + 1)*sizeof(char))) == NULL) {
	ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "mod_rrd_graph: Failed to copy URI.");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_memcpy(uri_copy, r->uri.data, r->uri.len);
    uri_copy[r->uri.len] = '\0'; /* RRDtool needs null-terminated strings */
    p = (char *)uri_copy + clcf->name.len;

    while(*p++) {
        if (*p == '"') {
            in_quote = !in_quote;
        } else if (*p == ' ' && !in_quote) {
            argc++;
        }
    }

    if (in_quote)
        return NGX_ERROR;

    argv     = ngx_palloc(r->pool, argc*sizeof(char *));
    argv_len = ngx_pcalloc(r->pool, argc*sizeof(size_t));
    argv[0] = "mod_rrd_graph";
    argv[1] = "-";
    argv[2] = p = (char *)uri_copy + clcf->name.len;
    argc = 3;
    while (*p) {
        if (*p == ' ' && !in_quote) {
            *p = '\0';
            argv[argc++] = p+1;
        } else {
            if (*p == '"')
                in_quote = !in_quote;

            argv_len[argc-1]++;
        }
        p++;
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_rrd_graph_module);
    /* splice in the RRD directory root */
    /* TODO guard against relative paths */
    for (i=2; i<argc; i++) {
        if (ngx_strncmp(argv[i], "DEF:", sizeof("DEF:") - 1) == 0) {
            p = argv[i] + sizeof("DEF:") - 1;
            if ((p = ngx_strchr(p, '=')) != NULL) {
                p++;
                tmp = ngx_pcalloc(r->pool, argv_len[i] + conf->root.len + 1);
                ngx_memcpy(tmp, argv[i], p - argv[i]); /* prefix */
                ngx_memcpy(tmp + (p - argv[i]), conf->root.data, conf->root.len); /* root dir */
                ngx_memcpy(tmp + (p - argv[i]) + conf->root.len, /* suffix */
                        p, argv_len[i] - (p - argv[i]));
                argv[i] = tmp;
            }
        }
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "mod_rrd_graph: parsed arg %s", argv[i]);
    }
    *argc_ptr = argc;
    *argv_ptr = argv;
    *argv_len_ptr = argv_len;
    return NGX_OK;
}

static ngx_int_t
ngx_http_rrd_graph_send_image(ngx_http_request_t *r, u_char *image, size_t image_size)
{
    int rc;
    ngx_chain_t   out;

    out.next = NULL;
    if ((out.buf = ngx_pcalloc(r->pool, sizeof(ngx_buf_t))) == NULL) {
	ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "mod_rrd_graph: Failed to allocate response buffer.");
        free(image);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (image_size > 4) {
        if (ngx_strncmp(image, ngx_http_png_header, 
                    sizeof(ngx_http_png_header)) == 0) {
            r->headers_out.content_type.len = sizeof("image/png") - 1;
            r->headers_out.content_type.data = (u_char *)"image/png";
        } else if (ngx_strncmp(image, ngx_http_pdf_header,
                    sizeof(ngx_http_pdf_header)) == 0) {
            r->headers_out.content_type.len = sizeof("application/pdf") - 1;
            r->headers_out.content_type.data = (u_char *)"application/pdf";
        } else if (ngx_strncmp(image, ngx_http_eps_header,
                    sizeof(ngx_http_eps_header)) == 0) {
            r->headers_out.content_type.len = sizeof("application/postscript") - 1;
            r->headers_out.content_type.data = (u_char *)"application/postscript";
        } else if (ngx_strncmp(image, ngx_http_svg_header,
                    sizeof(ngx_http_svg_header)) == 0) {
            r->headers_out.content_type.len = sizeof("image/svg+xml") - 1;
            r->headers_out.content_type.data = (u_char *)"image/svg+xml";
        }
    }

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = image_size;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        free(image);
        return rc;
    }

    out.buf->pos = image;
    out.buf->last = image + image_size;

    out.buf->memory = 1;
    out.buf->last_buf = 1;

    return ngx_http_output_filter(r, &out);
}

static void *
ngx_http_rrd_graph_create_conf(ngx_conf_t *cf)
{
    ngx_http_rrd_graph_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_rrd_graph_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }
    return conf;
}

static char *
ngx_http_rrd_graph_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
        ngx_http_rrd_graph_conf_t *prev = parent;
        ngx_http_rrd_graph_conf_t *conf = child;

        ngx_conf_merge_str_value(conf->root, prev->root, "");

        return NGX_CONF_OK;
}
