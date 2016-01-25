
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_UPSTREAM_H_INCLUDED_
#define _NGX_HTTP_UPSTREAM_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>
#include <ngx_event_pipe.h>
#include <ngx_http.h>


#define NGX_HTTP_UPSTREAM_FT_ERROR           0x00000002
#define NGX_HTTP_UPSTREAM_FT_TIMEOUT         0x00000004
#define NGX_HTTP_UPSTREAM_FT_INVALID_HEADER  0x00000008
#define NGX_HTTP_UPSTREAM_FT_HTTP_500        0x00000010
#define NGX_HTTP_UPSTREAM_FT_HTTP_502        0x00000020
#define NGX_HTTP_UPSTREAM_FT_HTTP_503        0x00000040
#define NGX_HTTP_UPSTREAM_FT_HTTP_504        0x00000080
#define NGX_HTTP_UPSTREAM_FT_HTTP_403        0x00000100
#define NGX_HTTP_UPSTREAM_FT_HTTP_404        0x00000200
#define NGX_HTTP_UPSTREAM_FT_UPDATING        0x00000400
#define NGX_HTTP_UPSTREAM_FT_BUSY_LOCK       0x00000800
#define NGX_HTTP_UPSTREAM_FT_MAX_WAITING     0x00001000
#define NGX_HTTP_UPSTREAM_FT_NOLIVE          0x40000000
#define NGX_HTTP_UPSTREAM_FT_OFF             0x80000000

#define NGX_HTTP_UPSTREAM_FT_STATUS          (NGX_HTTP_UPSTREAM_FT_HTTP_500  \
                                             |NGX_HTTP_UPSTREAM_FT_HTTP_502  \
                                             |NGX_HTTP_UPSTREAM_FT_HTTP_503  \
                                             |NGX_HTTP_UPSTREAM_FT_HTTP_504  \
                                             |NGX_HTTP_UPSTREAM_FT_HTTP_403  \
                                             |NGX_HTTP_UPSTREAM_FT_HTTP_404)

#define NGX_HTTP_UPSTREAM_INVALID_HEADER     40


#define NGX_HTTP_UPSTREAM_IGN_XA_REDIRECT    0x00000002
#define NGX_HTTP_UPSTREAM_IGN_XA_EXPIRES     0x00000004
#define NGX_HTTP_UPSTREAM_IGN_EXPIRES        0x00000008
#define NGX_HTTP_UPSTREAM_IGN_CACHE_CONTROL  0x00000010
#define NGX_HTTP_UPSTREAM_IGN_SET_COOKIE     0x00000020
#define NGX_HTTP_UPSTREAM_IGN_XA_LIMIT_RATE  0x00000040
#define NGX_HTTP_UPSTREAM_IGN_XA_BUFFERING   0x00000080
#define NGX_HTTP_UPSTREAM_IGN_XA_CHARSET     0x00000100
#define NGX_HTTP_UPSTREAM_IGN_VARY           0x00000200


typedef struct {
    ngx_msec_t                       bl_time;
    ngx_uint_t                       bl_state;

    ngx_uint_t                       status;
    time_t                           response_sec;
    ngx_uint_t                       response_msec;
    time_t                           header_sec;
    ngx_uint_t                       header_msec;
    off_t                            response_length;

    ngx_str_t                       *peer;
} ngx_http_upstream_state_t;


typedef struct {
    ngx_hash_t                       headers_in_hash;
    ngx_array_t                      upstreams;
                                             /* ngx_http_upstream_srv_conf_t */
} ngx_http_upstream_main_conf_t;

typedef struct ngx_http_upstream_srv_conf_s  ngx_http_upstream_srv_conf_t;

typedef ngx_int_t (*ngx_http_upstream_init_pt)(ngx_conf_t *cf,
    ngx_http_upstream_srv_conf_t *us);
typedef ngx_int_t (*ngx_http_upstream_init_peer_pt)(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us);


typedef struct {
    ngx_http_upstream_init_pt        init_upstream;
    ngx_http_upstream_init_peer_pt   init;
    void                            *data;
} ngx_http_upstream_peer_t;


typedef struct {
    ngx_str_t                        name;
    ngx_addr_t                      *addrs;
    ngx_uint_t                       naddrs;
    ngx_uint_t                       weight;
    ngx_uint_t                       max_fails;
    time_t                           fail_timeout;

    unsigned                         down:1;
    unsigned                         backup:1;
} ngx_http_upstream_server_t;


#define NGX_HTTP_UPSTREAM_CREATE        0x0001
#define NGX_HTTP_UPSTREAM_WEIGHT        0x0002
#define NGX_HTTP_UPSTREAM_MAX_FAILS     0x0004
#define NGX_HTTP_UPSTREAM_FAIL_TIMEOUT  0x0008
#define NGX_HTTP_UPSTREAM_DOWN          0x0010
#define NGX_HTTP_UPSTREAM_BACKUP        0x0020


struct ngx_http_upstream_srv_conf_s {
    ngx_http_upstream_peer_t         peer;
    void                           **srv_conf;

    ngx_array_t                     *servers;  /* ngx_http_upstream_server_t */

    ngx_uint_t                       flags;
    ngx_str_t                        host;
    u_char                          *file_name;
    ngx_uint_t                       line;
    in_port_t                        port;
    in_port_t                        default_port;
    ngx_uint_t                       no_port;  /* unsigned no_port:1 */
};


typedef struct {
    ngx_addr_t                      *addr;
    ngx_http_complex_value_t        *value;
} ngx_http_upstream_local_t;


typedef struct {
/*
����ngx_http_upstream_t�ṹ����û��ʵ��resolved��Աʱ��upstream����ṹ��Ż���Ч�����ᶨ�����η�����������
*/
    ngx_http_upstream_srv_conf_t    *upstream;
/*
����TCP���ӵĳ�ʱʱ�䣬ʵ���Ͼ���д�¼���ӵ���ʱ����ʱ���õĳ�ʱʱ�䣬�μ�ͼ12-3�еĵ�8��
*/
    ngx_msec_t                       connect_timeout;
/*
��������ĳ�ʱʱ�䡣ͨ������д�¼���ӵ���ʱ�������õĳ�ʱʱ�䣬�μ�ͼ12-4�еĵ�3��
*/
    ngx_msec_t                       send_timeout;
/*
������Ӧ�ĳ�ʱʱ�䡣ͨ�����Ƕ��¼���ӵ���ʱ�������õĳ�ʱʱ�䣬�μ�ͼ12-4�еĵ�5��
*/
    ngx_msec_t                       read_timeout;
//Ŀǰ������
    ngx_msec_t                       timeout;
    ngx_msec_t                       next_upstream_timeout;
//TCP��SO_SNOLOWATѡ���ʾ���ͻ�����������
    size_t                           send_lowat;
/*
�����˽���ͷ���Ļ�����������ڴ��С��ngx_http_upstream_t�е�buffer����������
����ת����Ӧ�����λ�����buffering��־λΪ0�������ת����Ӧʱ����ͬ����ʾ���հ���Ļ�������С

�����������ٲ�಻�󣬻��������ٶȸ���ʱ�������ܹ�������������Ŀ��ǣ���Ȼϣ���ڴ����ʹ�õ���һЩ��
��ʱ�򽫻Ὺ��һ��̶���С���ڴ棬��buffer_sizeָ����С�����������������ε�����Ҳ�������ѱ����
��Ӧ����ת�������Ρ�������Ҳ����ȱ��ģ��������ٶȹ���������黺�������ڴ�д��ʱ�����޷��ٽ������ε�
��Ӧ������ȴ��������е�����ȫ�����͸����κ���ܼ������ա�
*/
    size_t                           buffer_size;
    size_t                           limit_rate;
/*
����buffering��־λΪ1������������ת����Ӧʱ��Ч���������õ�ngx_event_pipe_t�ṹ���busy_size��Ա�У�
���庬��μ�12.8.1��
*/
    size_t                           busy_buffers_size;
/*
��buffering��־λΪ1ʱ����������ٶȿ��������ٶȣ����п��ܰ��������ε���Ӧ�洢����ʱ�ļ��У�
��max_temp_file_sizeָ������ʱ�ļ�����󳤶ȡ�ʵ���ϣ���������ngx_event_pipe_t�ṹ���е�temp_file
*/
    size_t                           max_temp_file_size;
//��ʾ���������е���Ӧд����ʱ�ļ�ʱһ��д���ַ�������󳤶�
    size_t                           temp_file_write_size;

//����3����ԱĿǰ��û���κ�����
    size_t                           busy_buffers_size_conf;
    size_t                           max_temp_file_size_conf;
    size_t                           temp_file_write_size_conf;

/*
����������Զ������������ʱ���ͱ���Ҫ�����㹻���ڴ滺����������������Ӧ��bufsָ����ÿ���ڴ滺�����Ĵ�С��
�Լ��������ж��ٿ��ڴ滺���������ﵽ�ڴ�ʹ������ʱ�����������Ӧ���浽�����ļ��У���Ȼ�����ļ�Ҳ����
��С���Ƶģ�max_temp_file_sizeָ������ʱ�����ļ�����󳤶ȣ���Ȼ�ڴ�ʹ��̵Ļ��嶼������Ȼ�ᷢ����ʱ
�޷�����������Ӧ�ĳ����������ָ��ʾ�С�ö��ˣ��ر�����ʱ�ļ����������õĽϴ�ʱ��
*/
//�Ի�����Ӧ�ķ�ʽת�����η������İ���ʱ��ʹ�õ��ڴ��С

    ngx_bufs_t                       bufs;
/*
���ngx_http_upstream_t�ṹ���б��������İ�ͷ��headers_in��Ա��
ignore_headers���԰��ն�����λʹ��upstream��ת����ͷʱ������ĳЩͷ���Ĵ���
��Ϊ32λ���ͣ�������ignore_headers�����Ա�ʾ32����Ҫ�������账���ͷ����
Ȼ��Ŀǰupstream���ƽ��ṩ8��λ���ں���8��HTTPͷ���Ĵ���������
#define NGX_HTTP_UPSTREAM_IGN_XA_REDIRECT	  0x00000002
#define NGX_HTTP_UPSTREAM_IGN_XA_EXPIRES	  0x00000004
#define NGX_HTTP_UPSTREAM_IGN_EXPIRES        0x00000008
#define NGX_HTTP_UPSTREAM_IGN_CACHE_CONTROL  0x00000010
#define NGX_HTTP_UPSTREAM_IGN_SET_COOKIE     0x00000020
#define NGX_HTTP_UPSTREAM_IGN_XA_LIMIT_RATE  0x00000040
#define NGX_HTTP_UPSTREAM_IGN_XA_BUFFERING   0x00000080
#define NGX_HTTP_UPSTREAM_IGN_XA_CHARSET     0x00000100
*/
    ngx_uint_t                       ignore_headers;
/*
�Զ�����λ����ʾһЩ�����룬�������������Ӧʱ������Щ�����룬��ô��û�н���Ӧת�������οͻ���ʱ��
����ѡ����һ�����η��������ط����󡣲μ�12.9���н��ܵ�ngx_http_upstream_next����
*/
    ngx_uint_t                       next_upstream;
/*
��buffering��־λΪ1�������ת����Ӧʱ�����п��ܰ���Ӧ��ŵ���ʱ�ļ��С�
��ngx_http_upstream_t�е�store��־λΪ1ʱ��store_access��ʾ��������Ŀ¼���ļ���Ȩ��
*/
    ngx_uint_t                       store_access;
    ngx_uint_t                       next_upstream_tries;
/*
����ת����Ӧ��ʽ�ı�־λ��bufferingΪ1ʱ��ʾ�򿪻��棬��ʱ��Ϊ���ε����ٿ������ε����٣�
�ᾡ�������ڴ���ߴ����л����������ε���Ӧ�����bufferingΪ0�����Ὺ��һ��̶���С���ڴ����Ϊ������ת����Ӧ
*/
    ngx_flag_t                       buffering;
    ngx_flag_t                       request_buffering;
//��������
    ngx_flag_t                       pass_request_headers;
//��������
    ngx_flag_t                       pass_request_body;
/*
��ʾ��־λ������Ϊ1ʱ����ʾ�����η���������ʱ�������Nginx�����οͻ��˼�������Ƿ�Ͽ���
Ҳ����˵����ʹ���οͻ��������ر������ӣ�Ҳ�����ж������η�������Ľ���
*/
    ngx_flag_t                       ignore_client_abort;
/*
������������Ӧ�İ�ͷʱ��������������õ�headers_in�ṹ���е�status_n���������400��
�����ͼ������error_page��ָ���Ĵ�������ƥ�䣬���ƥ���ϣ�����error_page��ָ������Ӧ��
��������������η������Ĵ����롣���ngx_http_upstream_intercept_errors����
*/
    ngx_flag_t                       intercept_errors;
/*
buffering��־λΪ1�������ת����Ӧʱ�������塣��ʱ�����cyclic_temp_fileΪ1��
�����ͼ������ʱ�ļ����Ѿ�ʹ�ù��Ŀռ䡣�����齫cyclic_temp_file��Ϊ1
*/
    ngx_flag_t                       cyclic_temp_file;
    ngx_flag_t                       force_ranges;
//��buffering��־λΪ1�������ת����Ӧ�����ʱ�ļ���·��
    ngx_path_t                      *temp_path;
/*
��ת����ͷ����ʵ������ͨ��ngx_http_upstream_hide_headers_hash������
����hide_headers��pass_headers��̬���鹹�������Ҫ���ص�HTTPͷ��ɢ�б�
*/
    ngx_hash_t                       hide_headers_hash;
/*
��ת��������Ӧͷ����ngx_http_upstream_t��headers_in�ṹ���е�ͷ���������οͻ���ʱ��
�����ϣ��ĳЩͷ��ת�������Σ������õ�hide_headers��̬������
*/
    ngx_array_t                     *hide_headers;
/*
��ת��������Ӧͷ����ngx_http_upstream_t��headers_in�ṹ���е�ͷ���������οͻ���ʱ��
upstream����Ĭ�ϲ���ת���硰Date������Server��֮���ͷ�������ȷʵϣ��ֱ��ת�����ǵ����Σ�
�����õ�pass_headers��̬������
*/
    ngx_array_t                     *pass_headers;
//�������η�����ʱʹ�õı�����ַ
    ngx_http_upstream_local_t       *local;

#if (NGX_HTTP_CACHE)
    ngx_shm_zone_t                  *cache_zone;
    ngx_http_complex_value_t        *cache_value;

    ngx_uint_t                       cache_min_uses;
    ngx_uint_t                       cache_use_stale;
    ngx_uint_t                       cache_methods;

    ngx_flag_t                       cache_lock;
    ngx_msec_t                       cache_lock_timeout;
    ngx_msec_t                       cache_lock_age;

    ngx_flag_t                       cache_revalidate;

    ngx_array_t                     *cache_valid;
    ngx_array_t                     *cache_bypass;
    ngx_array_t                     *no_cache;
#endif
/*
��ngx_http_upstream_t�е�store��־λΪ1ʱ�������Ҫ�����ε���Ӧ��ŵ��ļ��У�
store_lengths����ʾ���·���ĳ��ȣ���store_values��ʾ���·��
*/
    ngx_array_t                     *store_lengths;
    ngx_array_t                     *store_values;

#if (NGX_HTTP_CACHE)
    signed                           cache:2;
#endif
/*
��ĿǰΪֹ��store��־λ��������ngx_http_upstream_t�е�store��ͬ����ֻ��0��1��ʹ�õ�
*/
    signed                           store:2;
/*
�����intercept_errors��־λ������400���ϵĴ����뽫����error_page�ȽϺ����д���
ʵ������������ǿ�����һ����������ģ������intercept_404��־λ��Ϊ1��
�����η���404ʱ��ֱ��ת���������������Σ�������ȥ��error_page���бȽ�
*/

    unsigned                         intercept_404:1;
/*
���ñ�־λΪ1ʱ���������ngx_http_upstream_t��headers_in�ṹ�����X-Accel-Bufferingͷ��������ֵ����yes��no��
���ı�buffering��־λ������ֵΪyesʱ��buffering��־λΪ1����ˣ�change_bufferingΪ1ʱ���п��ܸ������η��������ص���Ӧͷ����
��̬�ؾ������������������Ȼ�����������������
*/
    unsigned                         change_buffering:1;

#if (NGX_HTTP_SSL)
    ngx_ssl_t                       *ssl;
    ngx_flag_t                       ssl_session_reuse;

    ngx_http_complex_value_t        *ssl_name;
    ngx_flag_t                       ssl_server_name;
    ngx_flag_t                       ssl_verify;
#endif
//ʹ��upstream��ģ�����ƣ������ڼ�¼��־
    ngx_str_t                        module;
} ngx_http_upstream_conf_t;


typedef struct {
    ngx_str_t                        name;
    ngx_http_header_handler_pt       handler;
    ngx_uint_t                       offset;
    ngx_http_header_handler_pt       copy_handler;
    ngx_uint_t                       conf;
    ngx_uint_t                       redirect;  /* unsigned   redirect:1; */
} ngx_http_upstream_header_t;


typedef struct {
    ngx_list_t                       headers;

    ngx_uint_t                       status_n;
    ngx_str_t                        status_line;

    ngx_table_elt_t                 *status;
    ngx_table_elt_t                 *date;
    ngx_table_elt_t                 *server;
    ngx_table_elt_t                 *connection;

    ngx_table_elt_t                 *expires;
    ngx_table_elt_t                 *etag;
    ngx_table_elt_t                 *x_accel_expires;
    ngx_table_elt_t                 *x_accel_redirect;
    ngx_table_elt_t                 *x_accel_limit_rate;

    ngx_table_elt_t                 *content_type;
    ngx_table_elt_t                 *content_length;

    ngx_table_elt_t                 *last_modified;
    ngx_table_elt_t                 *location;
    ngx_table_elt_t                 *accept_ranges;
    ngx_table_elt_t                 *www_authenticate;
    ngx_table_elt_t                 *transfer_encoding;
    ngx_table_elt_t                 *vary;

#if (NGX_HTTP_GZIP)
    ngx_table_elt_t                 *content_encoding;
#endif

    ngx_array_t                      cache_control;
    ngx_array_t                      cookies;

    off_t                            content_length_n;
    time_t                           last_modified_time;

    unsigned                         connection_close:1;
    unsigned                         chunked:1;
} ngx_http_upstream_headers_in_t;


typedef struct {
    ngx_str_t                        host;
    in_port_t                        port;
    ngx_uint_t                       no_port; /* unsigned no_port:1 */

    ngx_uint_t                       naddrs;
    ngx_addr_t                      *addrs;

    struct sockaddr                 *sockaddr;
    socklen_t                        socklen;

    ngx_resolver_ctx_t              *ctx;
} ngx_http_upstream_resolved_t;


typedef void (*ngx_http_upstream_handler_pt)(ngx_http_request_t *r,
    ngx_http_upstream_t *u);


struct ngx_http_upstream_s {
//������¼��Ļص�������ÿһ���׶ζ��в�ͬ��read_event_handler
    ngx_http_upstream_handler_pt     read_event_handler;
//����д�¼��Ļص�������ÿһ���׶ζ��в�ͬ��write_event_handler
    ngx_http_upstream_handler_pt     write_event_handler;
//��ʾ���������η�������������ӡ�
    ngx_peer_connection_t            peer;

/* 
�������οͻ���ת����Ӧʱ��ngx_http_request_t�ṹ���е�subrequest_in_memory��־λΪ0����
������˻�������Ϊ�������ٸ��죨conf�����е�buffering��־λΪ1������ʱ��ʹ��pipe��Ա��ת����Ӧ��
��ʹ�����ַ�ʽת����Ӧʱ��������HTTPģ����ʹ��upstream����ǰ����pipe�ṹ�壬�����������ص�coredump����
*/
    ngx_event_pipe_t                *pipe;
/*
request_bufs������ķ�ʽ��ngx_buf_t��������������������ʾ������Ҫ���͵����η��������������ݡ�
���ԣ�HTTPģ��ʵ�ֵ�create_request�ص����������ڹ���request_bufs����
*/
    ngx_chain_t                     *request_bufs;
//�����������η�����Ӧ�ķ�ʽ
    ngx_output_chain_ctx_t           output;
    ngx_chain_writer_ctx_t           writer;
//ʹ��upstream����ʱ�ĸ������ã��ǳ��ؼ�����ָ����upstream�����з�ʽ��ע�⣬������������upstream����ǰ����
    ngx_http_upstream_conf_t        *conf;
#if (NGX_HTTP_CACHE)
    ngx_array_t                     *caches;
#endif
/*
HTTPģ����ʵ��process_header����ʱ�����ϣ��upstreamֱ��ת����Ӧ������Ҫ�ѽ���������Ӧͷ������ΪHTTP����Ӧͷ����
ͬʱ��Ҫ�Ѱ�ͷ�е���Ϣ���õ�headers_in�ṹ���У����������headers_in�����õ�ͷ����ӵ�Ҫ���͵����οͻ���
����Ӧͷ��headers_out��
*/
    ngx_http_upstream_headers_in_t   headers_in;

    ngx_http_upstream_resolved_t    *resolved;

    ngx_buf_t                        from_client;
/*
�������η�������Ӧ��ͷ�Ļ��������ڲ���Ҫ����Ӧֱ��ת�����ͻ��ˣ�����buffering��־λΪ0�������ת������ʱ��
���հ���Ļ�������Ȼʹ��buffer��ע�⣬���û���Զ���input_filter����������壬����ʹ��buffer�洢ȫ���İ��壬
��ʱbuffer�����㹻�����Ĵ�С��ngx_http_upstream_conf_t���ýṹ���е�buffer_size��Ա����
*/
    ngx_buf_t                        buffer;
//��ʾ�������η���������Ӧ����ĳ���
    off_t                            length;
/*
out_bufs�����ֳ������в�ͬ�����壺
�ٵ�����Ҫת�����壬��ʹ��Ĭ�ϵ�input_filter������Ҳ����ngx_http_upstream_non_buffered_filter�������������ʱ��
out_bufs����ָ����Ӧ���壬��ʵ�ϣ�out_bufs�����л�������ngx_buf_t��������ÿ����������ָ��buffer�����е�һ���֣�
�������һ���־���ÿ�ε���recv�������յ���һ��TCP����
�ڵ���Ҫת����Ӧ���嵽����ʱ��buffering��־λΪ0�����������������ȣ���
�������ָ����һ��������ת����Ӧ���������ʱ���ڽ��������εĻ�����Ӧ
*/
    ngx_chain_t                     *out_bufs;
/*
����Ҫת����Ӧ���嵽����ʱ��buffering��־λΪ0�����������������ȣ�������ʾ��һ��������ת����Ӧʱû�з����������
*/
    ngx_chain_t                     *busy_bufs;
/*
����������ڻ���out_bufs���Ѿ����͸����ε�ngx_buf_t�ṹ�壬��ͬ��Ӧ����buffering��־λΪ0���������������ȵĳ���
*/
    ngx_chain_t                     *free_bufs;
/*
�������ǰ�ĳ�ʼ������������data�������ڴ����û����ݽṹ����ʵ���Ͼ��������input_filter_ctxָ��
*/
    ngx_int_t                      (*input_filter_init)(void *data);
/*
�������ķ���������data�������ڴ����û����ݽṹ����ʵ���Ͼ��������input_filter_ctxָ�룬
��bytes��ʾ���ν��յ��İ��峤�ȡ�����NGX_ERRORʱ��ʾ����������������Ҫ���������򶼽�����upstream����
*/
    ngx_int_t                      (*input_filter)(void *data, ssize_t bytes);
/*
���ڴ���HTTPģ���Զ�������ݽṹ����input_filter_init��input_filter�������ص�ʱ����Ϊ�������ݹ�ȥ
*/
    void                            *input_filter_ctx;

#if (NGX_HTTP_CACHE)
    ngx_int_t                      (*create_key)(ngx_http_request_t *r);
#endif
//HTTPģ��ʵ�ֵ�create_request�������ڹ��췢�����η�����������
    ngx_int_t                      (*create_request)(ngx_http_request_t *r);
/*�����η�������ͨ��ʧ�ܺ�����������Թ�����Ҫ�ٴ������η������������ӣ�������reinit_request����*/
    ngx_int_t                      (*reinit_request)(ngx_http_request_t *r);
/*
�������η�����������Ӧ�İ�ͷ������NGX_AGAIN��ʾ��ͷ��û�н�������������
NGX_HTTP_UPSTREAM_INVALID_HEADER��ʾ��ͷ���Ϸ�������NGX_ERROR��ʾ���ִ��󣬷���NGX_OK��ʾ�����������İ�ͷ
*/
    ngx_int_t                      (*process_header)(ngx_http_request_t *r);
//��ǰ�汾��abort_request�ص�����û���������壬��upstream�����������ж��������
    void                           (*abort_request)(ngx_http_request_t *r);
//�������ʱ�����
    void                           (*finalize_request)(ngx_http_request_t *r,
                                         ngx_int_t rc);
/*
�����η��ص���Ӧ����Location����Refreshͷ����ʾ�ض���ʱ��
��ͨ��ngx_http_upstream_process_headers�������õ�����HTTPģ��ʵ�ֵ�rewrite_redirect����
*/
    ngx_int_t                      (*rewrite_redirect)(ngx_http_request_t *r,
                                         ngx_table_elt_t *h, size_t prefix);
    ngx_int_t                      (*rewrite_cookie)(ngx_http_request_t *r,
                                         ngx_table_elt_t *h);
//��������
    ngx_msec_t                       timeout;
//���ڱ�ʾ������Ӧ�Ĵ����롢���峤�ȵ���Ϣ
    ngx_http_upstream_state_t       *state;
//��ʹ���ļ�����ʱû������
    ngx_str_t                        method;
//schema��uri��Ա���ڼ�¼��־ʱ���õ�����������û������
    ngx_str_t                        schema;
    ngx_str_t                        uri;

#if (NGX_HTTP_SSL)
    ngx_str_t                        ssl_name;
#endif
/*
Ŀǰ�������ڱ�ʾ�Ƿ���Ҫ������Դ���൱��һ����־λ��ʵ�ʲ�����õ�����ָ��ķ���
*/
    ngx_http_cleanup_pt             *cleanup;
//�Ƿ�ָ���ļ�����·���ı�־λ
    unsigned                         store:1;
//�Ƿ������ļ�����
    unsigned                         cacheable:1;
//��������
    unsigned                         accel:1;
//�Ƿ����SSLЭ��������η�����
    unsigned                         ssl:1;
#if (NGX_HTTP_CACHE)
    unsigned                         cache_status:3;
#endif

/*
������ת�����ε���Ӧ����ʱ���Ƿ���������ڴ漰��ʱ�����ļ����ڻ������������͵����ε���Ӧ����
*/
    unsigned                         buffering:1;
    unsigned                         keepalive:1;
    unsigned                         upgrade:1;
/*
request_sent��ʾ�Ƿ��Ѿ������η��������������󣬵�request_sentΪ1ʱ����ʾupstream�����Ѿ������η�����������
ȫ�����߲��ֵ�������ʵ�ϣ������־λ�������Ϊ��ʹ��ngx_output_chain������������
��Ϊ�÷�����������ʱ���Զ���δ�������request_bufs�����¼������Ϊ�˷�ֹ���������ظ�����
������request_sent��־λ��¼�Ƿ���ù�ngx_output_chain����
*/
    unsigned                         request_sent:1;
/*
�����η���������Ӧ����Ϊ��ͷ�Ͱ�β���������Ӧֱ��ת�����ͻ��ˣ�header_sent��־λ��ʾ��ͷ�Ƿ��ͣ�
header_sentΪ1ʱ��ʾ�Ѿ��Ѱ�ͷת�����ͻ����ˡ������ת����Ӧ���ͻ��ˣ���header_sentû������
*/
    unsigned                         header_sent:1;
};


typedef struct {
    ngx_uint_t                      status;
    ngx_uint_t                      mask;
} ngx_http_upstream_next_t;


typedef struct {
    ngx_str_t   key;
    ngx_str_t   value;
    ngx_uint_t  skip_empty;
} ngx_http_upstream_param_t;


ngx_int_t ngx_http_upstream_cookie_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
ngx_int_t ngx_http_upstream_header_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

ngx_int_t ngx_http_upstream_create(ngx_http_request_t *r);
void ngx_http_upstream_init(ngx_http_request_t *r);
ngx_http_upstream_srv_conf_t *ngx_http_upstream_add(ngx_conf_t *cf,
    ngx_url_t *u, ngx_uint_t flags);
char *ngx_http_upstream_bind_set_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
char *ngx_http_upstream_param_set_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
ngx_int_t ngx_http_upstream_hide_headers_hash(ngx_conf_t *cf,
    ngx_http_upstream_conf_t *conf, ngx_http_upstream_conf_t *prev,
    ngx_str_t *default_hide_headers, ngx_hash_init_t *hash);


#define ngx_http_conf_upstream_srv_conf(uscf, module)                         \
    uscf->srv_conf[module.ctx_index]


extern ngx_module_t        ngx_http_upstream_module;
extern ngx_conf_bitmask_t  ngx_http_upstream_cache_method_mask[];
extern ngx_conf_bitmask_t  ngx_http_upstream_ignore_headers_masks[];


#endif /* _NGX_HTTP_UPSTREAM_H_INCLUDED_ */
