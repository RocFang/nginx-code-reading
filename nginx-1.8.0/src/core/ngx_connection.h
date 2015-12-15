
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_CONNECTION_H_INCLUDED_
#define _NGX_CONNECTION_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct ngx_listening_s  ngx_listening_t;

struct ngx_listening_s {
//socket�׽��־��
    ngx_socket_t        fd;

//����sockaddr��ַ
    struct sockaddr    *sockaddr;
//sockaddr��ַ����
    socklen_t           socklen;    /* size of sockaddr */
//�洢ip��ַ���ַ���addr_text��󳤶ȣ�����ָ����addr_text��������ڴ�Ĵ�С
    size_t              addr_text_max_len;
//���ַ�����ʽ�洢ip��ַ
    ngx_str_t           addr_text;

//�׽������ͣ����統type��SOCK_STREAMʱ����ʾtcp
    int                 type;

/*
tcpʵ�ּ���ʱ��backlog���У�����ʾ��������ͨ���������ֽ���tcp���ӣ�����û���κν��̿�ʼ���������������
*/
    int                 backlog;
//�ں��ж�������׽��ֵĽ��ջ�������С
    int                 rcvbuf;
//�ں��ж�������׽��ֵķ��ͻ�������С
    int                 sndbuf;
#if (NGX_HAVE_KEEPALIVE_TUNABLE)
    int                 keepidle;
    int                 keepintvl;
    int                 keepcnt;
#endif

    /* handler of accepted connection */
//���µ�tcp���ӳɹ������Ĵ�����
    ngx_connection_handler_pt   handler;

/*
ʵ���Ͽ�ܲ�������serversָ�룬����������Ϊһ������ָ�룬Ŀǰ��Ҫ����http����mail��ģ�飬���ڱ��浱ǰ�����˿ڶ�Ӧ�ŵ�����������
*/
    void               *servers;  /* array of ngx_http_in_addr_t, for example */

    ngx_log_t           log;
    ngx_log_t          *logp;

//���Ϊ�µ�tcp���Ӵ����ڴ�أ����ڴ�صĳ�ʼ��СӦ��Ϊpool_size. ��ngx_connection_t��pool��Ա��Ӧ��
    size_t              pool_size;
    /* should be here because of the AcceptEx() preread */
    size_t              post_accept_buffer_size;
    /* should be here because of the deferred accept */

/*
TCP_DEFER_ACCEPTѡ��ڽ���tcp���ӳɹ��ҽ��յ��û����������ݺ󣬲���Լ����׽��ָ���Ȥ�Ľ��̷����¼�֪ͨ�������ӽ����ɹ���
���post_accept_timeout������Ȼû���յ��û����ݣ����ں�ֱ�Ӷ�������
*/
    ngx_msec_t          post_accept_timeout;

//ǰһ��ngx_listening_t�ṹ�壬���ɵ�����
    ngx_listening_t    *previous;

//��ǰ���������Ӧ�ŵ�ngx_connection_t�ṹ��
    ngx_connection_t   *connection;

/*
��־λ��Ϊ1ʱ���ʾ�ڵ�ǰ���������Ч����ִ��ngx_init_cycleʱ���رռ����˿ڣ�Ϊ0ʱ�������رա��ñ�־λ��ܴ����Զ�����
*/
    unsigned            open:1;
/*
��־λ��Ϊ1ʱ��ʾʹ�����е�ngx_cycle_t����ʼ���µ�ngx_cycle_tʱ�����ر�ԭ�ȴ򿪵ļ����˿ڣ�����������������������,Ϊ0ʱ����ʾ
�����ر������򿪵ļ����˿ڡ��ñ�־λ��ܴ����Զ�����
*/
    unsigned            remain:1;
/*
��־λ��Ϊ1ʱ��ʾ�������õ�ǰngx_listening_t�ṹ���е��׽��֣�Ϊ0ʱ������ʼ���׽��֡��ñ�־λ��ܴ����Զ�����
*/
    unsigned            ignore:1;

//��ʾ�Ƿ��Ѿ��󶨣�ʵ����Ŀǰ�ñ�־λ��δʹ��
    unsigned            bound:1;       /* already bound */
/*
��ʾ��ǰ��������Ƿ�����ǰһ������,������nginxʱ�����Ϊ1�����ʾ����ǰһ�����̡�һ��ᱣ��֮ǰ�Ѿ����úõ��׽��֣������ı�
*/
    unsigned            inherited:1;   /* inherited from previous process */

//δʹ��
    unsigned            nonblocking_accept:1;

//��־λ��Ϊ1ʱ��ʾ��ǰ�ṹ���Ӧ���׽����Ѿ���������ngx_open_listening_sockets�е���listen�󼴱�����
    unsigned            listen:1;

//δʹ��
    unsigned            nonblocking:1;

//δʹ��
    unsigned            shared:1;    /* shared between threads or processes */

//��־λ��Ϊ1ʱ��ʾnginx�Ὣ�����ַת��Ϊ�ַ�����ʽ�ĵ�ַ
    unsigned            addr_ntop:1;

#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
    unsigned            ipv6only:1;
#endif
    unsigned            keepalive:2;

#if (NGX_HAVE_DEFERRED_ACCEPT)

//��־λ����ʾ�Ƿ�����׽����Ƿ�����TCP_DEFER_ACCEPT����
    unsigned            deferred_accept:1;
    unsigned            delete_deferred:1;
    unsigned            add_deferred:1;
#ifdef SO_ACCEPTFILTER
    char               *accept_filter;
#endif
#endif
#if (NGX_HAVE_SETFIB)
    int                 setfib;
#endif

#if (NGX_HAVE_TCP_FASTOPEN)
    int                 fastopen;
#endif

};


typedef enum {
     NGX_ERROR_ALERT = 0,
     NGX_ERROR_ERR,
     NGX_ERROR_INFO,
     NGX_ERROR_IGNORE_ECONNRESET,
     NGX_ERROR_IGNORE_EINVAL
} ngx_connection_log_error_e;


typedef enum {
     NGX_TCP_NODELAY_UNSET = 0,
     NGX_TCP_NODELAY_SET,
     NGX_TCP_NODELAY_DISABLED
} ngx_connection_tcp_nodelay_e;


typedef enum {
     NGX_TCP_NOPUSH_UNSET = 0,
     NGX_TCP_NOPUSH_SET,
     NGX_TCP_NOPUSH_DISABLED
} ngx_connection_tcp_nopush_e;


#define NGX_LOWLEVEL_BUFFERED  0x0f
#define NGX_SSL_BUFFERED       0x01
#define NGX_SPDY_BUFFERED      0x02


/*
��Ϊweb������,ÿһ���û��������ٶ�Ӧ��һ��tcp���ӣ�Ϊ�˼�ʱ����������ӣ�������Ҫһ�����¼���һ��д�¼���ʹ��epoll
������Ч�ĸ��ݴ������¼�������Ӧģ���ȡ������߷�����Ӧ�����nginx�����˻��������ݽṹngx_connection_t��ʾ���ӣ����
���ӱ�ʾ�ǿͻ�����������ġ�nginx�������������ܵ�tcp���ӣ����ǿ��Լ򵥳�֮Ϊ�������ӡ�ͬʱ������Щ����Ĵ�������У�
nginx����ͼ�����������η������������ӣ����Դ����������η�����ͨ�ţ����������������ngx_connection_t���ǲ�ͬ�ģ�nginx������
ngx_peer_connection_t��ʾ�������ӣ���Ȼngx_peer_connection_t����ngx_connection_tΪ����ʵ�ֵġ�

ע��:���������Ӷ����������ⴴ������������ӳ��л�ȡ����ngx_get_connection.
*/
struct ngx_connection_s {
/*
����δʹ��ʱ��data��Ա���ڳ䵱���ӳ��п������ӱ��е�nextָ�롣�����ӱ�ʹ��ʱ��data��������ʹ������nginxģ�����������http
����У�dataָ��ngx_http_request_t����
*/
    void               *data;
//���Ӷ�Ӧ�Ķ��¼�
    ngx_event_t        *read;
//���Ӷ�Ӧ��д�¼�
    ngx_event_t        *write;

//�׽��־��
    ngx_socket_t        fd;

//ֱ�����������ַ����ķ���
    ngx_recv_pt         recv;
//ֱ�ӷ��������ַ����ķ���
    ngx_send_pt         send;
//��ngx_chain_t����Ϊ���������������ַ����ķ���
    ngx_recv_chain_pt   recv_chain;
//��ngx_chain_t����Ϊ���������������ַ����ķ���
    ngx_send_chain_pt   send_chain;

//�����Ӷ�Ӧ��ngx_listening_t�������󣬴�������listening�����˿ڵ��¼�����
    ngx_listening_t    *listening;

//����������Ѿ����ͳ�ȥ���ֽ���
    off_t               sent;

//���Լ�¼��־��ngx_log_t����
    ngx_log_t          *log;

/*
�ڴ�أ�һ����acceptһ��������ʱ���ᴴ��һ���ڴ�أ�����������ӽ���ʱ�������ڴ�ء�ע�⣬������˵��������ָ�ɹ�������tcp
���ӣ������е�ngx_connection_t�ṹ�嶼��Ԥ�ȷ���ġ�����ڴ�صĴ�С���������listening���������е�pool_size��Ա����
*/
    ngx_pool_t         *pool;

//�ͻ��˵�sockaddr�ṹ��
    struct sockaddr    *sockaddr;
//sockaddr�ṹ��ĳ���
    socklen_t           socklen;
//�ͻ����ַ�����ʽ��ip��ַ
    ngx_str_t           addr_text;

    ngx_str_t           proxy_protocol_addr;

#if (NGX_SSL)
    ngx_ssl_connection_t  *ssl;
#endif

/*
�����ļ����˿ڶ�Ӧ��sockaddr�ṹ�壬Ҳ����listening���������е�sockaddr��Ա
*/
    struct sockaddr    *local_sockaddr;
    socklen_t           local_socklen;

/*
���ڽ��ա�����ͻ��˷������ַ�����ÿ���¼�����ģ������ɾ��������ӳ��з�����Ŀռ��buffer������ջ����ֶΡ����磬��httpģ���У�
���Ĵ�С������client_header_buffer_size������
*/
    ngx_buf_t          *buffer;

/*
���ֶ���������ǰ������˫������Ԫ�ص���ʽ��ӵ�ngx_cycle_t���Ľṹ���reusable_connections_queue˫�������У���ʾ�����õ�����
*/
    ngx_queue_t         queue;

/*
����ʹ�ô�����ngx_connection_t�ṹ��ÿ�ν���һ�����Կͻ��˵����ӣ����������������˷�������������ʱ(ngx_peer_connection_tҲʹ����),number
�����1
*/
    ngx_atomic_uint_t   number;

//������������
    ngx_uint_t          requests;
/*
�����е�ҵ�����͡��κ��¼�������ģ�鶼�����Զ�����Ҫ�ı�־λ�����buffered�ֶ���8λ��������ͬʱ��ʾ8����ͬ��ҵ�񡣵�����ģ��
���Զ���buffered��־λʱע�ⲻҪ�����ʹ�õ�ģ�鶨��ı�־λ��ͻ.Ŀǰ�Ѿ��������:
#define NGX_LOWLEVEL_BUFFERED  0x0f
#define NGX_SSL_BUFFERED       0x01
#define NGX_SPDY_BUFFERED      0x02

#define NGX_HTTP_LOWLEVEL_BUFFERED         0xf0
#define NGX_HTTP_WRITE_BUFFERED            0x10
#define NGX_HTTP_GZIP_BUFFERED             0x20
#define NGX_HTTP_SSI_BUFFERED              0x01
#define NGX_HTTP_SUB_BUFFERED              0x02
#define NGX_HTTP_COPY_BUFFERED             0x04

#define NGX_HTTP_IMAGE_BUFFERED  0x08

ͬʱ������httpģ����ԣ�buffered �ĵ�4λҪ���ã���ʵ�ʷ�����Ӧ��ngx_http_write_filter_module����ģ���У�
��4λ��ʶΪ1����ζ��nginx��һֱ��Ϊ��httpģ�黹��Ҫ����������󣬱���ȴ�httpģ�齫��4λȫ��Ϊ0�Ż�����
��������
*/
    unsigned            buffered:8;

    unsigned            log_error:3;     /* ngx_connection_log_error_e */

/*
��־λ��Ϊ1ʱ��ʾ���ڴ��ַ���������Ŀǰ������
*/
    unsigned            unexpected_eof:1;
//��־λ��Ϊ1ʱ��ʾ�����ѳ�ʱ
    unsigned            timedout:1;
//��־λ��Ϊ1ʱ��ʾ���Ӵ�������г��ִ���
    unsigned            error:1;
/*
��־λ��Ϊ1ʱ��ʾ�����Ѿ����١����������ָ����tcp���ӣ�������ngx_connection_t�ṹ�塣��destroyΪ1ʱ��
ngx_connection_t�ṹ����Ȼ���ڣ������Ӧ���׽��֡��ڴ�ص��Ѿ�������
*/
    unsigned            destroyed:1;

/*
��־λ��Ϊ1ʱ��ʾ���Ӵ��ڿ���״̬����keepalive��������������֮���״̬
*/
    unsigned            idle:1;
//��־λ��Ϊ1ʱ��ʾ���ӿ����ã����������queue�ֶ��Ƕ�Ӧʹ�õ�
    unsigned            reusable:1;
//��־λ��Ϊ1ʱ��ʾ���ӹر�
    unsigned            close:1;

//��־λ��Ϊ1ʱ��ʾ���ڽ��ļ��е����ݷ������ӵ���һ��
    unsigned            sendfile:1;
/*
��־λ�����Ϊ1�����ʾֻ���������׽��ֶ�Ӧ���ͻ�������������������õĴ�С��ֵʱ���¼�����ģ��
�Ż�ַ����¼�������ngx_handle_write_event�����е�lowat�����Ƕ�Ӧ��
*/
    unsigned            sndlowat:1;

/*
��־λ����ʾ���ʹ��tcp��nodelay���ԡ�����ȡֵ��Χ����Ϊ:
typedef enum {
     NGX_TCP_NODELAY_UNSET = 0,
     NGX_TCP_NODELAY_SET,
     NGX_TCP_NODELAY_DISABLED
} ngx_connection_tcp_nodelay_e;
*/
    unsigned            tcp_nodelay:2;   /* ngx_connection_tcp_nodelay_e */

/*
��־λ����ʾ���ʹ��tcp��nopush���ԣ�����ȡֵ��Χ����Ϊ:
typedef enum {
     NGX_TCP_NOPUSH_UNSET = 0,
     NGX_TCP_NOPUSH_SET,
     NGX_TCP_NOPUSH_DISABLED
} ngx_connection_tcp_nopush_e;
*/
    unsigned            tcp_nopush:2;    /* ngx_connection_tcp_nopush_e */

    unsigned            need_last_buf:1;

#if (NGX_HAVE_IOCP)
    unsigned            accept_context_updated:1;
#endif

#if (NGX_HAVE_AIO_SENDFILE)
    unsigned            busy_count:2;
#endif

#if (NGX_THREADS)
    ngx_thread_task_t  *sendfile_task;
#endif
};


ngx_listening_t *ngx_create_listening(ngx_conf_t *cf, void *sockaddr,
    socklen_t socklen);
ngx_int_t ngx_set_inherited_sockets(ngx_cycle_t *cycle);
ngx_int_t ngx_open_listening_sockets(ngx_cycle_t *cycle);
void ngx_configure_listening_sockets(ngx_cycle_t *cycle);
void ngx_close_listening_sockets(ngx_cycle_t *cycle);
void ngx_close_connection(ngx_connection_t *c);
ngx_int_t ngx_connection_local_sockaddr(ngx_connection_t *c, ngx_str_t *s,
    ngx_uint_t port);
ngx_int_t ngx_connection_error(ngx_connection_t *c, ngx_err_t err, char *text);

ngx_connection_t *ngx_get_connection(ngx_socket_t s, ngx_log_t *log);
void ngx_free_connection(ngx_connection_t *c);

void ngx_reusable_connection(ngx_connection_t *c, ngx_uint_t reusable);

#endif /* _NGX_CONNECTION_H_INCLUDED_ */
