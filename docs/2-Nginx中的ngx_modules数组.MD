# 1.ngx_modules数组的产生
ngx_modules数组是在执行configure脚本后自动生成的，在objs/ngx_modules.c文件中。该数组即当前编译版本中的所有Nginx模块。

做如下操作，可以看到ngx_moduels数组的一般形式：

## 1.1 最简单的Nginx框架，不包含任何HTTP模块
```
cd nginx-1.6.2
./configure --without-http
```
此时，objs/ngx_modules.c的内容为:
```
#include <ngx_config.h>
#include <ngx_core.h>



extern ngx_module_t  ngx_core_module;
extern ngx_module_t  ngx_errlog_module;
extern ngx_module_t  ngx_conf_module;
extern ngx_module_t  ngx_events_module;
extern ngx_module_t  ngx_event_core_module;
extern ngx_module_t  ngx_epoll_module;

ngx_module_t *ngx_modules[] = {
    &ngx_core_module,
    &ngx_errlog_module,
    &ngx_conf_module,
    &ngx_events_module,
    &ngx_event_core_module,
    &ngx_epoll_module,
    NULL
};
```
## 1.2 默认的ngx_modules数组:
```
make clean
cd nginx-1.6.2
./configure
```
此时，objs/ngx_modules.c的内容为:
```
#include <ngx_config.h>
#include <ngx_core.h>



extern ngx_module_t  ngx_core_module;
extern ngx_module_t  ngx_errlog_module;
extern ngx_module_t  ngx_conf_module;
extern ngx_module_t  ngx_events_module;
extern ngx_module_t  ngx_event_core_module;
extern ngx_module_t  ngx_epoll_module;
extern ngx_module_t  ngx_regex_module;
extern ngx_module_t  ngx_http_module;
extern ngx_module_t  ngx_http_core_module;
extern ngx_module_t  ngx_http_log_module;
extern ngx_module_t  ngx_http_upstream_module;
extern ngx_module_t  ngx_http_static_module;
extern ngx_module_t  ngx_http_autoindex_module;
extern ngx_module_t  ngx_http_index_module;
extern ngx_module_t  ngx_http_auth_basic_module;
extern ngx_module_t  ngx_http_access_module;
extern ngx_module_t  ngx_http_limit_conn_module;
extern ngx_module_t  ngx_http_limit_req_module;
extern ngx_module_t  ngx_http_geo_module;
extern ngx_module_t  ngx_http_map_module;
extern ngx_module_t  ngx_http_split_clients_module;
extern ngx_module_t  ngx_http_referer_module;
extern ngx_module_t  ngx_http_rewrite_module;
extern ngx_module_t  ngx_http_proxy_module;
extern ngx_module_t  ngx_http_fastcgi_module;
extern ngx_module_t  ngx_http_uwsgi_module;
extern ngx_module_t  ngx_http_scgi_module;
extern ngx_module_t  ngx_http_memcached_module;
extern ngx_module_t  ngx_http_empty_gif_module;
extern ngx_module_t  ngx_http_browser_module;
extern ngx_module_t  ngx_http_upstream_ip_hash_module;
extern ngx_module_t  ngx_http_upstream_least_conn_module;
extern ngx_module_t  ngx_http_upstream_keepalive_module;
extern ngx_module_t  ngx_http_write_filter_module;
extern ngx_module_t  ngx_http_header_filter_module;
extern ngx_module_t  ngx_http_chunked_filter_module;
extern ngx_module_t  ngx_http_range_header_filter_module;
extern ngx_module_t  ngx_http_gzip_filter_module;
extern ngx_module_t  ngx_http_postpone_filter_module;
extern ngx_module_t  ngx_http_ssi_filter_module;
extern ngx_module_t  ngx_http_charset_filter_module;
extern ngx_module_t  ngx_http_userid_filter_module;
extern ngx_module_t  ngx_http_headers_filter_module;
extern ngx_module_t  ngx_http_copy_filter_module;
extern ngx_module_t  ngx_http_range_body_filter_module;
extern ngx_module_t  ngx_http_not_modified_filter_module;

ngx_module_t *ngx_modules[] = {
    &ngx_core_module,
    &ngx_errlog_module,
    &ngx_conf_module,
    &ngx_events_module,
    &ngx_event_core_module,
    &ngx_epoll_module,
    &ngx_regex_module,
    &ngx_http_module,
    &ngx_http_core_module,
    &ngx_http_log_module,
    &ngx_http_upstream_module,
    &ngx_http_static_module,
    &ngx_http_autoindex_module,
    &ngx_http_index_module,
    &ngx_http_auth_basic_module,
    &ngx_http_access_module,
    &ngx_http_limit_conn_module,
    &ngx_http_limit_req_module,
    &ngx_http_geo_module,
    &ngx_http_map_module,
    &ngx_http_split_clients_module,
    &ngx_http_referer_module,
    &ngx_http_rewrite_module,
    &ngx_http_proxy_module,
    &ngx_http_fastcgi_module,
    &ngx_http_uwsgi_module,
    &ngx_http_scgi_module,
    &ngx_http_memcached_module,
    &ngx_http_empty_gif_module,
    &ngx_http_browser_module,
    &ngx_http_upstream_ip_hash_module,
    &ngx_http_upstream_least_conn_module,
    &ngx_http_upstream_keepalive_module,
    &ngx_http_write_filter_module,
    &ngx_http_header_filter_module,
    &ngx_http_chunked_filter_module,
    &ngx_http_range_header_filter_module,
    &ngx_http_gzip_filter_module,
    &ngx_http_postpone_filter_module,
    &ngx_http_ssi_filter_module,
    &ngx_http_charset_filter_module,
    &ngx_http_userid_filter_module,
    &ngx_http_headers_filter_module,
    &ngx_http_copy_filter_module,
    &ngx_http_range_body_filter_module,
    &ngx_http_not_modified_filter_module,
    NULL
};
```

# 2.直接使用ngx_modules的场景
如上所述，ngx_modules数组代表了当前Nginx中的所有模块，由于每一个Nginx模块，即ngx_module_t类型的变量，其ctx变量一般为如下几个类型之一:

1. ngx_core_module_t
2. ngx_event_module_t
3. ngx_http_module_t
4. ngx_mail_module_t

所以，可以对所有的Nginx模块按其ctx类型进行分类，当然并不是所有的nginx模块都有ctx成员，例如ngx_conf_module模块的ctx成员为NULL,但可以认为绝大部分模块都属于上述四类模块之一。

每一类模块下的所有模块，由于其ctx结构是一样的，因而在程序执行逻辑上会有共同点。具体来说，我们可以遍历ngx_modules数组成员，判断其属于上述四类的哪一类模块，再调用其对应的ctx成员中的函数指针，这样就会屏蔽掉具体的模块名称，抽象到框架的层面上。

那么，如何判断一个模块属于上述四类模块中的哪一类呢？这就是模块变量的type成员的作用了。

1. 所有的ngx_core_module_t类型的模块，其type成员为NGX_CORE_MODULE
2. 所有的ngx_event_module_t类型的模块，其type成员为NGX_EVENT_MODULE
3. 所有的ngx_http_module_t类型的模块，其type成员为NGX_HTTP_MODULE
4. 所有的ngx_mail_module_t类型的模块，其type成员为NGX_MAIL_MODULE

所以,在遍历ngx_modules数组时，即可根据每一个数组成员的type成员，来判断该模块属于哪种类型的模块，进而执行该模块对应的钩子函数。
