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

下面，我们以nginx-1.6.2为例，看看程序在哪些地方对nginx_modules数组进行了遍历。

## 2.1
```
 ngx_max_module = 0;
    for (i = 0; ngx_modules[i]; i++) {
        ngx_modules[i]->index = ngx_max_module++;
    }
```
上述代码在nginx.c的main函数中，可以看到，其作用为:

1. 统计系统中到底有多少个模块，记录在全局变量ngx_max_module中。
2. 将每个模块在ngx_modules数组中的序号，记录在模块的index变量中。

## 2.2 用来解析每个模块的配置
具体见函数ngx_conf_handler。

## 2.3 执行每个模块的ctx中的钩子函数
例如,ngx_init_cycle函数中:
```
for (i = 0; ngx_modules[i]; i++) {
        if (ngx_modules[i]->type != NGX_CORE_MODULE) {
            continue;
        }

        module = ngx_modules[i]->ctx;

        if (module->create_conf) {
            rv = module->create_conf(cycle);
            if (rv == NULL) {
                ngx_destroy_pool(pool);
                return NULL;
            }
            cycle->conf_ctx[ngx_modules[i]->index] = rv;
        }
    }
```
以上代码对所有的ngx_core_module_t类型的模块，调用其ctx成员中的create_conf钩子函数。

同样在在ngx_init_cycle函数：
```
  for (i = 0; ngx_modules[i]; i++) {
        if (ngx_modules[i]->type != NGX_CORE_MODULE) {
            continue;
        }

        module = ngx_modules[i]->ctx;

        if (module->init_conf) {
            if (module->init_conf(cycle, cycle->conf_ctx[ngx_modules[i]->index])
                == NGX_CONF_ERROR)
            {
                environ = senv;
                ngx_destroy_cycle_pools(&conf);
                return NULL;
            }
        }
    }

```
以上代码对所有的ngx_core_module_t类型的模块，调用其ctx成员的init_conf钩子函数。

继续看ngx_init_cycle函数:
```
   for (i = 0; ngx_modules[i]; i++) {
        if (ngx_modules[i]->init_module) {
            if (ngx_modules[i]->init_module(cycle) != NGX_OK) {
                /* fatal */
                exit(1);
            }
        }
    }
```
以上代码调用所有的nginx模块（ngx_module_t变量）的init_module钩子函数（如果不为空的话）。

在ngx_event_process_init函数中:
```
    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_EVENT_MODULE) {
            continue;
        }

        if (ngx_modules[m]->ctx_index != ecf->use) {
            continue;
        }

        module = ngx_modules[m]->ctx;

        if (module->actions.init(cycle, ngx_timer_resolution) != NGX_OK) {
            /* fatal */
            exit(2);
        }

        break;
    }
```
调用event模块的ctx成员中的actions.init钩子函数，对于epoll,则是ngx_epoll_init函数。

在ngx_events_block函数中:
```
  ngx_event_max_module = 0;
  for (i = 0; ngx_modules[i]; i++) {
        if (ngx_modules[i]->type != NGX_EVENT_MODULE) {
            continue;
        }

        ngx_modules[i]->ctx_index = ngx_event_max_module++;
    }
```
上面的代码，对于所有的EGX_EVENT_MODULE类型的模块，初始化其ctx_index变量。主要有两点:
1. ngx_event_max_module代表了ngx_event_module_t类型模块的个数。而ngx_max_module则代表了所有模块的个数。
2. ctx_index成员表示该模块在该类模块（本例中为ngx_event_module_t类型的模块)中的序号。
