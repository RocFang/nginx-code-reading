# 1.Nginx中的基本模块类型
Nginx中的模块主要包含如下几个类别：

1. Core模块
2. HTTP模块（标准HTTP模块和第三方HTTP模块）
3. Mail模块

其中，Core模块是最基本的模块。由于Nginx主要是一个HTTP服务器，所以默认编译时会把HTTP模块给编译进去，而不会编译Mail模块。如果要排除HTTP模块，则在编译时加入选项--without-http,同理，如果要包含Mail模块，则在编译时加入选项--with-mail.
 
# 2.Nginx的核心模块
我们先看Nginx有哪些核心模块，将HTTP模块排除在外。执行如下操作:
```
cd nginx-1.6.2
./configure --without-http
```
此时，会生成objs目录，打开objs/ngx_modules.c，可以看到其内容为:
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
其中，ngx_modules数组中包含的几个模块即为Nginx中的几个核心模块。

1. ngx_core_module
2. ngx_errlog_module
3. ngx_conf_module
4. ngx_events_module
5. ngx_event_core_module
6. ngx_epoll_module


