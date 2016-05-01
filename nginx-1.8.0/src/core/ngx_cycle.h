
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_CYCLE_H_INCLUDED_
#define _NGX_CYCLE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#ifndef NGX_CYCLE_POOL_SIZE
#define NGX_CYCLE_POOL_SIZE     NGX_DEFAULT_POOL_SIZE
#endif


#define NGX_DEBUG_POINTS_STOP   1
#define NGX_DEBUG_POINTS_ABORT  2


typedef struct ngx_shm_zone_s  ngx_shm_zone_t;
/*
这个方法被回调时，其第1个参数就是ngx_shared_memory_add返回的，而且是刚刚设置过其init函数指针成员的ngx_shm_zone_t结构体。
对于ngx_shm_zone_init_pt的第2个参数void*data，在理解它之前先要搞清楚Nginx的reload重载配置文件流程。
重新解析配置文件意味着所有的模块（包括http模块）都会重新初始化，然而，之前正处于使用中的共享内存可能是有数据的、可以复用的，
如果丢弃了这些旧数据而重新开辟新的共享内存，是会造成严重错误的。所以如果处于重读配置文件流程中，
会尽可能地使用旧共享内存（如果存在的话），表现在ngx_shm_zone_init_pt的第2个参数void*data上时，就意味着：
如果Nginx是首次启动，data则为空指针NULL；若是重读配置文件，由于配置项、http模块的初始化导致共享内存再次创建，
那么data就会指向第一次创建共享内存时，ngx_shared_memory_add返回的ngx_shm_zone_t中的data成员。
读者朋友在处理data参数时请务必考虑以上场景，考虑如何使用老的共享内存，以避免不必要的错误。
*/
typedef ngx_int_t (*ngx_shm_zone_init_pt) (ngx_shm_zone_t *zone, void *data);

struct ngx_shm_zone_s {
	// 当ngx_shm_zone_init_pt方法回调时，通常在使用slab内存池的代码前需要做一些初始化工作，
    // 这一工作可能需要用到在解析配置文件时就获取到的一些参数，而data主要担当传递参数的职责
    void                     *data;
	 // 描述共享内存的结构体
    ngx_shm_t                 shm;
	// 在真正创建好slab共享内存池后，就会回调init指向的方法
    ngx_shm_zone_init_pt      init;
	 // 对应于ngx_shared_memory_add的tag参数
    void                     *tag;
};


struct ngx_cycle_s {
    void                  ****conf_ctx;
    ngx_pool_t               *pool;

    ngx_log_t                *log;
    ngx_log_t                 new_log;

    ngx_uint_t                log_use_stderr;  /* unsigned  log_use_stderr:1; */

    ngx_connection_t        **files;
    ngx_connection_t         *free_connections;
    ngx_uint_t                free_connection_n;

    ngx_queue_t               reusable_connections_queue;

//动态数据，每个数组元素存储着ngx_listening_t成员，表示监听端口及相关的参数
    ngx_array_t               listening;
    ngx_array_t               paths;
    ngx_list_t                open_files;
    ngx_list_t                shared_memory;

    ngx_uint_t                connection_n;
    ngx_uint_t                files_n;

    ngx_connection_t         *connections;
    ngx_event_t              *read_events;
    ngx_event_t              *write_events;

    ngx_cycle_t              *old_cycle;

    ngx_str_t                 conf_file;
    ngx_str_t                 conf_param;
    ngx_str_t                 conf_prefix;
    ngx_str_t                 prefix;
    ngx_str_t                 lock_file;
    ngx_str_t                 hostname;
};


typedef struct {
     ngx_flag_t               daemon;
     ngx_flag_t               master;

     ngx_msec_t               timer_resolution;

     ngx_int_t                worker_processes;
     ngx_int_t                debug_points;

     ngx_int_t                rlimit_nofile;
     ngx_int_t                rlimit_sigpending;
     off_t                    rlimit_core;

     int                      priority;

     ngx_uint_t               cpu_affinity_n;
     uint64_t                *cpu_affinity;

     char                    *username;
     ngx_uid_t                user;
     ngx_gid_t                group;

     ngx_str_t                working_directory;
     ngx_str_t                lock_file;

     ngx_str_t                pid;
     ngx_str_t                oldpid;

     ngx_array_t              env;
     char                   **environment;

#if (NGX_OLD_THREADS)
     ngx_int_t                worker_threads;
     size_t                   thread_stack_size;
#endif

} ngx_core_conf_t;


#if (NGX_OLD_THREADS)

typedef struct {
     ngx_pool_t              *pool;   /* pcre's malloc() pool */
} ngx_core_tls_t;

#endif


#define ngx_is_init_cycle(cycle)  (cycle->conf_ctx == NULL)


ngx_cycle_t *ngx_init_cycle(ngx_cycle_t *old_cycle);
ngx_int_t ngx_create_pidfile(ngx_str_t *name, ngx_log_t *log);
void ngx_delete_pidfile(ngx_cycle_t *cycle);
ngx_int_t ngx_signal_process(ngx_cycle_t *cycle, char *sig);
void ngx_reopen_files(ngx_cycle_t *cycle, ngx_uid_t user);
char **ngx_set_environment(ngx_cycle_t *cycle, ngx_uint_t *last);
ngx_pid_t ngx_exec_new_binary(ngx_cycle_t *cycle, char *const *argv);
uint64_t ngx_get_cpu_affinity(ngx_uint_t n);
ngx_shm_zone_t *ngx_shared_memory_add(ngx_conf_t *cf, ngx_str_t *name,
    size_t size, void *tag);


extern volatile ngx_cycle_t  *ngx_cycle;
extern ngx_array_t            ngx_old_cycles;
extern ngx_module_t           ngx_core_module;
extern ngx_uint_t             ngx_test_config;
extern ngx_uint_t             ngx_quiet_mode;
#if (NGX_OLD_THREADS)
extern ngx_tls_key_t          ngx_core_tls_key;
#endif


#endif /* _NGX_CYCLE_H_INCLUDED_ */
