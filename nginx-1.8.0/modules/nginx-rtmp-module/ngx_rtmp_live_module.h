
/*
 * Copyright (C) Roman Arutyunyan
 */


#ifndef _NGX_RTMP_LIVE_H_INCLUDED_
#define _NGX_RTMP_LIVE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_rtmp.h"
#include "ngx_rtmp_cmd_module.h"
#include "ngx_rtmp_bandwidth.h"
#include "ngx_rtmp_streams.h"

/*
在live开启的情况下，每个发布者和每个订阅者各自都对应一个ngx_rtmp_live_ctx_t。
*/

typedef struct ngx_rtmp_live_ctx_s ngx_rtmp_live_ctx_t;
typedef struct ngx_rtmp_live_stream_s ngx_rtmp_live_stream_t;


typedef struct {
    unsigned                            active:1;
    uint32_t                            timestamp;
    uint32_t                            csid;
    uint32_t                            dropped;
} ngx_rtmp_live_chunk_stream_t;


struct ngx_rtmp_live_ctx_s {
	// 指向对应的请求session,每一个请求，无论是发布者还是订阅者，都会对应一个session
    ngx_rtmp_session_t                 *session;
	// 对于同一个stream，每一个用户，包括发布者和订阅者，其stream指针均指向同一个。
    ngx_rtmp_live_stream_t             *stream;
	// 同一个流的每个用户，包括发布者和订阅者，其ctx结构会通过这个next指针串联成一个链表。链表的起始为最后一个订阅者ctx，终点为发布者ctx。
    ngx_rtmp_live_ctx_t                *next;
    ngx_uint_t                          ndropped;
    ngx_rtmp_live_chunk_stream_t        cs[2];
    ngx_uint_t                          meta_version;
    ngx_event_t                         idle_evt;
    unsigned                            active:1;
	//publishing为1,则表示当前session的主体为发布者
    unsigned                            publishing:1;
    unsigned                            silent:1;
    unsigned                            paused:1;
};


struct ngx_rtmp_live_stream_s {
	//流名
    u_char                              name[NGX_RTMP_MAX_NAME];
    ngx_rtmp_live_stream_t             *next;
    ngx_rtmp_live_ctx_t                *ctx;
    ngx_rtmp_bandwidth_t                bw_in;
    ngx_rtmp_bandwidth_t                bw_in_audio;
    ngx_rtmp_bandwidth_t                bw_in_video;
    ngx_rtmp_bandwidth_t                bw_out;
    ngx_msec_t                          epoch;
    unsigned                            active:1;
	// publishing为1，则表示该流正在被推送
    unsigned                            publishing:1;
};


typedef struct {
    ngx_int_t                           nbuckets;
    ngx_rtmp_live_stream_t            **streams;
    ngx_flag_t                          live;
    ngx_flag_t                          meta;
    ngx_msec_t                          sync;
    ngx_msec_t                          idle_timeout;
    ngx_flag_t                          atc;
    ngx_flag_t                          interleave;
    ngx_flag_t                          wait_key;
    ngx_flag_t                          wait_video;
    ngx_flag_t                          publish_notify;
    ngx_flag_t                          play_restart;
    ngx_flag_t                          idle_streams;
    ngx_msec_t                          buflen;
    ngx_pool_t                         *pool;
    ngx_rtmp_live_stream_t             *free_streams;
} ngx_rtmp_live_app_conf_t;


extern ngx_module_t  ngx_rtmp_live_module;


#endif /* _NGX_RTMP_LIVE_H_INCLUDED_ */
