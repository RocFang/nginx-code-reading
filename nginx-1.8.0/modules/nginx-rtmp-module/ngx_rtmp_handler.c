
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_rtmp.h"
#include "ngx_rtmp_amf.h"


static void ngx_rtmp_recv(ngx_event_t *rev);
static void ngx_rtmp_send(ngx_event_t *rev);
static void ngx_rtmp_ping(ngx_event_t *rev);
static ngx_int_t ngx_rtmp_finalize_set_chunk_size(ngx_rtmp_session_t *s);


ngx_uint_t                  ngx_rtmp_naccepted;


ngx_rtmp_bandwidth_t        ngx_rtmp_bw_out;
ngx_rtmp_bandwidth_t        ngx_rtmp_bw_in;


#ifdef NGX_DEBUG
char*
ngx_rtmp_message_type(uint8_t type)
{
    static char*    types[] = {
        "?",
        "chunk_size",
        "abort",
        "ack",
        "user",
        "ack_size",
        "bandwidth",
        "edge",
        "audio",
        "video",
        "?",
        "?",
        "?",
        "?",
        "?",
        "amf3_meta",
        "amf3_shared",
        "amf3_cmd",
        "amf_meta",
        "amf_shared",
        "amf_cmd",
        "?",
        "aggregate"
    };

    return type < sizeof(types) / sizeof(types[0])
        ? types[type]
        : "?";
}


char*
ngx_rtmp_user_message_type(uint16_t evt)
{
    static char*    evts[] = {
        "stream_begin",
        "stream_eof",
        "stream dry",
        "set_buflen",
        "recorded",
        "",
        "ping_request",
        "ping_response",
    };

    return evt < sizeof(evts) / sizeof(evts[0])
        ? evts[evt]
        : "?";
}
#endif

/* rtmp 包处理逻辑 */
void
ngx_rtmp_cycle(ngx_rtmp_session_t *s)
{
    ngx_connection_t           *c;

    c = s->connection;
    c->read->handler =  ngx_rtmp_recv;
    c->write->handler = ngx_rtmp_send;

    s->ping_evt.data = c;
    s->ping_evt.log = c->log;
    s->ping_evt.handler = ngx_rtmp_ping;
	//设置ping的定时器，默认为60s,ping_timeout默认为30s
    ngx_rtmp_reset_ping(s);

    ngx_rtmp_recv(c->read);
}

/*
分配一个ngx_chain_t和一个ngx_buf_t的内存
并为ngx_buf_t一般情况下大小为128+18=146字节的内存。
ngx_chaint_t的buf指针指向该ngx_buf_t结构.
*/
static ngx_chain_t *
ngx_rtmp_alloc_in_buf(ngx_rtmp_session_t *s)
{
    ngx_chain_t        *cl;
    ngx_buf_t          *b;
    size_t              size;

    if ((cl = ngx_alloc_chain_link(s->in_pool)) == NULL
       || (cl->buf = ngx_calloc_buf(s->in_pool)) == NULL)
    {
        return NULL;
    }

    cl->next = NULL;
    b = cl->buf;
    size = s->in_chunk_size + NGX_RTMP_MAX_CHUNK_HEADER;

    b->start = b->last = b->pos = ngx_palloc(s->in_pool, size);
    if (b->start == NULL) {
        return NULL;
    }
    b->end = b->start + size;

    return cl;
}


void
ngx_rtmp_reset_ping(ngx_rtmp_session_t *s)
{
    ngx_rtmp_core_srv_conf_t   *cscf;

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
    if (cscf->ping == 0) {
        return;
    }

    s->ping_active = 0;
    s->ping_reset = 0;
    ngx_add_timer(&s->ping_evt, cscf->ping);

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "ping: wait %Mms", cscf->ping);
}


static void
ngx_rtmp_ping(ngx_event_t *pev)
{
    ngx_connection_t           *c;
    ngx_rtmp_session_t         *s;
    ngx_rtmp_core_srv_conf_t   *cscf;

    c = pev->data;
    s = c->data;

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    /* i/o event has happened; no need to ping */
    if (s->ping_reset) {
        ngx_rtmp_reset_ping(s);
        return;
    }

    if (s->ping_active) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                "ping: unresponded");
        ngx_rtmp_finalize_session(s);
        return;
    }

    if (cscf->busy) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                "ping: not busy between pings");
        ngx_rtmp_finalize_session(s);
        return;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "ping: schedule %Mms", cscf->ping_timeout);

    if (ngx_rtmp_send_ping_request(s, (uint32_t)ngx_current_msec) != NGX_OK) {
        ngx_rtmp_finalize_session(s);
        return;
    }

    s->ping_active = 1;
    ngx_add_timer(pev, cscf->ping_timeout);
}


static void
ngx_rtmp_recv(ngx_event_t *rev)
{
    ngx_int_t                   n;
    ngx_connection_t           *c;
    ngx_rtmp_session_t         *s;
    ngx_rtmp_core_srv_conf_t   *cscf;
    ngx_rtmp_header_t          *h;
    ngx_rtmp_stream_t          *st, *st0;
    ngx_chain_t                *in, *head;
    ngx_buf_t                  *b;
    u_char                     *p, *pp, *old_pos;
    size_t                      size, fsize, old_size;
    uint8_t                     fmt, ext;
    uint32_t                    csid, timestamp;

    c = rev->data;
    s = c->data;
    b = NULL;
    old_pos = NULL;
    old_size = 0;
    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    if (c->destroyed) {
        return;
    }

    for( ;; ) {

        st = &s->in_streams[s->in_csid];

        /* allocate new buffer */
		// 分配chain链
		// 注意，如果一次调用recv接收一个chunk时，没接收完，再次进入该循环体时，st->in不为NULL,即不会分配新的buffer。
		//但是，如果一个message分为多个chunk，在一个chunk接收完，再次进入该循环体接收下一个chunk时，则要进入该
		//代码块再次分配一块内存来装新的chunk
        if (st->in == NULL) {
            st->in = ngx_rtmp_alloc_in_buf(s);
            if (st->in == NULL) {
                ngx_log_error(NGX_LOG_INFO, c->log, 0,
                        "in buf alloc failed");
                ngx_rtmp_finalize_session(s);
                return;
            }
        }

        h  = &st->hdr;
        in = st->in;
        b  = in->buf;

        if (old_size) {

            ngx_log_debug1(NGX_LOG_DEBUG_RTMP, c->log, 0,
                    "reusing formerly read data: %d", old_size);

            b->pos = b->start;
            b->last = ngx_movemem(b->pos, old_pos, old_size);

            if (s->in_chunk_size_changing) {
                ngx_rtmp_finalize_set_chunk_size(s);
            }

        } else {

            if (old_pos) {
                b->pos = b->last = b->start;
            }
//ngx_unix_recv
// 接收一个rtmp chunk
            n = c->recv(c, b->last, b->end - b->last);

            if (n == NGX_ERROR || n == 0) {
                ngx_rtmp_finalize_session(s);
                return;
            }

            if (n == NGX_AGAIN) {
                if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                    ngx_rtmp_finalize_session(s);
                }
                return;
            }

            s->ping_reset = 1;
            ngx_rtmp_update_bandwidth(&ngx_rtmp_bw_in, n);
            b->last += n;
            s->in_bytes += n;

            if (s->in_bytes >= 0xf0000000) {
                ngx_log_debug0(NGX_LOG_DEBUG_RTMP, c->log, 0,
                               "resetting byte counter");
                s->in_bytes = 0;
                s->in_last_ack = 0;
            }

            if (s->ack_size && s->in_bytes - s->in_last_ack >= s->ack_size) {

                s->in_last_ack = s->in_bytes;

                ngx_log_debug1(NGX_LOG_DEBUG_RTMP, c->log, 0,
                        "sending RTMP ACK(%uD)", s->in_bytes);

                if (ngx_rtmp_send_ack(s, s->in_bytes)) {
                    ngx_rtmp_finalize_session(s);
                    return;
                }
            }
        }

        old_pos = NULL;
        old_size = 0;

        /* 开始解析头部parse headers */
		//当一个chunk没有一次接收完，再次进入循环体内开始接收时，不会执行下面的代码块。
        if (b->pos == b->start) {
            p = b->pos;

            /* chunk basic header */
			//获取chunk stream id
			//fmt在basic header 的高两位
            fmt  = (*p >> 6) & 0x03;
			//获取第一个字节中除了fmt后的剩余6位，注意，此时并一定是csid，下面的csid只是一个临时的
            csid = *p++ & 0x3f;
			
            //fmt后面6位为0，表示basic chunk header 有2个字节长.
            //第一个字节的前两位为fmt,后面6位为0，csid在第二个字节表示。第二个字节的数值=csid-64，即
            //csid等于第二个字节的数值加64.p++开始指向basic chunk header后面的message header.
            if (csid == 0) {
                if (b->last - p < 1)
                    continue;
                csid = 64;
                csid += *(uint8_t*)p++;

            } else if (csid == 1) {
            //fmt后面6位为1，表示basic chunk header 有3个字节长
            //第一个字节的前两位为fmt,后面6位为1，csid在第二个和第三个字节这两个字节中表示。这两个字节的值等于
            //csid-64.即，csid=后面两个字节表示的整数值+64.
            // p最后也指向basic chunk header 后面的 message header.
                if (b->last - p < 2)
                    continue;
                csid = 64;
                csid += *(uint8_t*)p++;
                csid += (uint32_t)256 * (*(uint8_t*)p++);
            }

            //此时的csid才是解析完成之后真正的csid.
            ngx_log_debug2(NGX_LOG_DEBUG_RTMP, c->log, 0,
                    "RTMP bheader fmt=%d csid=%D",
                    (int)fmt, csid);
            // 系统默认的max_stream为32.
            if (csid >= (uint32_t)cscf->max_streams) {
                ngx_log_error(NGX_LOG_INFO, c->log, 0,
                    "RTMP in chunk stream too big: %D >= %D",
                    csid, cscf->max_streams);
                ngx_rtmp_finalize_session(s);
                return;
            }

            /* link orphan */
			//默认未设置时为0
            if (s->in_csid == 0) {

                /* unlink from stream #0 */
                st->in = st->in->next;

                /* link to new stream */
				// 将解析出来的csid保存在s->in_csid中，表示从客户端接收到的chunk的basic chunk header里的csid.
                s->in_csid = csid;
				//注意这里st已经变了
                st = &s->in_streams[csid];
                if (st->in == NULL) {
                    in->next = in;
                } else {
                    in->next = st->in->next;
                    st->in->next = in;
                }
                st->in = in;
                h = &st->hdr;
                h->csid = csid;
            }

            ext = st->ext;
            timestamp = st->dtime;

			//fmt可以为0，1，2，3四种情况，不同情况下，basic chunk header 后面的message header格式不同。
			//经过之前的解析，p现在指向basic chunk header后面的message header.
            if (fmt <= 2 ) {
				//当fmt为0时，message header的前三个字节为timestamp
				//当fmt为1时，message header的前三个字节为timestamp delta
				//当fmt为2时，message header的前三个字节为timestamp delta
                if (b->last - p < 3)
                    continue;
                /* timestamp:
                //将p指向的三个字节(大端)，转换为一个整数
                 *  big-endian 3b -> little-endian 4b */
                pp = (u_char*)&timestamp;
                pp[2] = *p++;
                pp[1] = *p++;
                pp[0] = *p++;
                pp[3] = 0;
                //如果timestamp解析出来为0x00ffffff，则说明三个字节不能表示timestamp，要用扩展位.ext
                //是个标志位，表示是否需要扩展时间戳.
                //此时,p已经向后移动了三个字节。
                ext = (timestamp == 0x00ffffff);

                if (fmt <= 1) {
				//经过前面解析timestamp，此时p已经向后移动了三个字节。
				//如果fmp为0或1，timestamp后面的三个字节用来表示message length，紧跟着用一个字节来表示message type id.
                    if (b->last - p < 4)
                        continue;
                    /* size:
                     *  big-endian 3b -> little-endian 4b
                     * type:
                     *  1b -> 1b*/
                    // 解析用三个字节表示的message length
                    pp = (u_char*)&h->mlen;
                    pp[2] = *p++;
                    pp[1] = *p++;
                    pp[0] = *p++;
                    pp[3] = 0;
					// 用一个字节装载message type id.
                    h->type = *(uint8_t*)p++;

                    if (fmt == 0) {
					//如果fmt为0，则message type id后面紧跟着4个字节表示message stream id.
                        if (b->last - p < 4)
                            continue;
                        /* stream:
                         *  little-endian 4b -> little-endian 4b */
                        pp = (u_char*)&h->msid;
                        pp[0] = *p++;
                        pp[1] = *p++;
                        pp[2] = *p++;
                        pp[3] = *p++;
                    }
                }
            }

            /* extended header */
			//如果前面解析的三个字节表示的时间戳为0xffffff，则说明三个字节无法描述完整时间戳，需要使用扩展时间戳。
			//扩展时间戳如果有的话，紧跟在message header后面，用4个字节表示。
            if (ext) {
                if (b->last - p < 4)
                    continue;
                pp = (u_char*)&timestamp;
                pp[3] = *p++;
                pp[2] = *p++;
                pp[1] = *p++;
                pp[0] = *p++;
            }

            if (st->len == 0) {
				//起初，st->len为0.
				
                /* Messages with type=3 should
                 * never have ext timestamp field
                 * according to standard.
                 * However that's not always the case
                 * in real life */
// 关于这个问题的说明，参考:http://nginx-rtmp.blogspot.hk/2012/03/hello-world.html
				//cscf->publish_time_fix默认开启，即为1
                st->ext = (ext && cscf->publish_time_fix);
                if (fmt) {
	//dtime表示timestamp delta。对于一个chunk,当basic chunk header中的fmt为0时，
	//basic chunk header后面的message header的前三个字节表示timestamp，当fmt为1和2时，则这三个字节表示timestamp delta.
                    st->dtime = timestamp;
                } else {
                    h->timestamp = timestamp;
                    st->dtime = 0;
                }
            }

            ngx_log_debug8(NGX_LOG_DEBUG_RTMP, c->log, 0,
                    "RTMP mheader fmt=%d %s (%d) "
                    "time=%uD+%uD mlen=%D len=%D msid=%D",
                    (int)fmt, ngx_rtmp_message_type(h->type), (int)h->type,
                    h->timestamp, st->dtime, h->mlen, st->len, h->msid);

            /* header done */
			//此时已经解析完了chunk header，p指向chunk data了，b->pos也是指向chunk体。
            b->pos = p;
            //检查message length大小是否超过限制
            //max_message默认为1M，由max_message指令配置。
            if (h->mlen > cscf->max_message) {
                ngx_log_error(NGX_LOG_INFO, c->log, 0,
                        "too big message: %uz", cscf->max_message);
                ngx_rtmp_finalize_session(s);
                return;
            }
        }

        //  chunk 头的各部分已经解析完毕，b->pos此时指向chunk 体的起始位置.
        // size 表示本次接收到chunk体的实际长度，有可能小于一个约定的chunk size(128字节)
        size = b->last - b->pos;
		// mlen 表示message length,起始的时候st->len为0，所以fsize起始为message length.
		//当由于一个message 被切割成多个chunk，导致再次进入循环时，fsize表示该消息剩下的长度
        fsize = h->mlen - st->len;
        // s->in_chunk_size表示协议双方约定的chunk体的大小
        if (size < ngx_min(fsize, s->in_chunk_size))
			//本次接收到的已经存放在缓冲区的chunk体，如果小于message length和chunk size的较小者的话
			//说明本次接收没有完成，需要继续接收。
            continue;

        /* buffer is ready */

		//此时一个chunk的完整内容都已经接收完毕
		//第一次时，fsize为message length
        if (fsize > s->in_chunk_size) {
			//说明一个消息被分成了多个chunk
            /* collect fragmented chunks */
            st->len += s->in_chunk_size;
            b->last = b->pos + s->in_chunk_size;
            old_pos = b->last;
            old_size = size - s->in_chunk_size;

        } else {
            /* handle! */
            head = st->in->next;

			//注意，下面这一句尤为重要。在此之前，一个chunk stream里的一条message，由多个chunk组成，每个chunk
			//是一个ngx_chain_t，st的in指向的是最后的一个chunk，最后一个chunk的next再指向第一个chunk,第一个chunk指向第二个chunk...
			//倒数第二个chunk的next又指向最后一个chunk。这样形成了一个环。 head = st->in->next;此时head指向第一个chunk.此时head指向的
			//仍然是一个ngx_chain_t环。经过下面这一句st->in->next = NULL;之后，就将环解开了，变成了一个单向链表。
            st->in->next = NULL;
            b->last = b->pos + fsize;
            old_pos = b->last;
            old_size = size - fsize;
            st->len = 0;
            h->timestamp += st->dtime;
			//调用ngx_rtmp_amf_message_handler/ngx_rtmp_codec_av

			//s为本ngx_rtmp_session_t结构体，h为本消息的ngx_rtmp_header_t
            if (ngx_rtmp_receive_message(s, h, head) != NGX_OK) {
                ngx_rtmp_finalize_session(s);
                return;
            }

            if (s->in_chunk_size_changing) {
                /* copy old data to a new buffer */
                if (!old_size) {
                    ngx_rtmp_finalize_set_chunk_size(s);
                }

            } else {
                /* add used bufs to stream #0 */
                st0 = &s->in_streams[0];
                st->in->next = st0->in;
                st0->in = head;
                st->in = NULL;
            }
        }

        s->in_csid = 0;
    }
}


static void
ngx_rtmp_send(ngx_event_t *wev)
{
    ngx_connection_t           *c;
    ngx_rtmp_session_t         *s;
    ngx_int_t                   n;
    ngx_rtmp_core_srv_conf_t   *cscf;

    c = wev->data;
    s = c->data;

    if (c->destroyed) {
        return;
    }

    if (wev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                "client timed out");
        c->timedout = 1;
        ngx_rtmp_finalize_session(s);
        return;
    }

    if (wev->timer_set) {
        ngx_del_timer(wev);
    }

    if (s->out_chain == NULL && s->out_pos != s->out_last) {
        s->out_chain = s->out[s->out_pos];
        s->out_bpos = s->out_chain->buf->pos;
    }

    while (s->out_chain) {
        n = c->send(c, s->out_bpos, s->out_chain->buf->last - s->out_bpos);

        if (n == NGX_AGAIN || n == 0) {
            ngx_add_timer(c->write, s->timeout);
            if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
                ngx_rtmp_finalize_session(s);
            }
            return;
        }

        if (n < 0) {
            ngx_rtmp_finalize_session(s);
            return;
        }

        s->out_bytes += n;
        s->ping_reset = 1;
        ngx_rtmp_update_bandwidth(&ngx_rtmp_bw_out, n);
        s->out_bpos += n;
        if (s->out_bpos == s->out_chain->buf->last) {
            s->out_chain = s->out_chain->next;
            if (s->out_chain == NULL) {
                cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
                ngx_rtmp_free_shared_chain(cscf, s->out[s->out_pos]);
                ++s->out_pos;
                s->out_pos %= s->out_queue;
                if (s->out_pos == s->out_last) {
                    break;
                }
                s->out_chain = s->out[s->out_pos];
            }
            s->out_bpos = s->out_chain->buf->pos;
        }
    }

    if (wev->active) {
        ngx_del_event(wev, NGX_WRITE_EVENT, 0);
    }

    ngx_event_process_posted((ngx_cycle_t *) ngx_cycle, &s->posted_dry_events);
}


/*
为一个message生成chunk头，lh参数是前一个message的头部，根据前一个头部来决定当前消息的头部的fmt，进而决定当前待发送包的chunk头中的
消息头
*/
void
ngx_rtmp_prepare_message(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_rtmp_header_t *lh, ngx_chain_t *out)
{
    ngx_chain_t                *l;
    u_char                     *p, *pp;
    ngx_int_t                   hsize, thsize, nbufs;
    uint32_t                    mlen, timestamp, ext_timestamp;
    static uint8_t              hdrsize[] = { 12, 8, 4, 1 };
    u_char                      th[7];
    ngx_rtmp_core_srv_conf_t   *cscf;
    uint8_t                     fmt;
    ngx_connection_t           *c;

    c = s->connection;
    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    if (h->csid >= (uint32_t)cscf->max_streams) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                "RTMP out chunk stream too big: %D >= %D",
                h->csid, cscf->max_streams);
        ngx_rtmp_finalize_session(s);
        return;
    }

    /* detect packet size */
    mlen = 0;
    nbufs = 0;
    for(l = out; l; l = l->next) {
        mlen += (l->buf->last - l->buf->pos);
        ++nbufs;
    }
    // fmt影响的是chunk里message header的内容
    fmt = 0;
    if (lh && lh->csid && h->msid == lh->msid) {
		//fmt=1
        ++fmt;
        if (h->type == lh->type && mlen && mlen == lh->mlen) {
			//fmt=2
            ++fmt;
            if (h->timestamp == lh->timestamp) {
				//fmt=3
                ++fmt;
            }
        }
        timestamp = h->timestamp - lh->timestamp;
    } else {
        timestamp = h->timestamp;
    }

    /*if (lh) {
        *lh = *h;
        lh->mlen = mlen;
    }*/

    hsize = hdrsize[fmt];

    ngx_log_debug8(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "RTMP prep %s (%d) fmt=%d csid=%uD timestamp=%uD "
            "mlen=%uD msid=%uD nbufs=%d",
            ngx_rtmp_message_type(h->type), (int)h->type, (int)fmt,
            h->csid, timestamp, mlen, h->msid, nbufs);

    ext_timestamp = 0;
    if (timestamp >= 0x00ffffff) {
        ext_timestamp = timestamp;
        timestamp = 0x00ffffff;
        hsize += 4;
    }

    if (h->csid >= 64) {
        ++hsize;
        if (h->csid >= 320) {
            ++hsize;
        }
    }

    /* fill initial header */
    out->buf->pos -= hsize;
    p = out->buf->pos;

    /* basic header */
    *p = (fmt << 6);
    if (h->csid >= 2 && h->csid <= 63) {
        *p++ |= (((uint8_t)h->csid) & 0x3f);
    } else if (h->csid >= 64 && h->csid < 320) {
        ++p;
        *p++ = (uint8_t)(h->csid - 64);
    } else {
        *p++ |= 1;
        *p++ = (uint8_t)(h->csid - 64);
        *p++ = (uint8_t)((h->csid - 64) >> 8);
    }

    /* create fmt3 header for successive fragments */
    thsize = p - out->buf->pos;
    ngx_memcpy(th, out->buf->pos, thsize);
    th[0] |= 0xc0;

    /* message header */
    if (fmt <= 2) {
        pp = (u_char*)&timestamp;
        *p++ = pp[2];
        *p++ = pp[1];
        *p++ = pp[0];
        if (fmt <= 1) {
            pp = (u_char*)&mlen;
            *p++ = pp[2];
            *p++ = pp[1];
            *p++ = pp[0];
            *p++ = h->type;
            if (fmt == 0) {
                pp = (u_char*)&h->msid;
                *p++ = pp[0];
                *p++ = pp[1];
                *p++ = pp[2];
                *p++ = pp[3];
            }
        }
    }

    /* extended header */
    if (ext_timestamp) {
        pp = (u_char*)&ext_timestamp;
        *p++ = pp[3];
        *p++ = pp[2];
        *p++ = pp[1];
        *p++ = pp[0];

        /* This CONTRADICTS the standard
         * but that's the way flash client
         * wants data to be encoded;
         * ffmpeg complains */
        if (cscf->play_time_fix) {
            ngx_memcpy(&th[thsize], p - 4, 4);
            thsize += 4;
        }
    }

    /* append headers to successive fragments */
    for(out = out->next; out; out = out->next) {
        out->buf->pos -= thsize;
        ngx_memcpy(out->buf->pos, th, thsize);
    }
}


ngx_int_t
ngx_rtmp_send_message(ngx_rtmp_session_t *s, ngx_chain_t *out,
        ngx_uint_t priority)
{
    ngx_uint_t                      nmsg;

// s->out_queue为rtmp core配置中out_queue配置，默认为256.在ngx_rtmp_init_session中分配了out_queue个ngx_chain_t指针
    nmsg = (s->out_last - s->out_pos) % s->out_queue + 1;


	/*
	如果是视频内容，则priority由frametype决定:
	视频framtype:
	1. key fram 关键帧
	2. inter frame 非关键帧
	3. disponsable inter frame
	4. generated key frame
	5. video info/command frame
	*/
    if (priority > 3) {
        priority = 3;
    }

    /* drop packet?
     * Note we always leave 1 slot free */
    if (nmsg + priority * s->out_queue / 4 >= s->out_queue) {
        ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                "RTMP drop message bufs=%ui, priority=%ui",
                nmsg, priority);
        return NGX_AGAIN;
    }

    s->out[s->out_last++] = out;
	//取模是为了wrapp around
    s->out_last %= s->out_queue;

    //增加shared buffer 中的ref引用计数
    ngx_rtmp_acquire_shared_chain(out);

    ngx_log_debug3(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "RTMP send nmsg=%ui, priority=%ui #%ui",
            nmsg, priority, s->out_last);
    //如果live模块配置了buffer指令，则s->out_buffer为1，否则为0
    //out_cork默认值为out_queue的八分之一，所以在out_queue采用默认设置即256时，out_cork为32.
    if (priority && s->out_buffer && nmsg < s->out_cork) {
        return NGX_OK;
    }

    if (!s->connection->write->active) {
        ngx_rtmp_send(s->connection->write);
        /*return ngx_add_event(s->connection->write, NGX_WRITE_EVENT, NGX_CLEAR_EVENT);*/
    }

    return NGX_OK;
}

/* ngx_rtmp_receive_message负责调用具体的消息处理函数。
ngx_rtmp_core_main_conf_t->events是一个ngx_array_t类型的数组，数组里每一个ngx_array_t元素，代表了
接收到的消息类型的处理序列。每一个对应的消息的处理序列，也是一个由不同的处理函数组成的数组。
ngx_rtmp_receive_message根据接收到的消息类型，找到events里对应的消息处理序列的入口，在顺序
调用该消息处理序列里所有的处理函数。

例如，对于视频消息，其消息类型为8，所以为调用ngx_rtmp_core_main_conf_t->events第八个元素里的所有函数，
即ngx_rtmp_codec_av、
ngx_rtmp_record_av、
ngx_rtmp_live_av、
ngx_rtmp_hls_video、
ngx_rtmp_dash_video
*/
ngx_int_t
ngx_rtmp_receive_message(ngx_rtmp_session_t *s,
        ngx_rtmp_header_t *h, ngx_chain_t *in)
{
    ngx_rtmp_core_main_conf_t  *cmcf;
    ngx_array_t                *evhs;
    size_t                      n;
    ngx_rtmp_handler_pt        *evh;

    cmcf = ngx_rtmp_get_module_main_conf(s, ngx_rtmp_core_module);

#ifdef NGX_DEBUG
    {
        int             nbufs;
        ngx_chain_t    *ch;

        for(nbufs = 1, ch = in;
                ch->next;
                ch = ch->next, ++nbufs);

        ngx_log_debug7(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                "RTMP recv %s (%d) csid=%D timestamp=%D "
                "mlen=%D msid=%D nbufs=%d",
                ngx_rtmp_message_type(h->type), (int)h->type,
                h->csid, h->timestamp, h->mlen, h->msid, nbufs);
    }
#endif

    if (h->type > NGX_RTMP_MSG_MAX) {
        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                "unexpected RTMP message type: %d", (int)h->type);
        return NGX_OK;
    }

    evhs = &cmcf->events[h->type];
    evh = evhs->elts;

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "nhandlers: %d", evhs->nelts);

    for(n = 0; n < evhs->nelts; ++n, ++evh) {
        if (!evh) {
            continue;
        }
        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                "calling handler %d", n);
/*

ngx_rtmp_amf_message_handler
*/
        switch ((*evh)(s, h, in)) {
            case NGX_ERROR:
                ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                        "handler %d failed", n);
                return NGX_ERROR;
            case NGX_DONE:
                return NGX_OK;
        }
    }

    return NGX_OK;
}


ngx_int_t
ngx_rtmp_set_chunk_size(ngx_rtmp_session_t *s, ngx_uint_t size)
{
    ngx_rtmp_core_srv_conf_t           *cscf;
    ngx_chain_t                        *li, *fli, *lo, *flo;
    ngx_buf_t                          *bi, *bo;
    ngx_int_t                           n;

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
        "setting chunk_size=%ui", size);

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    s->in_old_pool = s->in_pool;
    s->in_chunk_size = size;
    s->in_pool = ngx_create_pool(4096, s->connection->log);

    /* copy existing chunk data */
    if (s->in_old_pool) {
        s->in_chunk_size_changing = 1;
        s->in_streams[0].in = NULL;

        for(n = 1; n < cscf->max_streams; ++n) {
            /* stream buffer is circular
             * for all streams except for the current one
             * (which caused this chunk size change);
             * we can simply ignore it */
            li = s->in_streams[n].in;
            if (li == NULL || li->next == NULL) {
                s->in_streams[n].in = NULL;
                continue;
            }
            /* move from last to the first */
            li = li->next;
            fli = li;
            lo = ngx_rtmp_alloc_in_buf(s);
            if (lo == NULL) {
                return NGX_ERROR;
            }
            flo = lo;
            for ( ;; ) {
                bi = li->buf;
                bo = lo->buf;

                if (bo->end - bo->last >= bi->last - bi->pos) {
                    bo->last = ngx_cpymem(bo->last, bi->pos,
                            bi->last - bi->pos);
                    li = li->next;
                    if (li == fli)  {
                        lo->next = flo;
                        s->in_streams[n].in = lo;
                        break;
                    }
                    continue;
                }

                bi->pos += (ngx_cpymem(bo->last, bi->pos,
                            bo->end - bo->last) - bo->last);
                lo->next = ngx_rtmp_alloc_in_buf(s);
                lo = lo->next;
                if (lo == NULL) {
                    return NGX_ERROR;
                }
            }
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_finalize_set_chunk_size(ngx_rtmp_session_t *s)
{
    if (s->in_chunk_size_changing && s->in_old_pool) {
        ngx_destroy_pool(s->in_old_pool);
        s->in_old_pool = NULL;
        s->in_chunk_size_changing = 0;
    }
    return NGX_OK;
}


