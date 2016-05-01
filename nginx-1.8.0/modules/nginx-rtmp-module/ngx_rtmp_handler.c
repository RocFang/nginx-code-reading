
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

/* rtmp �������߼� */
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
	//����ping�Ķ�ʱ����Ĭ��Ϊ60s,ping_timeoutĬ��Ϊ30s
    ngx_rtmp_reset_ping(s);

    ngx_rtmp_recv(c->read);
}

/*
����һ��ngx_chain_t��һ��ngx_buf_t���ڴ�
��Ϊngx_buf_tһ������´�СΪ128+18=146�ֽڵ��ڴ档
ngx_chaint_t��bufָ��ָ���ngx_buf_t�ṹ.
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
		// ����chain��
		// ע�⣬���һ�ε���recv����һ��chunkʱ��û�����꣬�ٴν����ѭ����ʱ��st->in��ΪNULL,����������µ�buffer��
		//���ǣ����һ��message��Ϊ���chunk����һ��chunk�����꣬�ٴν����ѭ���������һ��chunkʱ����Ҫ�����
		//������ٴη���һ���ڴ���װ�µ�chunk
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
// ����һ��rtmp chunk
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

        /* ��ʼ����ͷ��parse headers */
		//��һ��chunkû��һ�ν����꣬�ٴν���ѭ�����ڿ�ʼ����ʱ������ִ������Ĵ���顣
        if (b->pos == b->start) {
            p = b->pos;

            /* chunk basic header */
			//��ȡchunk stream id
			//fmt��basic header �ĸ���λ
            fmt  = (*p >> 6) & 0x03;
			//��ȡ��һ���ֽ��г���fmt���ʣ��6λ��ע�⣬��ʱ��һ����csid�������csidֻ��һ����ʱ��
            csid = *p++ & 0x3f;
			
            //fmt����6λΪ0����ʾbasic chunk header ��2���ֽڳ�.
            //��һ���ֽڵ�ǰ��λΪfmt,����6λΪ0��csid�ڵڶ����ֽڱ�ʾ���ڶ����ֽڵ���ֵ=csid-64����
            //csid���ڵڶ����ֽڵ���ֵ��64.p++��ʼָ��basic chunk header�����message header.
            if (csid == 0) {
                if (b->last - p < 1)
                    continue;
                csid = 64;
                csid += *(uint8_t*)p++;

            } else if (csid == 1) {
            //fmt����6λΪ1����ʾbasic chunk header ��3���ֽڳ�
            //��һ���ֽڵ�ǰ��λΪfmt,����6λΪ1��csid�ڵڶ����͵������ֽ��������ֽ��б�ʾ���������ֽڵ�ֵ����
            //csid-64.����csid=���������ֽڱ�ʾ������ֵ+64.
            // p���Ҳָ��basic chunk header ����� message header.
                if (b->last - p < 2)
                    continue;
                csid = 64;
                csid += *(uint8_t*)p++;
                csid += (uint32_t)256 * (*(uint8_t*)p++);
            }

            //��ʱ��csid���ǽ������֮��������csid.
            ngx_log_debug2(NGX_LOG_DEBUG_RTMP, c->log, 0,
                    "RTMP bheader fmt=%d csid=%D",
                    (int)fmt, csid);
            // ϵͳĬ�ϵ�max_streamΪ32.
            if (csid >= (uint32_t)cscf->max_streams) {
                ngx_log_error(NGX_LOG_INFO, c->log, 0,
                    "RTMP in chunk stream too big: %D >= %D",
                    csid, cscf->max_streams);
                ngx_rtmp_finalize_session(s);
                return;
            }

            /* link orphan */
			//Ĭ��δ����ʱΪ0
            if (s->in_csid == 0) {

                /* unlink from stream #0 */
                st->in = st->in->next;

                /* link to new stream */
				// ������������csid������s->in_csid�У���ʾ�ӿͻ��˽��յ���chunk��basic chunk header���csid.
                s->in_csid = csid;
				//ע������st�Ѿ�����
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

			//fmt����Ϊ0��1��2��3�����������ͬ����£�basic chunk header �����message header��ʽ��ͬ��
			//����֮ǰ�Ľ�����p����ָ��basic chunk header�����message header.
            if (fmt <= 2 ) {
				//��fmtΪ0ʱ��message header��ǰ�����ֽ�Ϊtimestamp
				//��fmtΪ1ʱ��message header��ǰ�����ֽ�Ϊtimestamp delta
				//��fmtΪ2ʱ��message header��ǰ�����ֽ�Ϊtimestamp delta
                if (b->last - p < 3)
                    continue;
                /* timestamp:
                //��pָ��������ֽ�(���)��ת��Ϊһ������
                 *  big-endian 3b -> little-endian 4b */
                pp = (u_char*)&timestamp;
                pp[2] = *p++;
                pp[1] = *p++;
                pp[0] = *p++;
                pp[3] = 0;
                //���timestamp��������Ϊ0x00ffffff����˵�������ֽڲ��ܱ�ʾtimestamp��Ҫ����չλ.ext
                //�Ǹ���־λ����ʾ�Ƿ���Ҫ��չʱ���.
                //��ʱ,p�Ѿ�����ƶ��������ֽڡ�
                ext = (timestamp == 0x00ffffff);

                if (fmt <= 1) {
				//����ǰ�����timestamp����ʱp�Ѿ�����ƶ��������ֽڡ�
				//���fmpΪ0��1��timestamp����������ֽ�������ʾmessage length����������һ���ֽ�����ʾmessage type id.
                    if (b->last - p < 4)
                        continue;
                    /* size:
                     *  big-endian 3b -> little-endian 4b
                     * type:
                     *  1b -> 1b*/
                    // �����������ֽڱ�ʾ��message length
                    pp = (u_char*)&h->mlen;
                    pp[2] = *p++;
                    pp[1] = *p++;
                    pp[0] = *p++;
                    pp[3] = 0;
					// ��һ���ֽ�װ��message type id.
                    h->type = *(uint8_t*)p++;

                    if (fmt == 0) {
					//���fmtΪ0����message type id���������4���ֽڱ�ʾmessage stream id.
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
			//���ǰ������������ֽڱ�ʾ��ʱ���Ϊ0xffffff����˵�������ֽ��޷���������ʱ�������Ҫʹ����չʱ�����
			//��չʱ�������еĻ���������message header���棬��4���ֽڱ�ʾ��
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
				//�����st->lenΪ0.
				
                /* Messages with type=3 should
                 * never have ext timestamp field
                 * according to standard.
                 * However that's not always the case
                 * in real life */
// ������������˵�����ο�:http://nginx-rtmp.blogspot.hk/2012/03/hello-world.html
				//cscf->publish_time_fixĬ�Ͽ�������Ϊ1
                st->ext = (ext && cscf->publish_time_fix);
                if (fmt) {
	//dtime��ʾtimestamp delta������һ��chunk,��basic chunk header�е�fmtΪ0ʱ��
	//basic chunk header�����message header��ǰ�����ֽڱ�ʾtimestamp����fmtΪ1��2ʱ�����������ֽڱ�ʾtimestamp delta.
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
			//��ʱ�Ѿ���������chunk header��pָ��chunk data�ˣ�b->posҲ��ָ��chunk�塣
            b->pos = p;
            //���message length��С�Ƿ񳬹�����
            //max_messageĬ��Ϊ1M����max_messageָ�����á�
            if (h->mlen > cscf->max_message) {
                ngx_log_error(NGX_LOG_INFO, c->log, 0,
                        "too big message: %uz", cscf->max_message);
                ngx_rtmp_finalize_session(s);
                return;
            }
        }

        //  chunk ͷ�ĸ������Ѿ�������ϣ�b->pos��ʱָ��chunk �����ʼλ��.
        // size ��ʾ���ν��յ�chunk���ʵ�ʳ��ȣ��п���С��һ��Լ����chunk size(128�ֽ�)
        size = b->last - b->pos;
		// mlen ��ʾmessage length,��ʼ��ʱ��st->lenΪ0������fsize��ʼΪmessage length.
		//������һ��message ���и�ɶ��chunk�������ٴν���ѭ��ʱ��fsize��ʾ����Ϣʣ�µĳ���
        fsize = h->mlen - st->len;
        // s->in_chunk_size��ʾЭ��˫��Լ����chunk��Ĵ�С
        if (size < ngx_min(fsize, s->in_chunk_size))
			//���ν��յ����Ѿ�����ڻ�������chunk�壬���С��message length��chunk size�Ľ�С�ߵĻ�
			//˵�����ν���û����ɣ���Ҫ�������ա�
            continue;

        /* buffer is ready */

		//��ʱһ��chunk���������ݶ��Ѿ��������
		//��һ��ʱ��fsizeΪmessage length
        if (fsize > s->in_chunk_size) {
			//˵��һ����Ϣ���ֳ��˶��chunk
            /* collect fragmented chunks */
            st->len += s->in_chunk_size;
            b->last = b->pos + s->in_chunk_size;
            old_pos = b->last;
            old_size = size - s->in_chunk_size;

        } else {
            /* handle! */
            head = st->in->next;

			//ע�⣬������һ����Ϊ��Ҫ���ڴ�֮ǰ��һ��chunk stream���һ��message���ɶ��chunk��ɣ�ÿ��chunk
			//��һ��ngx_chain_t��st��inָ���������һ��chunk�����һ��chunk��next��ָ���һ��chunk,��һ��chunkָ��ڶ���chunk...
			//�����ڶ���chunk��next��ָ�����һ��chunk�������γ���һ������ head = st->in->next;��ʱheadָ���һ��chunk.��ʱheadָ���
			//��Ȼ��һ��ngx_chain_t��������������һ��st->in->next = NULL;֮�󣬾ͽ����⿪�ˣ������һ����������
            st->in->next = NULL;
            b->last = b->pos + fsize;
            old_pos = b->last;
            old_size = size - fsize;
            st->len = 0;
            h->timestamp += st->dtime;
			//����ngx_rtmp_amf_message_handler/ngx_rtmp_codec_av

			//sΪ��ngx_rtmp_session_t�ṹ�壬hΪ����Ϣ��ngx_rtmp_header_t
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
Ϊһ��message����chunkͷ��lh������ǰһ��message��ͷ��������ǰһ��ͷ����������ǰ��Ϣ��ͷ����fmt������������ǰ�����Ͱ���chunkͷ�е�
��Ϣͷ
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
    // fmtӰ�����chunk��message header������
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

// s->out_queueΪrtmp core������out_queue���ã�Ĭ��Ϊ256.��ngx_rtmp_init_session�з�����out_queue��ngx_chain_tָ��
    nmsg = (s->out_last - s->out_pos) % s->out_queue + 1;


	/*
	�������Ƶ���ݣ���priority��frametype����:
	��Ƶframtype:
	1. key fram �ؼ�֡
	2. inter frame �ǹؼ�֡
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
	//ȡģ��Ϊ��wrapp around
    s->out_last %= s->out_queue;

    //����shared buffer �е�ref���ü���
    ngx_rtmp_acquire_shared_chain(out);

    ngx_log_debug3(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "RTMP send nmsg=%ui, priority=%ui #%ui",
            nmsg, priority, s->out_last);
    //���liveģ��������bufferָ���s->out_bufferΪ1������Ϊ0
    //out_corkĬ��ֵΪout_queue�İ˷�֮һ��������out_queue����Ĭ�����ü�256ʱ��out_corkΪ32.
    if (priority && s->out_buffer && nmsg < s->out_cork) {
        return NGX_OK;
    }

    if (!s->connection->write->active) {
        ngx_rtmp_send(s->connection->write);
        /*return ngx_add_event(s->connection->write, NGX_WRITE_EVENT, NGX_CLEAR_EVENT);*/
    }

    return NGX_OK;
}

/* ngx_rtmp_receive_message������þ������Ϣ��������
ngx_rtmp_core_main_conf_t->events��һ��ngx_array_t���͵����飬������ÿһ��ngx_array_tԪ�أ�������
���յ�����Ϣ���͵Ĵ������С�ÿһ����Ӧ����Ϣ�Ĵ������У�Ҳ��һ���ɲ�ͬ�Ĵ�������ɵ����顣
ngx_rtmp_receive_message���ݽ��յ�����Ϣ���ͣ��ҵ�events���Ӧ����Ϣ�������е���ڣ���˳��
���ø���Ϣ�������������еĴ�������

���磬������Ƶ��Ϣ������Ϣ����Ϊ8������Ϊ����ngx_rtmp_core_main_conf_t->events�ڰ˸�Ԫ��������к�����
��ngx_rtmp_codec_av��
ngx_rtmp_record_av��
ngx_rtmp_live_av��
ngx_rtmp_hls_video��
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


