
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_rtmp.h"

/*
该函数分配一段连续的内存，该内存布局按顺序如下:
(1)1个整数:用来表示该共享缓冲区的引用计数，初始化为1.
(2)一个ngx_chain_t类型的结构体
(3)一个ngx_buf_t类型的结构体
(4)一段NGX_RTMP_MAX_CHUNK_HEADER + cscf->chunk_size大小的内存，作为数据区。
其中，ngx_chain_t结构体里的buf指针就指向这个ngx_buf_t结构体；ngx_chain_t结构体里的next置为NULL.
ngx_buf_t结构体里的start指针指向它后面的数据区的起始位置
end指针指向数据区的结束位置。
pos和last指针均指向数据区里，从起始位置往后NGX_RTMP_MAX_CHUNK_HEADER大小的位置.

为了尽可能的节省分配内存带来的开销，如果cscf->free链里有元素，则不用重新分配这个连续内存，直接从free链里取出一个元素即可.

该函数的返回值为指向这段内存的ngx_chain_t类型起始位置的指针。
*/
ngx_chain_t *
ngx_rtmp_alloc_shared_buf(ngx_rtmp_core_srv_conf_t *cscf)
{
    u_char                     *p;
    ngx_chain_t                *out;
    ngx_buf_t                  *b;
    size_t                      size;

    if (cscf->free) {
        out = cscf->free;
        cscf->free = out->next;

    } else {

        size = cscf->chunk_size + NGX_RTMP_MAX_CHUNK_HEADER;

        p = ngx_pcalloc(cscf->pool, NGX_RTMP_REFCOUNT_BYTES
                + sizeof(ngx_chain_t)
                + sizeof(ngx_buf_t)
                + size);
        if (p == NULL) {
            return NULL;
        }

        p += NGX_RTMP_REFCOUNT_BYTES;
        out = (ngx_chain_t *)p;

        p += sizeof(ngx_chain_t);
        out->buf = (ngx_buf_t *)p;

        p += sizeof(ngx_buf_t);
        out->buf->start = p;
        out->buf->end = p + size;
    }

    out->next = NULL;
    b = out->buf;
	/*b->pos指向message body*/
    b->pos = b->last = b->start + NGX_RTMP_MAX_CHUNK_HEADER;
    b->memory = 1;

    /* buffer has refcount =1 when created! */
    ngx_rtmp_ref_set(out, 1);

    return out;
}


/*
该函数的作用是回收in指向的共享缓冲区，但是注意，回收不是说直接将该缓冲区free了。
首先会检查该缓冲区的引用计数，如果该缓冲区的引用计数减一后仍然大于0，则说明该缓冲区当前
不应该被回收，所以该函数直接返回。
如果该缓冲区的引用计数减一后等于0，则说明这个共享缓冲区此时并没有被使用，可以回收。
所谓回收，也只是将这个共享缓冲区挂载在cscf的free链的头部。下次调用ngx_rtmp_alloc_shared_buf时，可以直接使用。

注意，in本身可以是一个链表，而不是仅仅一个ngx_chain_t类型的结构体。也就是说，该函数可以完成一个链表的整体回收。
*/
void
ngx_rtmp_free_shared_chain(ngx_rtmp_core_srv_conf_t *cscf, ngx_chain_t *in)
{
    ngx_chain_t        *cl;

    if (ngx_rtmp_ref_put(in)) {
        return;
    }

    for (cl = in; ; cl = cl->next) {
        if (cl->next == NULL) {
            cl->next = cscf->free;
            cscf->free = in;
            return;
        }
    }
}

/*
1. 当前系统中，只有ngx_rtmp_mp4_send中在调用ngx_rtmp_append_shared_bufs时，有不为NULL的head参数
2. in链参数为一条message的内容，本质是一条普通的chain链
3. head参数要么为NULL(大多数情况也是如此),当其为NULL的时候，将in链重组，重组过程是，调用ngx_rtmp_alloc_shared_buf
   重新分配一个chain链，这个chain链的buffer大小保证了只要一个节点就能保存in链的内容，并且在chain链前分配一个引用计数。
4. head参数如果不为NULL(如ngx_rtmp_mp4_send中)，则head参数不是一个普通的chain链，而是用ngx_rtmp_alloc_shared_buf分配过的chain链，
   主要是buffer大小、引用计数两个特点与普通chain链不同
*/
ngx_chain_t *
ngx_rtmp_append_shared_bufs(ngx_rtmp_core_srv_conf_t *cscf,
        ngx_chain_t *head, ngx_chain_t *in)
{
    ngx_chain_t                    *l, **ll;
    u_char                         *p;
    size_t                          size;

    ll = &head;
    p = in->buf->pos;
    l = head;

    if (l) {
        for(; l->next; l = l->next);
        ll = &l->next;
    }

    for ( ;; ) {

        if (l == NULL || l->buf->last == l->buf->end) {
            l = ngx_rtmp_alloc_shared_buf(cscf);
            if (l == NULL || l->buf == NULL) {
                break;
            }

            *ll = l;
            ll = &l->next;
        }

        while (l->buf->end - l->buf->last >= in->buf->last - p) {
            l->buf->last = ngx_cpymem(l->buf->last, p,
                    in->buf->last - p);
            in = in->next;
            if (in == NULL) {
                goto done;
            }
            p = in->buf->pos;
        }

        size = l->buf->end - l->buf->last;
        l->buf->last = ngx_cpymem(l->buf->last, p, size);
        p += size;
    }

done:
    *ll = NULL;

    return head;
}
