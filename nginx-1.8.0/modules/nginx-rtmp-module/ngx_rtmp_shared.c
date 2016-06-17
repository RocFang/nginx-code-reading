
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_rtmp.h"

/*
�ú�������һ���������ڴ棬���ڴ沼�ְ�˳������:
(1)1������:������ʾ�ù������������ü�������ʼ��Ϊ1.
(2)һ��ngx_chain_t���͵Ľṹ��
(3)һ��ngx_buf_t���͵Ľṹ��
(4)һ��NGX_RTMP_MAX_CHUNK_HEADER + cscf->chunk_size��С���ڴ棬��Ϊ��������
���У�ngx_chain_t�ṹ�����bufָ���ָ�����ngx_buf_t�ṹ�壻ngx_chain_t�ṹ�����next��ΪNULL.
ngx_buf_t�ṹ�����startָ��ָ�������������������ʼλ��
endָ��ָ���������Ľ���λ�á�
pos��lastָ���ָ�������������ʼλ������NGX_RTMP_MAX_CHUNK_HEADER��С��λ��.

Ϊ�˾����ܵĽ�ʡ�����ڴ�����Ŀ��������cscf->free������Ԫ�أ��������·�����������ڴ棬ֱ�Ӵ�free����ȡ��һ��Ԫ�ؼ���.

�ú����ķ���ֵΪָ������ڴ��ngx_chain_t������ʼλ�õ�ָ�롣
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
	/*b->posָ��message body*/
    b->pos = b->last = b->start + NGX_RTMP_MAX_CHUNK_HEADER;
    b->memory = 1;

    /* buffer has refcount =1 when created! */
    ngx_rtmp_ref_set(out, 1);

    return out;
}


/*
�ú����������ǻ���inָ��Ĺ�������������ע�⣬���ղ���˵ֱ�ӽ��û�����free�ˡ�
���Ȼ���û����������ü���������û����������ü�����һ����Ȼ����0����˵���û�������ǰ
��Ӧ�ñ����գ����Ըú���ֱ�ӷ��ء�
����û����������ü�����һ�����0����˵���������������ʱ��û�б�ʹ�ã����Ի��ա�
��ν���գ�Ҳֻ�ǽ������������������cscf��free����ͷ�����´ε���ngx_rtmp_alloc_shared_bufʱ������ֱ��ʹ�á�

ע�⣬in���������һ�����������ǽ���һ��ngx_chain_t���͵Ľṹ�塣Ҳ����˵���ú����������һ�������������ա�
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
1. ��ǰϵͳ�У�ֻ��ngx_rtmp_mp4_send���ڵ���ngx_rtmp_append_shared_bufsʱ���в�ΪNULL��head����
2. in������Ϊһ��message�����ݣ�������һ����ͨ��chain��
3. head����ҪôΪNULL(��������Ҳ�����),����ΪNULL��ʱ�򣬽�in�����飬��������ǣ�����ngx_rtmp_alloc_shared_buf
   ���·���һ��chain�������chain����buffer��С��֤��ֻҪһ���ڵ���ܱ���in�������ݣ�������chain��ǰ����һ�����ü�����
4. head���������ΪNULL(��ngx_rtmp_mp4_send��)����head��������һ����ͨ��chain����������ngx_rtmp_alloc_shared_buf�������chain����
   ��Ҫ��buffer��С�����ü��������ص�����ͨchain����ͬ
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
