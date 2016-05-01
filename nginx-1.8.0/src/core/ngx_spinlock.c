
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


void
ngx_spinlock(ngx_atomic_t *lock, ngx_atomic_int_t value, ngx_uint_t spin)
{

#if (NGX_HAVE_ATOMIC_OPS)

    ngx_uint_t  i, n;
	// �޷���ȡ��ʱ���̵Ĵ��뽫һֱ�����ѭ����ִ��
    for ( ;; ) {
		// lockΪ0ʱ��ʾ����û�б��������̳��еģ���ʱ��lockֵ��Ϊvalue������ʾ��ǰ���̳�������
        if (*lock == 0 && ngx_atomic_cmp_set(lock, 0, value)) {
            return;
        }
		// ngx_ncpu�Ǵ������ĸ�������������1ʱ��ʾ���ڶദ����ϵͳ��
        if (ngx_ncpu > 1) {
			/*�ڶദ�����£����õ������ǵ�ǰ���̲�Ҫ���̡��ó�������ʹ�õ�CPU��������
			���ǵȴ�һ��ʱ�䣬���������������ϵĽ����Ƿ���ͷ����������ٽ��̼��л��Ĵ���*/
            for (n = 1; n < spin; n <<= 1) {
				/*ע�⣬���ŵȴ��Ĵ���Խ��Խ�࣬ʵ��ȥ���lock�Ƿ��ͷŵ�Ƶ����Խ��ԽС��
				Ϊʲô�������أ���Ϊ���lockֵ������CPU����ִ��ngx_cpu_pause����CPU���ܺ���˵�Ǻ�ʡ���*/
                for (i = 0; i < n; i++) {
					 /*ngx_cpu_pause�������ܹ���ϵ��ר��Ϊ�����������ṩ��ָ�
					 �������CPU���ڴ����������ȴ�״̬��ͨ��һЩCPU�Ὣ�Լ����ڽ���״̬��
					 ���͹��ġ�ע�⣬��ִ��ngx_cpu_pause�󣬵�ǰ����û�С��ó�����ʹ�õĴ�����*/
                    ngx_cpu_pause();
                }
				/*������Ƿ��ͷ��ˣ����lockֵΪ0���ͷ������󣬾Ͱ�����ֵ��Ϊvalue����ǰ���̳������ɹ�������*/
                if (*lock == 0 && ngx_atomic_cmp_set(lock, 0, value)) {
                    return;
                }
            }
        }
		/*��ǰ������Ȼ���ڿ�ִ��״̬������ʱ���ó�����������ʹ�ô��������ȵ���������ִ��״̬�Ľ��̣�
		�������ڽ��̱��ں��ٴε���ʱ����forѭ�������п����������������ͷ�����
		ע�⣬��ͬ���ں˰汾����sched_yieldϵͳ���õ�ʵ�ֿ����ǲ�ͬ�ģ������ǵ�Ŀ�Ķ�����ʱ���ó���������*/
        ngx_sched_yield();
    }

#else

#if (NGX_THREADS)

#error ngx_spinlock() or ngx_atomic_cmp_set() are not defined !

#endif

#endif

}
