static ngx_int_t test_ngx_uint_t(ngx_uint_t a, ngx_uint_t b);  
static ngx_int_t test_ngx_str_t();  
static ngx_int_t test_ngx_palloc();  
static void test_ngx_pool_cleanup();
static void test_ngx_pool_cleanup_2();
static ngx_int_t test_ngx_array();  
static ngx_int_t test_ngx_queue();  
static ngx_int_t yahoo_no_cmp(const ngx_queue_t* p, const ngx_queue_t* n);

typedef struct yahoo_s {
    ngx_queue_t   queue;
} yahoo_t;

typedef struct yahoo_guy_s {
    ngx_uint_t    id;
    u_char*       name;
    ngx_queue_t   queue;
} yahoo_guy_t;

