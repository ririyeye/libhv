/*
 * dtls chat server (broadcast style)
 * Build: cmake -DWITH_OPENSSL=ON -DWITH_DTLS=ON .. && make
 * Run:   bin/dtls_chat_server 12345
 * Client: use dtls_chat_client or modify nc (no native dtls)
 */

#include "hloop.h"
#include "hssl.h"
#include "hbase.h"     // hv_rand, HV_ALLOC/HV_FREE
#include "hsocket.h"   // SOCKADDR_STRLEN, SOCKADDR_STR
#include "list.h"

#if !WITH_DTLS
#error "Need -DWITH_DTLS=ON"
#endif

typedef struct conn_s {
    hio_t* io;
    struct list_node node;
    char addr[SOCKADDR_STRLEN];
} conn_t;

static struct list_head g_conns;
static int g_roomid = 0;

static void broadcast(const char* msg, int len) {
    struct list_node* n; conn_t* c;
    list_for_each(n, &g_conns) {
        c = list_entry(n, conn_t, node);
        hio_write(c->io, msg, len);
    }
}

static void on_close(hio_t* io) {
    conn_t* c = (conn_t*)hevent_userdata(io);
    if (!c) return;
    list_del(&c->node);
    char msg[256];
    int m = snprintf(msg, sizeof(msg), "client[%s] leave room[%06d]\n", c->addr, g_roomid);
    broadcast(msg, m);
    HV_FREE(c);
}

static void on_recv(hio_t* io, void* buf, int len) {
    conn_t* c = (conn_t*)hevent_userdata(io);
    char msg[512];
    int m = snprintf(msg, sizeof(msg), "client[%s] say: %.*s", c->addr, len, (char*)buf);
    broadcast(msg, m);
}

static void on_accept(hio_t* io) {
    char l[SOCKADDR_STRLEN]={0}, p[SOCKADDR_STRLEN]={0};
    printf("[DTLS] accept fd=%d %s <= %s\n", hio_fd(io),
           SOCKADDR_STR(hio_localaddr(io), l),
           SOCKADDR_STR(hio_peeraddr(io), p));
    conn_t* c = NULL; HV_ALLOC_SIZEOF(c);
    strcpy(c->addr, p);
    c->io = io;
    hevent_set_userdata(io, c);
    list_add(&c->node, &g_conns);
    char msg[256];
    int m = snprintf(msg, sizeof(msg), "client[%s] join room[%06d]\n", c->addr, g_roomid);
    broadcast(msg, m);
    hio_setcb_read(io, on_recv);
    hio_setcb_close(io, on_close);
    hio_read_start(io);
}

int main(int argc, char** argv) {
    if (argc < 2) { printf("Usage: %s port\n", argv[0]); return -1; }
    int port = atoi(argv[1]);
    list_init(&g_conns);
    g_roomid = hv_rand(100000, 999999);

    hloop_t* loop = hloop_new(0);
    hio_t* listenio = hloop_create_dtls_server(loop, "0.0.0.0", port, on_accept);
    if (!listenio) { fprintf(stderr, "create dtls server failed\n"); return -2; }
    hssl_ctx_opt_t opt; memset(&opt, 0, sizeof(opt));
    opt.crt_file = "cert/server.crt"; opt.key_file = "cert/server.key"; opt.endpoint = HSSL_SERVER;
    if (hio_new_ssl_ctx(listenio, &opt) != 0) { fprintf(stderr, "ssl ctx failed\n"); return -3; }
    printf("[DTLS] chat server listenfd=%d room=%06d port=%d\n", hio_fd(listenio), g_roomid, port);
    hloop_run(loop);
    hloop_free(&loop);
    return 0;
}
