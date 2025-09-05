/*
 * dtls echo server
 *
 * Build: cmake -DWITH_OPENSSL=ON -DWITH_DTLS=ON .. && make
 * Run:   bin/dtls_echo_server 12345
 * Test:  (no dedicated client) use dtls_echo_client or dtls_client_test
 */

#include "hloop.h"
#include "hssl.h"
#include "hsocket.h"

#if !WITH_DTLS
#error "Rebuild with -DWITH_OPENSSL=ON -DWITH_DTLS=ON to use this example"
#endif

static void on_close(hio_t* io) {
    printf("[DTLS] close fd=%d err=%d\n", hio_fd(io), hio_error(io));
}

static void on_recv(hio_t* io, void* buf, int len) {
    if (len <= 0) return;
    printf("[DTLS] recv fd=%d len=%d: %.*s", hio_fd(io), len, len, (char*)buf);
    hio_write(io, buf, len); // echo
}

static void on_accept(hio_t* io) {
    char l[SOCKADDR_STRLEN] = {0}, p[SOCKADDR_STRLEN] = {0};
    printf("[DTLS] accept fd=%d %s <= %s\n", hio_fd(io), SOCKADDR_STR(hio_localaddr(io), l), SOCKADDR_STR(hio_peeraddr(io), p));
    hio_setcb_close(io, on_close);
    hio_setcb_read(io, on_recv);
    hio_read_start(io);
}

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("Usage: %s port\n", argv[0]);
        return -1;
    }
    int port = atoi(argv[1]);
    hloop_t* loop = hloop_new(0);
    hio_t* listenio = hloop_create_dtls_server(loop, "0.0.0.0", port, on_accept);
    if (!listenio) {
        fprintf(stderr, "create dtls server failed\n");
        return -2;
    }

    hssl_ctx_opt_t opt;
    memset(&opt, 0, sizeof(opt));
    opt.crt_file = "cert/server.crt"; // adjust path if needed
    opt.key_file = "cert/server.key";
    opt.endpoint = HSSL_SERVER;
    if (hio_new_ssl_ctx(listenio, &opt) != 0) {
        fprintf(stderr, "hssl_ctx_new failed\n");
        return -3;
    }
    printf("[DTLS] echo server listenfd=%d port=%d\n", hio_fd(listenio), port);
    hloop_run(loop);
    hloop_free(&loop);
    return 0;
}
