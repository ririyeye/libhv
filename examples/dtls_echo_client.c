/*
 * dtls echo client
 *
 * Build: cmake -DWITH_OPENSSL=ON -DWITH_DTLS=ON .. && make
 * Run:   bin/dtls_echo_client 127.0.0.1 12345 "hello dtls"
 */

#include "hloop.h"
#include "hssl.h"
#include "hsocket.h"

#if !WITH_DTLS
#error "Rebuild with -DWITH_OPENSSL=ON -DWITH_DTLS=ON to use this example"
#endif

static const char* g_msg = "hello";

static void on_close(hio_t* io) {
    printf("[DTLS] close fd=%d err=%d\n", hio_fd(io), hio_error(io));
}

static void on_read(hio_t* io, void* buf, int len) {
    printf("[DTLS] recv: %.*s\n", len, (char*)buf);
    hio_close(io); // done
}

static void on_connect(hio_t* io) {
    printf("[DTLS] connected fd=%d\n", hio_fd(io));
    hio_setcb_read(io, on_read);
    hio_read_start(io);
    hio_write(io, g_msg, (int)strlen(g_msg));
}

int main(int argc, char** argv) {
    if (argc < 3) {
        printf("Usage: %s host port [msg]\n", argv[0]);
        return -1;
    }
    const char* host = argv[1];
    int port = atoi(argv[2]);
    if (argc > 3) g_msg = argv[3];

    hloop_t* loop = hloop_new(0);
    hio_t* io = hio_create_socket(loop, host, port, HIO_TYPE_UDP, HIO_CLIENT_SIDE);
    if (!io) {
        fprintf(stderr, "socket create failed\n");
        return -2;
    }

    hssl_ctx_opt_t opt;
    memset(&opt, 0, sizeof(opt));
    opt.endpoint = HSSL_CLIENT;
    if (hio_new_ssl_ctx(io, &opt) != 0) {
        fprintf(stderr, "hssl ctx failed\n");
        return -3;
    }
    hio_enable_ssl(io); // will treat UDP as DTLS

    hio_setcb_connect(io, on_connect);
    hio_setcb_close(io, on_close);
    hio_connect(io);

    hloop_run(loop);
    hloop_free(&loop);
    return 0;
}
