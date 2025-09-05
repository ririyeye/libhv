/*
 * dtls chat client
 * Build: cmake -DWITH_OPENSSL=ON -DWITH_DTLS=ON .. && make
 * Run:   bin/dtls_chat_client 127.0.0.1 12345
 */

#include "hloop.h"
#include "hssl.h"

#if !WITH_DTLS
#error "Need -DWITH_DTLS=ON"
#endif

static void on_close(hio_t* io) {
    printf("connection closed fd=%d error=%d\n", hio_fd(io), hio_error(io));
}

static void on_recv(hio_t* io, void* buf, int len) {
    printf("%.*s", len, (char*)buf);
}

static void stdin_read_cb(hio_t* io, void* buf, int len) {
    hio_t* peer = (hio_t*)hevent_userdata(io);
    if (!peer) return;
    if (len <= 0) {
        hio_close(peer);
        return;
    }
    hio_write(peer, buf, len);
}

static void on_connect(hio_t* io) {
    printf("connected. type=%d fd=%d\n", hio_type(io), hio_fd(io));
    hio_setcb_read(io, on_recv);
    hio_setcb_close(io, on_close);
    hio_read_start(io);

    // attach stdin listener
    hloop_t* loop = hevent_loop(io);
    hio_t* stdio = hio_get(loop, 0); // stdin fd=0
    hevent_set_userdata(stdio, io);
    hio_setcb_read(stdio, stdin_read_cb);
    hio_read_start(stdio);
}

int main(int argc, char** argv) {
    if (argc < 3) {
        printf("Usage: %s host port\n", argv[0]);
        return -1;
    }
    const char* host = argv[1];
    int port = atoi(argv[2]);
    hloop_t* loop = hloop_new(0);
    hio_t* io = hloop_create_dtls_client(loop, host, port, on_connect, on_close);
    if (!io) {
        fprintf(stderr, "create dtls client failed\n");
        return -2;
    }
    hssl_ctx_opt_t opt;
    memset(&opt, 0, sizeof(opt));
    opt.endpoint = HSSL_CLIENT;
    opt.verify_peer = 0; // for test
    if (hio_new_ssl_ctx(io, &opt) != 0) {
        fprintf(stderr, "ssl ctx failed\n");
        return -3;
    }
    hloop_run(loop);
    hloop_free(&loop);
    return 0;
}
