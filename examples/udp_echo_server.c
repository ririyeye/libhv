/*
 * udp echo server
 *
 * @build   make examples
 * @server  bin/udp_echo_server 1234
 * @client  bin/nc -u 127.0.0.1 1234
 *          nc     -u 127.0.0.1 1234
 *
 */

#include "hloop.h"
#include "hsocket.h"

/*
 * @test    kcp_server
 * #define  TEST_KCP 1
 *
 * @build   ./configure --with-kcp && make clean && make
 * @server  bin/udp_echo_server 1234
 * @client  bin/nc -k 127.0.0.1 1234
 *
 */
#define TEST_KCP 0
#define TEST_SSL 1

static void on_recvfrom(hio_t* io, void* buf, int readbytes) {
    printf("on_recvfrom fd=%d readbytes=%d\n", hio_fd(io), readbytes);
    char localaddrstr[SOCKADDR_STRLEN] = {0};
    char peeraddrstr[SOCKADDR_STRLEN] = {0};
    printf("[%s] <=> [%s]\n",
            SOCKADDR_STR(hio_localaddr(io), localaddrstr),
            SOCKADDR_STR(hio_peeraddr(io), peeraddrstr));

    char* str = (char*)buf;
    printf("< %.*s", readbytes, str);
    // echo
    printf("> %.*s", readbytes, str);
    hio_write(io, buf, readbytes);

#if TEST_KCP
    if (strncmp(str, "CLOSE", 5) == 0) {
        hio_close_rudp(io, hio_peeraddr(io));
    }
#endif
}

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("Usage: %s port|path\n", argv[0]);
        return -10;
    }
    const char* host = "0.0.0.0";
    int port = atoi(argv[1]);
#if ENABLE_UDS
    if (port == 0) {
        host = argv[1];
        port = -1;
    }
#endif

    hloop_t* loop = hloop_new(0);
#if TEST_SSL
    hio_t* io = hloop_create_dtls_server(loop, host, port);
#else
    hio_t* io = hloop_create_udp_server(loop, host, port);
#endif
    if (io == NULL) {
        return -20;
    }
#if TEST_KCP
    hio_set_kcp(io, NULL);
#endif

#if TEST_SSL
    hssl_ctx_opt_t ssl_param;
    memset(&ssl_param, 0, sizeof(ssl_param));
    ssl_param.crt_file = "cert/server.crt";
    ssl_param.key_file = "cert/server.key";
    ssl_param.endpoint = HSSL_SERVER;
    if (hio_new_ssl_ctx(io, &ssl_param) != 0) {
        fprintf(stderr, "hssl_ctx_new failed!\n");
        return -30;
    }
#endif

    hio_setcb_read(io, on_recvfrom);
    hio_read(io);
    hloop_run(loop);
    hloop_free(&loop);
    return 0;
}
