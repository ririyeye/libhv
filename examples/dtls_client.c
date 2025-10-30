/*
 * dtls client
 *
 * @build   make examples
 * @server  bin/dtls_echo_server 1234
 * @client  bin/dtls_client 127.0.0.1 1234
 *
 */

#include "hloop.h"
#include "hsocket.h"
#include "hthread.h"

static const char* host = "127.0.0.1";
static int port = 1234;
static hio_t* io = NULL;

static void on_recv(hio_t* io, void* buf, int readbytes) {
    printf("< %.*s", readbytes, (char*)buf);
}

static void send_heartbeat(hio_t* io) {
    static int cnt = 0;
    char buf[64];
    int len = snprintf(buf, sizeof(buf), "PING %d\n", ++cnt);
    printf("> %s", buf);
    hio_write(io, buf, len);
}

static void on_stdin(hio_t* stdin_io, void* buf, int readbytes) {
    printf("> %.*s", readbytes, (char*)buf);
    hio_write(io, buf, readbytes);
}

int main(int argc, char** argv) {
    if (argc < 3) {
        printf("Usage: %s host port\n", argv[0]);
        return -10;
    }
    host = argv[1];
    port = atoi(argv[2]);

    hloop_t* loop = hloop_new(0);

    // dtls client
    io = hloop_create_dtls_client(loop, host, port);
    if (io == NULL) {
        return -20;
    }
    printf("dtls client connect to %s:%d\n", host, port);
    hio_setcb_read(io, on_recv);
    hio_read(io);

    // uncomment to test heartbeat
    // hio_set_heartbeat(io, 3000, send_heartbeat);

    // stdin use default readbuf
    hread(loop, 0, NULL, 0, on_stdin);

    hloop_run(loop);
    hloop_free(&loop);
    return 0;
}
