/*
 * dtls server test (C++)
 *
 * @build   make examples
 * @server  bin/dtls_server_test 1234
 * @client  bin/dtls_client 127.0.0.1 1234
 *
 */

#include "DtlsServer.h"

using namespace hv;

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s port\n", argv[0]);
        return -10;
    }
    int port = atoi(argv[1]);

    DtlsServer srv;
    int bindfd = srv.createsocket(port);
    if (bindfd < 0) {
        printf("Failed to bind port %d\n", port);
        return -20;
    }
    printf("dtls server listening on port %d, sockfd=%d\n", port, bindfd);
    
    srv.onMessage = [&srv](const SocketChannelPtr& channel, Buffer* buf) {
        // echo
        printf("< %.*s", (int)buf->size(), (char*)buf->data());
        printf("> %.*s", (int)buf->size(), (char*)buf->data());
        srv.sendto(buf);
    };
    
    srv.start();

    // press Enter to stop
    while (getchar() != '\n');
    return 0;
}
