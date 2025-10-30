/*
 * dtls client test (C++)
 *
 * @build   make examples  
 * @server  bin/dtls_server_test 1234
 * @client  bin/dtls_client_test 127.0.0.1 1234
 *
 */

#include "DtlsClient.h"

using namespace hv;

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Usage: %s host port\n", argv[0]);
        return -10;
    }
    const char* host = argv[1];
    int port = atoi(argv[2]);

    DtlsClient cli;
    int sockfd = cli.createsocket(port, host);
    if (sockfd < 0) {
        printf("Failed to create socket to %s:%d\n", host, port);
        return -20;
    }
    printf("dtls client connect to %s:%d, sockfd=%d\n", host, port, sockfd);
    
    cli.onMessage = [](const SocketChannelPtr& channel, Buffer* buf) {
        printf("< %.*s", (int)buf->size(), (char*)buf->data());
    };
    
    cli.start();
    
    // send test messages
    const char* msg1 = "Hello DTLS\n";
    const char* msg2 = "Test message 2\n";
    const char* msg3 = "Goodbye DTLS\n";
    
    printf("> %s", msg1);
    cli.sendto(msg1, strlen(msg1));
    sleep(1);
    
    printf("> %s", msg2);
    cli.sendto(msg2, strlen(msg2));
    sleep(1);
    
    printf("> %s", msg3);
    cli.sendto(msg3, strlen(msg3));
    sleep(1);

    return 0;
}
