# DTLS API Documentation

## Overview

DTLS (Datagram Transport Layer Security) API infrastructure has been added to libhv with full UDP API compatibility. The DTLS API mirrors the UDP API, providing a familiar interface for secure datagram communication.

> **Current Status:** The DTLS API infrastructure is complete and ready for use. The actual DTLS encryption 
> layer (TLS handshake and encrypted communication) will be integrated when building with OpenSSL support, 
> similar to how TLS/SSL works for TCP connections.

## Features

- **UDP-Compatible API**: DTLS functions follow the same patterns as UDP functions
- **C and C++ Support**: Both C-style and C++ template-based APIs available
- **Event Loop Integration**: Seamless integration with libhv's event loop system
- **Cross-Platform**: Works on all platforms supported by libhv
- **Encryption Ready**: Infrastructure prepared for OpenSSL DTLS integration

## C API

### Server

```c
#include "hloop.h"

// Create DTLS server
hio_t* io = hloop_create_dtls_server(loop, "0.0.0.0", port);

// Set read callback
hio_setcb_read(io, on_recvfrom);

// Start reading
hio_read(io);
```

### Client

```c
#include "hloop.h"

// Create DTLS client
hio_t* io = hloop_create_dtls_client(loop, "127.0.0.1", port);

// Set read callback
hio_setcb_read(io, on_recv);

// Start reading
hio_read(io);

// Send data
hio_write(io, data, len);
```

### Helper Functions

```c
// Enable DTLS on an existing hio_t
int hio_enable_dtls(hio_t* io);

// Check if hio_t is DTLS
bool hio_is_dtls(hio_t* io);
```

## C++ API

### Server

```cpp
#include "DtlsServer.h"

using namespace hv;

DtlsServer srv;
int bindfd = srv.createsocket(port);

srv.onMessage = [&srv](const SocketChannelPtr& channel, Buffer* buf) {
    // Handle received data
    srv.sendto(buf);  // Echo back
};

srv.start();
```

### Client

```cpp
#include "DtlsClient.h"

using namespace hv;

DtlsClient cli;
int sockfd = cli.createsocket(port, host);

cli.onMessage = [](const SocketChannelPtr& channel, Buffer* buf) {
    // Handle received data
};

cli.start();

// Send data
cli.sendto(data, len);
```

## Examples

### C Examples

- **dtls_echo_server.c**: Simple DTLS echo server
- **dtls_client.c**: DTLS client with stdin input

### C++ Examples

- **dtls_server_test.cpp**: C++ DTLS server example
- **dtls_client_test.cpp**: C++ DTLS client example

## Building Examples

```bash
mkdir build && cd build
cmake ..
make

# Run server
./bin/dtls_echo_server 1234

# Run client (in another terminal)
./bin/dtls_client 127.0.0.1 1234
```

## Architecture

### Type Hierarchy

```
HIO_TYPE_SOCK_DGRAM (0x000FF000)
├── HIO_TYPE_UDP    (0x00001000)
├── HIO_TYPE_KCP    (0x00002000)
└── HIO_TYPE_DTLS   (0x00010000)
```

DTLS is defined as a datagram socket type, similar to UDP and KCP, allowing it to use the same underlying socket infrastructure.

### Function Mapping

| Function | UDP | DTLS |
|----------|-----|------|
| Server Creation | `hloop_create_udp_server` | `hloop_create_dtls_server` |
| Client Creation | `hloop_create_udp_client` | `hloop_create_dtls_client` |
| C++ Server Class | `UdpServer` | `DtlsServer` |
| C++ Client Class | `UdpClient` | `DtlsClient` |

## SSL/TLS Integration

When building with OpenSSL support (`WITH_OPENSSL=ON`), DTLS will use OpenSSL's DTLS methods for encryption. The API remains the same, with encryption handled transparently.

### SSL Context Configuration

```c
// Set SSL context (when WITH_OPENSSL is enabled)
hssl_ctx_opt_t ssl_opt = {
    .crt_file = "server.crt",
    .key_file = "server.key",
    .endpoint = HSSL_SERVER
};

hio_new_ssl_ctx(io, &ssl_opt);
```

## Notes

1. **API Compatibility**: All DTLS functions are fully compatible with UDP functions
2. **Socket Type**: DTLS uses datagram sockets (SOCK_DGRAM)
3. **Encryption**: Actual DTLS encryption requires OpenSSL or compatible SSL library
4. **Thread Safety**: Same thread-safety guarantees as UDP operations

## Future Enhancements

- Full OpenSSL DTLS integration
- DTLS 1.3 support
- Cookie exchange for DoS protection
- DTLS session management utilities

## See Also

- UDP API documentation
- SSL/TLS API documentation  
- KCP API documentation (for reliable UDP)
