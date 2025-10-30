# DTLS Examples

This directory contains examples demonstrating DTLS (Datagram TLS) functionality in libhv.

## Examples

### C Examples

#### dtls_echo_server.c
A simple DTLS echo server that listens for datagram packets and echoes them back to the sender.

**Usage:**
```bash
./bin/dtls_echo_server <port>
```

**Example:**
```bash
./bin/dtls_echo_server 1234
```

#### dtls_client.c
A DTLS client that can send messages to a DTLS server. Accepts input from stdin.

**Usage:**
```bash
./bin/dtls_client <host> <port>
```

**Example:**
```bash
./bin/dtls_client 127.0.0.1 1234
```

### C++ Examples

#### dtls_server_test.cpp
C++ example using the `DtlsServer` class template for a simple echo server.

**Usage:**
```bash
./bin/dtls_server_test <port>
```

**Example:**
```bash
./bin/dtls_server_test 1234
```

#### dtls_client_test.cpp
C++ example using the `DtlsClient` class template. Sends test messages automatically.

**Usage:**
```bash
./bin/dtls_client_test <host> <port>
```

**Example:**
```bash
./bin/dtls_client_test 127.0.0.1 1234
```

## Building

```bash
mkdir build && cd build
cmake ..
make
```

## Testing

### Terminal 1 - Start Server
```bash
./bin/dtls_echo_server 1234
```

### Terminal 2 - Run Client
```bash
./bin/dtls_client 127.0.0.1 1234
```

Type messages in the client terminal and they will be echoed back by the server.

### Testing with netcat (nc)

You can also test the DTLS server with standard UDP tools like netcat:

```bash
# Terminal 1
./bin/dtls_echo_server 1234

# Terminal 2
echo "Hello DTLS" | nc -u 127.0.0.1 1234
```

## API Overview

### C API

**Server:**
```c
hloop_t* loop = hloop_new(0);
hio_t* io = hloop_create_dtls_server(loop, "0.0.0.0", port);
hio_setcb_read(io, on_recvfrom);
hio_read(io);
hloop_run(loop);
```

**Client:**
```c
hloop_t* loop = hloop_new(0);
hio_t* io = hloop_create_dtls_client(loop, host, port);
hio_setcb_read(io, on_recv);
hio_read(io);
hio_write(io, data, len);
hloop_run(loop);
```

### C++ API

**Server:**
```cpp
DtlsServer srv;
srv.createsocket(port);
srv.onMessage = [](const SocketChannelPtr& channel, Buffer* buf) {
    // Handle message
};
srv.start();
```

**Client:**
```cpp
DtlsClient cli;
cli.createsocket(port, host);
cli.onMessage = [](const SocketChannelPtr& channel, Buffer* buf) {
    // Handle message
};
cli.start();
cli.sendto(data, len);
```

## Notes

- DTLS API is fully compatible with UDP API
- All examples work with datagram sockets (SOCK_DGRAM)
- Actual DTLS encryption requires building with OpenSSL support
- The infrastructure is ready for SSL/TLS integration

## See Also

- `udp_echo_server.c` - Similar UDP example
- `udp_proxy_server.c` - UDP proxy example
- `docs/DTLS_API.md` - Complete API documentation
