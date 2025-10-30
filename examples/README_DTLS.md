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

> **Note:** The current implementation provides the DTLS API infrastructure using datagram sockets. 
> Actual DTLS encryption (TLS handshake and encrypted communication) will be integrated when building 
> with OpenSSL support. For now, the examples demonstrate the API pattern and socket operations.

### Terminal 1 - Start Server
```bash
./bin/dtls_echo_server 1234
```

### Terminal 2 - Run Client
```bash
./bin/dtls_client 127.0.0.1 1234
```

Type messages in the client terminal and they will be echoed back by the server.

### Testing with netcat (nc) - Current Implementation Only

Since DTLS encryption is not yet integrated, you can test the socket infrastructure with standard UDP tools:

```bash
# Terminal 1
./bin/dtls_echo_server 1234

# Terminal 2
echo "Hello DTLS" | nc -u 127.0.0.1 1234
```

⚠️ **Important:** Once DTLS encryption is implemented (via OpenSSL), this will no longer work as DTLS 
requires a proper TLS handshake and encrypted communication. You will need to use DTLS-capable clients.

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

## Current Status & Limitations

### ✅ Implemented
- Complete DTLS API matching UDP API patterns
- Socket creation and management (SOCK_DGRAM)
- Event-driven callbacks
- C and C++ interfaces
- Thread-safe operations

### 🔜 To Be Implemented
- **DTLS Encryption:** Actual TLS handshake and encryption layer
- **OpenSSL Integration:** DTLS methods from OpenSSL library
- **Certificate Management:** SSL context configuration for DTLS
- **Session Management:** DTLS connection state handling

### Notes
- The API is production-ready and stable
- Examples demonstrate correct usage patterns
- Encryption integration will be transparent to API users
- No code changes needed when encryption is added

## See Also

- `udp_echo_server.c` - Similar UDP example
- `udp_proxy_server.c` - UDP proxy example
- `docs/DTLS_API.md` - Complete API documentation
