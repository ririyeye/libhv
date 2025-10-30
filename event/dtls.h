#ifndef HV_DTLS_H_
#define HV_DTLS_H_

#include "hconfig.h"
#include "hloop.h"

#ifdef WITH_DTLS

#include "rbtree.h"
#include "hsocket.h"
#include "hmutex.h"
#include "hssl.h"
#include "list.h"

typedef struct dtls_ctx_s {
    struct rb_root  rb_root;
    hmutex_t        mutex;
} dtls_ctx_t;

typedef enum {
    DTLS_STATE_INIT = 0,
    DTLS_STATE_HANDSHAKING,
    DTLS_STATE_ESTABLISHED,
    DTLS_STATE_CLOSING,
    DTLS_STATE_CLOSED
} dtls_state_e;

typedef struct dtls_session_s {
    struct rb_node  rb_node;
    sockaddr_u      addr;           // key: peer address
    // session state
    hio_t*          io;             // parent io
    hssl_t          ssl;            // SSL session
    dtls_state_e    state;          // handshake state
    // pending write queue
    struct list_head pending_writes;
    hmutex_t        write_mutex;
    // BIO buffers
    void*           rbio;           // read BIO
    void*           wbio;           // write BIO
} dtls_session_t;

typedef struct dtls_pending_write_s {
    struct list_node node;
    void*           data;
    int             len;
} dtls_pending_write_t;

// DTLS context management
void dtls_ctx_init(dtls_ctx_t* ctx);
void dtls_ctx_cleanup(dtls_ctx_t* ctx);

// DTLS session management
dtls_session_t* dtls_session_get(dtls_ctx_t* ctx, struct sockaddr* addr);
dtls_session_t* dtls_session_search(dtls_ctx_t* ctx, struct sockaddr* addr);
void dtls_session_del(dtls_ctx_t* ctx, struct sockaddr* addr);
void dtls_session_free(dtls_session_t* session);

// DTLS operations
int dtls_session_init_ssl(dtls_session_t* session, hio_t* io);
int dtls_session_handshake(dtls_session_t* session);
int dtls_session_read(dtls_session_t* session, void* buf, int len);
int dtls_session_write(dtls_session_t* session, const void* buf, int len);
int dtls_session_flush_pending(dtls_session_t* session);

// hio integration
dtls_session_t* hio_get_dtls_session(hio_t* io, struct sockaddr* addr);
int hio_close_dtls_session(hio_t* io, struct sockaddr* peeraddr);

#endif // WITH_DTLS

#endif // HV_DTLS_H_
