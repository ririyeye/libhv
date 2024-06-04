#ifndef HV_DTLS_H_
#define HV_DTLS_H_

#include "hloop.h"
#include "hsocket.h"

#if WITH_DTLS

#ifdef WITH_OPENSSL
#include "openssl/ssl.h"
#include "openssl/err.h"
#endif

typedef enum {
    dtls_not_init = 0,
    dtls_shakehand_start,
    dtls_shakehand_ok,
} dtls_step;

typedef struct dtls_s {
    dtls_step sta;
    int serverflg;
    hssl_t ssl_ctx;
    htimer_t* t_shake;
    sockaddr_u addr;
    hio_t* io;
    int mtu;
} dtls_t;

// NOTE: dtls_create in hio_get_dtls
void dtls_release(dtls_t* dtls);

int hssl_dtls_read(hio_t *io, void* buf, size_t len);
int hssl_dtls_write(hio_t *io, const void* buf, size_t len);

int hssl_dtls_read_node(hio_t* io, void* buf, int len);
int hssl_dtls_write_node(hio_t* io, const void* buf, int len);

#endif

#endif // HV_DTLS_H_
