// DTLS support header
#ifndef HV_DTLS_H_
#define HV_DTLS_H_

#include "hloop.h"
#include "hsocket.h"

#if WITH_DTLS

#ifdef WITH_OPENSSL
#include "openssl/ssl.h"
#include "openssl/err.h"
#elif defined(WITH_MBEDTLS)
#include "mbedtls/ssl.h"
#endif

typedef enum {
    dtls_not_init = 0,
    dtls_shakehand_start,
    dtls_shakehand_ok,
} dtls_step;

typedef struct dtls_s {
    dtls_step sta;
    hssl_t ssl;
    htimer_t* t_shake;
    sockaddr_u addr;
    hio_t* io;
    int mtu;
} dtls_t;

void dtls_release(dtls_t* dtls);

int hssl_dtls_read_accept(hio_t *io, void* buf, size_t len);
void set_dtls_ctx_fd(hio_t* io);
#endif // WITH_DTLS

#endif // HV_DTLS_H_
