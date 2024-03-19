#ifndef HV_DTLS_H_
#define HV_DTLS_H_

#include "hloop.h"
#include "hsocket.h"

#if WITH_DTLS

typedef struct dtls_s {
    int connected;
    hssl_t ssl_ctx;
    htimer_t* t_shake;
    sockaddr_u addr;
    hio_t* io;
} dtls_t;

// NOTE: dtls_create in hio_get_dtls
void dtls_release(dtls_t* dtls);

int hssl_dtls_read(hio_t *io, void* buf, size_t len);
int hssl_dtls_write(hio_t *io, const void* buf, size_t len);

#endif

#endif // HV_DTLS_H_
