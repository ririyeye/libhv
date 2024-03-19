#include "hconfig.h"
#include "hloop.h"
#include "hevent.h"
#include "dtls.h"
#if WITH_DTLS

void dtls_release(dtls_t* dtls) {
    hssl_free_dtls(dtls->ssl_ctx);
}

static void on_shakehand_timeout(htimer_t* timer) {
    printf("shake hand timeout\n");
    htimer_del(timer);

    dtls_t* dtls = hevent_userdata(timer);
    dtls->t_shake = NULL;

    hio_close_rudp(dtls->io, (struct sockaddr*)&dtls->addr);
}

dtls_t* hio_get_dtls(hio_t* io) {
    rudp_entry_t* rudp = hio_get_rudp(io);

    assert(rudp != NULL);
    dtls_t* dtls = &rudp->dtls;
    if (dtls->ssl_ctx != NULL) {
        return dtls;
    }

    memcpy(&dtls->addr, hio_peeraddr(io), sizeof(sockaddr_u));
    dtls->io = io;
    if (io->loop) {
        dtls->t_shake = htimer_add(io->loop, on_shakehand_timeout, 1000, 1);
        hevent_set_userdata(dtls->t_shake, dtls);
    }

    nonblocking(io->fd);
    dtls->ssl_ctx = hssl_new_dtls(io->ssl_ctx, io->fd);
    dtls->connected = 0;
    return dtls;
}

HV_EXPORT int hssl_dtls_read(hio_t* io, void* buf, size_t readbytes) {
    dtls_t* dtls = hio_get_dtls(io);

    int rd = -1;

    if (dtls->connected) {
        rd = hssl_read(dtls->ssl_ctx, buf, readbytes);
    }
    else {
        if (dtls->t_shake) {
            htimer_reset(dtls->t_shake, 1000);
        }
        if (0 == hssl_accept(dtls->ssl_ctx)) {
            htimer_del(dtls->t_shake);
            dtls->connected = 1;
            printf("handshake = ok\n");
        }
        return 0;
    }

    return rd;
}

HV_EXPORT int hssl_dtls_write(hio_t* io, const void* buf, size_t len) {

    dtls_t* dtls = hio_get_dtls(io);

    return hssl_write(dtls->ssl_ctx, buf, len);
}

#endif
