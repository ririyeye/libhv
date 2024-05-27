#include "hconfig.h"
#include "hloop.h"
#include "hevent.h"
#include "dtls.h"
#if WITH_DTLS

static int _dtls_output(dtls_t* dtls, const char* buf, int len) {
    int nsend = sendto(dtls->io->fd, buf, len, 0, hio_peeraddr(dtls->io), sizeof(sockaddr_u));
    // printf("sendto nsend=%d\n", nsend);
    return nsend;
}

void dtls_release(dtls_t* dtls) {
    hssl_free_dtls(dtls->ssl_ctx);
    if (dtls->t_shake) {
        htimer_del(dtls->t_shake);
    }
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

    dtls->io = io;
    // set addr
    memcpy(&dtls->addr, hio_peeraddr(io), sizeof(sockaddr_u));

    // set ssl ctx
    dtls->ssl_ctx = hssl_new_dtls(io->ssl_ctx, io->fd, (struct sockaddr*)&dtls->addr);

    // set bio
    dtls->bio_recv = BIO_new(BIO_s_mem());
    dtls->bio_send = BIO_new(BIO_s_mem());

    BIO_set_mem_eof_return(dtls->bio_recv, -1);
    BIO_set_mem_eof_return(dtls->bio_send, -1);

    SSL_set_bio(dtls->ssl_ctx, dtls->bio_recv, dtls->bio_send);

    dtls->t_shake = NULL;
    dtls->mtu = 1024;

    dtls->sta = dtls_not_init;
    return dtls;
}

HV_EXPORT int hssl_dtls_read(hio_t* io, void* buf, size_t total) {
    dtls_t* dtls = hio_get_dtls(io);

    char* buf8 = (char*)buf;

    size_t readbytes = total;
    char read_buf[total];
    int read_len = 0;
    int bytes;
    int sta;

    if (io->side == HIO_SERVER_SIDE && dtls->sta == dtls_not_init) {
        if (!dtls->t_shake) {
            dtls->t_shake = htimer_add(io->loop, on_shakehand_timeout, 1000, 1);
            hevent_set_userdata(dtls->t_shake, dtls);
        }
        htimer_reset(dtls->t_shake, 1000);
        dtls->sta = dtls_shakehand_start;
    }

    while (readbytes > 0) {
        bytes = BIO_write(dtls->bio_recv, buf8, readbytes);

        if (bytes <= 0) {
            return -1;
        }

        buf8 += bytes;
        readbytes -= bytes;

        // handle handshake
        if (!SSL_is_init_finished(dtls->ssl_ctx)) {
            bytes = SSL_accept(dtls->ssl_ctx);
            sta = SSL_get_error(dtls->ssl_ctx, bytes);
            if (sta == SSL_ERROR_WANT_READ || sta == SSL_ERROR_WANT_WRITE) {
                do {
                    char sndtmp[dtls->mtu];
                    bytes = BIO_read(dtls->bio_send, sndtmp, dtls->mtu);
                    if (bytes > 0) {
                        _dtls_output(dtls, sndtmp, bytes);
                    }
                    else if (!BIO_should_retry(dtls->bio_send)) {
                        goto final;
                    }
                } while (bytes > 0);
            }
        }
        if (SSL_is_init_finished(dtls->ssl_ctx)) {
            dtls->sta = dtls_shakehand_ok;
            if (dtls->t_shake) {
                htimer_del(dtls->t_shake);
                dtls->t_shake = NULL;
            }
        }
        // handle data read
        do {

            bytes = SSL_read(dtls->ssl_ctx, read_buf, total - read_len);
            if (bytes > 0) {
                read_len += bytes;
            }
        } while (bytes > 0);

        sta = SSL_get_error(dtls->ssl_ctx, bytes);
        if (sta == SSL_ERROR_WANT_READ || sta == SSL_ERROR_WANT_WRITE) {
            do {
                char sndtmp[dtls->mtu];
                bytes = BIO_read(dtls->bio_send, sndtmp, dtls->mtu);
                if (bytes > 0) {
                    int len = _dtls_output(dtls, sndtmp, bytes);
                    printf("222 sendlen = %d\n", len);
                }
                else if (!BIO_should_retry(dtls->bio_send)) {
                    goto final;
                }
            } while (bytes > 0);
        }
    }

final:
    if (read_len > 0) {
        memcpy(buf, read_buf, read_len);
        // printf("get dat len = %d\n", read_len);
        return read_len;
    }

    return -1;
}

HV_EXPORT int hssl_dtls_write(hio_t* io, const void* buf, size_t len) {

    dtls_t* dtls = hio_get_dtls(io);

    char* buf8 = (char*)buf;

    int sendlen = 0;
    char tmpbuf[2048];
    int bytes;
    int sta;

    if (io->side == HIO_SERVER_SIDE) {
        if (dtls->sta == dtls_not_init) {
            return -1;
        }

        // while data remain
        while (len > 0) {
            int bytes = SSL_write(dtls->ssl_ctx, buf8, len);
            int sta = SSL_get_error(dtls->ssl_ctx, bytes);

            if (bytes > 0) {
                len -= bytes;
                buf8 += bytes;
                sendlen += bytes;

                do {
                    bytes = BIO_read(dtls->bio_send, tmpbuf, dtls->mtu);
                    if (bytes) {
                        _dtls_output(dtls, tmpbuf, bytes);
                    }
                } while (bytes > 0);
            }
        }
        return sendlen;
    }
    return -1;
}

#endif
