#include "hconfig.h"
#include "hloop.h"
#include "hevent.h"
#include "dtls.h"
#if WITH_DTLS

static void on_dtls_master_recv(hio_t* io, void* buf, int readbytes) {}

void set_dtls_ctx_fd(hio_t* io) {
    BIO* bio = BIO_new_dgram(io->fd, BIO_NOCLOSE);
    BIO_ctrl_set_connected(bio, io->peeraddr);
    BIO_socket_nbio(io->fd, 1);
    SSL_set_bio(io->ssl, bio, bio);
}

static int _dtls_output(dtls_t* dtls, const char* buf, int len) {
    int nsend = sendto(dtls->io->fd, buf, len, 0, hio_peeraddr(dtls->io), sizeof(sockaddr_u));
    // printf("sendto nsend=%d\n", nsend);
    return nsend;
}

void dtls_release(dtls_t* dtls) {
    hssl_free(dtls->ssl);
    if (dtls->t_shake) {
        htimer_del(dtls->t_shake);
    }
}

static void on_shakehand_timeout(htimer_t* timer) {
    htimer_del(timer);

    dtls_t* dtls = hevent_userdata(timer);
    dtls->t_shake = NULL;

    hio_close_rudp(dtls->io, (struct sockaddr*)&dtls->addr);
}

dtls_t* hio_get_dtls(hio_t* io) {
    rudp_entry_t* rudp = hio_get_rudp(io);

    assert(rudp != NULL);
    dtls_t* dtls = &rudp->dtls;

    if (dtls->ssl != NULL) {
        return dtls;
    }

    dtls->io = io;
    // set addr
    memcpy(&dtls->addr, hio_peeraddr(io), sizeof(sockaddr_u));

    // set ssl ctx
    dtls->ssl = hssl_new(io->ssl_ctx, -1);

    // set bio
    BIO* bio_recv = BIO_new(BIO_s_mem());
    BIO* bio_send = BIO_new(BIO_s_mem());

    BIO_set_mem_eof_return(bio_recv, -1);
    BIO_set_mem_eof_return(bio_send, -1);

    SSL_set_bio(dtls->ssl, bio_recv, bio_send);

    dtls->t_shake = NULL;
    dtls->mtu = 1024;

    dtls->sta = dtls_not_init;
    return dtls;
}

static hio_t* hio_create_socket_node(hloop_t* loop, sockaddr_u* local_addr, sockaddr_u* remote_addr) {
    int ret = -1;

    int sockfd = socket(remote_addr->sa.sa_family, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return NULL;
    }
    hio_t* io = NULL;
#ifdef OS_UNIX
    so_reuseaddr(sockfd, 1);
#endif
    if (remote_addr->sa.sa_family == AF_INET6) {
        ip_v6only(sockfd, 0);
    }
    if (bind(sockfd, &local_addr->sa, sizeof(sockaddr_u)) < 0) {
        perror("bind");
        closesocket(sockfd);
        return NULL;
    }
    if (connect(sockfd, &remote_addr->sa, sizeof(sockaddr_u))) {
        perror("connect");
        return NULL;
    }

    io = hio_get(loop, sockfd);

    io->io_type = HIO_TYPE_DTLS;
    io->side = HIO_SERVER_SIDE;

    hio_set_localaddr(io, &local_addr->sa, sockaddr_len(local_addr));
    hio_set_peeraddr(io, &remote_addr->sa, sockaddr_len(remote_addr));
    return io;
}

int hssl_dtls_read_accept(hio_t* io, void* buf, size_t total) {
    dtls_t* dtls = hio_get_dtls(io);

    char* buf8 = (char*)buf;

    size_t readbytes = total;
    int bytes;
    int sta;

    if (dtls->sta == dtls_not_init) {
        if (!dtls->t_shake) {
            dtls->t_shake = htimer_add(io->loop, on_shakehand_timeout, 1000, 1);
            hevent_set_userdata(dtls->t_shake, dtls);
        }
        htimer_reset(dtls->t_shake, 1000);
        dtls->sta = dtls_shakehand_start;
    }

    while (readbytes > 0) {
        bytes = BIO_write(SSL_get_rbio(dtls->ssl), buf8, readbytes);

        if (bytes <= 0) {
            return -1;
        }

        buf8 += bytes;
        readbytes -= bytes;

        // handle handshake
        if (!SSL_is_init_finished(dtls->ssl)) {
            bytes = SSL_accept(dtls->ssl);
            sta = SSL_get_error(dtls->ssl, bytes);
            if (sta == SSL_ERROR_WANT_READ || sta == SSL_ERROR_WANT_WRITE) {
                do {
                    char sndtmp[dtls->mtu];
                    bytes = BIO_read(SSL_get_wbio(dtls->ssl), sndtmp, dtls->mtu);
                    if (bytes > 0) {
                        _dtls_output(dtls, sndtmp, bytes);
                    }
                    else if (!BIO_should_retry(SSL_get_wbio(dtls->ssl))) {
                        goto final;
                    }
                } while (bytes > 0);
            }
        }
        if (SSL_is_init_finished(dtls->ssl)) {
            char test[1024];
            bytes = SSL_read(dtls->ssl, test, 1024);
            sta = SSL_get_error(dtls->ssl, bytes);
            if (sta == SSL_ERROR_WANT_READ || sta == SSL_ERROR_WANT_WRITE) {
                do {
                    char sndtmp[dtls->mtu];
                    bytes = BIO_read(SSL_get_wbio(dtls->ssl), sndtmp, dtls->mtu);
                    if (bytes > 0) {
                        _dtls_output(dtls, sndtmp, bytes);
                    }
                } while (bytes > 0);
            }

            dtls->sta = dtls_shakehand_ok;
            if (dtls->t_shake) {
                htimer_del(dtls->t_shake);
                dtls->t_shake = NULL;
            }

            struct sockaddr* local_addr = hio_localaddr(io);
            struct sockaddr* remote_addr = hio_peeraddr(io);
            hio_t* newio = hio_create_socket_node(io->loop, (sockaddr_u*)local_addr, (sockaddr_u*)remote_addr);
            if (!newio) {
                printf("hio_create_socket_node err \n");
            }
            printf("new fd = %d \n", newio->fd);
            newio->ssl = dtls->ssl;

            BIO* bio_d = BIO_new_dgram(newio->fd, BIO_NOCLOSE);
            BIO_ctrl_set_connected(bio_d, remote_addr);
            BIO_socket_nbio(newio->fd, 1);

            SSL_set_bio(newio->ssl, bio_d, bio_d);
            io->accept_cb(newio);

            dtls->io = NULL;
            dtls->ssl = NULL;
            hio_close_rudp(io, (struct sockaddr*)&dtls->addr);

            return -1;
        }
    }
final:
    return -1;
}

#endif
