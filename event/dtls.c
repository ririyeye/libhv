#include "dtls.h"

#ifdef WITH_DTLS

#include "hevent.h"
#include "hsocket.h"

void dtls_session_free(dtls_session_t* session) {
    if (session->ssl) {
        hssl_free(session->ssl);
        session->ssl = NULL;
    }
    
    // Free pending writes
    hmutex_lock(&session->write_mutex);
    struct list_node* node = session->pending_writes.next;
    while (node != &session->pending_writes) {
        dtls_pending_write_t* pw = list_entry(node, dtls_pending_write_t, node);
        node = node->next;
        HV_FREE(pw->data);
        HV_FREE(pw);
    }
    hmutex_unlock(&session->write_mutex);
    
    hmutex_destroy(&session->write_mutex);
    HV_FREE(session);
}

void dtls_ctx_init(dtls_ctx_t* ctx) {
    ctx->rb_root.rb_node = NULL;
    hmutex_init(&ctx->mutex);
}

void dtls_ctx_cleanup(dtls_ctx_t* ctx) {
    struct rb_node* n = NULL;
    dtls_session_t* session = NULL;
    while ((n = ctx->rb_root.rb_node)) {
        session = rb_entry(n, dtls_session_t, rb_node);
        rb_erase(n, &ctx->rb_root);
        dtls_session_free(session);
    }
    hmutex_destroy(&ctx->mutex);
}

dtls_session_t* dtls_session_search(dtls_ctx_t* ctx, struct sockaddr* addr) {
    struct rb_node* n = ctx->rb_root.rb_node;
    dtls_session_t* session = NULL;
    int cmp = 0;
    bool exists = false;
    
    while (n) {
        session = rb_entry(n, dtls_session_t, rb_node);
        cmp = sockaddr_compare((sockaddr_u*)addr, &session->addr);
        if (cmp < 0) {
            n = n->rb_left;
        } else if (cmp > 0) {
            n = n->rb_right;
        } else {
            exists = true;
            break;
        }
    }
    return exists ? session : NULL;
}

dtls_session_t* dtls_session_get(dtls_ctx_t* ctx, struct sockaddr* addr) {
    hmutex_lock(&ctx->mutex);
    struct rb_node** n = &ctx->rb_root.rb_node;
    struct rb_node* parent = NULL;
    dtls_session_t* session = NULL;
    int cmp = 0;
    bool exists = false;
    
    // Search for existing session
    while (*n) {
        parent = *n;
        session = rb_entry(*n, dtls_session_t, rb_node);
        cmp = sockaddr_compare((sockaddr_u*)addr, &session->addr);
        if (cmp < 0) {
            n = &(*n)->rb_left;
        } else if (cmp > 0) {
            n = &(*n)->rb_right;
        } else {
            exists = true;
            break;
        }
    }
    
    if (!exists) {
        // Create new session
        HV_ALLOC_SIZEOF(session);
        memcpy(&session->addr, addr, SOCKADDR_LEN(addr));
        session->state = DTLS_STATE_INIT;
        session->ssl = NULL;
        session->io = NULL;
        list_init(&session->pending_writes);
        hmutex_init(&session->write_mutex);
        
        rb_link_node(&session->rb_node, parent, n);
        rb_insert_color(&session->rb_node, &ctx->rb_root);
    }
    hmutex_unlock(&ctx->mutex);
    return session;
}

void dtls_session_del(dtls_ctx_t* ctx, struct sockaddr* addr) {
    hmutex_lock(&ctx->mutex);
    dtls_session_t* session = dtls_session_search(ctx, addr);
    if (session) {
        rb_erase(&session->rb_node, &ctx->rb_root);
        dtls_session_free(session);
    }
    hmutex_unlock(&ctx->mutex);
}

int dtls_session_init_ssl(dtls_session_t* session, hio_t* io) {
    session->io = io;
    
    if (io->ssl_ctx == NULL) {
        // No SSL context configured yet
        return -1;
    }
    
    // Create SSL session for this DTLS connection
    session->ssl = hssl_new(io->ssl_ctx, io->fd);
    if (session->ssl == NULL) {
        return -2;
    }
    
    // TODO: Set up BIO for DTLS
    // OpenSSL requires memory BIO for DTLS to handle datagram semantics
    // This will be implemented when OpenSSL integration is enabled
    
    session->state = DTLS_STATE_HANDSHAKING;
    return 0;
}

int dtls_session_handshake(dtls_session_t* session) {
    if (session->ssl == NULL || session->state != DTLS_STATE_HANDSHAKING) {
        return -1;
    }
    
    // TODO: Perform DTLS handshake
    // This will use hssl_accept for server or hssl_connect for client
    // and handle WANT_READ/WANT_WRITE appropriately
    
    return 0;
}

int dtls_session_read(dtls_session_t* session, void* buf, int len) {
    if (session->ssl == NULL || session->state != DTLS_STATE_ESTABLISHED) {
        return -1;
    }
    
    // TODO: Read decrypted data from SSL session
    return hssl_read(session->ssl, buf, len);
}

int dtls_session_write(dtls_session_t* session, const void* buf, int len) {
    if (session->ssl == NULL) {
        return -1;
    }
    
    if (session->state != DTLS_STATE_ESTABLISHED) {
        // Queue the write until handshake completes
        hmutex_lock(&session->write_mutex);
        dtls_pending_write_t* pw;
        HV_ALLOC_SIZEOF(pw);
        pw->len = len;
        HV_ALLOC(pw->data, len);
        memcpy(pw->data, buf, len);
        list_add_tail(&pw->node, &session->pending_writes);
        hmutex_unlock(&session->write_mutex);
        return len; // Return success, data is queued
    }
    
    // TODO: Write encrypted data through SSL session
    return hssl_write(session->ssl, buf, len);
}

int dtls_session_flush_pending(dtls_session_t* session) {
    if (session->state != DTLS_STATE_ESTABLISHED) {
        return 0;
    }
    
    hmutex_lock(&session->write_mutex);
    struct list_node* node = session->pending_writes.next;
    int total_sent = 0;
    
    while (node != &session->pending_writes) {
        dtls_pending_write_t* pw = list_entry(node, dtls_pending_write_t, node);
        node = node->next;
        
        int nwrite = hssl_write(session->ssl, pw->data, pw->len);
        if (nwrite > 0) {
            total_sent += nwrite;
        }
        
        list_del(&pw->node);
        HV_FREE(pw->data);
        HV_FREE(pw);
    }
    hmutex_unlock(&session->write_mutex);
    
    return total_sent;
}

dtls_session_t* hio_get_dtls_session(hio_t* io, struct sockaddr* addr) {
    if (addr == NULL) addr = io->peeraddr;
    dtls_session_t* session = dtls_session_get(&io->dtls_ctx, addr);
    if (session->io == NULL) {
        session->io = io;
    }
    return session;
}

static void hio_close_dtls_session_event_cb(hevent_t* ev) {
    dtls_session_t* session = (dtls_session_t*)ev->userdata;
    dtls_session_del(&session->io->dtls_ctx, (struct sockaddr*)&session->addr);
}

int hio_close_dtls_session(hio_t* io, struct sockaddr* peeraddr) {
    if (peeraddr == NULL) peeraddr = io->peeraddr;
    
    dtls_session_t* session = dtls_session_get(&io->dtls_ctx, peeraddr);
    if (session) {
        hevent_t ev;
        memset(&ev, 0, sizeof(ev));
        ev.cb = hio_close_dtls_session_event_cb;
        ev.userdata = session;
        ev.priority = HEVENT_HIGH_PRIORITY;
        hloop_post_event(io->loop, &ev);
    }
    return 0;
}

#endif // WITH_DTLS
