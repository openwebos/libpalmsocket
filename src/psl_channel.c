/* @@@LICENSE
*
*      Copyright (c) 2009-2013 LG Electronics, Inc.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
* LICENSE@@@ */

/**
 * *****************************************************************************
 * @file psl_channel.c
 * @ingroup psl_internal 
 * 
 * @brief  Implementation of the PmSockIOChannel.  It wraps
 *         our openssl integration as a GIOChannel abstraction
 * 
 * *****************************************************************************
 */
#include "psl_build_config.h"

#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>
#include <glib.h>

#include "palmsocket.h"

#include "psl_common.h"
#include "psl_log.h"
#include "psl_assert.h"
#include "psl_error_utils.h"

#include "psl_refcount.h"

#include "psl_thread_context.h"
#include "psl_ssl_context.h"

#include "psl_channel.h"
#include "psl_channel_fsm.h"
#include "psl_channel_fsm_events.h"

#include "psl_channel_watch.h"

#include "psl_channel_fwd.h"




/**
 * Our private Palm Socket IO Channel data
 */
struct PmSockIOChannel_ {
    GIOChannel          base_; ///< MUST BE FIRST MEMBER

    /**
     * The channel's state machine: the FSM instance is created when
     * the channel is created.  The FSM instance is unreferenced and
     * pFsm is set to NULL when our headerRef member reaches 0. 
     *  
     * @see PmSockIOChannel_::headerRef
     */
    PslChanFsm*         pFsm;

    /** 
     * @note DEADLOCK WORK-AROUND:
     * 
     * This reference count tracks references to the
     * PmSockIOChannel_ "header" instance.  It's a separate
     * reference count from the g_io_channel refcount that's 
     * maintained inside the GIOChannel structure by 
     * g_io_channel_ref/unref. The channel instance owns a single 
     * header reference.  Each watch created by this channel 
     * acquires a single header reference, but does _not_ acquire a 
     * g_io_channel reference. We free the header memory (struct 
     * PmSockIOChannel_) only when the header reference count 
     * (headerRef field) reaches zero. 
     * 
     * EXPLANATION: This works around a deadlock in glib's gmain 
     * logic when a palmsock channel watch (GSource) is being 
     * destroyed after the corresponding palmsock channel instance: 
     * each palmsocket channel instance maintains an internally-used
     * multi-fd-watch (GSource) instance.  Each channel watch needs 
     * to acquire a reference to the correspodning channel in order 
     * to avoid references to invalid data, should the user destroy 
     * the channel before the watch (this policy follows glib's 
     * g_io_channel/watch implementation examples). When the watch 
     * is destroyed and its reference count reaches zero, glib locks
     * the gmain context's non-recursive mutex and calls the watch's
     * "finalize" callback.  The watch's "finalize" callback 
     * unreferences the corresponding channel instance.  If the 
     * watch owns the last remaining reference to the channel, the 
     * channel's GIOFuncs::io_free callback is called and it 
     * destroys/unreferences the channel's private multi-fd-watch 
     * (GSource) instance, causing glib to attempt to lock the 
     * gmain context's non-recursive mutex a second time in a row, 
     * causing the non-recursive mutex to deadlock.  The separation 
     * between g_io_channel reference counting and our internal 
     * "headerRef" reference counting works around this deadlock by 
     * freeing the FSM and its private multi-fd-watch (GSource) when 
     * the user's reference to the channel (g_io_channel refcount) 
     * drops to zero, and freeing only the channel's "header" memory 
     * (struct PmSockIOChannel_) when the hederRef refcount drops to 
     * zero, thus avoiding the deadlock scenario described above. 
     */
    PslRefcount         headerRef;
};


PslError
psl_chan_connect_crypto_helper(
    PmSockIOChannel*                        ch,
    PslChanFsmEvtConnKind                   connKind,
    PmSockSSLContext*                       pSSLCtx,
    const PmSockCryptoConfArgs*             pCryptoConf,
    const PslChanFsmEvtCompletionCbInfo*    pCb);


static PslError
psl_chan_shut_crypto_helper(PmSockIOChannel*                  ch,
                            PslChanFsmEvtShutCryptoKind       shutKind,
                            const PmSockShutCryptoConf* const pConf,
                            PmSockCompletionCb*               completionCb);


/**
 * palmsocket channel's GIOFuncs
 */
static GIOStatus
palmsock_io_read(GIOChannel   *channel, 
                 gchar        *buf, 
                 gsize         count,
                 gsize        *bytes_read,
                 GError      **err);

static GIOStatus
palmsock_io_write(GIOChannel   *channel, 
                  const gchar  *buf, 
                  gsize         count,
                  gsize        *bytes_written,
                  GError      **err);

static GIOStatus
palmsock_io_close(GIOChannel   *channel,
                  GError      **err);

static GSource*
palmsock_io_create_watch(GIOChannel   *channel,
                         GIOCondition  condition);

static void
palmsock_io_free(GIOChannel  *channel);


static GIOStatus
palmsock_io_set_flags(GIOChannel *channel,
                      GIOFlags    flags,
                      GError    **err);

static GIOFlags
palmsock_io_get_flags(GIOChannel *channel);


/**
 * Table of GIOChannel methods for the palmsocket IO channel
 * 
 * @note GIOChannel::funcs is declared to acept this table as
 *       non-const
 */
static GIOFuncs g_pslChannelFuncs = {
  .io_read          = palmsock_io_read,
  .io_write         = palmsock_io_write,
  .io_seek          = NULL, ///< seek is optional and we don't support it
  .io_close         = palmsock_io_close,
  .io_create_watch  = palmsock_io_create_watch,
  .io_free          = palmsock_io_free,
  .io_set_flags     = palmsock_io_set_flags,
  .io_get_flags     = palmsock_io_get_flags
};


/* =============================================================================
 *                            FUNCTIONS
 * =============================================================================
 */


/* ==========================================================================
 *  @note To be deprecated...
 * ==========================================================================
 */
GIOChannel*
PmNewIoChannel(const char*  const serverAddr,
               gint         const serverPort,
               const char*        bindAddr,
               gint         const bindPort,
               GError**     const error)
{
    PSL_LOG_INFO("%s:  serverAddr='%s', serverPort=%d, " \
                 "bindAddr='%s', bindPort=%d",
                 __func__,
                 PSL_LOG_OBFUSCATE_STR(serverAddr), (int)serverPort,
                 PSL_LOG_MAKE_SAFE_STR(bindAddr), (int)bindPort);


    PmSockIOChannel*        ch = NULL;

    PslError const createClientErr = PmSockCreateChannel(
        NULL/*threadCtx*/,
        kPmSockOptFlag_sigpipeGuard,
        "legacy_channel",
        &ch);
    if (createClientErr) {
        PSL_ERR_LOG_AND_SET_GERROR(error, PmSockErrGErrorDomain(),
                                   createClientErr, "PslError=%d (%s)",
                                   (int)createClientErr,
                                   PmSockErrStringFromError(createClientErr));
        goto error_cleanup;
    }


    PslError const connAddrErr = PmSockSetConnectAddress(ch, AF_INET,
                                                         serverAddr, serverPort);
    if (connAddrErr) {
        PSL_ERR_LOG_AND_SET_GERROR(error, PmSockErrGErrorDomain(),
                                   connAddrErr, "PslError=%d (%s)",
                                   (int)connAddrErr,
                                   PmSockErrStringFromError(connAddrErr));
        goto error_cleanup;
    }

    PslError const bindErr = PmSockSetSocketBindAddress(ch, AF_INET, bindAddr,
                                                        bindPort);
    if (bindErr) {
        PSL_ERR_LOG_AND_SET_GERROR(error, PmSockErrGErrorDomain(),
                                   bindErr, "PslError=%d (%s)",
                                   (int)bindErr,
                                   PmSockErrStringFromError(bindErr));
        goto error_cleanup;
    }

    /// Success
    PSL_ASSERT(ch);
    return (GIOChannel*)ch;

error_cleanup:
    PSL_ASSERT(!error || *error);

    if (ch) {
        g_io_channel_unref((GIOChannel*)ch);
    }

    return NULL;
}


/* ==========================================================================
 *  @note To be deprecated...
 * ==========================================================================
 */
gint
PmSocketConnect(GIOChannel*         const base,
                gpointer            const context,
                PmSocketConnectCb   const cb,
                GError**            const pError)
{
    PmSockIOChannel* const  ch = (PmSockIOChannel*) base;

    PSL_LOG_INFO("%s (ch=%p):", __func__, base);

    PSL_ASSERT(ch);
    PSL_ASSERT(cb);

    PslChanFsmEvtCompletionCbInfo const callback = {
        .which              = kPslChanFsmEvtCompletionCbId_connect,

        .u.connectCb          = {
            .func       = cb,
            .userData   = context
        }
    };

    if (0 == psl_chan_fsm_evt_dispatch_CONNECT(ch->pFsm,
                                               kPslChanFsmEvtConnKind_plain,
                                               NULL/*sslCtx*/,
                                               NULL/*pCryptoConfo*/,
                                               &callback)) {
        return 0;
    }
    else {
        psl_chan_fsm_set_gerror_from_last_error(ch->pFsm, pError,
                                                kPslChanFsmGErrorTarget_psl);
        return -1;
    }
}



/* ==========================================================================
 *  @note To be deprecated...
 * ==========================================================================
 */
#define LEGACY_CERT_VERIFY_OPTIONS                      \
    (kPmSockCertVerifyOpt_checkHostname |               \
     kPmSockCertVerifyOpt_fallbackToInstalledLeaf)

static const PmSockCryptoConfArgs g_legacyCryptoConfigArgs = {
    .enabledOpts            = kPmSockCryptoConfigEnabledOpt_verifyOpts,

    .verifyOpts             = LEGACY_CERT_VERIFY_OPTIONS
};

gint
PmSslSocketConnect(GIOChannel* base, gpointer context, PmSocketConnectCb cb,
                   GError **pError)
{
    PmSockIOChannel* const  ch = (PmSockIOChannel*) base;

    PSL_LOG_INFO("%s (ch=%p):", __func__, base);

    PSL_ASSERT(ch);
    PSL_ASSERT(cb);

    PslChanFsmEvtCompletionCbInfo const callback = {
        .which              = kPslChanFsmEvtCompletionCbId_connect,

        .u.connectCb          = {
            .func       = cb,
            .userData   = context
        }
    };

    if (0 == psl_chan_connect_crypto_helper(ch,
                                            kPslChanFsmEvtConnKind_cryptoClient,
                                            NULL/*pSSLCtx*/,
                                            &g_legacyCryptoConfigArgs,
                                            &callback)) {
        return 0;
    }
    else {
        psl_chan_fsm_set_gerror_from_last_error(ch->pFsm, pError,
                                                kPslChanFsmGErrorTarget_psl);
        return -1;
    }
}



/* ==========================================================================
 *  @note To be deprecated...
 * ==========================================================================
 */
gint
PmSetSocketEncryption(GIOChannel*               const base,
                      gboolean                  const toEncrypted,
                      gpointer                  const cbArg,
                      PmSecureSocketSwitchCb    const cb,
                      GError**                  const pError)
{
    PmSockIOChannel* const  ch = (PmSockIOChannel*) base;

    PSL_LOG_INFO("%s (ch=%p): toEncrypted=%d, cb=%p, cbArgPtr=%p",
                 __func__, base, (int)toEncrypted, cb, cbArg);

    PSL_ASSERT(ch);
    PSL_ASSERT(cb);

    PslChanFsmEvtCompletionCbInfo const callback = {
        .which              = kPslChanFsmEvtCompletionCbId_switch,

        .u.switchCb           = {
            .func       = cb,
            .userData   = cbArg
        }
    };

    if (toEncrypted) {
        if (0 == psl_chan_connect_crypto_helper(ch,
                                                kPslChanFsmEvtConnKind_cryptoClient,
                                                NULL/*pSSLCtx*/,
                                                &g_legacyCryptoConfigArgs,
                                                &callback)) {
            return 0;
        }

    }

    else {
        if (0 == psl_chan_fsm_evt_dispatch_SHUT_CRYPTO(
            ch->pFsm, kPslChanFsmEvtShutCrypto_twoWay, NULL/*pConf*/, &callback)) {

            return 0;
        }
    }

    psl_chan_fsm_set_gerror_from_last_error(ch->pFsm, pError,
                                            kPslChanFsmGErrorTarget_psl);
    return -1;
}



/* ==========================================================================
 * ==========================================================================
 */
PslError
PmSockCreateChannel(PmSockThreadContext*       threadCtx,
                    PmSockOptionFlags    const options,
                    const char*          const userLabel,
                    PmSockIOChannel**    const ppChannel)
{
    PSL_LOG_INFO("%s: threadCtx=%p, user='%s'", __func__, threadCtx,
                 PSL_LOG_MAKE_SAFE_STR(userLabel));

    PSL_ASSERT(ppChannel);

    PslError    pslerr = 0;

    struct PmSockIOChannel_* const ch = g_new0(struct PmSockIOChannel_, 1);
    if (!ch) {pslerr = PSL_ERR_MEM; goto error_cleanup;}

    // Init headerRef (sets refcount to 1)
    psl_refcount_init(&ch->headerRef, "PSL_CHAN_HEADER_REF", ch);

    g_io_channel_init(&ch->base_);
    ch->base_.use_buffer = false;       // override g_io_channel_init()
    ch->base_.close_on_unref = true;    // override g_io_channel_init()
    ch->base_.is_seekable = false;
    ch->base_.funcs = &g_pslChannelFuncs;
    palmsock_io_get_flags(&ch->base_); // Cache IO flags that need it

    if (!threadCtx) {
        pslerr = PmSockThreadCtxNewFromGMain(NULL/*NULL=default gmain ctx*/,
                                             userLabel, &threadCtx);
        if (pslerr) {goto error_cleanup;}
    }
    else {
        (void)PmSockThreadCtxRef(threadCtx);
    }

    // Init our FSM
    pslerr = psl_chan_fsm_new(&ch->pFsm, threadCtx,
                              options, &ch->base_, userLabel);

    // psl_chan_fsm_new gets own reference on success
    PmSockThreadCtxUnref(threadCtx);
    threadCtx = NULL;

    if (pslerr) {goto error_cleanup;}

    PSL_LOG_DEBUG("%s: SUCCESS: user=\"%s\", ch=%p, fsm=%p",
                  __func__, PSL_LOG_MAKE_SAFE_STR(userLabel), ch, ch->pFsm);

    *ppChannel = ch;
    return 0;

error_cleanup:
    PSL_ASSERT(pslerr);
    PSL_LOG_ERROR("%s: ERROR: PslError=%d (%s)", __func__, (int)pslerr,
                  PmSockErrStringFromError(pslerr));
    if (ch) {
        g_io_channel_unref((GIOChannel*)ch);
    }

    return pslerr;
}



/* ==========================================================================
 * ==========================================================================
 */
PslError
PmSockGetLastError(const PmSockIOChannel* const  ch)
{
    PSL_ASSERT(ch);

    PslError const pslerr = psl_chan_fsm_get_last_error(ch->pFsm);

    PSL_LOG_DEBUG("%s (ch=%p): returning PslError=%d (%s)",
                  __func__, ch, (int)pslerr, PmSockErrStringFromError(pslerr));

    return pslerr;
}



/* ==========================================================================
 * ==========================================================================
 */
PmSockThreadContext*
PmSockPeekThreadContext(const PmSockIOChannel* const ch)
{
    PSL_ASSERT(ch);

    return psl_chan_fsm_peek_thread_ctx(ch->pFsm);
}



/* ==========================================================================
 * ==========================================================================
 */
void
PmSockSetUserData(PmSockIOChannel* const ch, void* const userData)
{
    PSL_ASSERT(ch);

    PSL_LOG_INFO("%s (ch=%p): userData=%p", __func__, ch, userData);

    psl_chan_fsm_set_userdata(ch->pFsm, userData);
}



/* ==========================================================================
 * ==========================================================================
 */
void*
PmSockGetUserData(const PmSockIOChannel* const ch)
{
    PSL_ASSERT(ch);

    void* const userData = psl_chan_fsm_get_userdata(ch->pFsm);

    PSL_LOG_DEBUG("%s (ch=%p): userData=%p", __func__, ch, userData);

    return userData;
}



/* ==========================================================================
 * ==========================================================================
 */
PslError
PmSockSetConnectAddress(PmSockIOChannel*    const ch,
                        int                 const addrFamily,
                        const char*         const serverAddress,
                        int                 const serverPort)
{
    PSL_LOG_INFO("%s (ch=%p): addrFamily=%d, serverAddr=%s, serverPort=%d",
                 __func__, ch, addrFamily, PSL_LOG_OBFUSCATE_STR(serverAddress),
                 serverPort);

    PSL_ASSERT(ch);

    if (0 == psl_chan_fsm_evt_dispatch_SET_SERVER(ch->pFsm,
                                                  addrFamily,
                                                  serverAddress,
                                                  serverPort)) {
        return 0;
    }
    else {
        return psl_chan_fsm_get_last_error(ch->pFsm);
    }
}



/* ==========================================================================
 * ==========================================================================
 */
PslError
PmSockSetSocketBindAddress(PmSockIOChannel* const ch,
                           int              const addrFamily,
                           const char*      const bindAddress,
                           int              const bindPort)
{
    PSL_LOG_INFO("%s (ch=%p): addrFamily=%d, bindAddr=%s, bindPort=%d",
                 __func__, ch, addrFamily, PSL_LOG_MAKE_SAFE_STR(bindAddress),
                 bindPort);

    PSL_ASSERT(ch);

    if (0 == psl_chan_fsm_evt_dispatch_SET_SOCK_BIND(ch->pFsm, addrFamily,
                                                     bindAddress, bindPort)) {
        return 0;
    }
    else {
        return psl_chan_fsm_get_last_error(ch->pFsm);
    }
}



/* ==========================================================================
 * ==========================================================================
 */
PslError
PmSockSetConnectedFD(PmSockIOChannel*   const ch,
                     int                const fd,
                     PmSockFileDescOpts const opts)
{
    PSL_LOG_INFO("%s (ch=%p): fd=%d, PmSockFileDescOpts=0x%lX",
                 __func__, ch, fd, (unsigned long)opts);

    PSL_ASSERT(ch);

    if (0 == psl_chan_fsm_evt_dispatch_SET_CONN_FD(ch->pFsm, fd, opts)) {
        return 0;
    }
    else {
        return psl_chan_fsm_get_last_error(ch->pFsm);
    }
}



/* ==========================================================================
 * ==========================================================================
 */
PslError
PmSockConnectPlain(PmSockIOChannel*     const ch,
                   PmSockCompletionCb*  const completionCb)
{
    PSL_LOG_INFO("%s (ch=%p): completionCb=%p", __func__, ch, completionCb);

    PSL_ASSERT(ch);

    PslChanFsmEvtCompletionCbInfo const callback = {
        .which              = (completionCb
                               ? kPslChanFsmEvtCompletionCbId_completion
                               : kPslChanFsmEvtCompletionCbId_none),

        .u.completionCb       = {
            .func       = completionCb
        }
    };

    if (0 == psl_chan_fsm_evt_dispatch_CONNECT(ch->pFsm,
                                               kPslChanFsmEvtConnKind_plain,
                                               NULL/*sslCtx*/,
                                               NULL/*pCryptoConf*/,
                                               &callback)) {
        return 0;
    }
    else {
        return psl_chan_fsm_get_last_error(ch->pFsm);
    }
}



/* ==========================================================================
 * ==========================================================================
 */
PslError
PmSockConnectCrypto(PmSockIOChannel*              const ch,
                    PmSockSSLContext*             const pSSLCtx,
                    const PmSockCryptoConfArgs*   const pConf,
                    PmSockCompletionCb*           const completionCb)
{
    PSL_LOG_INFO("%s (ch=%p): pSSLCtx=%p, completionCb=%p",
                 __func__, ch, pSSLCtx, completionCb);

    PslChanFsmEvtCompletionCbInfo const callback = {
        .which              = (completionCb
                               ? kPslChanFsmEvtCompletionCbId_completion
                               : kPslChanFsmEvtCompletionCbId_none),

        .u.completionCb     = {
            .func       = completionCb
        }
    };

    return psl_chan_connect_crypto_helper(ch, kPslChanFsmEvtConnKind_cryptoClient,
                                          pSSLCtx, pConf, &callback);
}//PmSockConnectCrypto



/* ==========================================================================
 * ==========================================================================
 */
PslError
PmSockAcceptCrypto(PmSockIOChannel*              const ch,
                   PmSockSSLContext*             const pSSLCtx,
                   const PmSockCryptoConfArgs*   const pConf,
                   PmSockCompletionCb*           const completionCb)
{
    PSL_LOG_INFO("%s (ch=%p): pSSLCtx=%p, completionCb=%p",
                 __func__, ch, pSSLCtx, completionCb);

    PslChanFsmEvtCompletionCbInfo const callback = {
        .which              = (completionCb
                               ? kPslChanFsmEvtCompletionCbId_completion
                               : kPslChanFsmEvtCompletionCbId_none),

        .u.completionCb     = {
            .func       = completionCb
        }
    };

    return psl_chan_connect_crypto_helper(ch, kPslChanFsmEvtConnKind_cryptoServer,
                                          pSSLCtx, pConf, &callback);
}


PslError
PmSockGetPeerCertVerifyError(PmSockIOChannel*               const ch,
                             PmSockPeerCertVerifyErrorInfo* const pRes)
{
    PSL_LOG_DEBUG("%s (ch=%p, pRes=%p)", __func__, ch, pRes);

    PSL_ASSERT(ch);

    if (0 == psl_chan_fsm_evt_dispatch_GET_PEER_CERT_VERIFY_ERR(ch->pFsm, pRes)) {
        return 0;
    }
    else {
        return psl_chan_fsm_get_last_error(ch->pFsm);
    }
}


PslError
PmSockRenegotiateCrypto(PmSockIOChannel*             const ch,
                        const PmSockRenegotiateConf* const pConf,
                        PmSockCompletionCb*          const cb)
{
    PSL_LOG_INFO("%s (ch=%p), pConf=%p, completionCb=%p",
                 __func__, ch, pConf, cb);

    PSL_ASSERT(ch);

    if (0 == psl_chan_fsm_evt_dispatch_RENEGOTIATE_CRYPTO(ch->pFsm, pConf, cb)) {
        return 0;
    }
    else {
        return psl_chan_fsm_get_last_error(ch->pFsm);
    }
}



/* ==========================================================================
 * ==========================================================================
 */
PslError
PmSockShutCryptoOneWay(PmSockIOChannel*            const ch,
                       const PmSockShutCryptoConf* const pConf,
                       PmSockCompletionCb*         const cb)
{
    PSL_LOG_INFO("%s (ch=%p): pConf=%p, completionCb=%p", __func__, ch, pConf, cb);

    return psl_chan_shut_crypto_helper(ch, kPslChanFsmEvtShutCrypto_oneWay,
                                       pConf, cb);
}



/* ==========================================================================
 * ==========================================================================
 */
PslError
PmSockShutCryptoTwoWay(PmSockIOChannel*            const ch,
                       const PmSockShutCryptoConf* const pConf,
                       PmSockCompletionCb*         const cb)
{
    PSL_LOG_INFO("%s (ch=%p): pConf=%p, completionCb=%p", __func__, ch, pConf, cb);

    return psl_chan_shut_crypto_helper(ch, kPslChanFsmEvtShutCrypto_twoWay,
                                       pConf, cb);
}



/* ==========================================================================
 * ==========================================================================
 */
PslError
PmSockResumePlain(PmSockIOChannel* const ch)
{
    PSL_LOG_INFO("%s (ch=%p)", __func__, ch);

    PSL_ASSERT(ch);

    if (0 == psl_chan_fsm_evt_dispatch_RESUME_PLAINTEXT(ch->pFsm)) {
        return 0;
    }
    else {
        return psl_chan_fsm_get_last_error(ch->pFsm);
    }
}



/* ==========================================================================
 * ==========================================================================
 */
PslError
PmSockShutSocket(PmSockIOChannel* const ch, int const how)
{
    PSL_LOG_INFO("%s (ch=%p): how=%d", __func__, ch, (int)how);

    PSL_ASSERT(ch);

    if (0 == psl_chan_fsm_evt_dispatch_SHUT_SOCK(ch->pFsm, how)) {
        return 0;
    }
    else {
        return psl_chan_fsm_get_last_error(ch->pFsm);
    }

}



/* ==========================================================================
 * ==========================================================================
 */
bool
PmSockIsClosed(const PmSockIOChannel* const ch)
{
    PSL_ASSERT(ch);

    bool const isClosed = psl_chan_fsm_is_closed(ch->pFsm);

    PSL_LOG_DEBUG("%s (ch=%p): isClosed=%d",
                  __func__, ch, (int)isClosed);

    return isClosed;
}



/* ==========================================================================
 * ==========================================================================
 */
PslError
PmSockCreateWatch(PmSockIOChannel*  const ch,
                  GIOCondition      const conditions,
                  PmSockWatch**     const ppWatch)
{
    PSL_LOG_INFO("%s (ch=%p): conditions=0x%lX, ppWatch=%p", __func__, ch,
                 (unsigned long)conditions, ppWatch);

    PslError const pslErr = psl_chan_watch_new(ppWatch, ch, conditions);
    if (pslErr) {
        psl_chan_fsm_set_last_error(ch->pFsm, kPslChanFsmErrorSource_psl, pslErr);
    }

    return pslErr;
}



/* ==========================================================================
 * 
 * psl_chan_connect_crypto_helper(): common code for
 * PmSslSocketConnect, PmSockConnectCrypto(), and
 * PmSetSocketEncryption()
 * 
 * ==========================================================================
 */
PslError
psl_chan_connect_crypto_helper(
    PmSockIOChannel*                        const ch,
    PslChanFsmEvtConnKind                   const connKind,
    PmSockSSLContext*                             pSSLCtx,
    const PmSockCryptoConfArgs*             const pCryptoConf,
    const PslChanFsmEvtCompletionCbInfo*    const pCb)
{
    PSL_LOG_DEBUG("%s (ch=%p): connKind=%d, pSSLCtx=%p",
                  __func__, ch, (int)connKind, pSSLCtx);

    PSL_ASSERT(ch);

    if (!pSSLCtx) {
        char userLabel[100];
        snprintf(userLabel, sizeof(userLabel), "Default SSLCtx for ch=%p", ch);
        PslError const pslerr = PmSockSSLCtxNew(userLabel, &pSSLCtx);
        if (pslerr) {
            psl_chan_fsm_set_last_error(ch->pFsm, kPslChanFsmErrorSource_psl, pslerr);
            return pslerr;
        }
    }
    else {
        (void)PmSockSSLCtxRef(pSSLCtx); // facilitates general handling below
    }

    PslSmeEventStatus const evtStatus = psl_chan_fsm_evt_dispatch_CONNECT(
        ch->pFsm, connKind, pSSLCtx, pCryptoConf, pCb);

    // @note CONNECT evt handler acquires its own reference as needed
    PmSockSSLCtxUnref(pSSLCtx);
    pSSLCtx = NULL;

    if (kPslSmeEventStatus_success == evtStatus) {
        return PSL_ERR_NONE;
    }
    else {
        return psl_chan_fsm_get_last_error(ch->pFsm);
    }
}//psl_chan_connect_crypto_helper



/* ==========================================================================
 * 
 * psl_chan_shut_crypto_helper(): Common code for
 * PmSockShutCryptoOneWay() and PmSockShutCryptoTwoWay()
 * 
 * ==========================================================================
 */
static PslError
psl_chan_shut_crypto_helper(PmSockIOChannel*            const ch,
                            PslChanFsmEvtShutCryptoKind const shutKind,
                            const PmSockShutCryptoConf* const pConf,
                            PmSockCompletionCb*         const completionCb)
{
    PSL_ASSERT(ch);

    PslChanFsmEvtCompletionCbInfo const callback = {
        .which              = (completionCb
                               ? kPslChanFsmEvtCompletionCbId_completion
                               : kPslChanFsmEvtCompletionCbId_none),

        .u.completionCb       = {
            .func       = completionCb
        }
    };

    if (0 == psl_chan_fsm_evt_dispatch_SHUT_CRYPTO(
        ch->pFsm, shutKind, pConf, &callback)) {

        return 0;
    }
    else {
        return psl_chan_fsm_get_last_error(ch->pFsm);
    }
}



/* ==========================================================================
 * psl_chan_do_io_readiness_preflight(): here, we attempt to
 * emulate poll() revents on a socket, regardless of whether
 * we're in error, plaintext, or SSL/TLS mode.
 *  
 * #define POLLIN       0x0001
 * #define POLLPRI      0x0002
 * #define POLLOUT      0x0004
 * #define POLLERR      0x0008
 * #define POLLHUP      0x0010
 * #define POLLNVAL     0x0020
 * 
 * Results of an experiment with poll() on Ubuntu 8.04:
 * 
 * Creating socket pair sv[0] and sv[1]
 * poll results of connected socket sv[0] before sending data to it:
 * poll(): events=0x1, revents=0x0
 * poll(): events=0x4, revents=0x4
 * poll(): events=0x2, revents=0x0
 * poll(): events=0x0, revents=0x0
 * poll(): events=0x38, revents=0x0
 * Sending data from sv[1] to sv[0]
 * poll results on connected socket sv[0] after sending to it:
 * poll(): events=0x1, revents=0x1
 * poll(): events=0x4, revents=0x4
 * poll(): events=0x2, revents=0x0
 * poll(): events=0x0, revents=0x0
 * poll(): events=0x38, revents=0x0
 * Closing sv[1]:
 * poll results on closed socket sv[1]:
 * poll(): events=0x1, revents=0x20
 * poll(): events=0x4, revents=0x20
 * poll(): events=0x2, revents=0x20
 * poll(): events=0x0, revents=0x20
 * poll(): events=0x38, revents=0x20
 * poll results on connected socket sv[0] after closing sv[1], before reading:
 * poll(): events=0x1, revents=0x11
 * poll(): events=0x4, revents=0x14
 * poll(): events=0x2, revents=0x10
 * poll(): events=0x0, revents=0x10
 * poll(): events=0x38, revents=0x10
 * Reading pending data from sv[0] after closing sv[1]:
 * poll results on connected socket sv[0] after closing sv[1], and reading:
 * poll(): events=0x1, revents=0x11
 * poll(): events=0x4, revents=0x14
 * poll(): events=0x2, revents=0x10
 * poll(): events=0x0, revents=0x10
 * poll(): events=0x38, revents=0x10
 * Testing poll results on a failed connection:
 * Connecting to 1.2.3.4:80, expecting it to fail
 * poll results of failed connection:
 * poll(): events=0x1, revents=0x10
 * poll(): events=0x4, revents=0x14
 * poll(): events=0x2, revents=0x10
 * poll(): events=0x0, revents=0x10
 * poll(): events=0x38, revents=0x10
 * 
 * ==========================================================================
 */
void
psl_chan_do_io_readiness_preflight(struct PmSockIOChannel_*     const ch,
                                   GIOCondition                 const monCond,
                                   PslChanIOReadiness*          const pRes)
{
    PSL_LOG_DEBUGLOW("%s (ch=%p): monCond=0x%lX",
                     __func__, ch, (unsigned long)monCond);

    PSL_ASSERT(ch);
    PSL_ASSERT(pRes);

    pRes->fd = PSL_INVALID_FD;
    pRes->isClosed = psl_chan_fsm_is_closed(ch->pFsm);
    pRes->pollCond = pRes->readyCond = (GIOCondition)0;

    if (!monCond) {
        PSL_LOG_DEBUGLOW("%s (ch=%p): nothing monitored", __func__, ch);
    }

    else if (pRes->isClosed) {
        pRes->readyCond = G_IO_NVAL;

        PSL_LOG_DEBUGLOW("%s (ch=%p): channel is closed", __func__, ch);

    }

    else { /// full check
        /// For suppressing monitoring of specific conditions
        GIOCondition suppressMonCond = (GIOCondition)0;

        /// Allowed to indicate these conditions
        GIOCondition const allowIndCond = (monCond |
                                           PSL_FAIL_GIOCONDITIONS);

        PslChanFsmEvtIOReadyHint readableHint  = kPslChanFsmEvtIOReadyHint_notReady;
        PslChanFsmEvtIOReadyHint writeableHint = kPslChanFsmEvtIOReadyHint_notReady;
        (void)psl_chan_fsm_evt_dispatch_CHECK_IO(ch->pFsm, &readableHint,
                                                 &writeableHint, &pRes->fd);

        switch (readableHint) {
        case kPslChanFsmEvtIOReadyHint_ready:
            PSL_LOG_DEBUGLOW("%s (ch=%p): forced readable", __func__, ch);
            pRes->readyCond |= G_IO_IN;
            break;

        case kPslChanFsmEvtIOReadyHint_notReady:
            PSL_LOG_DEBUGLOW("%s (ch=%p): forced non-readable", __func__, ch);
            suppressMonCond |= G_IO_IN;
            break;

        case kPslChanFsmEvtIOReadyHint_poll:
            PSL_LOG_DEBUGLOW("%s (ch=%p): pollable input", __func__, ch);
            break;

        case kPslChanFsmEvtIOReadyHint_hup:
            PSL_LOG_DEBUGLOW("%s (ch=%p): input forced G_IO_HUP",
                             __func__, ch);
            pRes->readyCond |= G_IO_HUP;
            break;

        case kPslChanFsmEvtIOReadyHint_readyhup:
            PSL_LOG_DEBUGLOW("%s (ch=%p): input forced READY + G_IO_HUP",
                             __func__, ch);
            pRes->readyCond |= (G_IO_IN | G_IO_HUP);
            break;
        }


        switch (writeableHint) {
        case kPslChanFsmEvtIOReadyHint_ready:
            PSL_LOG_DEBUGLOW("%s (ch=%p): forced writable", __func__, ch);
            pRes->readyCond |= G_IO_OUT;
            break;

        case kPslChanFsmEvtIOReadyHint_notReady:
            PSL_LOG_DEBUGLOW("%s (ch=%p): forced non-writeable",
                             __func__, ch);
            suppressMonCond |= G_IO_OUT;
            break;

        case kPslChanFsmEvtIOReadyHint_poll:
            PSL_LOG_DEBUGLOW("%s (ch=%p): pollable output", __func__, ch);
            break;

        case kPslChanFsmEvtIOReadyHint_hup:
            PSL_LOG_DEBUGLOW("%s (ch=%p): output forced G_IO_HUP",
                             __func__, ch);
            pRes->readyCond |= G_IO_HUP;
            break;

        case kPslChanFsmEvtIOReadyHint_readyhup:
            PSL_LOG_DEBUGLOW("%s (ch=%p): output forced READY + G_IO_HUP",
                             __func__, ch);
            pRes->readyCond |= (G_IO_OUT | G_IO_HUP);
            break;
        }

        pRes->readyCond &= allowIndCond;

        if (pRes->fd >= 0) {
            pRes->pollCond = allowIndCond;
            pRes->pollCond &= ~(pRes->readyCond | suppressMonCond);
        }
        else {
            PSL_ASSERT(kPslChanFsmEvtIOReadyHint_poll != readableHint &&
                       kPslChanFsmEvtIOReadyHint_poll != writeableHint);

            PSL_LOG_DEBUGLOW("%s (ch=%p): no fd to poll", __func__, ch);
        }

    }//full check

    PSL_LOG_DEBUGLOW("%s (ch=%p): LEAVING: isClosed=%d, fd=%d, " \
                     "GIOCondition: ready=0x%lX, poll=0x%lX",
                     __func__, ch, (int)pRes->isClosed, pRes->fd,
                     (unsigned long)pRes->readyCond,
                     (unsigned long)pRes->pollCond);
}



/* ==========================================================================
 * ==========================================================================
 */
struct PmSockIOChannel_*
psl_chan_header_ref(struct PmSockIOChannel_* ch)
{
    PSL_ASSERT(ch);

    psl_refcount_atomic_ref(&ch->headerRef);

    return ch;
}



/* ==========================================================================
 * ==========================================================================
 */
void
psl_chan_header_unref(struct PmSockIOChannel_* ch)
{
    PSL_ASSERT(ch);

    if (psl_refcount_atomic_unref(&ch->headerRef)) {
        psl_chan_fsm_unref(ch->pFsm);
        ch->pFsm = NULL;
        g_free(ch);
    }
}



/** =========================================================================
 * GIOFuncs::io_close implementation
 * 
 * @param base
 * @param err
 * 
 * @return GIOStatus
 * 
 * ==========================================================================
 */
static GIOStatus
palmsock_io_close(GIOChannel *const base,
                  GError    **const error)
{
    PSL_LOG_INFO("%s (ch=%p)", __func__, base);

    PSL_ASSERT(base);

    struct PmSockIOChannel_* const ch = (struct PmSockIOChannel_*)base;

    /**
     * @note We may be partially-constructed when g_io_channel_unref
     *       is called during error cleanup in
     *       PmSockCreateChannel())
     */
    psl_chan_fsm_evt_dispatch_CLOSE(ch->pFsm);
    return G_IO_STATUS_NORMAL;
}



/** =========================================================================
 * GIOFuncs::io_free implementation
 * 
 * @param base
 * 
 * ==========================================================================
 */
static void
palmsock_io_free(GIOChannel* base)
{
    PSL_LOG_INFO("%s (ch=%p)", __func__, base);

    PSL_ASSERT(base);

    struct PmSockIOChannel_* const ch = (struct PmSockIOChannel_*)base;

    /**
     * @note We may be partially-constructed when g_io_channel_unref
     *       is called during error cleanup in
     *       PmSockCreateChannel())
     */
    if (ch->pFsm) {
        psl_chan_fsm_finalize(ch->pFsm);

        /**
         * @note After this point, our FSM instance is in a diminished 
         *       zombie-like capacity, and any remaining, _active_
         *       PmSockWatch instances associated with this channel will
         *       report the G_IO_NVAL GIOCondition.  Users should no
         *       longer call any GIOChannel and PmSockIOChannel
         *       functions on the channel instance.
         */
    }

    psl_chan_header_unref(ch);
    /**
     * @note There may still be PmSockWatch (GSource) instances with
     *       valid channel header references to this channel
     *       instance if the user is destroying the channel before
     *       the watch(es); After finalizing
     */
    return;
}



/** =========================================================================
 * GIOFuncs::io_read implementation
 * 
 * @param base
 * @param buf
 * @param count
 * @param bytes_read
 * @param err
 * 
 * @return GIOStatus
 * 
 * ==========================================================================
 */
static GIOStatus
palmsock_io_read(GIOChannel*    const base, 
                 gchar*         const buf, 
                 gsize          const cnt,
                 gsize*         const bytes_read,
                 GError**       const pError)
{
    PSL_LOG_DEBUGLOW("%s (ch=%p)", __func__, base);

    PSL_ASSERT(base);
    PSL_ASSERT(buf && bytes_read);

    struct PmSockIOChannel_* const ch = (struct PmSockIOChannel_*)base;

    GIOStatus gioStatus = G_IO_STATUS_NORMAL;

    if (0 == psl_chan_fsm_evt_dispatch_READ(ch->pFsm, buf, cnt,
                                            &gioStatus, bytes_read)) {
        return gioStatus;
    }
    else {
        psl_chan_fsm_set_gerror_from_last_error(
            ch->pFsm, pError, kPslChanFsmGErrorTarget_giochannel);
        return G_IO_STATUS_ERROR;
    }
}



/** =========================================================================
 * GIOFuncs::io_write implementation
 * 
 * @param channel
 * @param buf
 * @param count
 * @param bytes_written
 * @param err
 * 
 * @return GIOStatus
 * 
 * ==========================================================================
 */
static GIOStatus
palmsock_io_write(GIOChannel*   const base, 
                  const gchar*  const buf, 
                  gsize         const cnt,
                  gsize*        const bytes_written,
                  GError**      const pError)
{
    PSL_LOG_DEBUGLOW("%s (ch=%p)", __func__, base);

    PSL_ASSERT(base);
    PSL_ASSERT(buf && bytes_written);

    struct PmSockIOChannel_* const ch = (struct PmSockIOChannel_*)base;

    GIOStatus gioStatus = G_IO_STATUS_NORMAL;

    if (0 == psl_chan_fsm_evt_dispatch_WRITE(ch->pFsm, buf, cnt,
                                             &gioStatus, bytes_written)) {
        return gioStatus;
    }
    else {
        psl_chan_fsm_set_gerror_from_last_error(
            ch->pFsm, pError, kPslChanFsmGErrorTarget_giochannel);
        return G_IO_STATUS_ERROR;
    }
}



/** =========================================================================
 * GIOFuncs::io_create_watch implementation
 * 
 * @param channel
 * @param condition
 * 
 * @return GSource*
 * 
 * ==========================================================================
 */
static GSource*
palmsock_io_create_watch(GIOChannel*    const base,
                         GIOCondition   const conditions)
{
    struct PmSockIOChannel_* const ch = (struct PmSockIOChannel_*)base;

    PSL_LOG_INFO("%s (ch=%p): conditions=0x%lX", __func__, base,
                 (unsigned long)conditions);

    PmSockWatch* watch = NULL;
    PslError const pslErr = psl_chan_watch_new(&watch, ch, conditions);
    if (pslErr) {
        psl_chan_fsm_set_last_error(ch->pFsm, kPslChanFsmErrorSource_psl,
                                    pslErr);
        watch = NULL;
    }

    return (GSource*)watch;
}



/** =========================================================================
 * GIOFuncs::io_set_flags implementation
 * 
 * @param channel
 * @param flags
 * @param err
 * 
 * @return GIOStatus
 * 
 * ==========================================================================
 */
static GIOStatus
palmsock_io_set_flags(GIOChannel* const base,
                      GIOFlags    const flags,
                      GError**    const pError)
{
    struct PmSockIOChannel_* const ch = (struct PmSockIOChannel_*)base;

    PSL_LOG_INFO("%s (ch=%p)", __func__, base);

    /// @note we don't support BLOCKING mode, but there is no harm in "applying"
    /// the non-blocking mode again
    /// 
    /// @note NON_BLOCKING mode is automatically disabled during execution of
    /// g_io_channel_close, g_io_channel_shutdown, or final g_io_channel_unref
    /// if gio encoding or bufferred IO is turned on on the channel, so we don't
    /// support gio encoding and buffering.  This is because those functions
    /// will want to "flush" the channel when encoding or bufferred IO is
    /// enabled.

    /// @note We only support the G_IO_FLAG_NONBLOCK flag
    if (flags != G_IO_FLAG_NONBLOCK) {
        PSL_LOG_ERROR("%s (ch=%p): ERROR: these flags are not supported: 0x%lX",
                      __func__, base,
                      (unsigned long)(flags & ~G_IO_FLAG_NONBLOCK));

        psl_chan_fsm_set_last_error(ch->pFsm, kPslChanFsmErrorSource_psl,
                                    PSL_ERR_INVAL);
        psl_chan_fsm_set_gerror_from_last_error(
            ch->pFsm, pError, kPslChanFsmGErrorTarget_giochannel);
        return G_IO_STATUS_ERROR;
    }

    return G_IO_STATUS_NORMAL;
}


/** =========================================================================
 * GIOFuncs::io_get_flags implementation
 * 
 * @param channel
 * 
 * @return GIOFlags
 * 
 * ==========================================================================
 */
static GIOFlags
palmsock_io_get_flags(GIOChannel* const base)
{
    PSL_LOG_INFO("%s (ch=%p)", __func__, base);

    //PmSockIOChannel* ch = (PmSockIOChannel*) base;
    GIOFlags flags = 0;

    flags |= G_IO_FLAG_NONBLOCK;

    /*
     * @todo should we make
     *       readable/writable dynamic (based on FSM comms mode)
     *       instead?
     */
    base->is_readable = base->is_writeable = true;
    base->is_seekable = false;

    return flags;
}
