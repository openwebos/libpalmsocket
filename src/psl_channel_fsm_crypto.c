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
 * @file psl_channel_fsm_crypto.c
 * @ingroup psl_internal 
 * 
 * @brief  Implementation of Crypto mode states for the
 *         PmSockIOChannel Finite State Machine.
 * 
 * *****************************************************************************
 */
#include "psl_build_config.h"

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <limits.h>
#include <errno.h>

#include <glib.h>

#include <openssl/ssl.h>

#include "palmsockopensslutils.h"
#include "palmsocket.h"

#include "psl_common.h"
#include "psl_log.h"
#include "psl_error_utils.h"
#include "psl_io_buf.h"
#include "psl_sme.h"
#include "psl_multi_fd_watch.h"
#include "psl_thread_context.h"
#include "psl_ssl_context.h"
#include "psl_openssl_init.h"

#include "psl_channel_fsm_events.h"
#include "psl_channel_fsm_crypto.h"
#include "psl_channel_fsm.h"
#include "psl_channel_fsm_main.h"



#define DEFAULT_CIPHER_LIST "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH"


#if 0
/// Verification chains above this value will trigger
/// X509_V_ERR_CERT_CHAIN_TOO_LONG error
static const int kCryptoMaxCertVerifyDepth = 8;
#endif


/**
 * Optimization hint
 */
typedef enum CryptoDeferredIOHint_ {

    /// Pass this value when calling crypto_process_deferred_ssl_io()
    /// and the input/output deferred I/O state 'freshness' is unknown (e.g.,
    /// when calling crypto_process_deferred_ssl_io() from our fd-watch
    /// callback)
    kCryptoDeferredIOHint_none,

    /// Pass this value when calling crypto_process_deferred_ssl_io()
    /// immediately after crypto_handle_READ() (indicates that the input
    /// deferred I/O state is already up to date
    kCryptoDeferredIOHint_afterRead,

    /// Pass this value when calling crypto_process_deferred_ssl_io()
    /// immediately after crypto_handle_WRITE (indicates that the output
    /// deferred I/O state is already up to date
    kCryptoDeferredIOHint_afterWrite
} CryptoDeferredIOHint;





static PSL_CHAN_FSM_STATE_HANDLER_DECLARE(crypto_mode_state_handler,
                                          PslChanFsmCryptoModeState);

static PSL_CHAN_FSM_STATE_HANDLER_DECLARE(crypto_conn_state_handler,
                                          PslChanFsmCryptoConnState);

static PSL_CHAN_FSM_STATE_HANDLER_DECLARE(crypto_fail_state_handler,
                                          PslChanFsmCryptoFailState);

static PSL_CHAN_FSM_STATE_HANDLER_DECLARE(crypto_renegotiate_state_handler,
                                          PslChanFsmCryptoRenegotiateState);

static PSL_CHAN_FSM_STATE_HANDLER_DECLARE(crypto_shut_state_handler,
                                          PslChanFsmCryptoShutState);

static PSL_CHAN_FSM_STATE_HANDLER_DECLARE(crypto_ssl_state_handler,
                                          PslChanFsmCryptoSSLState);


/**
 * Create and configure our openssl channel; prepare the
 * openssl channel for client or server mode based on connKind.
 * 
 * @param pFsm
 * 
 * @param sslCtx
 * 
 * @param connKind one of the SSL/TLS values
 * 
 * @return PslError
 */
static PslError
crypto_create_and_config_ssl(PslChanFsm*                           pFsm,
                             PslChanFsmEvtConnKind                 connKind,
                             const PslChanFsmEvtCryptoConnectArgs* pCryptoConnArgs);


/**
 * Process SSL/TLS renegotiation phases. 
 *  
 * @note Assumes that crypto_process_deferred_ssl_io() has
 *       already been called when appropriate
 *  
 * Modifies PslChanFsmCryptoRenegotiateState::phase and 
 * PslChanFsmCryptoRenegotiateState::pslerr 
 * 
 * @param pState 
 * @param pFsm 
 * @param pFdWatch pointer to PSL_CHAN_FSM_EVT_FD_WATCH arg, or 
 *                 NULL if none
 * @param pErr Non-NULL pointer to variable for returning error 
 *             code; the error code is meaningful only if the
 *             the function's return value indicates that
 *             negotiation is done: in this case, *pErr will
 *             contain 0 on success or non-zero PslError code
 *             that represents the failure.
 * 
 * @return bool TRUE if done (consult pslerror); FALSE not done 
 */
static bool
crypto_do_renegotiate(PslChanFsmCryptoRenegotiateState*     pState,
                      PslChanFsm*                           pFsm,
                      const struct PslChanFsmEvtArgFdWatch* pFdWatch);


/**
 * Call SSL_do_handshake and interpret the results; schedule
 * socket watch as needed.  Used during SSL/TLS
 * session-establishement and renegotiation.
 * 
 * @param pFsm
 * @param pPslErr Pointer to location for returning error code.
 *                Should be used in combination with the
 *                function's return value.  If return value
 *                indicates that connection attempt is done,
 *                then the error code value will indicate the
 *                outcome of the handshake: 0 = success;
 * 
 * @return bool TRUE if handshake attempt is done, in which
 *         case the error code returned via pPslErr should be
 *         consulted to determine success vs. failure; FALSE if
 *         connection attempt is still in progress, so this
 *         function should be called again upon the next
 *         delivery of PSL_CHAN_FSM_EVT_FD_WATCH.
 */
static bool
crypto_do_SSL_handshake(PslChanFsm*                  pFsm,
                        PslError*                    pPslErr);


/**
 * Our verify_callback function set via SSL_set_verify()
 * 
 * @param preverify_ok
 * @param x509_ctx
 * 
 * @return int
 */
static int
crypto_ssl_peer_verify_callback(int             preverify_ok,
                                X509_STORE_CTX* x509_ctx);


/**
 * crypto_resolve_peer_cert_error(): Helper function for 
 * resolving detected peer certificate verification errors; used 
 * by crypto_ssl_peer_verify_callback(). 
 *  
 * Attempts to suppress the error; if that fails, calls user's 
 * peer cert verify callback (if any) as the last resort. 
 *  
 * Updates the certificate verification error status as needed 
 * (in X509_STORE_CTX and the crypto mode's shared sslInfo) 
 * 
 * @param pFsm 
 * @param x509_ctx 
 * 
 * @return bool TRUE if error was suppressed, FALSE if the error 
 *         is still pending
 */
static bool
crypto_resolve_peer_cert_error(PslChanFsm*     pFsm,
                               X509_STORE_CTX* x509_ctx);

/**
 * crypto_call_user_peer_cert_verify_callback(): Helper function 
 * for invoking user's peer cert verify callback function. 
 *  
 * The user's callback function may override our preverify_ok 
 * value. 
 *  
 * If user did not provide a perr cert verify callback, this 
 * function simply returns the value of the preverify_ok arg.
 * 
 * Updates the certificate verification error status as needed 
 * (in X509_STORE_CTX and the crypto mode's shared sslInfo) 
 * 
 * @param pFsm 
 * @param preverify_ok TRUE if we and openssl deem that the 
 *                     current certificate node is OK (passed
 *                     all of our verification checks); FALSE if
 *                     the current certificate node being
 *                     verified has a pending verification
 *                     error.
 * @param x509_ctx 
 * 
 * @return bool TRUE if peer verification status is OK, FALSE if
 *         a verification error is pending
 */
static bool
crypto_call_user_peer_cert_verify_callback(PslChanFsm*     pFsm,
                                           bool            preverify_ok,
                                           X509_STORE_CTX* x509_ctx);


/**
 * Helper function for PslChanFsmCryptoConnState event handler.
 * Requests a crypto-conn done callback, if any was specified in
 * the state's kFsmEventBegin arg.
 * 
 * @note MAY be called ONLY from the scope of
 *       PslChanFsmCryptoConnState's PSL_CHAN_FSM_EVT_FD_WATCH
 *       dispatch.
 * @param pFsm
 * @param pState
 * @param pslErr
 */
static void
crypto_conn_sched_done_cb_if_any(PslChanFsm*                pFsm,
                                 PslChanFsmCryptoConnState* pState,
                                 PslError                   pslErr);


/**
 * Performs an encrypted 'read' operation conforming to glib's
 * GIOFuncs::io_read() semantics
 * 
 * @param pFsm
 * @param arg
 * 
 * @return PslSmeEventStatus
 */
static PslSmeEventStatus
crypto_handle_READ(PslChanFsm*                          pFsm,
                   const struct PslChanFsmEvtArgRead*   arg);


/**
 * Performs preprocessing of the read request to determine 
 * whether the READ request may complete without any data 
 * trasfer. 
 * 
 * @param pFsm 
 * @param arg 
 * @param pEvtStatus If the function returns TRUE, then the 
 *                   variable pointed to by this arg will be set
 *                   to the appropriate PslSmeEventStatus value
 *                   to reflect success or failure of the
 *                   request.
 * 
 * @return bool TRUE if the READ request can complete without 
 *         further reading, in which case the output fields of
 *         arg and last channel error are set accordingly. FALSE
 *         if READ needs to take place, in which case the output
 *         fields of arg are undefined.
 */
PSL_CONFIG_INLINE_FUNC bool
crypto_preprocess_READ(PslChanFsm*                          pFsm,
                       const struct PslChanFsmEvtArgRead*   arg,
                       PslSmeEventStatus*                   pEvtStatus);


/**
 * Performs an encrypted 'write' operation conforming to glib's
 * GIOFuncs::io_write() semantics
 * 
 * @param pFsm
 * @param arg
 * 
 * @return PslSmeEventStatus
 */
static PslSmeEventStatus
crypto_handle_WRITE(PslChanFsm*                         pFsm,
                    const struct PslChanFsmEvtArgWrite* arg);

static PslError
crypto_start_renegotiation(PslChanFsm* pFsm);

PSL_CONFIG_INLINE_FUNC GIOCondition
crypto_giocondition_from_chanssl_iostate(PslChanFsmSSLIOStateId req);

/**
 * crypto_update_multi_fd_watch_giocondition(): optimization 
 * wrapper around psl_multi_fd_watch_add_or_update_fd().  Calls 
 * psl_multi_fd_watch_add_or_update_fd only if the new condition 
 * differs from the last saved conditions. 
 *  
 * @note This logic requires everything in the fsm_crypto module
 *       to call crypto_update_multi_fd_watch_giocondition()
 *       instead of calling
 *       psl_multi_fd_watch_add_or_update_fd() directly.
 *       Otherwise, bad things will happen.  This works in
 *       tandem with crypto_reset_multi_fd_watch()
 * 
 * @param pFsm 
 * @param cond 
 * 
 * @return PSL_CONFIG_INLINE_FUNC void 
 */
PSL_CONFIG_INLINE_FUNC void
crypto_update_multi_fd_watch_giocondition(PslChanFsm*  pFsm,
                                          GIOCondition cond);

/**
 * crypto_reset_multi_fd_watch(): wrapper around 
 * psl_multi_fd_watch_reset() for the fsm_crypto module. 
 * Cleares PslChanFsmCryptoSharedInfo::lastGIOCondition to 
 * support the condition caching optimization employed by 
 * crypto_update_multi_fd_watch_giocondition(). 
 *  
 * @note This logic requires everything in the fsm_crypto module
 *       to call crypto_reset_multi_fd_watch() instead of
 *       calling psl_multi_fd_watch_reset() directly. Otherwise,
 *       bad things will happen.
 * 
 * @param pFsm 
 * 
 * @return PSL_CONFIG_INLINE_FUNC void 
 */
PSL_CONFIG_INLINE_FUNC void
crypto_reset_multi_fd_watch(PslChanFsm* pFsm);


PSL_CONFIG_INLINE_FUNC void
crypto_schedule_deferred_ssl_io(PslChanFsm* pFsm);


static PslSmeEventStatus
crypto_process_deferred_ssl_io(PslChanFsm*          pFsm,
                               CryptoDeferredIOHint hint,
                               GIOCondition         revents);

unsigned int
crypto_total_input_bytes_ready(PslChanFsm* pFsm);


static PslError
crypto_read_low(PslChanFsm* pFsm,
                void*       pDst,
                int         cnt,
                bool        deferredIOAllowed,
                int*        pNumRead,
                bool*       pIOPerformed);


static PslError
crypto_write_low(PslChanFsm*    pFsm,
                 const void*    pSrc,
                 int            cnt,
                 int            maxWriteCnt,
                 int*           pNumWritten,
                 int*           pDeferredWriteCnt);


static PslError
crypto_do_shutdown(PslChanFsm*                  pFsm,
                   PslChanFsmEvtShutCryptoKind  how,
                   PslChanFsmCryptoShutPhase    currPhase,
                   PslChanFsmCryptoShutPhase*   pNewPhase);


static const char*
crypto_string_from_shutphase(PslChanFsmCryptoShutPhase phase);


static const char*
crypto_string_from_ssl_want(int ssl_wantResult);




/** ===========================================================================
 *                            FUNCTIONS
 * ============================================================================
 */


/**
 * Returns TRUE if the error code is one of: PSL_ERR_SSL_WANT_READ
 * or PSL_ERR_SSL_WANT_WRITE
 * 
 * @param pslErr
 * 
 * @return bool
 */
PSL_CONFIG_INLINE_FUNC bool
crypto_is_deferred_io_pslerror(PslError const pslErr)
{
    return (PSL_ERR_SSL_WANT_READ == pslErr || PSL_ERR_SSL_WANT_WRITE == pslErr);
}


PSL_CONFIG_INLINE_FUNC PslChanFsmCryptoSharedInfo*
crypto_shared_info(PslChanFsm* const pFsm)
{
    return &pFsm->aliveState.cryptoModeState.sslInfo;
}



/** ========================================================================
 * Returns TRUE if the given PslChanFsmSSLIOStateId represents a
 * pending I/O request (versus idle or error)
 * @param ioState
 * 
 * @return bool
 * 
 * =========================================================================
 */
PSL_CONFIG_INLINE_FUNC bool
crypto_deferred_io_pending(PslChanFsmSSLIOStateId const ioState)
{
    return (kPslChanFsmSSLIOState_wantRead  == ioState ||
            kPslChanFsmSSLIOState_wantWrite == ioState);
}



/** ========================================================================
 * Determines the I/O ready hint for the SSL input direction
 * @param fsm
 * 
 * @return PslChanFsmEvtIOReadyHint
 * 
 * =========================================================================
 */
PSL_CONFIG_INLINE_FUNC PslChanFsmEvtIOReadyHint
crypto_get_input_ready_hint(PslChanFsm* const pFsm)
{
    const PslChanFsmCryptoInput* const input = &(crypto_shared_info(pFsm)->io.in);
    /**
     * @note We leave it up to openssl to make an accurate
     *       assessment of its own needs; so, we assume that openssl
     *       is ready for input until it tells us that it isn't.
     */
    if (crypto_deferred_io_pending(input->ioState)) {
        return kPslChanFsmEvtIOReadyHint_notReady;
    }

    if (kPslChanFsmSSLIOState_error == input->ioState &&
        PSL_ERR_SSL_CLEAN_EOF != input->pslErr) {

        PSL_ASSERT(input->pslErr);
        return kPslChanFsmEvtIOReadyHint_readyhup;
    }

    return kPslChanFsmEvtIOReadyHint_ready;
}



/** ========================================================================
 * Determines the I/O ready hint for the SSL output direction
 * @param fsm
 * 
 * @return PslChanFsmEvtIOReadyHint
 * 
 * =========================================================================
 */
PSL_CONFIG_INLINE_FUNC PslChanFsmEvtIOReadyHint
crypto_get_output_ready_hint(PslChanFsm* const pFsm)
{
    const PslChanFsmCryptoOutput* const output = &(crypto_shared_info(pFsm)->io.out);
    /**
     * @note We leave it up to openssl to make an accurate
     *       assessment of its own needs; so, if openssl hasn't yet
     *       told us that it's not ready for output, we assume that
     *       it's ready
     */
    if (crypto_deferred_io_pending(output->ioState)) {
        return kPslChanFsmEvtIOReadyHint_notReady;
    }

    if (kPslChanFsmSSLIOState_error == output->ioState) {
        PSL_ASSERT(output->pslErr);
        return kPslChanFsmEvtIOReadyHint_readyhup;
    }

    return kPslChanFsmEvtIOReadyHint_ready;
}



/** ========================================================================
 * Map PslChanFsmSSLIOStateId to GIOCondition for use with our 
 * internal multi-fd watch 
 * @param req
 * 
 * @return GIOCondition
 * 
 * =========================================================================
 */
PSL_CONFIG_INLINE_FUNC GIOCondition
crypto_giocondition_from_chanssl_iostate(PslChanFsmSSLIOStateId const req)
{
    GIOCondition    cond = 0;

    switch (req) {
    case kPslChanFsmSSLIOState_idle:    /// FALLTHROUGH
    case kPslChanFsmSSLIOState_error:
        break;

    case kPslChanFsmSSLIOState_wantRead:
        cond = G_IO_IN;
        break;
    case kPslChanFsmSSLIOState_wantWrite:
        cond = G_IO_OUT;
        break;
    }

    return cond;
}


/** ========================================================================
 * =========================================================================
 */
void
psl_chan_fsm_crypto_init(PslChanFsm* const fsm, PslSmeStateBase* parentState)
{
    /// Initialize our states
    PslChanFsmCryptoModeState*  const cryptoModeState =
        (PslChanFsmCryptoModeState*)psl_chan_fsm_get_crypto_mode_state(fsm);

    psl_sme_init_state(
        &cryptoModeState->base,
        (PslSmeStateHandlerFnType*)&crypto_mode_state_handler,
        "CRYPTO_MODE");

    psl_sme_init_state(
        &cryptoModeState->failState.base,
        (PslSmeStateHandlerFnType*)&crypto_fail_state_handler,
        "CRYPTO_FAIL");

    psl_sme_init_state(
        &cryptoModeState->connState.base,
        (PslSmeStateHandlerFnType*)&crypto_conn_state_handler,
        "CRYPTO_CONN");

    psl_sme_init_state(
        &cryptoModeState->renegotiateState.base,
        (PslSmeStateHandlerFnType*)&crypto_renegotiate_state_handler,
        "CRYPTO_RENEG");

    psl_sme_init_state(
        &cryptoModeState->sslState.base,
        (PslSmeStateHandlerFnType*)&crypto_ssl_state_handler,
        "CRYPTO_SSL");

    psl_sme_init_state(
        &cryptoModeState->shutState.base,
        (PslSmeStateHandlerFnType*)&crypto_shut_state_handler,
        "CRYPTO_SHUT");


    /// Add our state to the FSM
    psl_sme_insert_state(
        &fsm->base,
        &cryptoModeState->base,
        parentState);

    psl_sme_insert_state(
        &fsm->base,
        &cryptoModeState->failState.base,
        &cryptoModeState->base);

    psl_sme_insert_state(
        &fsm->base,
        &cryptoModeState->connState.base,
        &cryptoModeState->base);

    psl_sme_insert_state(
        &fsm->base,
        &cryptoModeState->renegotiateState.base,
        &cryptoModeState->base);

    psl_sme_insert_state(
        &fsm->base,
        &cryptoModeState->shutState.base,
        &cryptoModeState->base);

    psl_sme_insert_state(
        &fsm->base,
        &cryptoModeState->sslState.base,
        &cryptoModeState->base);

}// psl_chan_fsm_crypto_init



/** ========================================================================
 * =========================================================================
 */
static PslSmeEventStatus
crypto_mode_state_handler(PslChanFsmCryptoModeState*    const pState,
                          PslChanFsm*                   const pFsm,
                          PslSmeEventId                 const evtId,
                          const PslChanFsmEvtArg*       const evtArg)
{
    const int kMaxIOBufSize = (16 * 1024);

    switch (evtId) 
    {
    case kFsmEventEnterScope:
        psl_openssl_init_conditional(kPmSockOpensslInitType_DEFAULT);
        memset(&pState->sslInfo, 0, sizeof(pState->sslInfo));
        pState->sslInfo.io.in.ioState = kPslChanFsmSSLIOState_idle;
        pState->sslInfo.io.out.ioState = kPslChanFsmSSLIOState_idle;
        (void)psl_io_buf_init(&pState->sslInfo.io.out.buf, kMaxIOBufSize);
        return kPslSmeEventStatus_success;
        break;

    case kFsmEventExitScope:
        (void)psl_io_buf_uninit(&pState->sslInfo.io.out.buf);
        if (pState->sslInfo.ssl) {
            SSL_free(pState->sslInfo.ssl);
            pState->sslInfo.ssl = NULL; // so CLOSE evt handler won't complain
        }
        if (pState->sslInfo.sslCtx) {
            PmSockSSLCtxUnref(pState->sslInfo.sslCtx);
            pState->sslInfo.sslCtx = NULL;
        }
        PmSockOpensslUninit();
        return kPslSmeEventStatus_success;
        break;

    case kFsmEventBegin:
        return kPslSmeEventStatus_success;
        break;

    case PSL_CHAN_FSM_EVT_GET_PEER_CERT_VERIFY_ERR:
        if (pState->sslInfo.ssl && pState->sslInfo.sslHandshakeFinished) {
            PmSockPeerCertVerifyErrorInfo*  const pRes =
                evtArg->getPeerCertVerifyErr.pRes;
            pRes->opensslx509_v_err = SSL_get_verify_result(pState->sslInfo.ssl);
            pRes->psl_v_err = pState->sslInfo.pv.verifyFailCode;
        }
        else {
            memset(evtArg->getPeerCertVerifyErr.pRes, 0,
                   sizeof(*evtArg->getPeerCertVerifyErr.pRes));
        }
        return kPslSmeEventStatus_success;
        break;

    case PSL_CHAN_FSM_EVT_SHUT_SOCK:
        return psl_chan_fsm_plain_shut_sock_and_goto_shut_on_success(
            pFsm, evtArg->shutSock.how);
        break;

    default:
        break; // allow default processing by parent
    }

    return kPslSmeEventStatus_passToParent;
}// crypto_mode_state_handler



/** ========================================================================
 * =========================================================================
 */
static PslSmeEventStatus
crypto_fail_state_handler(PslChanFsmCryptoFailState*    const pState,
                          PslChanFsm*                   const pFsm,
                          PslSmeEventId                 const evtId,
                          const PslChanFsmEvtArg*       const evtArg)
{   
    switch (evtId) 
    {
    case kFsmEventEnterScope:
    case kFsmEventExitScope:
        return kPslSmeEventStatus_success;
        break;

    case kFsmEventBegin:
        pState->arg = evtArg->begin.cryptoFail;
        PSL_ASSERT(pState->arg.pslError);
        return kPslSmeEventStatus_success;
        break;

    case PSL_CHAN_FSM_EVT_CHECK_IO:
        return psl_chan_fsm_evt_make_full_CHECK_IO_response(
            &evtArg->checkIO, kPslChanFsmEvtIOReadyHint_hup,
            kPslChanFsmEvtIOReadyHint_hup, PSL_INVALID_FD);
        break;

    case PSL_CHAN_FSM_EVT_READ:
    case PSL_CHAN_FSM_EVT_WRITE:
        psl_chan_fsm_set_last_error(pFsm, kPslChanFsmErrorSource_psl,
                                    pState->arg.pslError);
        return kPslSmeEventStatus_errorCatchAll;
        break;

    default:
        break; // allow default processing by parent
    }

    return kPslSmeEventStatus_passToParent;
}//crypto_fail_state_handler



/** ========================================================================
 * =========================================================================
 */
static PslSmeEventStatus
crypto_shut_state_handler(PslChanFsmCryptoShutState*    const pState,
                          PslChanFsm*                   const pFsm,
                          PslSmeEventId                 const evtId,
                          const PslChanFsmEvtArg*       const evtArg)
{   
    switch (evtId) 
    {
    case kFsmEventEnterScope:
        pState->phase = kPslChanFsmCryptoShutPhase_init;
        return kPslSmeEventStatus_success;
        break;

    case kFsmEventExitScope:
        /// We use it, so clean up
        crypto_reset_multi_fd_watch(pFsm);
        return kPslSmeEventStatus_success;
        break;

    case kFsmEventBegin:
        {
            pState->arg = evtArg->begin.cryptoShut;
            crypto_reset_multi_fd_watch(pFsm);

            PslChanFsmCryptoSharedInfo* const sslInfo = crypto_shared_info(pFsm);

            if (kPslChanFsmEvtShutCrypto_twoWay == pState->arg.how) {
                if (crypto_deferred_io_pending(sslInfo->io.in.ioState)) {
                    /// Cancel the deferred input transaction, we won't be
                    /// doing any reading in Two-Way shutdown
                    sslInfo->io.in.ioState = kPslChanFsmSSLIOState_idle;
                    sslInfo->io.in.deferredByteAvailable = false;
                }
            }

            /// Let's get started
            psl_multi_fd_watch_set_poll_timeout(pFsm->fdWatchInfo.fdWatch, 0);
        }
        return kPslSmeEventStatus_success;
        break;

    case PSL_CHAN_FSM_EVT_RESUME_PLAINTEXT:
        {
            PslChanFsmCryptoSharedInfo* const sslInfo = crypto_shared_info(pFsm);

            if (kPslChanFsmCryptoShutPhase_success != pState->phase) {
                PSL_LOG_ERROR(
                    "%s (fsm=%p): ERROR: RESUME_PLAINTEXT is not " \
                    "allowed without successful completion of the requested " \
                    "crypto-shut operation: crypto-shut phase=%s",
                    __func__, pFsm, crypto_string_from_shutphase(pState->phase));
                return kPslSmeEventStatus_passToParent; // for catch-all handling
            }

            int const shutState = SSL_get_shutdown(sslInfo->ssl);
            int const passBits = SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN;
            if ((shutState & passBits) == passBits) {
                psl_chan_fsm_goto_plain_tcp_state(pFsm);
                return kPslSmeEventStatus_success;
            }

            PSL_LOG_ERROR(
                "%s (fsm=%p): ERROR: RESUME_PLAINTEXT is not " \
                "allowed before successful completion of bi-directional " \
                "SSL shutdown; SSL_get_shutdown returned 0x%X",
                __func__, pFsm, (unsigned)shutState);
        }
        return kPslSmeEventStatus_passToParent;     // for catch-all handling
        break;

    case PSL_CHAN_FSM_EVT_SHUT_CRYPTO:
        if (pState->arg.how == evtArg->shutCrypto.how) {
            PSL_LOG_ERROR("%s (fsm=%p): ERROR: SHUT_CRYPTO with " \
                            "same how=%d already in progress", __func__, pFsm,
                            (int)pState->arg.how);
            return kPslSmeEventStatus_passToParent; // for catch-all handling
        }

        if (kPslChanFsmEvtShutCrypto_twoWay == pState->arg.how &&
            kPslChanFsmEvtShutCrypto_oneWay == evtArg->shutCrypto.how) {

            PSL_LOG_ERROR("%s (fsm=%p): ERROR: One-Way SHUT_CRYPTO requested " \
                            "while Two-Way already in progress", __func__, pFsm);
            return kPslSmeEventStatus_passToParent; // for catch-all handling
        }

        /// So, it's a switch from one-way to two-way shutdown
        PSL_LOG_INFO("%s (fsm=%p): User requested switch from One-Way to " \
                     "Two-Way SHUT_CRYPTO; switching...", __func__, pFsm);
        psl_chan_fsm_goto_crypto_shut_state(pFsm,
                                            evtArg->shutCrypto.how,
                                            &evtArg->shutCrypto.cb);
        return kPslSmeEventStatus_success;
        break;

    case PSL_CHAN_FSM_EVT_CHECK_IO:
        {
            PSL_ASSERT(kPslChanFsmCryptoShutPhase_failed != pState->phase);
            PslChanFsmEvtIOReadyHint const wrhint = 
                (kPslChanFsmCryptoShutPhase_success == pState->phase
                 ? kPslChanFsmEvtIOReadyHint_ready
                 : kPslChanFsmEvtIOReadyHint_notReady);

            PslChanFsmEvtIOReadyHint rdhint = kPslChanFsmEvtIOReadyHint_notReady;
            if (kPslChanFsmEvtShutCrypto_twoWay == pState->arg.how) {
                if (kPslChanFsmCryptoShutPhase_success == pState->phase) {
                    rdhint = kPslChanFsmEvtIOReadyHint_ready;
                }
            }
            else if (kPslChanFsmCryptoShutPhase_success == pState->phase ||
                     kPslChanFsmCryptoShutPhase_flushOut == pState->phase) {
                rdhint = crypto_get_input_ready_hint(pFsm);
            }

            return psl_chan_fsm_evt_make_full_CHECK_IO_response(
                &evtArg->checkIO, rdhint, wrhint, pFsm->fd);
        }
        break;

    case PSL_CHAN_FSM_EVT_FD_WATCH:
        {
            PslChanFsmCryptoSharedInfo* sslInfo = crypto_shared_info(pFsm);

            if (kPslChanFsmCryptoShutPhase_init == pState->phase) {
                pState->phase = kPslChanFsmCryptoShutPhase_flushOut;
                crypto_reset_multi_fd_watch(pFsm);
            }

            GIOCondition const cond = (1 == evtArg->fdWatch.numrecs
                                       ? evtArg->fdWatch.pollrecs[0].indEvents
                                       : 0);

            if (kPslChanFsmCryptoShutPhase_success == pState->phase) {
                /// @note We shouldn't get PSL_CHAN_FSM_EVT_FD_WATCH after
                ///       two-way success.
                PSL_ASSERT(kPslChanFsmEvtShutCrypto_oneWay == pState->arg.how);
                return crypto_process_deferred_ssl_io(
                    pFsm, kCryptoDeferredIOHint_none, cond);
            }
            else if (kPslChanFsmCryptoShutPhase_flushOut == pState->phase) {
                (void)crypto_process_deferred_ssl_io(
                    pFsm, kCryptoDeferredIOHint_none, cond);

                if (crypto_deferred_io_pending(sslInfo->io.out.ioState)) {
                    return kPslSmeEventStatus_success;
                }

                /**
                 * Done with flushing... start SSL/TLS shutdown
                 */
                crypto_reset_multi_fd_watch(pFsm);
                pState->phase = kPslChanFsmCryptoShutPhase_shut1;
                PSL_LOG_DEBUG("%s (fsm=%p): Done with flushOut, starting shut1",
                              __func__, pFsm);
            }

            if (kPslChanFsmCryptoShutPhase_shut1 == pState->phase ||
                kPslChanFsmCryptoShutPhase_shut2 == pState->phase) {
                PslError pslErr;
                if (kPslChanFsmSSLIOState_error == sslInfo->io.out.ioState) {
                    pslErr = sslInfo->io.out.pslErr;
                    PSL_ASSERT(pslErr);
                }
                else {
                    pslErr = crypto_do_shutdown(
                        pFsm, pState->arg.how, pState->phase, &pState->phase);
                }
                if (pslErr) {
                    /// Schedule notification, if any, and transition to fail
                    psl_chan_fsm_sched_fdwatch_completion_cb(
                        pFsm, &pState->arg.cb, pslErr, false/*toCrypto*/);
                    psl_chan_fsm_goto_crypto_fail_state(pFsm, pslErr);
                    return kPslSmeEventStatus_error;
                }

                PSL_ASSERT(kPslChanFsmCryptoShutPhase_failed != pState->phase);

                if (kPslChanFsmCryptoShutPhase_success == pState->phase) {
                    psl_chan_fsm_sched_fdwatch_completion_cb(
                        pFsm, &pState->arg.cb, PSL_ERR_NONE,
                        false/*toCrypto*/);

                    /// If this was a legacy API request, automatically
                    /// transition to plaintext
                    if (kPslChanFsmEvtCompletionCbId_switch ==
                        pState->arg.cb.which) {
                        PSL_ASSERT(kPslChanFsmEvtShutCrypto_twoWay ==
                                   pState->arg.how);
                        psl_chan_fsm_goto_plain_tcp_state(pFsm);
                        return kPslSmeEventStatus_success;
                    }

                    /// Otherwise, we remain in this state until further notice
                    crypto_reset_multi_fd_watch(pFsm);
                    if (kPslChanFsmEvtShutCrypto_oneWay == pState->arg.how) {
                        return crypto_process_deferred_ssl_io(
                            pFsm, kCryptoDeferredIOHint_none, 0);
                    }
                }//if kPslChanFsmCryptoShutPhase_success
            }//if shutting down
        }
        return kPslSmeEventStatus_success;
        break;

    case PSL_CHAN_FSM_EVT_READ:
        // @note Only reading is allowed in Crypto-Shut and only in certain phases;
        //       (writing is not allowed in Crypto-Shut)

        PSL_LOG_DEBUG(
            "%s (fsm=%p): PSL_CHAN_FSM_EVT_READ: requested cnt=%zd, how=%d, currPhase=%s",
            __func__, pFsm, evtArg->read.cnt, (int)pState->arg.how,
            crypto_string_from_shutphase(pState->phase));

        /*
         * @note We may still be in kPslChanFsmCryptoShutPhase_init 
         *       if READ is called before our initial multi-fd-watch's dispatch
         */

        if (kPslChanFsmEvtShutCrypto_twoWay == pState->arg.how) {
            if (kPslChanFsmCryptoShutPhase_success == pState->phase) {
                *evtArg->read.pGioStatus = G_IO_STATUS_EOF;
                *evtArg->read.pNumRead = 0;
            }
            else {
                *evtArg->read.pGioStatus = G_IO_STATUS_AGAIN;
                *evtArg->read.pNumRead = 0;
            }
        }
        else {
            if (kPslChanFsmCryptoShutPhase_success == pState->phase ||
                kPslChanFsmCryptoShutPhase_flushOut == pState->phase) {
                return crypto_handle_READ(pFsm, &evtArg->read);
            }
            else {
                /*
                 * @note Suppressing READ during the shut1 phase of a
                 *       unidirectional shutdown simplifies our logic by
                 *       eliminating openssl state side-effects
                 *       (WANT_READ/WANT_WRITE) between SSL_shutdown() and
                 *       SSL_read()
                 */
                *evtArg->read.pGioStatus = G_IO_STATUS_AGAIN;
                *evtArg->read.pNumRead = 0;
            }
        }

        PSL_LOG_DEBUG(
            "%s (fsm=%p): PSL_CHAN_FSM_EVT_READ completed with: GIOStatus=%s,"
            "numRead=%zd, evtStatus=%d",
            __func__, pFsm, psl_chan_fsm_str_from_giostatus(*evtArg->read.pGioStatus),
            *evtArg->read.pNumRead, (int)kPslSmeEventStatus_success);

        return kPslSmeEventStatus_success;
        break;

    default:
        break; // allow default processing by parent
    }

    return kPslSmeEventStatus_passToParent;
}//crypto_shut_state_handler



/** ========================================================================
 * =========================================================================
 */
static PslSmeEventStatus
crypto_conn_state_handler(PslChanFsmCryptoConnState*    const pState,
                          PslChanFsm*                   const pFsm,
                          PslSmeEventId                 const evtId,
                          const PslChanFsmEvtArg*       const evtArg)
{   
    switch (evtId) 
    {
    case kFsmEventEnterScope:
        pState->failPslErr = 0;
        pState->started = false;
        return kPslSmeEventStatus_success;
        break;

    case kFsmEventExitScope:
        /// We use it, so clean up
        crypto_reset_multi_fd_watch(pFsm);
        PmSockSSLCtxUnref(pState->arg.common.u.crypto.sslCtx);
        return kPslSmeEventStatus_success;
        break;

    case kFsmEventBegin:
        {
            pState->arg = evtArg->begin.cryptoConn;
            crypto_reset_multi_fd_watch(pFsm);

            PSL_LOG_INFO("%s (fsm=%p): Initiating SSL conn. handshake",
                         __func__, pFsm);

            /// Kick off connection establishment
            psl_multi_fd_watch_set_poll_timeout(pFsm->fdWatchInfo.fdWatch, 0);
        }
        return kPslSmeEventStatus_success;
        break;

    case PSL_CHAN_FSM_EVT_FD_WATCH:
        if (!pState->started) {
            pState->started = true;
            crypto_reset_multi_fd_watch(pFsm);

            pState->failPslErr = crypto_create_and_config_ssl(
                pFsm, pState->arg.common.connKind, &pState->arg.common.u.crypto);
        }

        if (!pState->failPslErr) {
            //const struct PslChanFsmEvtArgFdWatch* const arg =
            //  &evtArg->fdWatch;

            /// Continue SSL session establishment
            bool const done = crypto_do_SSL_handshake(
                pFsm, &pState->failPslErr);

            if (done) {
                crypto_shared_info(pFsm)->sslHandshakeFinished = true;
            }

            if (done && !pState->failPslErr) {
                crypto_conn_sched_done_cb_if_any(pFsm, pState, 0);
                psl_chan_fsm_goto_crypto_ssl_state(pFsm);
                return kPslSmeEventStatus_success;
            }
        }

        if (pState->failPslErr) { /// May also be error from kFsmEventBegin
            /// Schedule a callback to notify user
            crypto_conn_sched_done_cb_if_any(pFsm, pState, pState->failPslErr);
            psl_chan_fsm_set_last_error(pFsm, kPslChanFsmErrorSource_psl,
                                        pState->failPslErr);
            psl_chan_fsm_goto_crypto_fail_state(pFsm, pState->failPslErr);
            return kPslSmeEventStatus_error;
        }
        return kPslSmeEventStatus_success;
        break;

    default:
        break; // allow default processing by parent
    }

    return kPslSmeEventStatus_passToParent;
}// crypto_conn_state_handler



/** ========================================================================
 * =========================================================================
 */
static PslSmeEventStatus
crypto_renegotiate_state_handler(PslChanFsmCryptoRenegotiateState*  const pState,
                                 PslChanFsm*                        const pFsm,
                                 PslSmeEventId                      const evtId,
                                 const PslChanFsmEvtArg*            const evtArg)
{   
    switch (evtId) 
    {
    case kFsmEventEnterScope:
        pState->phase = kPslChanFsmCryptoRenegPhase_init;
        pState->pslerr = PSL_ERR_NONE;
        return kPslSmeEventStatus_success;
        break;

    case kFsmEventExitScope:
        /// We use it, so clean up
        crypto_reset_multi_fd_watch(pFsm);
        return kPslSmeEventStatus_success;
        break;

    case kFsmEventBegin:
        {
            pState->arg = evtArg->begin.cryptoRenegotiate;
            crypto_reset_multi_fd_watch(pFsm);

            /// Let's get started (triggers PSL_CHAN_FSM_EVT_FD_WATCH)
            psl_multi_fd_watch_set_poll_timeout(pFsm->fdWatchInfo.fdWatch, 0);

            /**
             * Suppress deferred input processing: we don't want SSL state 
             * side-effects between SSL_read and SSL_do_handshake 
             * processing.  We will allow reads only when data becomes 
             * available in the input holding buffer as the implicit result 
             * of SSL_do_handshake processing. 
             *  
             * The renegotiate state handler will make sure that we don't 
             * get back into deferred input mode 
             */
            if (crypto_deferred_io_pending(crypto_shared_info(pFsm)->io.in.ioState)) {
                crypto_shared_info(pFsm)->io.in.ioState = kPslChanFsmSSLIOState_idle;
            }
        }
        return kPslSmeEventStatus_success;
        break;

    case PSL_CHAN_FSM_EVT_FD_WATCH:
        {
            /// @note numrecs may be 0 when we request a timer callback
            ///       our own GSource dispatch in order to switch execution
            ///       context
            if (evtArg->fdWatch.numrecs > 0 &&
                kPslChanFsmCryptoRenegPhase_flushOut == pState->phase) {
                (void)crypto_process_deferred_ssl_io(
                    pFsm, kCryptoDeferredIOHint_none,
                    evtArg->fdWatch.pollrecs[0].indEvents);
            }

            if (crypto_do_renegotiate(pState, pFsm, &evtArg->fdWatch)) {
                /// Done!
                PSL_ASSERT(kPslChanFsmCryptoRenegPhase_done == pState->phase);

                psl_chan_fsm_sched_fdwatch_completion_cb(
                    pFsm, &pState->arg.data.cb, pState->pslerr, false/*toCrypto*/);

                if (pState->pslerr) {
                    psl_chan_fsm_goto_crypto_fail_state(pFsm, pState->pslerr);
                }
                else {
                    psl_chan_fsm_goto_crypto_ssl_state(pFsm);
                }

                return kPslSmeEventStatus_success;
            }
        }
        return kPslSmeEventStatus_success;
        break;

    case PSL_CHAN_FSM_EVT_CHECK_IO:
        {
            PslChanFsmEvtIOReadyHint const readableHint =
                (crypto_total_input_bytes_ready(pFsm) > 0
                 ? kPslChanFsmEvtIOReadyHint_ready
                 : kPslChanFsmEvtIOReadyHint_notReady);

            return psl_chan_fsm_evt_make_full_CHECK_IO_response(
                &evtArg->checkIO, readableHint,
                kPslChanFsmEvtIOReadyHint_notReady, pFsm->fd);
        }
        break;

    case PSL_CHAN_FSM_EVT_READ:
        {
            /// Prevent unwanted side-effects from the interaction between
            /// openssl's renegotiation logic and deferred I/O processing (which
            /// calls SSL_read) by limiting read size only to data that is already
            /// in the holding buffer(s).
            unsigned const numAvailable = crypto_total_input_bytes_ready(pFsm);

            if (0 == numAvailable && evtArg->read.cnt > 0) {
                *evtArg->read.pNumRead = 0;
                *evtArg->read.pGioStatus = G_IO_STATUS_AGAIN;
                return kPslSmeEventStatus_success;
            }

            else {
                struct PslChanFsmEvtArgRead temp = evtArg->read;
                temp.cnt = (numAvailable < evtArg->read.cnt
                            ? numAvailable
                            : evtArg->read.cnt);

                PslSmeEventStatus const evtstatus = crypto_handle_READ(pFsm, &temp);
                PSL_ASSERT(!crypto_deferred_io_pending(
                    crypto_shared_info(pFsm)->io.in.ioState));

                /// Keep renegotiation going in case it was suspended due to
                /// non-empty input holding buffer(s)
                if (crypto_do_renegotiate(pState, pFsm, NULL/*pFdWatch*/)) {
                    /// Renegotiation completed: wake up our
                    /// PSL_CHAN_FSM_EVT_FD_WATCH handler
                    psl_multi_fd_watch_set_poll_timeout(pFsm->fdWatchInfo.fdWatch, 0);
                }

                return evtstatus;
            }
        }
        break;

    case PSL_CHAN_FSM_EVT_WRITE:
        *evtArg->write.pNumWritten = 0;
        *evtArg->write.pGioStatus = G_IO_STATUS_AGAIN;
        return kPslSmeEventStatus_success;
        break;

    case PSL_CHAN_FSM_EVT_SHUT_CRYPTO:
        psl_chan_fsm_goto_crypto_shut_state(pFsm,
                                            evtArg->shutCrypto.how,
                                            &evtArg->shutCrypto.cb);
        return kPslSmeEventStatus_success;
        break;

    default:
        break; // allow default processing by parent
    }

    return kPslSmeEventStatus_passToParent;
}//crypto_renegotiate_state_handler


/** ========================================================================
 * =========================================================================
 */
static PslSmeEventStatus
crypto_ssl_state_handler(PslChanFsmCryptoSSLState*  const pState,
                         PslChanFsm*                const pFsm,
                         PslSmeEventId              const evtId,
                         const PslChanFsmEvtArg*    const evtArg)
{   
    switch (evtId) 
    {
    case kFsmEventEnterScope:
        return kPslSmeEventStatus_success;
        break;

    case kFsmEventExitScope:
        /// We use it, so clean up
        crypto_reset_multi_fd_watch(pFsm);
        return kPslSmeEventStatus_success;
        break;

    case kFsmEventBegin:
        crypto_reset_multi_fd_watch(pFsm);
        // Force update of deferred I/O state (this is particularly necessary
        // when returning to crypto-ssl state from crypto-renegotiate state)
        (void)crypto_process_deferred_ssl_io(pFsm, kCryptoDeferredIOHint_none,
                                             (GIOCondition)0);
        return kPslSmeEventStatus_success;
        break;

    case PSL_CHAN_FSM_EVT_CHECK_IO:
        {
            PslChanFsmEvtIOReadyHint const rdhint = crypto_get_input_ready_hint(pFsm);
            PslChanFsmEvtIOReadyHint const wrhint = crypto_get_output_ready_hint(pFsm);
            return psl_chan_fsm_evt_make_full_CHECK_IO_response(
                &evtArg->checkIO, rdhint, wrhint, pFsm->fd);
        }
        break;

    case PSL_CHAN_FSM_EVT_FD_WATCH:
        {
            const struct PslChanFsmEvtArgFdWatch*   const arg =
                &evtArg->fdWatch;

            /// If we're here, there must be exactly one pollrec
            PSL_ASSERT(1 == arg->numrecs && arg->pollrecs[0].fd == pFsm->fd);

            return crypto_process_deferred_ssl_io(
                pFsm, kCryptoDeferredIOHint_none, arg->pollrecs[0].indEvents);
        }
        break;

    case PSL_CHAN_FSM_EVT_READ:
        return crypto_handle_READ(pFsm, &evtArg->read);
        break;

    case PSL_CHAN_FSM_EVT_WRITE:
        return crypto_handle_WRITE(pFsm, &evtArg->write);
        break;

    case PSL_CHAN_FSM_EVT_RENEGOTIATE_CRYPTO:
        if ((evtArg->renegotiateCrypto.data.conf.opts &
             kPmSockRenegOpt_waitForClientHandshake) &&
            crypto_shared_info(pFsm)->connKind != kPslChanFsmEvtConnKind_cryptoServer) {

            PSL_LOG_ERROR(
                "%s (fsm=%p): ERROR: kPmSockRenegOpt_waitForClientHandshake " \
                "is not allowed for Client mode",  __func__, pFsm);
            psl_chan_fsm_set_last_error(pFsm, kPslChanFsmErrorSource_psl, PSL_ERR_INVAL);
            return kPslSmeEventStatus_error;
        }

        psl_chan_fsm_goto_crypto_renegotiate_state(pFsm, &evtArg->renegotiateCrypto.data);
        return kPslSmeEventStatus_success;
        break;

    case PSL_CHAN_FSM_EVT_SHUT_CRYPTO:
        psl_chan_fsm_goto_crypto_shut_state(pFsm,
                                            evtArg->shutCrypto.how,
                                            &evtArg->shutCrypto.cb);
        return kPslSmeEventStatus_success;
        break;

    default:
        break; // allow default processing by parent
    }

    return kPslSmeEventStatus_passToParent;
}//crypto_ssl_state_handler



/** ========================================================================
 * =========================================================================
 */
static PslError
crypto_create_and_config_ssl(
    PslChanFsm*                           const pFsm,
    PslChanFsmEvtConnKind                 const connKind,
    const PslChanFsmEvtCryptoConnectArgs* const pCryptoConnArgs)
{
    PSL_LOG_DEBUG("%s (fsm=%p): connKind=%d", __func__, pFsm, (int)connKind);

    PslChanFsmCryptoSharedInfo* const sslInfo = crypto_shared_info(pFsm);

    PSL_ASSERT(!sslInfo->ssl);

    char sslErrTextBuf[PSL_ERR_OPENSSL_ERROR_BUF_SIZE] = "";
    PslError pslErr = 0;

    sslInfo->connKind = connKind;

    sslInfo->sslCtx = PmSockSSLCtxRef(pCryptoConnArgs->sslCtx);
    sslInfo->cryptoConf = pCryptoConnArgs->conf;

    /// Instantiate the SSL channel
    sslInfo->ssl = SSL_new(pCryptoConnArgs->sslCtx->opensslCtx);
    if (!sslInfo->ssl) {
        pslErr = psl_err_process_and_purge_openssl_err_stack(
            pFsm, sslErrTextBuf, sizeof(sslErrTextBuf), PSL_ERR_SSL_CONFIG, NULL);
        pslErr = pslErr ? pslErr : PSL_ERR_SSL_CONFIG;
        goto error_cleanup;
    }

    /**
     * We abstract the fickle nature of SSL request repeats
     * (_WANT_READ, _WANT_WRITE) from our clients.
     * 
     * SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER permits us to substitute
     * our own buffer for repeating the SSL_write() operation at a
     * later time.
     * 
     * SSL_MODE_ENABLE_PARTIAL_WRITE permits us and the caller to
     * free up space in our buffers sooner rather than later.
     */
    long const reqMode =
        SSL_MODE_ENABLE_PARTIAL_WRITE |
        SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER;

    long const resMode = SSL_set_mode(sslInfo->ssl, reqMode);
    PSL_ASSERT((resMode & reqMode) == reqMode);
                  

    /**
     * Configure the SSL channel
     * 
     * @note The new SSL channel will inherit defautls that we
     *       configured in the associated openssl SSL Context
     */

    if (!SSL_set_fd(sslInfo->ssl, pFsm->fd)) {
        pslErr = psl_err_process_and_purge_openssl_err_stack(
            pFsm, sslErrTextBuf, sizeof(sslErrTextBuf), PSL_ERR_SSL_CONFIG, NULL);
        pslErr = pslErr ? pslErr : PSL_ERR_SSL_CONFIG;
        goto error_cleanup;
    }

    /// We leave additional peer verification to the user (via
    /// PmSockOpensslPeerVerifyCb)
#if 0 
    /**
     * Set certificate verification depth
     * 
     * @note We add 1 to the maximum depth in order to catch the
     *       verify_depth error as recommended in openssl
     *       documentation (see 'man SSL_CTX_set_verify_depth')
     */
    SSL_set_verify_depth(sslInfo->ssl, kCryptoMaxCertVerifyDepth + 1);
#endif


    /**
     * @todo Investigate: our
     *       version of openssl appears to be unpatched for the
     *       secure renegotiation as described in RFC5746 The patch
     *       counters the prefix attack described in CVE-2009-3555;
     *       (SSL_OP_LEGACY_SERVER_CONNECT,
     *       SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION, and
     *       SSL_get_secure_renegotiation_support are missing) see
     *       http://www.openssl.org/docs/ssl/SSL_CTX_set_options.html#.
     */
    /// @note SSL_CTX_set_options returns the new option-set, which we ignore
    (void)SSL_set_options(sslInfo->ssl, SSL_OP_ALL | SSL_OP_NO_SSLv2);

    if (!SSL_set_cipher_list(sslInfo->ssl, DEFAULT_CIPHER_LIST)) {
        pslErr = psl_err_process_and_purge_openssl_err_stack(
            pFsm, sslErrTextBuf, sizeof(sslErrTextBuf), PSL_ERR_SSL_CONFIG, NULL);
        pslErr = pslErr ? pslErr : PSL_ERR_SSL_CONFIG;
        goto error_cleanup;
    }


    /**
     * Associate our fsm instance as a cookie with this channel so
     * we can save any intermediate results during peer verification
     * for later use
     */
    if (!SSL_set_app_data(sslInfo->ssl, pFsm)) {
        pslErr = psl_err_process_and_purge_openssl_err_stack(
            pFsm, sslErrTextBuf, sizeof(sslErrTextBuf), PSL_ERR_SSL_CONFIG, NULL);
        pslErr = pslErr ? pslErr : PSL_ERR_SSL_CONFIG;
        goto error_cleanup;
    }


    /**
     * Set a peer verity_callback for additional cert validation and
     * instruct openssl to also carry out its default certificate
     * chain verification of the peer
     */
    if (kPslChanFsmEvtConnKind_cryptoClient == connKind) {
        SSL_set_verify(sslInfo->ssl, SSL_VERIFY_PEER,
                       &crypto_ssl_peer_verify_callback);
    }
    else {
        /// Our default configuration for server mode is to not request
        /// client cert.
        SSL_set_verify(sslInfo->ssl, SSL_VERIFY_NONE,
                       &crypto_ssl_peer_verify_callback);
    }

    /**
     * Prepare SSL channel for client or server mode
     */
    switch (connKind) {
    case kPslChanFsmEvtConnKind_cryptoClient:
        SSL_set_connect_state(sslInfo->ssl);
        break;

    case kPslChanFsmEvtConnKind_cryptoServer:
        SSL_set_accept_state(sslInfo->ssl);
        break;

    default:
        PSL_LOG_CRITICAL(
            "%s (fsm=%p): ERROR: unexpected PslChanFsmEvtConnKind=%d",
            __func__, pFsm, (int)connKind);
        pslErr = PSL_ERR_FAILED;
        goto error_cleanup;
        break;
    }


    /**
     * Execute user's openssl lifecycle callback, if any
     * 
     * @note The user may override some of the openssl settings
     */
    if (sslInfo->cryptoConf.lifecycleCb) {
        PSL_LOG_DEBUG(
            "%s (fsm=%p): Invoking user's openssl lifecycle callback=%p: " \
            "phase=init, userData=%p", __func__, pFsm,
            sslInfo->cryptoConf.lifecycleCb, pFsm->userSettings.userData);

        /**
         * @note We're NOT protecting ourselves here via FSM refcount
         *       because this callback is defined as non-reentrant with
         *       respect to the given channel instance; also, since
         *       we're calling from the scope of FSM dispatch, any calls
         *       back into the FSM would result in run-to-completion
         *       violation.
         */
        sslInfo->cryptoConf.lifecycleCb((PmSockIOChannel*)pFsm->channel,
                                        pFsm->userSettings.userData,
                                        sslInfo->ssl,
                                        kPmSockOpensslLifecyclePhase_init);
    }

    return 0;

error_cleanup:
    PSL_ASSERT(pslErr);

    PSL_LOG_ERROR("%s (fsm=%p): ERROR: openssl SSL channel configuration " \
                  "failed; pslerr=%d (%s//%s)", __func__, pFsm, pslErr,
                  PmSockErrStringFromError(pslErr), sslErrTextBuf);

    if (sslInfo->ssl) {
        SSL_free(sslInfo->ssl);
        sslInfo->ssl = NULL;
    }

    if (sslInfo->sslCtx) {
        PmSockSSLCtxUnref(sslInfo->sslCtx);
        sslInfo->sslCtx = NULL;
    }

    return pslErr;
}//crypto_create_and_config_ssl



/** ========================================================================
 * @note Assumes that crypto_process_deferred_ssl_io() has
 *       already been called when appropriate
 * ========================================================================= 
 */
static bool
crypto_do_renegotiate(PslChanFsmCryptoRenegotiateState*     const pState,
                      PslChanFsm*                           const pFsm,
                      const struct PslChanFsmEvtArgFdWatch* const pFdWatch)
{
    const PslChanFsmCryptoSharedInfo* const sslInfo = crypto_shared_info(pFsm);

    PSL_LOG_DEBUG(
        "%s (fsm=%p): ENTERING: pState=%p, pFdWatch=%p, " \
        "PslChanFsmCryptoRenegPhase=%d, pState->PslError=%d, openSSL state=%d (%s)",
        __func__, pFsm, pState, pFdWatch, (int)pState->phase, pState->pslerr,
        SSL_state(sslInfo->ssl), SSL_state_string_long(sslInfo->ssl));

    #if 0
    PSL_ASSERT(!pFdWatch || (pFdWatch->numrecs <= 1));
    GIOCondition const revents = ((!pFdWatch || !pFdWatch->numrecs)
                                  ? (GIOCondition)0
                                  : pFdWatch->pollrecs[0].indEvents
                                  );
    #endif

    if (kPslChanFsmCryptoRenegPhase_init == pState->phase) {
        crypto_reset_multi_fd_watch(pFsm);

        pState->phase = kPslChanFsmCryptoRenegPhase_flushOut;
    }

    if (kPslChanFsmCryptoRenegPhase_flushOut == pState->phase) {
        if (!crypto_deferred_io_pending(sslInfo->io.out.ioState)) {
            if (pState->pslerr) {
                pState->phase = kPslChanFsmCryptoRenegPhase_done;
            }
            else {
                pState->phase = 
                    (kPslChanFsmEvtConnKind_cryptoServer == sslInfo->connKind
                     ? kPslChanFsmCryptoRenegPhase_requestHello
                     : kPslChanFsmCryptoRenegPhase_handshake);

            }

            PSL_LOG_DEBUG("%s (fsm=%p): finished flushOut: new phase=%d",
                          __func__, pFsm, (int)pState->phase);

            /**
             * Done with flushing... start SSL/TLS renegotiate
             */
            pState->pslerr = crypto_start_renegotiation(pFsm);
        }
    }


    if (kPslChanFsmCryptoRenegPhase_requestHello == pState->phase) {
        PslError pslerr;
        if (crypto_do_SSL_handshake(pFsm, &pslerr)) {
            if (pslerr || !(pState->arg.data.conf.opts &
                            kPmSockRenegOpt_waitForClientHandshake)) {
                pState->pslerr = pslerr;
                pState->phase = kPslChanFsmCryptoRenegPhase_done;
            }
            else {
                /**
                 * @note UGLY, but NECESSARY manipulation of openssl's internal 
                 *       data structure. SSL_ST_ACCEPT forces wait for the
                 *       handshake to complete, not permitting writes until it
                 *       does.  It also allows us to detect when the handshake
                 *       completes.  SSL_set_accept_state() isn't useful here
                 *       because it clears the current SSL/TLS state and would
                 *       cause MAC errors.  Unfortunately, openssl doesn't seem
                 *       to provide a proper API for this.
                 */
                PSL_LOG_DEBUG("%s (fsm=%p): Forcing SSL_ST_ACCEPT to force " \
                              "wait for completion of renegotiation " \
                              "handshake per kPmSockRenegOpt_waitForClientHandshake",
                              __func__, pFsm);
                sslInfo->ssl->state = SSL_ST_ACCEPT;
                pState->phase = kPslChanFsmCryptoRenegPhase_handshake;
            }

            PSL_LOG_DEBUG("%s (fsm=%p): finished requestHello: new phase=%d",
                          __func__, pFsm, (int)pState->phase);
        }
    }


    if (kPslChanFsmCryptoRenegPhase_handshake == pState->phase) {
        if (crypto_total_input_bytes_ready(pFsm) > 0) {
            PSL_LOG_DEBUG("%s (fsm=%p): Suspending renegotiation handshake " \
                          "until input holding buffer is purged", __func__, pFsm);
            crypto_reset_multi_fd_watch(pFsm);
        }
        else {
            PslError pslerr;
            if (crypto_do_SSL_handshake(pFsm, &pslerr)) {
                pState->pslerr = pslerr;
                pState->phase = kPslChanFsmCryptoRenegPhase_done;
    
                PSL_LOG_DEBUG(
                    "%s (fsm=%p): SSL handshake completed: PslError=%d (%s), " \
                    "SSL_renegotiate_pending()=%d", __func__, pFsm, pslerr,
                    PmSockErrStringFromError(pslerr),
                    SSL_renegotiate_pending(sslInfo->ssl));
            }
        }
    }

    bool const isDone = (kPslChanFsmCryptoRenegPhase_done == pState->phase);

    PSL_LOG_DEBUG(
        "%s (fsm=%p): LEAVING: isDone=%d, PslChanFsmCryptoRenegPhase=%d, " \
        "pState->PslError=%d (%s), openSSL state=%d (%s)",
        __func__, pFsm, (int)isDone, (int)pState->phase, pState->pslerr,
        PmSockErrStringFromError(pState->pslerr),
        SSL_state(sslInfo->ssl), SSL_state_string_long(sslInfo->ssl));

    return isDone;
}//crypto_do_renegotiate



/** ========================================================================
 * crypto_start_renegotiation(): kicks off 
 * renegotiation for the crypto-renegotiate state 
 *  
 * @param pFsm 
 * 
 * @return PslError 
 *  
 * =========================================================================
 */
static PslError
crypto_start_renegotiation(PslChanFsm* pFsm)
{
    PslError pslerr = PSL_ERR_NONE;
    const PslChanFsmCryptoSharedInfo* const sslInfo = crypto_shared_info(pFsm);

    PSL_LOG_DEBUG("%s (fsm=%p): ENTERING: openSSL state=%d (%s)", __func__, pFsm,
                  SSL_state(sslInfo->ssl),
                  SSL_state_string_long(sslInfo->ssl));


    /// SSL_renegotiate returns: 1=flags set successfully; 0=failed
    int sslRet = SSL_renegotiate(sslInfo->ssl);

    switch (sslRet) {
    case 1:             // renegotiation flags set successfully
        break;

    default:            // setting of renegotiation flags failed
        {
            pslerr = psl_err_get_and_process_SSL_channel_error(
                pFsm, sslInfo->ssl, sslRet, PSL_ERR_SSL_PROTOCOL);
            PSL_ASSERT(pslerr);

            PSL_LOG_ERROR("%s (fsm=%p): ERROR: SSL_renegotiate() failed with " \
                          "pslerr=%d (%s)", __func__, pFsm, pslerr,
                          PmSockErrStringFromError(pslerr));
        }
        break;
    }

    PSL_LOG_DEBUG("%s (fsm=%p): LEAVING: PslError=%d (%s), openSSL state=%d (%s)",
                  __func__, pFsm, pslerr, PmSockErrStringFromError(pslerr),
                  SSL_state(sslInfo->ssl), SSL_state_string_long(sslInfo->ssl));
    return pslerr;
}//crypto_start_renegotiation



/** ========================================================================
 * @note This may be used for various handshakes: e.g.,
 *       session-establishment (connect/accept) and
 *       renegotiation
 * ========================================================================= 
 */
static bool
crypto_do_SSL_handshake(PslChanFsm*                const pFsm,
                        PslError*                  const pPslErr)
{
    const PslChanFsmCryptoSharedInfo* const sslInfo = crypto_shared_info(pFsm);

    PSL_LOG_DEBUG("%s (fsm=%p): ENTERING: connKind=%d, openSSL state=%d (%s)",
                  __func__, pFsm, (int)sslInfo->connKind, SSL_state(sslInfo->ssl),
                  SSL_state_string_long(sslInfo->ssl));

    *pPslErr = 0;

    bool handshakeFinished = false;

    int const sslRet = SSL_do_handshake(sslInfo->ssl);
    int const savederrno = errno;
    PSL_LOG_DEBUG("%s (fsm=%p): SSL_do_handshake() return=%d, errno=%d",
                  __func__, pFsm, sslRet, savederrno);
    switch (sslRet) {
    case 1: /// Handshake completed successfully!
        PSL_LOG_INFO("%s (fsm=%p): SUCCESS: SSL Handshake completed",
                     __func__, pFsm);
        handshakeFinished = true;    // done with success
        break;

    case 0: /// Controlled shutdown by the specifications of TLS/SSL
        /// Consult SSL_get_error() to get more info
        *pPslErr = psl_err_get_and_process_SSL_channel_error(
            pFsm, sslInfo->ssl, sslRet, PSL_ERR_SSL_PROTOCOL);
        PSL_ASSERT(*pPslErr);
        handshakeFinished = true;    // done with hard error
        break;

    default:/// Handshake failure or further action is needed
        /// Consult SSL_get_error()
        {
            PSL_ASSERT(sslRet < 0);

            PslError const tempPslErr = (
                psl_err_get_and_process_SSL_channel_error(pFsm,
                                                          sslInfo->ssl,
                                                          sslRet,
                                                          PSL_ERR_SSL_PROTOCOL));
            PSL_ASSERT(tempPslErr);

            switch (tempPslErr) {
            case PSL_ERR_SSL_WANT_READ:
                crypto_update_multi_fd_watch_giocondition(pFsm, G_IO_IN);
                /// not done yet
                break;
    
            case PSL_ERR_SSL_WANT_WRITE:
                crypto_update_multi_fd_watch_giocondition(pFsm, G_IO_OUT);
                /// not done yet
                break;

            default:
                *pPslErr = tempPslErr;  
                handshakeFinished = true;    // done with hard error
                break;
            }

        }
    }//switch (sslRet)

    PSL_LOG_DEBUG("%s (fsm=%p): LEAVING: handshakeFinished=%d, PslError=%d (%s), " \
                  "openSSL state=%d (%s)",
                  __func__, pFsm, (int)handshakeFinished, *pPslErr,
                  PmSockErrStringFromError(*pPslErr), SSL_state(sslInfo->ssl),
                  SSL_state_string_long(sslInfo->ssl));

    return handshakeFinished;
}//crypto_do_SSL_handshake



/** ========================================================================
 * 
 * @note This function is called once or more for each cert in 
 *       the certificate chain being verified by openssl
 * 
 * =========================================================================
 */
static int
crypto_ssl_peer_verify_callback(int                   preverify_ok,
                                X509_STORE_CTX* const x509_ctx)
{
    int const original_preverify_ok = preverify_ok;

    /**
     * Get the SSL channel and retrieve our corresponding FSM
     * instance
     */
    SSL* const ssl = X509_STORE_CTX_get_ex_data(
        x509_ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
    PSL_ASSERT(ssl);

    PslChanFsm* const pFsm = (PslChanFsm*)SSL_get_app_data(ssl);
    PSL_ASSERT(pFsm);

    PSL_LOG_DEBUG("%s (fsm=%p): ENTERING: preverify_ok=%d, x509_ctx=%p",
                  __func__, pFsm, (int)preverify_ok, x509_ctx);

    PslChanFsmCryptoSharedInfo* const sslInfo = crypto_shared_info(pFsm);

    if (!sslInfo->pv.verifyInProgress) {
        PSL_LOG_DEBUG(
            "%s (fsm=%p): Detected start of a new verification session: " \
            "first_verify_session=%d, openSSL state=%d (%s)", __func__, pFsm,
            (int)!sslInfo->pv.peerVerifyCalled,
            SSL_state(sslInfo->ssl), SSL_state_string_long(sslInfo->ssl));
        sslInfo->pv.verifyInProgress = true;
    }

    sslInfo->pv.peerVerifyCalled = true;
    sslInfo->pv.verifyFailCode = preverify_ok ? PSL_ERR_NONE : PSL_ERR_SSL_CERT_VERIFY;


    if (PSL_LOG_IS_DEBUG_ENABLED()) {
        int const verifyDepth = X509_STORE_CTX_get_error_depth(x509_ctx);
        int const certErr = X509_STORE_CTX_get_error(x509_ctx);
        const char* const opensslX509ErrorStr = X509_verify_cert_error_string(certErr);
        X509* const curCert = X509_STORE_CTX_get_current_cert(x509_ctx);

        /// @note peer cert is at depth=0
        if (!curCert) {
            PSL_LOG_ERROR("%s (fsm=%p): On entry: WARNING: NULL PEER CERTIFICATE: " \
                          "preverify_ok=%d, x509Error=%d (%s); depth=%d",
                          __func__, pFsm, (int)preverify_ok, certErr,
                          PSL_LOG_MAKE_SAFE_STR(opensslX509ErrorStr),
                          verifyDepth);
        }
        else {
            char x509OneLineSubjName[256] = "";
            X509_NAME_oneline(X509_get_subject_name(curCert),
                              x509OneLineSubjName, sizeof(x509OneLineSubjName));

            char x509OneLineIssuerName[256] = "";
            X509_NAME_oneline(X509_get_issuer_name(curCert), x509OneLineIssuerName,
                              sizeof(x509OneLineIssuerName));

            PSL_LOG_DEBUG("%s (fsm=%p): On entry: preverify_ok=%d, " \
                          "x509Error=%d (%s); depth=%d; subj='%s'; issuer='%s'",
                          __func__, pFsm, (int)preverify_ok, certErr,
                          PSL_LOG_MAKE_SAFE_STR(opensslX509ErrorStr),
                          verifyDepth,
                          PSL_LOG_OBFUSCATE_STR(x509OneLineSubjName),
                          PSL_LOG_OBFUSCATE_STR(x509OneLineIssuerName));
        }
    }//if PSL_LOG_IS_DEBUG_ENABLED


    if (!preverify_ok) {
        preverify_ok = crypto_resolve_peer_cert_error(pFsm, x509_ctx);
    }


    /**
     * Now, perform any optional verification tasks requested by 
     * user 
     */

    bool const isPeerCertDepth = (0 == X509_STORE_CTX_get_error_depth(x509_ctx));

    /// Handle kPmSockCertVerifyOpt_checkHostname
    if (preverify_ok && isPeerCertDepth &&
        (sslInfo->cryptoConf.verifyOpts & kPmSockCertVerifyOpt_checkHostname)) {

        bool matched;
        PslError pslerr = PmSockOpensslVerifyHostname(
            pFsm->userSettings.serverAddr.hostStr,
            X509_STORE_CTX_get_current_cert(x509_ctx),
            0/*verifyOpts*/,
            0/*nameMatchOpts*/,
            &matched);
        if (pslerr) {
            PSL_LOG_ERROR(
                "%s (fsm=%p): ERROR: PmSockOpensslVerifyHostname failed; " \
                "PslError=%d (%s)",
                __func__, pFsm, pslerr, PmSockErrStringFromError(pslerr));
        }
        else if (!matched) {
            pslerr = PSL_ERR_SSL_HOSTNAME_MISMATCH;
            PSL_LOG_WARNING(
                "%s (fsm=%p): ERROR: peer certificate does not match hostname",
                __func__, pFsm);
        }

        if (pslerr) {
            preverify_ok = false;
            sslInfo->pv.verifyFailCode = pslerr;
            /**
             * @todo Should we set X509_V_ERR_CERT_REJECTED, instead??? 
             *       X509_V_ERR_CERT_REJECTED would trigger "sslv3 alert bad
             *       certificate" on the remote side.
             *       X509_V_ERR_APPLICATION_VERIFICATION causes "sslv3 alert
             *       handshake failure"
             */
            X509_STORE_CTX_set_error(x509_ctx, X509_V_ERR_APPLICATION_VERIFICATION);

            preverify_ok = crypto_resolve_peer_cert_error(pFsm, x509_ctx);
        }
    }//checkHostname


    /**
     * Invoke user callback with preverify_ok=true if this is the
     * final callback from openssl for the current depth and either
     * there is no pending verification error or the error was
     * suppressed. 
     *  
     * This emulates openssl's model of ending every successful node
     * verification cycle with a preverify_ok=TRUE callback.
     */
    if (original_preverify_ok && preverify_ok) {
        preverify_ok = crypto_call_user_peer_cert_verify_callback(pFsm,
                                                                  preverify_ok,
                                                                  x509_ctx);
    }


    /// Check for end of verification session
    if (!preverify_ok || (isPeerCertDepth && original_preverify_ok)) {
        sslInfo->pv.verifyInProgress = false;
        PSL_LOG_DEBUG(
            "%s (fsm=%p): Detected end of verification session: " \
            "openSSL state=%d (%s)", __func__, pFsm,
            SSL_state(sslInfo->ssl), SSL_state_string_long(sslInfo->ssl));
    }

    PSL_LOG_DEBUG("%s (fsm=%p): LEAVING: preverify_ok=%d, PslError=%d (%s), " \
                  "X509_V_ERR_=%d (%s)", __func__, pFsm, (int)preverify_ok,
                  sslInfo->pv.verifyFailCode,
                  PmSockErrStringFromError(sslInfo->pv.verifyFailCode),
                  X509_STORE_CTX_get_error(x509_ctx),
                  X509_verify_cert_error_string(X509_STORE_CTX_get_error(x509_ctx)));

    return preverify_ok;
}//crypto_ssl_peer_verify_callback



/** ========================================================================
 * =========================================================================
 */
static bool
crypto_resolve_peer_cert_error(PslChanFsm*     const pFsm,
                               X509_STORE_CTX* const x509_ctx)
{
    bool preverify_ok = false;

    PslChanFsmCryptoSharedInfo* const sslInfo = crypto_shared_info(pFsm);

    PSL_LOG_DEBUG("%s (fsm=%p): ENTERING: PslError=%d (%s), " \
                  "X509_V_ERR_=%d (%s)", __func__, pFsm,
                  sslInfo->pv.verifyFailCode,
                  PmSockErrStringFromError(sslInfo->pv.verifyFailCode),
                  X509_STORE_CTX_get_error(x509_ctx),
                  X509_verify_cert_error_string(X509_STORE_CTX_get_error(x509_ctx)));


    /** 
     * First, Suppress errors that we consider to be suppressible 
     *  
     * @note The X509_STORE_CTX error may remain from a prior failed
     *       check on the same or other cert in the current chain,
     *       so we MUST check preverify_ok to make sure the error
     *       code applies to this specific invocation of the
     *       callback
     */
    int const certErr = X509_STORE_CTX_get_error(x509_ctx);

    switch (certErr) {
    case X509_V_ERR_UNABLE_TO_GET_CRL: // missing CRL extension
        PSL_LOG_DEBUG("%s (fsm=%p): Suppressing X509_V_ERR_UNABLE_TO_GET_CRL " \
                      "(CRL extension field missing)", __func__, pFsm);
        preverify_ok = true;
        break;
    default:
        break;
    }


    /// Employ kPmSockCertVerifyOpt_fallbackToInstalledLeaf, if enabled
    if (!preverify_ok && (sslInfo->cryptoConf.verifyOpts &
                          kPmSockCertVerifyOpt_fallbackToInstalledLeaf)) {
        PSL_LOG_DEBUG(
            "%s (fsm=%p): kPmSockCertVerifyOpt_fallbackToInstalledLeaf: " \
            "attempting to supressed PslError=%d (%s), X509_V_ERR_=%d (%s)",
            __func__, pFsm, sslInfo->pv.verifyFailCode,
            PmSockErrStringFromError(sslInfo->pv.verifyFailCode),
            X509_STORE_CTX_get_error(x509_ctx),
            PSL_LOG_MAKE_SAFE_STR(
                X509_verify_cert_error_string(X509_STORE_CTX_get_error(x509_ctx))));

        bool foundMatchingCert;
        PslError const pslerr = PmSockOpensslMatchCertInStore(
            x509_ctx, x509_ctx->cert, 0/*opts*/, &foundMatchingCert);
        if (pslerr) {
            foundMatchingCert = false;
        }

        if (foundMatchingCert) {
            preverify_ok = true;

            PSL_LOG_DEBUG(
                "%s (fsm=%p): kPmSockCertVerifyOpt_fallbackToInstalledLeaf " \
                "supressed cert verification error", __func__, pFsm);
        }

        else {
            PSL_LOG_ERROR(
                "%s (fsm=%p): ERROR: kPmSockCertVerifyOpt_fallbackToInstalledLeaf: " \
                "unable to supress cert verification error", __func__, pFsm);
        }
    }//fallbackToInstalledLeaf


    if (preverify_ok) {
        sslInfo->pv.verifyFailCode = PSL_ERR_NONE;
        X509_STORE_CTX_set_error(x509_ctx, X509_V_OK);
    }

    else {
        /** 
         * Our built-in failure resolution failed: invoke user's 
         * verification callback (if any) as the last resort; 
         */
        preverify_ok = crypto_call_user_peer_cert_verify_callback(pFsm,
                                                                  preverify_ok,
                                                                  x509_ctx);
    }

    PSL_LOG_HELPER(
        (preverify_ok ? kPmLogLevel_Debug : kPmLogLevel_Error),
        "%s (fsm=%p): LEAVING: preverify_ok=%d, PslError=%d (%s), " \
        "X509_V_ERR_=%d (%s)", __func__, pFsm, (int)preverify_ok,
        sslInfo->pv.verifyFailCode,
        PmSockErrStringFromError(sslInfo->pv.verifyFailCode),
        X509_STORE_CTX_get_error(x509_ctx),
        X509_verify_cert_error_string(X509_STORE_CTX_get_error(x509_ctx)));

    return preverify_ok;
}//crypto_resolve_peer_cert_error



/** ========================================================================
 * =========================================================================
 */
static bool
crypto_call_user_peer_cert_verify_callback(PslChanFsm*     const pFsm,
                                           bool                  preverify_ok,
                                           X509_STORE_CTX* const x509_ctx)
{
    PslChanFsmCryptoSharedInfo* const sslInfo = crypto_shared_info(pFsm);

    if (!sslInfo->cryptoConf.verifyCb) {
        return preverify_ok;
    }

    PmSockPeerVerifyCbInfo  extraInfo;
    memset(&extraInfo, 0, sizeof(extraInfo));
    extraInfo.channel = (PmSockIOChannel*)pFsm->channel;
    extraInfo.userData = pFsm->userSettings.userData;
    extraInfo.hostname = pFsm->userSettings.serverAddr.hostStr;
    extraInfo.pslVerifyError = sslInfo->pv.verifyFailCode;

    /**
     * @note We're NOT protecting ourselves here via FSM refcount
     *       because this callback is defined as non-reentrant with
     *       respect to the given channel instance; also, since
     *       we're calling from the scope of FSM dispatch, any calls
     *       back into the FSM would result in run-to-completion
     *       violation.
     */

    PSL_LOG_DEBUG(
        "%s (fsm=%p): Invoking user's peerCertVerify callback=%p: preverify_ok=%d, " \
        "userData=%p, PslError=%d (%s), X509_V_ERR_=%d (%s)", __func__, pFsm,
        sslInfo->cryptoConf.verifyCb, preverify_ok, pFsm->userSettings.userData,
        sslInfo->pv.verifyFailCode,
        PmSockErrStringFromError(sslInfo->pv.verifyFailCode),
        X509_STORE_CTX_get_error(x509_ctx),
        X509_verify_cert_error_string(X509_STORE_CTX_get_error(x509_ctx)));

    preverify_ok = sslInfo->cryptoConf.verifyCb(preverify_ok, x509_ctx, &extraInfo);

    PSL_LOG_DEBUG(
        "%s (fsm=%p): User's peerCertVerify callback=%p returned user_ok=%d",
        __func__, pFsm, sslInfo->cryptoConf.verifyCb, (int)preverify_ok);


    if (preverify_ok) {
        sslInfo->pv.verifyFailCode = PSL_ERR_NONE;
        X509_STORE_CTX_set_error(x509_ctx, X509_V_OK);
    }

    else {
        if (!sslInfo->pv.verifyFailCode) {
            sslInfo->pv.verifyFailCode = PSL_ERR_SSL_CERT_VERIFY;
        }

        if (X509_V_OK == X509_STORE_CTX_get_error(x509_ctx)) {
            X509_STORE_CTX_set_error(x509_ctx, X509_V_ERR_APPLICATION_VERIFICATION);
        }
    }


    PSL_LOG_DEBUG(
        "%s (fsm=%p): LEAVING: preverify_ok=%d, PslError=%d (%s), " \
        "X509_V_ERR_=%d (%s)", __func__, pFsm, (int)preverify_ok,
        sslInfo->pv.verifyFailCode,
        PmSockErrStringFromError(sslInfo->pv.verifyFailCode),
        X509_STORE_CTX_get_error(x509_ctx),
        X509_verify_cert_error_string(X509_STORE_CTX_get_error(x509_ctx)));

    return preverify_ok;
}//crypto_call_user_peer_cert_verify_callback



/** ========================================================================
 * =========================================================================
 */
static void
crypto_conn_sched_done_cb_if_any(PslChanFsm*                const pFsm,
                                 PslChanFsmCryptoConnState* const pState,
                                 PslError                   const pslErr)
{
    psl_chan_fsm_sched_fdwatch_completion_cb(pFsm, &pState->arg.common.cb,
                                             pslErr, true/*toCrypto*/);
}



/** ========================================================================
 * =========================================================================
 */
static PslSmeEventStatus
crypto_handle_READ(PslChanFsm*                          const pFsm,
                   const struct PslChanFsmEvtArgRead*   const arg)
{
    PslChanFsmCryptoSharedInfo* const sslInfo = crypto_shared_info(pFsm);

    PSL_LOG_DEBUG("%s (fsm=%p): requested cnt=%ld", __func__, pFsm, (long)arg->cnt);

    PslChanFsmCryptoInput*      const input = &sslInfo->io.in;
    PslSmeEventStatus                 evtStatus;

    if (crypto_preprocess_READ(pFsm, arg, &evtStatus)) {
        goto Done;
    }

    evtStatus = kPslSmeEventStatus_success;
    *arg->pNumRead = 0;
    *arg->pGioStatus = G_IO_STATUS_NORMAL;

    uint8_t*    pdst = (uint8_t*)arg->buf;
    int         dstcnt = arg->cnt;

    /*
     * If there is data in our deferred read buffer already, then
     * satisfy the request from the buffer first
     */
    if (input->deferredByteAvailable) {
        *(pdst++) = input->deferredReadOneByteBuf[0];
        dstcnt--;
        *arg->pNumRead = 1;
        input->deferredByteAvailable = false;
        PSL_LOG_DEBUG("%s (fsm=%p): read 1 byte from deferred I/O buffer",
                      __func__, pFsm);

        if (!dstcnt) {
            goto Done;
        }
    }


    /*
     * Read from SSL channel
     * 
     * @see 'man SSL_read' and read the warning
     */
    PSL_ASSERT(!input->deferredByteAvailable);
    PSL_ASSERT(!crypto_deferred_io_pending(input->ioState));

    int numRead = 0;
    bool ioAttempted;
    PslError const readPslErr = crypto_read_low(
        pFsm, pdst, dstcnt, !(*arg->pNumRead), &numRead, &ioAttempted);

    /*
     * Post-process the results and check assumptions
     */
    *arg->pNumRead += numRead;

    if (!readPslErr || *arg->pNumRead) {
        // Either no error (and something or nothing read) or error and at
        // least one byte was read.
        //
        // In this case, we suppress returning of the error (if any) to the user
        // until a subsequent read call; 
    }
    else if (crypto_is_deferred_io_pslerror(readPslErr)) {
        // Nothing was read and input should be in the deferred I/O state
        PSL_ASSERT(crypto_deferred_io_pending(input->ioState));
        *arg->pGioStatus = G_IO_STATUS_AGAIN;
    }
    else {
        // Must be a sticky (non-deferred-I/O) error and nothing was read
        PSL_ASSERT(kPslChanFsmSSLIOState_error == input->ioState);

        if (PSL_ERR_SSL_CLEAN_EOF == readPslErr) {
            *arg->pGioStatus = G_IO_STATUS_EOF;
        }
        else {
            *arg->pGioStatus = G_IO_STATUS_ERROR;
            evtStatus = kPslSmeEventStatus_error;
        }
    }

    /// Process and update our deferred SSL I/O state in case the read
    /// operation altered the I/O deferral conditions
    if (ioAttempted) {
        (void)crypto_process_deferred_ssl_io(
            pFsm, kCryptoDeferredIOHint_afterRead, 0);
    }

Done:
    PSL_LOG_DEBUG(
        "%s (fsm=%p): completed with: GIOStatus=%s, numRead=%zd, evtStatus=%d",
        __func__, pFsm, psl_chan_fsm_str_from_giostatus(*arg->pGioStatus),
        *arg->pNumRead, (int)evtStatus);
    if (*arg->pNumRead) {
        PSL_LOG_DATASTREAM_DEBUGLOW(arg->buf, *arg->pNumRead);
    }
    return evtStatus;
}// crypto_handle_READ



/* =========================================================================
 * =========================================================================
 */
PSL_CONFIG_INLINE_FUNC bool
crypto_preprocess_READ(PslChanFsm*                          const pFsm,
                       const struct PslChanFsmEvtArgRead*   const arg,
                       PslSmeEventStatus*                   const pEvtStatus)
{
    PSL_LOG_DEBUGLOW("%s (fsm=%p): requested cnt=%zd", __func__, pFsm, arg->cnt);

    //PSL_ASSERT(arg->cnt >= 0); // cnt is unsigned, so always >= 0

    bool isDone = true;

    const PslChanFsmCryptoSharedInfo* const sslInfo = crypto_shared_info(pFsm);
    const PslChanFsmCryptoInput*      const input = &sslInfo->io.in;

    *pEvtStatus = kPslSmeEventStatus_success;
    *arg->pNumRead = 0;
    *arg->pGioStatus = G_IO_STATUS_NORMAL;

    /// Nothing ventured, nothing gained... (immitating read())
    /// openssl doesn't like read/write with 0 count.
    /// 
    /// @note We want this to be consistent regardless of channel status
    if (!arg->cnt) {
        PSL_LOG_DEBUG("%s (fsm=%p): zero-size read request.", __func__, pFsm);
        goto Done;
    }

    /// Handle sticky input error
    if (kPslChanFsmSSLIOState_error == input->ioState) {
        PSL_ASSERT(input->pslErr);

        if (PSL_ERR_SSL_CLEAN_EOF == input->pslErr) {
            /// @note G_IO_STATUS_EOF is a special case for reading, but not for
            ///       writing; We only want G_IO_STATUS_EOF for clean EOF
            *arg->pGioStatus = G_IO_STATUS_EOF;
            PSL_LOG_NOTICE("%s (fsm=%p): orderly SSL input shutdown was set; " \
                           "G_IO_STATUS_EOF", __func__, pFsm);
        }
        else {
            psl_chan_fsm_set_last_error(pFsm, kPslChanFsmErrorSource_psl,
                                        input->pslErr);
            *arg->pGioStatus = G_IO_STATUS_ERROR;
            PSL_LOG_ERROR(
                "%s (fsm=%p): ERROR: sticky input error was set: pslerr=%d (%s)",
                __func__, pFsm, input->pslErr,
                PmSockErrStringFromError(input->pslErr));
            *pEvtStatus = kPslSmeEventStatus_error;
        }

        goto Done;
    }

    /// If we have a deferred SSL read pending, treat it like EAGAIN
    if (crypto_deferred_io_pending(input->ioState)) {
        PSL_LOG_DEBUG(
            "%s (fsm=%p): deferred SSL_read pending", __func__, pFsm);
        *arg->pGioStatus = G_IO_STATUS_AGAIN;
        goto Done;
    }

    isDone = false;

Done:
    PSL_LOG_DEBUGLOW(
        "%s (fsm=%p): completed with: isDone=%d, GIOStatus=%s, numRead=%zd, " \
        "evtStatus=%d", __func__, pFsm, (int)isDone,
        psl_chan_fsm_str_from_giostatus(*arg->pGioStatus), *arg->pNumRead,
        (int)*pEvtStatus);

    return isDone;
}//crypto_preprocess_READ



/* =========================================================================
 * =========================================================================
 */
static PslSmeEventStatus
crypto_handle_WRITE(PslChanFsm*                         const pFsm,
                    const struct PslChanFsmEvtArgWrite* const arg)
{
    PslChanFsmCryptoSharedInfo* const sslInfo = crypto_shared_info(pFsm);

    PSL_LOG_DEBUG("%s (fsm=%p): requested cnt=%ld", __func__, pFsm, (long)arg->cnt);

    PslChanFsmCryptoOutput* const output = &sslInfo->io.out;
    PslSmeEventStatus             evtStatus = kPslSmeEventStatus_success;

    *arg->pNumWritten = 0;
    *arg->pGioStatus = G_IO_STATUS_NORMAL;

    /// Handle the sticky error case
    if (kPslChanFsmSSLIOState_error == output->ioState) {
        PSL_ASSERT(output->pslErr);
        psl_chan_fsm_set_last_error(pFsm, kPslChanFsmErrorSource_psl,
                                    output->pslErr);
        *arg->pGioStatus = G_IO_STATUS_ERROR;
        PSL_LOG_ERROR("%s (fsm=%p): ERROR: sticky output error was set: " \
                      "pslerr=%d (%s)", __func__, pFsm, output->pslErr,
                      PmSockErrStringFromError(output->pslErr));
        evtStatus = kPslSmeEventStatus_error;
        goto Done;
    }

    /**
     * @note 'man SSL_write' states that the behavior of calling it
     *       with num bytes = zero is undefined
     */
    if (!arg->cnt) {
        PSL_LOG_DEBUG("%s (fsm=%p): zero-size write request.",
                      __func__, pFsm);
        goto Done;
    }

    /// If we have an internal SSL write pending, treat it like EAGAIN
    if (crypto_deferred_io_pending(output->ioState)) {
        PSL_LOG_DEBUG("%s (fsm=%p): Deferred SSL_write pending", __func__, pFsm);
        *arg->pGioStatus = G_IO_STATUS_AGAIN;
        goto Done;
    }

    /**
     * Prepare for SSL_write
     * 
     * @note SSL_write is rather finicky: in case of
     *       SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE, it expects
     *       us to call it again with the same args. This is
     *       error-prone and unnatural for the GIOChannel interface
     *       that the original authors of libpalmsocket selected, so
     *       we're forced to go to the extra overhead of buffering
     *       the writes through our own buffer.
     * 
     * We optimize this somewhat by selecting
     * SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER mode during SSL channel
     * initialization, so that we only have to buffer the data if we
     * get WANT_READ or WANT_WRITE from SSL_write().
     * 
     * @see 'man SSL_write' and read the warnings
     */

    PSL_ASSERT(psl_io_buf_is_empty(&output->buf));
    PSL_ASSERT(!crypto_deferred_io_pending(output->ioState));

    int const maxWriteCnt = psl_io_buf_get_max_capacity(&output->buf);

    int numWritten = 0, deferredWriteCnt = 0;

    PslError const writePslErr = crypto_write_low(pFsm,
                                                  arg->buf,
                                                  arg->cnt,
                                                  maxWriteCnt,
                                                  &numWritten,
                                                  &deferredWriteCnt);

    /**
     * Post-process the results and check assumptions
     */
    *arg->pNumWritten = numWritten;


    if (writePslErr && crypto_is_deferred_io_pslerror(writePslErr)) {
        PSL_ASSERT(crypto_deferred_io_pending(output->ioState));
        PSL_ASSERT(deferredWriteCnt > 0);
        PSL_ASSERT(deferredWriteCnt <= maxWriteCnt);

        /// Get the deferred data into our internal buffer
        ssize_t tempBufSize;
        void* const dst = psl_io_buf_reset_set_size(&output->buf,
                                                    deferredWriteCnt,
                                                    &tempBufSize);
        /// Since we chose maxWriteCnt based on max I/O buf capacity,
        /// deferredWriteCnt MUST ALWAYS fit
        PSL_ASSERT(dst);
        PSL_ASSERT(tempBufSize == deferredWriteCnt);

        memcpy(dst, (uint8_t*)arg->buf + *arg->pNumWritten, tempBufSize);
        *arg->pNumWritten += tempBufSize; // so user won't write it again

        PSL_LOG_DEBUG("%s (fsm=%p): Buffering %d data bytes for deferred I/O",
                      __func__, pFsm, (int)tempBufSize);
    }
    else if (!writePslErr || numWritten) {
        /// Either no error (and something or nothing written) or at least
        /// one byte written (w/ or w/o sticky error termination).
        /// 
        PSL_ASSERT(!crypto_deferred_io_pending(output->ioState));
        PSL_ASSERT(!writePslErr ||
                   kPslChanFsmSSLIOState_error == output->ioState);
    }
    else { /// Must be sticky error without anything at all written or deferred
        PSL_ASSERT(0 == deferredWriteCnt);
        PSL_ASSERT(kPslChanFsmSSLIOState_error == output->ioState);
        *arg->pGioStatus = G_IO_STATUS_ERROR;

        evtStatus = kPslSmeEventStatus_error;
    }

    /// Process and update our deferred SSL I/O state in case the write
    /// operation altered the I/O deferral conditions
    (void)crypto_process_deferred_ssl_io(
        pFsm, kCryptoDeferredIOHint_afterWrite, 0);


Done:
    PSL_LOG_DEBUG(
        "%s (fsm=%p): completed with: GIOStatus=%s, numWritten=%u, " \
        "evtStatus=%d",
        __func__, pFsm, psl_chan_fsm_str_from_giostatus(*arg->pGioStatus),
        (unsigned)*arg->pNumWritten, (int)evtStatus);
    if (*arg->pNumWritten) {
        PSL_LOG_DATASTREAM_DEBUGLOW(arg->buf, *arg->pNumWritten);
    }

    return evtStatus;
}//crypto_handle_WRITE



/* =========================================================================
 * =========================================================================
 */
PSL_CONFIG_INLINE_FUNC void
crypto_update_multi_fd_watch_giocondition(PslChanFsm*  const pFsm,
                                          GIOCondition const cond)
{
    PslChanFsmCryptoSharedInfo* const pShared = crypto_shared_info(pFsm);

    if (cond == pShared->lastGIOCondition) {
        PSL_LOG_DEBUG(
            "%s (fsm=%p): same as last, skipping: GIOCondition=0x%lX",
            __func__, pFsm, (unsigned long)cond);
        return;
    }

    PSL_LOG_DEBUG("%s (fsm=%p): updating multi-fd-watch: GIOCondition: " \
                  "{new=0x%lX, last=0x%lX}", __func__, pFsm, (unsigned long)cond,
                  (unsigned long)pShared->lastGIOCondition);

    (void)psl_multi_fd_watch_add_or_update_fd(pFsm->fdWatchInfo.fdWatch,
                                              pFsm->fd, cond);
    pShared->lastGIOCondition = cond;
}



/* =========================================================================
 * =========================================================================
 */
PSL_CONFIG_INLINE_FUNC void
crypto_reset_multi_fd_watch(PslChanFsm* const pFsm)
{
    PSL_LOG_DEBUG("%s (fsm=%p): resetting multi-fd-watch", __func__, pFsm);

    (void)psl_multi_fd_watch_reset(pFsm->fdWatchInfo.fdWatch);
    crypto_shared_info(pFsm)->lastGIOCondition = (GIOCondition)0;
}



/** ========================================================================
 * Update our socket fd watch for monitoring deferred SSL I/O in
 * PslChanFsmCryptoSSLState and PslChanFsmCryptoShutState.
 * 
 * @param pFsm 
 * 
 * @return TRUE if monitor events were set; FALSE if nothing was
 *         set because there is nothing that needs monitoring at
 *         this time
 * 
 * =========================================================================
 */
PSL_CONFIG_INLINE_FUNC void
crypto_schedule_deferred_ssl_io(PslChanFsm*  const pFsm)
{
    GIOCondition const cond =
        crypto_giocondition_from_chanssl_iostate(
            crypto_shared_info(pFsm)->io.in.ioState) |
        crypto_giocondition_from_chanssl_iostate(
            crypto_shared_info(pFsm)->io.out.ioState);

    crypto_update_multi_fd_watch_giocondition(pFsm, cond);
}



/**
 * crypto_process_deferred_ssl_io(): Processes deferred SSL I/O.
 * Attempts to make as much progress as needed without blocking.
 * 
 * Called in the context of PSL_CHAN_FSM_EVT_FD_WATCH for
 * PslChanFsmCryptoSSLState and PslChanFsmCryptoShutState, and
 * also after PSL_CHAN_FSM_EVT_READ and PSL_CHAN_FSM_EVT_WRITE.
 * 
 * Attempts to complete any pending read/write operations from
 * our I/O buffers that were deferred as the result of openssl
 * PSL_ERR_SSL_WANT_READ and PSL_ERR_SSL_WANT_WRITE results.
 * 
 * Updates our input and output I/O states and socket fd-watch
 * as needed.
 * 
 * @note IMPORTANT: this logic is the most intricate in all of
 *       the palmsocket implementation.  The challenges stem
 *       from side-effects that interleaved SSL_read and
 *       SSL_write (as well as other openssl SSL channel
 *       functions that may do I/O) have on the openssl SSL
 *       channel's state. For example, if SSL_write returns
 *       _WANT_READ (can happen during re-negotiation) and the
 *       subsequent SSL_read also returns _WANT_READ, it's
 *       possible that the SSL_read call completed the
 *       re-negotiation, thus re-trying SSL_write might succeed
 *       after this, and the socket might not become readable
 *       for a very long time, if ever again, so not retrying
 *       SSL_write would result in stalled I/O. Of course,
 *       re-trying the SSL_write might also produce a
 *       side-effect on the deferred state of the preceding
 *       SSL_read, and so on. Unfortunately, openssl docs didn't
 *       have anything to say about such side-effects and how to
 *       deal with them, and other wrappers (e.g., libcurl) seem
 *       to be oblivious to this issue altogether at the time of
 *       this writing.  It's very important to get this logic
 *       right in order to avoid race conditions that result in
 *       stalled I/O as well as infinite loops.  It's also
 *       imporant to avoid unnecessary processing for
 *       performance reasons.
 * 
 * The gist of the solution is based on the following
 * assumptions:
 * 
 *      1. If SSL_write returns _WANT_READ, then we should be
 *      able to assume that if it had been SSL_read instead,
 *      then it would also return _WANT_READ, unless input data
 *      is already in openssl SSL channel's buffer (i.e.,
 *      SSL_pending would return a value greater than zero).
 * 
 *      2. If SSL_read returns _WANT_WRITE, then we should be
 *      able to assume that if we were to call SSL_write, it
 *      might also be limited by the _WANT_WRITE condition.
 * 
 * @param pFsm
 * @param hint I/O state "freshness" hint for optimization.
 * 
 * @param revents GIOCondition flags indicated on our socket; to
 *                force refresh of deferred I/O state, pass
 *                hint=kCryptoDeferredIOHint_none and revents=0.
 * 
 * @return PslSmeEventStatus
 */
static PslSmeEventStatus
crypto_process_deferred_ssl_io(PslChanFsm*          const pFsm,
                               CryptoDeferredIOHint       hint,
                               GIOCondition         const revents)
{
    PslChanFsmCryptoSharedInfo* const sslInfo = crypto_shared_info(pFsm);
    PslChanFsmCryptoInput*      const input = &sslInfo->io.in;
    PslChanFsmCryptoOutput*     const output = &sslInfo->io.out;

    PSL_LOG_DEBUG(
        "%s (fsm=%p): entry: CryptoDeferredIOHint==%d, GIOCondition revents=0x%lX, " \
        "in->ioState=%d, out->ioState=%d",
        __func__, pFsm, (int)hint, (unsigned long)revents,
        (int)input->ioState, (int)output->ioState);

    bool    freshin =
        (kCryptoDeferredIOHint_afterRead == hint ||
         !crypto_deferred_io_pending(input->ioState));

    bool    freshout =
        (kCryptoDeferredIOHint_afterWrite == hint ||
         !crypto_deferred_io_pending(output->ioState));


    /*
     * Process deferred I/O and update deferred input and output I/O states
     */
    while (!freshin || !freshout) {

        /*
         * The 'deferred write' step.
         * 
         * @note We use a loop so that a break statement can
         *       easily get us to the next step
         */
        while (!freshout) {
            PSL_ASSERT(crypto_deferred_io_pending(output->ioState));

            freshout = true;

            // After Reading, make optimistic switch of deferred output state
            // to WANT_WRITE; this should be the correct deferred output state
            // except occasionally during renegotiation handshake; this allows
            // us to avoid unnecessary I/O in the typical case; in the event of
            // renegotiation, output state will self-correct as soon as the
            // file descriptor becomes writeable and this function is called again.
            // 
            // This also covers the case where _input_ state immediately after
            // reading is WANT_WRITE, so deferred _output_ state should also be
            // WANT_WRITE.
            //
            // @note This optimization depends on the "deferred write" step
            //       being processed before the "deferred read" step
            if (kCryptoDeferredIOHint_afterRead == hint &&
                kPslChanFsmSSLIOState_error != input->ioState) {
                output->ioState = kPslChanFsmSSLIOState_wantWrite;
                break; // continue at 'deferred read' step
            }

            bool const writeable =
                ((kCryptoDeferredIOHint_none != hint) ||
                 (!revents || (revents & (G_IO_OUT | G_IO_HUP | G_IO_NVAL))));
            if (!writeable) {
                break; // continue at 'deferred read' step
            }

            // None of the optimizations kicked in, so we attempt to write
            // out the channel's deferred data

            // SSL_write may alter state for deferred read (e.g., during
            // renegotiation handshake), so force an update
            freshin = !crypto_deferred_io_pending(input->ioState);

            ssize_t cnt = 0;
            const void* const src = psl_io_buf_get_data_ptr(&output->buf, &cnt);
            PSL_ASSERT(src);
            PSL_ASSERT(cnt > 0);

            int const maxWriteCnt = cnt;
            int numWritten = 0, nextDeferredWriteCnt = 0;
            PslError const writePslErr = crypto_write_low(pFsm,
                                                          src,
                                                          cnt,
                                                          maxWriteCnt,
                                                          &numWritten,
                                                          &nextDeferredWriteCnt);
            hint = kCryptoDeferredIOHint_afterWrite;

            /*
             * Post-process the results and check assumptions
             */
            ssize_t     remainingCnt;
            (void)psl_io_buf_consume(&output->buf, numWritten, &remainingCnt);

            if (!writePslErr) {
                PSL_ASSERT(0 == remainingCnt);
                PSL_ASSERT(kPslChanFsmSSLIOState_error != output->ioState);

                // Done with deferred output!
                output->ioState = kPslChanFsmSSLIOState_idle;
            }
            else if (writePslErr && crypto_is_deferred_io_pslerror(writePslErr)) {
                PSL_ASSERT(crypto_deferred_io_pending(output->ioState));
                PSL_ASSERT(remainingCnt > 0);
                PSL_ASSERT(nextDeferredWriteCnt == remainingCnt);
            }
            else {
                // Must be sticky output error
                PSL_ASSERT(kPslChanFsmSSLIOState_error == output->ioState);
            }

            break;
        };  // this completes the 'deferred write' step


        /*
         * The 'deferred read' step
         */
        while (!freshin) {
            PSL_ASSERT(freshout);
            PSL_ASSERT(crypto_deferred_io_pending(input->ioState));

            freshin = true;

            /*
             * If input data is pending, perform a READ operation without
             * triggering I/O (and thus without impacting our deferred
             * output state, it is assumed); 
             *  
             * NOTE: we assume that processing of SSL_write() during handshake 
             * may result in buffering of input application data; if this 
             * assumption is incorrect, then no harm is done.
             */
            if (SSL_pending(sslInfo->ssl) > 0) {
                // Satisfy our one-byte read from openssl buffer and bail out
                PSL_ASSERT(!input->deferredByteAvailable);    
                int numRead = 0;
                PslError const readPslErr = crypto_read_low(
                    pFsm, input->deferredReadOneByteBuf, 1, false, &numRead, NULL);
                hint = kCryptoDeferredIOHint_afterRead;

                // Post-process the results and check assumptions
                if (!readPslErr) {
                    PSL_ASSERT(1 == numRead);
                    input->deferredByteAvailable = true;
                    input->ioState = kPslChanFsmSSLIOState_idle;
                }
                else {
                    // Read failure from non-empty openessl buffer should not
                    // result in deferred I/O state, since SSL_read API
                    // guarantees (in man page) no I/O ops if the pending
                    // buffer is non-empty
                    PSL_ASSERT(kPslChanFsmSSLIOState_error == input->ioState);
                }

                break; // done with deferred I/O !
            }

            if (kPslChanFsmSSLIOState_wantRead == output->ioState) {
                // There was no bufferred input data, and output
                // is in _WANT_READ state, so input should also be in
                // _WANT_READ state
                input->ioState = kPslChanFsmSSLIOState_wantRead;
                break; // done with deferred I/O !
            }

            // Assumption: output state is either: idle, error, or _WANT_WRITE
            PSL_ASSERT(!crypto_deferred_io_pending(output->ioState) ||
                       kPslChanFsmSSLIOState_wantWrite == output->ioState);

            bool const readable =
                ((kCryptoDeferredIOHint_none != hint) ||
                 (!revents || (revents & (G_IO_IN | G_IO_HUP | G_IO_NVAL))));
            if (!readable) {
                break; // done with deferred I/O !
            }

            /*
             * At this point, we have to perform a READ operation that may
             * cause I/O to take place that may impact our deferred output
             * state
             */
            freshout = !crypto_deferred_io_pending(output->ioState);
            do {
                int numRead = 0;
                PslError const readPslErr = crypto_read_low(
                    pFsm, input->deferredReadOneByteBuf, 1, true, &numRead, NULL);
                hint = kCryptoDeferredIOHint_afterRead;

                /*
                 * Post-process the results and check assumptions
                 */

                if (!readPslErr) {
                    PSL_ASSERT(1 == numRead);
                    input->deferredByteAvailable = true;
                    input->ioState = kPslChanFsmSSLIOState_idle;
                }
                else {
                    PSL_ASSERT(crypto_deferred_io_pending(input->ioState) ||
                               kPslChanFsmSSLIOState_error == input->ioState);
                }
            } while ( 0 );

            if (!crypto_deferred_io_pending(input->ioState)) {
                // Deferred output processing now needs to be updated.
                // @note The absence of deferred input will cause the loop
                //       to be terminated afterwards.
                break; 
            }

            /*
             * So, output state is now either non-deferred or _WANT_WRITE,
             * and input state is either _WANT_READ or _WANT_WRITE.
             * 
             * Since we perfored the read operation last, we know that our
             * input state is correct.  But what about the output state?
             * 
             * This is a bit tricky:
             * 
             *      1. If output state was non-deferred, then both output
             *         and input states are correct.
             * 
             *      2. If input state is _WANT_WRITE after the read
             *         operation that we just performed, and output state
             *         was _WANT_WRITE, then both states are correct (if we
             *         need to wait for writeable socket to satisfy deferred
             *         read, then deferred write should also need to wait
             *         for the same condition)
             * 
             *      3. If output state was _WANT_WRITE and input state is
             *         now _WANT_READ, we can't tell whether output state is
             *         correct (e.g., it's possible that the read operation
             *         that we just performed transitioned our SSL channel
             *         into re-negotiation state, in which case our deferred
             *         write would also need to wait for a readable socket);
             *         however, it doesn't matter: we'll be monitoring both
             *         I/O conditions in this case, and whichever occurs
             *         first will trigger another call to this function,
             *         causing the states to be updated; this should not
             *         result in an infinite loop situation.
             * 
             */
            freshin = freshout = true;
            break; // done with deferred I/O !
        }; // this completes the 'deferred read' step

    }//while (!freshout || !freshin) {


    /*
     * If a fatal error was detected on the file descriptor, abort 
     * deferred I/O, and force user's channel watch instance to 
     * report readiness, thus allowing user to detect the error
     */
    if ((revents & (G_IO_HUP | G_IO_NVAL))) {
        // If deferred input I/O was not fulfilled by now, it won't be ever;
        // 
        // If input is in the idle state, there may be data in SSL channel's
        // pending buffer that the user may wish to read;
        // 
        // If an error was already pending on input, we leave it alone.
        //
        // @note This is a workaround for an apparent bug in openssl: Normally,
        //       this extra error-handling logic should be unnecessary
        //       because the deferred I/O should have forced a call to SSL_read in
        //       the above logic, and SSL_read should have returned with a
        //       meaningful error code corresponding to the fatal error on the
        //       file descriptor.  And this is how things appear to work when
        //       deferred output is pending _only_ in _one_ direction when we get
        //       G_IO_HUP in revents after turning on Airplane mode. In this
        //       scenario the SSL_read() or SSL_write() indicates ECONNRESET (due
        //       to Palm's patch that destroys sockets when the corresponding
        //       interface goes down). However, there appears to be a bug in our
        //       current version of openssl (0.9.8k ???), whereby if _BOTH_ read
        //       and write are pending, SSL_write() (which we call first in the
        //       logic above) will indicate ECONNRESET, but the subsequent
        //       SSL_read() calls indicate SSL_WANT_READ (instead of ECONNRESET),
        //       and we were getting stuck in an endless loop before this
        //       work-around (gmainloop would keep calling us with G_IO_HUP, but
        //       SSL_read would keep returning SSL_WANT_READ).
        if (crypto_deferred_io_pending(input->ioState)) {
            input->ioState = kPslChanFsmSSLIOState_error;
            input->pslErr = PSL_ERR_TCP_CONNRESET;
        }

        // Further output is impossible, so set sticky error on the output,
        // unless output error was already set
        if (kPslChanFsmSSLIOState_error != output->ioState) {
            output->ioState = kPslChanFsmSSLIOState_error;
            output->pslErr = PSL_ERR_TCP_CONNRESET;
        }

        PSL_LOG_ERROR(
            "%s (fsm=%p): ERROR: connection reset by peer or invalid fd: " \
            "GIOCondition revents=0x%lX; aborting deferred I/O",
            __func__, pFsm, (unsigned long)revents);
    }


    /*
     * Update our fd-watch to monitor for I/O conditions based on
     * the (possibly) new input/ouput states
     */
    crypto_schedule_deferred_ssl_io(pFsm);

    PSL_LOG_DEBUG("%s (fsm=%p): completed: in->ioState=%d, out->ioState=%d",
                  __func__, pFsm, (int)input->ioState, (int)output->ioState);

    return kPslSmeEventStatus_success;
}//crypto_process_deferred_ssl_io


/** ========================================================================
 * Return the number of bytes that are ready to be read 
 * immediately without causing any I/O in the transport. 
 * 
 * @param pFsm 
 * 
 * @return unsigned int Number of bytes that are ready to be 
 *         read; this includes openssl's pending read buffer as
 *         well as our FSM's one-byte deferred I/O one-byte
 *         buffer.
 *  
 * =========================================================================
 */
unsigned int
crypto_total_input_bytes_ready(PslChanFsm* const pFsm)
{
    const PslChanFsmCryptoSharedInfo* const sslInfo = crypto_shared_info(pFsm);
    unsigned int const numReady = SSL_pending(sslInfo->ssl) +
        !!sslInfo->io.in.deferredByteAvailable;

    return numReady;
}


/** ========================================================================
 * crypto_read_low(): Low-level helper function for performing 
 * SSL_read() into user's buffer. Called by 
 * PSL_CHAN_FSM_EVT_READ handler and 
 * crypto_process_deferred_ssl_io(). 
 * 
 * @note Reads that may result in I/O are done into the deferred
 *       read buffer in case they will need to be retried again
 *       ('man SSL_read' requires that SSL_read be retried with
 *       the same args in the event of WANT_READ and WANT_WRITE
 *       errors)
 * 
 * @note Will NOT schedule deferred I/O processing.  Caller is
 *       responsible for schedule deferred I/O.
 * 
 * @note may be called with input ioState being one of the
 *       deferred I/O values or idle.
 * 
 * @note Updates input ioState and input pslErr based on
 *       SSL_read failure in case of sticky input error or just
 *       the input ioState if a deferred SSL_read is needed.
 * 
 * @note Updates last error if call terminated due to error or 
 *       WANT_READ/WANT_WRITE
 * 
 * @param pFsm
 * @param pDst
 * @param cnt 
 * @param deferredIOAllowed TRUE if entering the deferred I/O 
 *                  input state is allowed;
 * @param pNumRead Non-NULL pointer to variable for returning 
 *                 the count of bytes that were read.
 * @param pIOAttempted Optional (may be NULL) pointer to 
 *                     variable for returning an indication of
 *                     whether I/O was attempted: SSL_read was
 *                     called to read bytes beyond those that
 *                     were arleady pending, regardless of
 *                     whether read actually succeeded.  openssl
 *                     deferred I/O state may be altered when
 *                     I/O is attempted, but should be unchanged
 *                     if only pending bytes are removed.
 * 
 * @return PslError 0 if no error was encountered; otherwise, a
 *         non-zero PslError code identifying the cause of
 *         termination, including PSL_ERR_SSL_WANT_READ,
 *         PSL_ERR_SSL_WANT_WRITE, PSL_ERR_SSL_CLEAN_EOF, etc.
 * 
 * =========================================================================
 */
static PslError
crypto_read_low(PslChanFsm* const pFsm,
                void*       const pDst,
                int         const cnt,
                bool        const deferredIOAllowed,
                int*        const pNumRead,
                bool*       const pIOAttempted)
{
    PslChanFsmCryptoSharedInfo* const sslInfo = crypto_shared_info(pFsm);

    PSL_LOG_DEBUG("%s (fsm=%p): ENTERING: requested cnt=%d, deferredIOAllowed=%d, " \
                  "openSSL state=%d (%s)", __func__, pFsm, cnt, (int)deferredIOAllowed,
                  SSL_state(sslInfo->ssl), SSL_state_string_long(sslInfo->ssl));

    PSL_ASSERT(pDst || !cnt);
    PSL_ASSERT(cnt >= 0);
    PSL_ASSERT(pNumRead);

    bool ioAttempted = false;
    PslChanFsmCryptoInput* const input = &sslInfo->io.in;

    /*
     * @note When called from crypto_process_deferred_ssl_io(), the
     *       input may be in the deferred I/O state
     */
    PSL_ASSERT(kPslChanFsmSSLIOState_idle == input->ioState ||
               crypto_deferred_io_pending(input->ioState));

    PslError pslErrRes = 0; // result error code to be returned
    *pNumRead = 0;

    /*
     * Do SSL_read
     * 
     * @note SSL_read is rather finicky: in case of
     *       SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE, it expects
     *       us to call it again with exactly the same args (buf ptr
     *       and cnt).  This is error-prone and unnatural for the
     *       GIOChannel interface that the original authors of
     *       libpalmsocket selected, so we're forced to go to the
     *       extra overhead of buffering the reads through our own
     *       buffer when nothing is pending.
     * @see 'man SSL_read' and read the warning
     */
    int remainingCnt = cnt;

    while (remainingCnt) {
        int sslRet;
        int maxRead;

        int const sslPendingCnt = SSL_pending(sslInfo->ssl);

        if (sslPendingCnt > 0) {
            // Prefer to read directly into user's buffer to minimize copying
            maxRead = (remainingCnt <= sslPendingCnt
                       ? remainingCnt
                       : sslPendingCnt);
            sslRet = SSL_read(sslInfo->ssl,
                              (uint8_t*)pDst + *pNumRead, maxRead);
            if (sslRet > 0) {
                *pNumRead += sslRet;
                remainingCnt -= sslRet;
                PSL_LOG_DEBUG("%s (fsm=%p): SSL_read(%d): read=%d/%d " \
                              "from pendingcnt=%d",
                              __func__, pFsm, maxRead, sslRet,
                              *pNumRead, sslPendingCnt);
                continue;
            }
        }
        else {
            /*
             * No decoded app data is pending at the moment. Attempt to read
             * one byte into our internal buffer.  This may result in
             * reading and decoding of the next SSL app data record if it's 
             * already present in the socket's input packet buffers.  If an
             * an entire SSL record is not available, then openssl will fail with
             * WANT_READ or want WANT_WRITE and we will schedule a deferred
             * SSL_read() operation into an internal "deferred read" buffer. 
             *  
             * @note We use a one-byte "deferred read" buffer in order to minimize 
             *       the amount of data that needs to be copied. 
             * 
             * @note When we're called from
             *       crypto_process_deferred_ssl_io(), pDst might be the
             *       same as input->deferredReadOneByteBuf
             */
            ioAttempted = true;
            maxRead = 1;
            sslRet = SSL_read(sslInfo->ssl,
                              input->deferredReadOneByteBuf, maxRead);
            if (sslRet > 0) {
                PSL_ASSERT(1 == sslRet);
                *((uint8_t*)pDst + *pNumRead) = input->deferredReadOneByteBuf[0];
                *pNumRead += sslRet;
                remainingCnt -= sslRet;
                PSL_LOG_DEBUG("%s (fsm=%p): SSL_read(deferredOneByteBuf): " \
                              "read=%d/%d",
                              __func__, pFsm, sslRet, *pNumRead);
                continue;
            }
        }


        /*
         * SSL_read() failed; let's figure out if it's a real failure or
         * simply an action request (WANT_READ/WANT_WRITE) from openssl
         */

        remainingCnt = 0; // force loop termination

        pslErrRes = psl_err_get_and_process_SSL_channel_error(
            pFsm, sslInfo->ssl, sslRet, PSL_ERR_SSL_PROTOCOL);
        PSL_ASSERT(pslErrRes);

        // Direct reads from pending openssl data MUST not result in WANT_xxxx
        // since we can't guarantee availability of user's buffer during
        // deferred retries of SSL_read() (@see 'man SSL_read').
        PSL_ASSERT(!sslPendingCnt || !crypto_is_deferred_io_pslerror(pslErrRes));

        switch (pslErrRes) {
        case PSL_ERR_SSL_WANT_READ:
            if (deferredIOAllowed && !*pNumRead) {
                // We will repeat the SSL_read operation into our deferred
                // read buffer when the socket becomes readable
                input->ioState = kPslChanFsmSSLIOState_wantRead;
            }
            PSL_LOG_DEBUG("%s (fsm=%p): SSL_read(%d): PSL_ERR_SSL_WANT_READ",
                          __func__, pFsm, maxRead);
            break;
        case PSL_ERR_SSL_WANT_WRITE:
            if (deferredIOAllowed && !*pNumRead) {
                // We will repeat the SSL_read operation into our deferred
                // read buffer when the socket becomes writeable
                input->ioState = kPslChanFsmSSLIOState_wantWrite;
            }
            PSL_LOG_DEBUG("%s (fsm=%p): SSL_read(%d): PSL_ERR_SSL_WANT_WRITE",
                          __func__, pFsm, maxRead);
            break;

        default:
            input->ioState = kPslChanFsmSSLIOState_error;
            input->pslErr = pslErrRes; // save sticky input error

            if (PSL_ERR_SSL_CLEAN_EOF == pslErrRes) {
                PSL_LOG_NOTICE("%s (fsm=%p): SSL_read: rx orderly SSL " \
                               "close", __func__, pFsm);
            }
            else {
                PSL_LOG_ERROR("%s (fsm=%p): ERROR: SSL_read(%d) failed with " \
                              "pslerr=%d (%s)",
                              __func__, pFsm, maxRead, pslErrRes,
                              PmSockErrStringFromError(pslErrRes));
            }
            break;
        }//switch (pslErrRes)
    }//while more to read

    if (pslErrRes) {
        psl_chan_fsm_set_last_error(pFsm, kPslChanFsmErrorSource_psl,
                                    pslErrRes);
    }

    if (pIOAttempted) {
        *pIOAttempted = ioAttempted;
    }

    PSL_LOG_DEBUG(
        "%s (fsm=%p): LEAVING: requested cnt=%d, numRead=%d, ioAttempted=%d, " \
        "terminating PslError=%d (%s), openSSL state=%d (%s)",
                  __func__, pFsm, cnt, *pNumRead, (int)ioAttempted, pslErrRes,
                  PmSockErrStringFromError(pslErrRes), 
                  SSL_state(sslInfo->ssl), SSL_state_string_long(sslInfo->ssl));

    return pslErrRes;
}// crypto_read_low



/** ========================================================================
 * Low-level helper function for performing iterative
 * SSL_write() of the given source data with the given
 * constraints.  Called by PSL_CHAN_FSM_EVT_WRITE handler and by
 * crypto_deferred_io_pending().
 * 
 * @note Will NOT schedule deferred I/O processing.  Caller is
 *       responsible for calling crypto_deferred_io_pending()
 *       when appropriate.
 * 
 * @note Will NOT access (read/write/test) the deferred write
 *       buffer in any way as we may be called by
 *       crypto_process_deferred_ssl_io().
 * 
 * @note may be called with output ioState being one of the
 *       deferred I/O values or idle.
 * 
 * @note Updates output ioState and output pslErr based on
 *       SSL_write failure in case of sticky output error or
 *       just the output ioState if a deferred SSL_write is
 *       needed.
 * 
 * @note Updates last error if call termianted prematurely
 * 
 * @param pFsm
 * 
 * @param pSrc Non-NULL pointer to beginning of data to be
 *             written
 * 
 * @param cnt Non-negative number of data bytes to be written
 * 
 * @param maxWriteCnt Positive per-SSL_write() call maximum
 *                    write count.  Allows our caller to
 *                    guarantee that any deferred SSL_write
 *                    operation can be accommodated by the
 *                    deferred write buffer.  This function will
 *                    feed data to SSL_write in 0 or more
 *                    increments of maxWriteCnt, followed by the
 *                    remainder.
 * 
 * @param pNumWritten Number of bytes consumed by SSL_write.
 *                    This value is always valid regardless of
 *                    returned error code.
 * 
 * @param pDeferredWriteCnt If the iteration terminated due to a
 *                          deferred SSL_write(WANT_READ or
 *                          WANT_WRITE), this value will be set
 *                          to the number of bytes that we
 *                          attempted to write. This will be
 *                          noted by our caller for subsequent
 *                          deferred processing (will be passed
 *                          as cnt in next call to us
 *                          after the deferral condition is
 *                          met).  This value is always valid
 *                          regardless of returned error code.
 * 
 * @return PslError 0 (zero) if all requested data was consumed
 *         by SSL_write; otherwise, not all bytes were consumed
 *         and the non-zero PslError value is the reason why the
 *         request was terminated prematurely.  Any non-zero
 *         error code besides PSL_ERR_SSL_WANT_READ and
 *         PSL_ERR_SSL_WANT_WRITE is a sticky output error.
 * 
 * =========================================================================
 */
static PslError
crypto_write_low(PslChanFsm*    const pFsm,
                 const void*    const pSrc,
                 int            const cnt,
                 int            const maxWriteCnt,
                 int*           const pNumWritten,
                 int*           const pDeferredWriteCnt)
{
    PslChanFsmCryptoSharedInfo* const sslInfo = crypto_shared_info(pFsm);

    PSL_LOG_DEBUG("%s (fsm=%p): ENTERING: requested cnt=%d, maxWrCnt=%d, " \
                  "openSSL state=%d (%s)", __func__, pFsm, cnt, maxWriteCnt,
                  SSL_state(sslInfo->ssl), SSL_state_string_long(sslInfo->ssl));

    PslError pslErrRes = 0; // result error code to be returned

    PslChanFsmCryptoOutput*     const output = &sslInfo->io.out;

    PSL_ASSERT(pSrc || !cnt);
    PSL_ASSERT(cnt >= 0);
    PSL_ASSERT(maxWriteCnt > 0);
    PSL_ASSERT(pNumWritten);
    PSL_ASSERT(pDeferredWriteCnt);

    PSL_ASSERT(kPslChanFsmSSLIOState_idle == output->ioState ||
               crypto_deferred_io_pending(output->ioState));


    *pNumWritten = 0;
    *pDeferredWriteCnt = 0;

    int remainingCnt = cnt;

    while (remainingCnt) {
        int const writeReqCnt = ((remainingCnt <= maxWriteCnt)
                                 ? remainingCnt
                                 : maxWriteCnt);

        int const sslRet = SSL_write(sslInfo->ssl,
                                     (uint8_t*)pSrc + *pNumWritten,
                                     writeReqCnt);

        if (sslRet > 0) {
            *pNumWritten += sslRet;
            remainingCnt -= sslRet;
            PSL_LOG_DEBUG("%s (fsm=%p): SSL_write(%d): wrote=%d/%d",
                          __func__, pFsm, writeReqCnt, sslRet,
                          *pNumWritten);
            continue;
        }

        /**
         * SSL_write() failed; let's figure out if it's a real failure
         * or simply an action request from openssl
         */

        remainingCnt = 0; // force loop termination

        pslErrRes = psl_err_get_and_process_SSL_channel_error(
            pFsm, sslInfo->ssl, sslRet, PSL_ERR_SSL_PROTOCOL);
        PSL_ASSERT(pslErrRes);

        switch (pslErrRes) {
        case PSL_ERR_SSL_WANT_READ:
            /// We will complete the SSL_write operation ourselves from our
            /// reserved write buffer when the deferral condition is satisfied
            output->ioState = kPslChanFsmSSLIOState_wantRead;
            *pDeferredWriteCnt = writeReqCnt;
            PSL_LOG_DEBUG("%s (fsm=%p): SSL_write(%d): PSL_ERR_SSL_WANT_READ",
                          __func__, pFsm, writeReqCnt);
            break;
        case PSL_ERR_SSL_WANT_WRITE:
            /// We will complete the SSL_write operation ourselves from our
            /// reserved write buffer when the deferral condition is satisfied
            output->ioState = kPslChanFsmSSLIOState_wantWrite;
            *pDeferredWriteCnt = writeReqCnt;
            PSL_LOG_DEBUG("%s (fsm=%p): SSL_write(%d): PSL_ERR_SSL_WANT_WRITE",
                          __func__, pFsm, writeReqCnt);
            break;

        default:
            output->ioState = kPslChanFsmSSLIOState_error;
            output->pslErr = pslErrRes;

            psl_chan_fsm_set_last_error(pFsm, kPslChanFsmErrorSource_psl,
                                        pslErrRes);

            PSL_LOG_ERROR("%s (fsm=%p): ERROR: SSL_write(%d) failed with " \
                          "pslerror=%d (%s)",
                          __func__, pFsm, writeReqCnt, pslErrRes,
                          PmSockErrStringFromError(pslErrRes));
            break;
        }//switch (pslErrRes)
    }//while more may be written

    if (pslErrRes) {
        psl_chan_fsm_set_last_error(pFsm, kPslChanFsmErrorSource_psl,
                                    pslErrRes);
    }


    PSL_LOG_DEBUG(
        "%s (fsm=%p): LEAVING: numWritten=%d, deferredWriteCnt=%d, " \
        "terminating PslError=%d (%s), openSSL state=%d (%s)",
        __func__, pFsm, *pNumWritten, *pDeferredWriteCnt, pslErrRes,
        PmSockErrStringFromError(pslErrRes),
        SSL_state(sslInfo->ssl), SSL_state_string_long(sslInfo->ssl));

    return pslErrRes;
}//crypto_write_low



/**
 * Perform periodic TLS/SSL shutdown processing for PslChanFsmCryptoShutState
 * 
 * @param pFsm
 * @param how SSL shut-down type: one-way or two-way
 * @param currPhase Shutdown phase prior to this call
 * @param pNewPhase Non-NULL pointer to location for returning
 *                  an updated shutdown phase; could be the same
 *                  as currPhase, if phase didn't change during
 *                  this call.
 * 
 * @return PslError 0 on success (check *pNewPhase to see if
 *         done); otherwise a non-zero PslError code indicating
 *         why shutdown failed.
 */
static PslError
crypto_do_shutdown(PslChanFsm*                  const pFsm,
                   PslChanFsmEvtShutCryptoKind  const how,
                   PslChanFsmCryptoShutPhase    currPhase,
                   PslChanFsmCryptoShutPhase*   const pNewPhase)
{
    PSL_LOG_DEBUG("%s (fsm=%p): ENTERING: how=%d, currPhase=%s",
                  __func__, pFsm, (int)how,
                  crypto_string_from_shutphase(currPhase));

    PslError    pslErr = 0;
    PslChanFsmCryptoSharedInfo* const sslInfo = crypto_shared_info(pFsm);

    *pNewPhase = currPhase;

    PSL_ASSERT(kPslChanFsmCryptoShutPhase_shut1 == currPhase ||
               kPslChanFsmCryptoShutPhase_shut2 == currPhase);
    PSL_ASSERT(kPslChanFsmCryptoShutPhase_shut1 == currPhase ||
               kPslChanFsmEvtShutCrypto_twoWay == how);

    /**
     * @see 'man SSL_shutdown'
     */
    bool oneMoreTime = true;

    while (oneMoreTime) {
        oneMoreTime = false;

        if (currPhase != *pNewPhase) {
            PSL_LOG_DEBUG("%s (fsm=%p): prevPhase=%s, newPhase=%s",
                          __func__, pFsm,
                          crypto_string_from_shutphase(currPhase),
                          crypto_string_from_shutphase(*pNewPhase));

            currPhase = *pNewPhase;
        }

        int sslRet = SSL_shutdown(sslInfo->ssl);

        if (0 == sslRet) {
            /**
             * @note SSL_shutdown status reporting is broken with respect to
             *       non-blockin I/O in openssl 0.9.8 (before 0.9.8m).
             *       According to documentation, it's supposed to return 0
             *       only when sending of the "Close notify" completes, but
             *       it actually returns 0 in any of the following cases:
             *          1. It completed writing the "Close notify" alert to
             *          the socket
             *          2. It didn't complete writing the "Close notify"
             *          alert to the socket because the socket buffer was
             *          full.
             *          3. It completed writing the "Close notify" alert on
             *          a prior SSL_shutdown call, but the subsequent
             *          SSL_shutdown call tried to read the "Close notify"
             *          alert from the remote peer, but was unable to read
             *          anything due to EWOULDBLOCK condition on the socket.
             *  
             * @todo We may also need to be reading during bi-directional 
             *       shut-down in order to free up openssl's buffers so that
             *       the remote peer's "Close notify" can be read (in the
             *       scenario whereby unread input data is still
             *       pending/being sent at the time our shut-down is
             *       initiated)
             */
            int const ssl_wantResult = SSL_want(sslInfo->ssl);
            if (SSL_NOTHING != ssl_wantResult) {
                sslRet = -1;
                PSL_LOG_DEBUG(
                    "%s (fsm=%p): SSL_shutdown() returned 0, but SSL_want() " \
                    "reports '%s': changing SSL_shutdown() result to %d; " \
                    "currPhase=%s",
                    __func__, pFsm, crypto_string_from_ssl_want(ssl_wantResult),
                    sslRet, crypto_string_from_shutphase(currPhase));
            }
        }

        switch (sslRet) {
        case 0:             // unidirectional shutdown complete
            PSL_LOG_DEBUG("%s (fsm=%p): unidirectional shutdown finish detected",
                          __func__, pFsm);

            if (kPslChanFsmEvtShutCrypto_oneWay == how) {
                *pNewPhase = kPslChanFsmCryptoShutPhase_success;
                goto good_exit;
            }
            else {
                if (kPslChanFsmCryptoShutPhase_shut2 == currPhase) {
                    // NOTE: With openssl 0.9.8 (don't know about later versions),
                    // we keep getting 0 return value from SSL_shutdown() in phase2
                    // when there is incoming data from the other side, and
                    // SSL_shutdown() appears to be discarding that incoming data.
                    // So, SSL_shutdown() alternates between returning 0 and
                    // requesting SSL_WANT_READ until EOF from the other side.
                    PSL_LOG_DEBUG("%s (fsm=%p): resuming shut2 phase", __func__, pFsm);
                }
                else {
                    PSL_LOG_DEBUG("%s (fsm=%p): starting shut2 phase", __func__, pFsm);
                }
                *pNewPhase = kPslChanFsmCryptoShutPhase_shut2;
                oneMoreTime = true;
                continue;
            }
            break;

        case 1:             // bidirectional shutdown complete
            /**
             * @note this may happen even with only one call to
             *       SSL_shutdown() if the peer's 'close notify' alert was
             *       already received before our first SSL_shutdown() call
             */
            PSL_LOG_DEBUG("%s (fsm=%p): bidirectional shutdown finish detected",
                          __func__, pFsm);
            *pNewPhase = kPslChanFsmCryptoShutPhase_success;
            goto good_exit;
            break;

        default:            // error or openssl WANT_READ/WANT_WRITE
            PSL_ASSERT(-1 == sslRet);
            pslErr = psl_err_get_and_process_SSL_channel_error(
                pFsm, sslInfo->ssl, sslRet, PSL_ERR_SSL_PROTOCOL);
            PSL_ASSERT(pslErr);

            switch (pslErr) {
            case PSL_ERR_SSL_WANT_READ:
            case PSL_ERR_SSL_WANT_WRITE:
                goto good_exit;
                break;

            default:
                goto error_exit;
                break;
            }
            break;
        }
    }//while (oneMoreTime)

good_exit:
    if (!pslErr) {
        PSL_ASSERT(kPslChanFsmCryptoShutPhase_success == *pNewPhase);
        crypto_reset_multi_fd_watch(pFsm);
    }
    else {
        PSL_ASSERT(crypto_is_deferred_io_pslerror(pslErr));

        GIOCondition cond = PSL_ERR_SSL_WANT_READ == pslErr ? G_IO_IN : G_IO_OUT;

        PSL_LOG_DEBUG("%s (fsm=%p): updating multi-fd-watch: GIOCondition=0x%lX",
                      __func__, pFsm, (unsigned long) cond);
        crypto_update_multi_fd_watch_giocondition(pFsm, cond);
    }

    PSL_LOG_DEBUG("%s (fsm=%p): LEAVING: prevPhase=%s, newPhase=%s",
                  __func__, pFsm,
                  crypto_string_from_shutphase(currPhase),
                  crypto_string_from_shutphase(*pNewPhase));
    return 0;

error_exit:
    PSL_ASSERT(pslErr);

    *pNewPhase = kPslChanFsmCryptoShutPhase_failed;

    (void)crypto_reset_multi_fd_watch(pFsm);

    psl_chan_fsm_set_last_error(pFsm, kPslChanFsmErrorSource_psl,
                                pslErr);

    PSL_LOG_ERROR("%s (fsm=%p): LEAVING: ERROR: Crypto-Shut failed: pslErr=%d (%s); " \
                  "prevPhase=%s, newPhase=%s",
                  __func__, pFsm, (int)pslErr,
                  PmSockErrStringFromError(pslErr),
                  crypto_string_from_shutphase(currPhase),
                  crypto_string_from_shutphase(*pNewPhase));
    return pslErr;
}//crypto_do_shutdown


/**
 * Maps the given PslChanFsmCryptoShutPhase value to a static
 * string.
 * 
 * @param phase
 * 
 * @return const char*
 */
static const char*
crypto_string_from_shutphase(PslChanFsmCryptoShutPhase phase)
{
    switch (phase) {
    case kPslChanFsmCryptoShutPhase_init:       return "init";
        break;
    case kPslChanFsmCryptoShutPhase_flushOut:   return "flush-out";
        break;
    case kPslChanFsmCryptoShutPhase_shut1:      return "shut1";
        break;
    case kPslChanFsmCryptoShutPhase_shut2:      return "shut2";
        break;
    case kPslChanFsmCryptoShutPhase_success:    return "success";
        break;
    case kPslChanFsmCryptoShutPhase_failed:     return "failed";
    }

    PSL_LOG_ERROR("%s: ERROR: Unexpected PslChanFsmCryptoShutPhase=%d",
                  __func__, (int)phase);
    return "ERROR-UNEXPECTED-SHUT-PHASE (check log for value)";
}


/**
 * Maps the given value returned by SSL_want to a static string
 * 
 * @param ssl_wantResult SSL_WRITING, SSL_READING, etc.
 * 
 * @return const char* 
 */
static const char*
crypto_string_from_ssl_want(int const ssl_wantResult)
{
    switch (ssl_wantResult) {
    case SSL_NOTHING:           return "SSL_NOTHING";
        break;
    case SSL_WRITING:           return "SSL_WRITING";
        break;
    case SSL_READING:           return "SSL_READING";
        break;
    case SSL_X509_LOOKUP:       return "SSL_X509_LOOKUP";
        break;
    }

    PSL_LOG_ERROR("%s: ERROR: Unexpected SSL_want() result=%d",
                  __func__, ssl_wantResult);
    return "ERROR-UNEXPECTED-SSL_want()-RESULT (check log for value)";
}
