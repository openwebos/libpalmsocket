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
 * @file psl_channel_fsm.c
 * @ingroup psl_internal 
 * 
 * @brief  Finite State Machine implementation for the
 *         PmSockIOChannel.
 * 
 * *****************************************************************************
 */
#include "psl_build_config.h"

#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <unistd.h>

#include <glib.h>

//#define STATE_MACHINE_ENGINE_WEBOS_FEATURES ///< for FsmDbgEnableLoggingViaPmLogLib
#include <PmStateMachineEngine/PalmFsm.h>
#include <PmStateMachineEngine/PalmFsmDbg.h>

#include "palmsocket.h"

#include "psl_common.h"
#include "psl_log.h"
#include "psl_assert.h"
#include "psl_error_utils.h"
#include "psl_multi_fd_watch.h"

#include "psl_thread_context.h"
#include "psl_ssl_context.h"

#include "psl_sme.h"
#include "psl_channel_fsm_events.h"
#include "psl_channel_fsm_plain.h"
#include "psl_channel_fsm_crypto.h"
#include "psl_channel_fsm_fwd.h"
#include "psl_channel_fsm.h"
#include "psl_channel_fsm_main.h"


/**
 * Frees the FSM instance.  Called by psl_chan_fsm_unref() when
 * reference count drops to zero
 * 
 * @param pFsm Non-NULL fsm instance to be freed
 */
static void
chan_fsm_free(PslChanFsm* const pFsm);

static void
chan_fsm_destroy_widgets(PslChanFsm* const pFsm);

static gboolean
chan_fsm_fd_watch_cb(gpointer userData, const PslMultiFdPollRec* pollrecs,
                     int numrecs);
static PslMultiFdWatchSourceCb chan_fsm_fd_watch_cb; ///< validate prototype


static PSL_CHAN_FSM_STATE_HANDLER_DECLARE(chan_fsm_alive_state_handler,
                                          PslChanFsmAliveState);

static PSL_CHAN_FSM_STATE_HANDLER_DECLARE(chan_fsm_init_state_handler,
                                          PslChanFsmInitState);

static PSL_CHAN_FSM_STATE_HANDLER_DECLARE(chan_fsm_closed_state_handler,
                                          PslChanFsmClosedState);

static PSL_CHAN_FSM_STATE_HANDLER_DECLARE(chan_fsm_final_state_handler,
                                          PslChanFsmFinalState);



/** ===========================================================================
 *                            FUNCTIONS
 * ============================================================================
 */


/** ========================================================================
 * =========================================================================
 */
PslError
psl_chan_fsm_new(PslChanFsm**           const fsmResult,
                 PmSockThreadContext*   const threadCtx,
                 PmSockOptionFlags      const options,
                 GIOChannel*            const channel,
                 const char*            const userLabel)
{
    PSL_ASSERT(fsmResult && threadCtx);

    PslChanFsm* fsm = g_new0(PslChanFsm, 1);
    PSL_ASSERT(fsm);

    /**
     * @note chan_fsm_free() logic depends on the refcount being
     *       properly initialized
     */
    psl_refcount_init(&fsm->refCount, "PSL_FSM", fsm);

    fsm->channel = channel;

    fsm->fd = PSL_CHAN_FSM_CLOSED_FD_VALUE;

    /// Init userSettings
    fsm->userSettings.bindAddr.addrFamily = AF_UNSPEC;
    fsm->userSettings.serverAddr.addrFamily = AF_UNSPEC;
    fsm->userSettings.threadCtx = PmSockThreadCtxRef(threadCtx);

    PSL_ASSERT(!(options & ~kPmSockOptFlag_allValidOpts));
    fsm->userSettings.chanOpts = options;

    /// Create a multi-fd watch source instance
    fsm->fdWatchInfo.fdWatch = psl_multi_fd_watch_new();
    PSL_ASSERT(fsm->fdWatchInfo.fdWatch);
    g_source_set_can_recurse((GSource*)fsm->fdWatchInfo.fdWatch, false);
    g_source_set_callback((GSource*)fsm->fdWatchInfo.fdWatch,
                          (GSourceFunc)&chan_fsm_fd_watch_cb,
                          fsm, NULL);
    g_source_set_priority((GSource*)fsm->fdWatchInfo.fdWatch, G_PRIORITY_HIGH);
    g_source_attach((GSource*)fsm->fdWatchInfo.fdWatch,
                    fsm->userSettings.threadCtx->gmainCtx);

    /// Set up our FSM
    psl_sme_init_machine(&fsm->base,
                         "PSL_CHAN",
                         sizeof(fsm->beginEvtArgSupport.requestArgBuf),
                         &fsm->beginEvtArgSupport.requestArgBuf,
                         &fsm->beginEvtArgSupport.dispatchArgBuf);

    FsmDbgEnableLoggingViaPmLogLib(&fsm->base.base,
                                   kFsmDbgLogOptEvents,
                                   gPslLogContext,
                                   channel/*cookie*/);


    /// Initialize and insert our common states into the FSM

    psl_sme_init_state(
        &fsm->finalState.base,
        (PslSmeStateHandlerFnType*)&chan_fsm_final_state_handler,
        "FINAL");

    psl_sme_init_state(
        &fsm->aliveState.base,
        (PslSmeStateHandlerFnType*)&chan_fsm_alive_state_handler,
        "ALIVE");

    psl_sme_init_state(
        &fsm->aliveState.initState.base,
        (PslSmeStateHandlerFnType*)&chan_fsm_init_state_handler,
        "INIT");

    psl_sme_init_state(
        &fsm->aliveState.closedState.base,
        (PslSmeStateHandlerFnType*)&chan_fsm_closed_state_handler,
        "CLOSED");


    psl_sme_insert_state(
        &fsm->base,
        &fsm->finalState.base,
        NULL/*parent*/);

    psl_sme_insert_state(
        &fsm->base,
        &fsm->aliveState.base,
        NULL/*parent*/);

    psl_sme_insert_state(
        &fsm->base,
        &fsm->aliveState.initState.base,
        &fsm->aliveState.base/*parent*/);

    psl_sme_insert_state(
        &fsm->base,
        &fsm->aliveState.closedState.base,
        &fsm->aliveState.base/*parent*/);

    /// Initialize and insert the plaintext mode states
    psl_chan_fsm_plain_init(fsm, &fsm->aliveState.base);

    /// Initialize and insert the crypto mode states
    psl_chan_fsm_crypto_init(fsm, &fsm->aliveState.base);

    /// Start the FSM at the "init" state
    psl_sme_fsm_start(&fsm->base, &fsm->aliveState.initState.base);
    fsm->fsmStarted = true;


    PSL_LOG_DEBUG("%s (fsm=%p/%s): created", __func__, fsm,
                  PSL_LOG_MAKE_SAFE_STR(userLabel));

    *fsmResult = fsm;
    return 0;
}



/** ========================================================================
 * =========================================================================
 */
void
psl_chan_fsm_finalize(PslChanFsm* const pFsm)
{
    PSL_LOG_DEBUG("%s (fsm=%p)", __func__, pFsm);

    PSL_ASSERT(pFsm);

    if (pFsm->fsmStarted) {
        if (!pFsm->fsmClosed) {
            psl_chan_fsm_evt_dispatch_CLOSE(pFsm);
            PSL_ASSERT(pFsm->fsmClosed);
        }

        /// Trigger exits out of the active states to ensure orderly clean-up
        psl_chan_fsm_evt_dispatch_FINALIZE(pFsm);
    }
}///psl_chan_fsm_finalize



/** ========================================================================
 * =========================================================================
 */
PslChanFsm*
psl_chan_fsm_ref(PslChanFsm* const pFsm)
{
    PSL_LOG_DEBUGLOW("%s (fsm=%p)", __func__, pFsm);

    PSL_ASSERT(pFsm);

    psl_refcount_atomic_ref(&pFsm->refCount);

    return pFsm;
}



/** ========================================================================
 * =========================================================================
 */
void
psl_chan_fsm_unref(PslChanFsm* const pFsm)
{
    PSL_LOG_DEBUGLOW("%s (fsm=%p)", __func__, pFsm);

    PSL_ASSERT(pFsm);
    PSL_ASSERT(!pFsm->base.inEvtDispatch &&
               "MUST avoid FSM run-to-completion violation");

    if (psl_refcount_atomic_unref(&pFsm->refCount)) {
        chan_fsm_free(pFsm);
    }
}



/** ========================================================================
 * =========================================================================
 */
bool
psl_chan_fsm_is_closed(const PslChanFsm* const pFsm)
{
    PSL_ASSERT(pFsm);

    return pFsm->fsmClosed;
}



/** ========================================================================
 * =========================================================================
 */
PmSockThreadContext*
psl_chan_fsm_peek_thread_ctx(PslChanFsm* const pFsm)
{
    PSL_ASSERT(pFsm);
    return pFsm->userSettings.threadCtx;
}



/** ========================================================================
 * =========================================================================
 */
void
psl_chan_fsm_set_userdata(PslChanFsm* const pFsm, void* const userData)
{
    PSL_ASSERT(pFsm);

    pFsm->userSettings.userData = userData;
}



/** ========================================================================
 * =========================================================================
 */
void*
psl_chan_fsm_get_userdata(const PslChanFsm* const pFsm)
{
    PSL_ASSERT(pFsm);

    return pFsm->userSettings.userData;
}



/** ========================================================================
 * =========================================================================
 */
void
psl_chan_fsm_dispatch_completion_cb(
    PslChanFsm*                             const pFsm,
    const PslChanFsmEvtCompletionCbInfo*    const pCb,
    PslError                                const pslErr,
    bool                                    const switchingToCrypto)
{
    PSL_ASSERT(pFsm);
    PSL_ASSERT(pCb);

    if (pFsm->fsmClosed) {
        PSL_LOG_NOTICE("%s (fsm=%p): FSM is closed: suppressing callbacks",
                       __func__, pFsm);
        return;
    }

    enum PslChanFsmEvtCompletionCbId which = pCb->which;

    if (kPslChanFsmEvtCompletionCbId_none == which) {
        PSL_LOG_DEBUG("%s (fsm=%p): no callback to dispatch", __func__, pFsm);
        return;
    }

    /// Process external callback

    /// So we don't get destroyed while in callback
    (void)psl_chan_fsm_ref(pFsm);

    switch (which) {
    case kPslChanFsmEvtCompletionCbId_none:
        break;

    case kPslChanFsmEvtCompletionCbId_completion:
        {
            which = kPslChanFsmEvtCompletionCbId_none;

            PSL_LOG_DEBUG(
                "%s (fsm=%p/ch=%p): Dispatching 'completion' callback " \
                "to user: PslError=%d (%s)", __func__,
                pFsm, pFsm->channel, (int)pslErr,
                PmSockErrStringFromError(pslErr));

            PSL_ASSERT(pCb->u.completionCb.func);
            pCb->u.completionCb.func((PmSockIOChannel*)pFsm->channel,
                                        pFsm->userSettings.userData,
                                        pslErr);
        }
        break;

    case kPslChanFsmEvtCompletionCbId_connect: /// legacy support
        {
            which = kPslChanFsmEvtCompletionCbId_none;

            GError*     gerr = NULL;
            if (pslErr) {
                gerr = g_error_new(PmSockErrGErrorDomain(), pslErr, "%s",
                                   PmSockErrStringFromError(pslErr));
            }
            PSL_LOG_DEBUG(
                "%s (fsm=%p/ch=%p): Dispatching 'connect' callback " \
                "to legacy user: PslError=%d (%s)", __func__,
                pFsm, pFsm->channel, gerr ? (int)gerr->code : 0,
                gerr ? gerr->message : "success");

            PSL_ASSERT(pCb->u.connectCb.func);
            (void)pCb->u.connectCb.func(pFsm->channel,
                                      pCb->u.connectCb.userData, gerr);
            if (gerr) {g_error_free(gerr);}
        }
        break;

    case kPslChanFsmEvtCompletionCbId_switch: /// legacy support
        {
            which = kPslChanFsmEvtCompletionCbId_none;

            GError* gerr = NULL;
            if (pslErr) {
                gerr = g_error_new(PmSockErrGErrorDomain(), pslErr, "%s",
                                   PmSockErrStringFromError(pslErr));
            }
            PSL_LOG_DEBUG(
                "%s (fsm=%p/ch=%p): Dispatching 'security switch' callback " \
                "to legacy user: switchingToCrypto=%d, PslError code=%d (%s)",
                __func__, pFsm, pFsm->channel, switchingToCrypto,
                gerr ? (int)gerr->code : 0, gerr ? gerr->message : "success");

            PSL_ASSERT(pCb->u.switchCb.func);
            (void)pCb->u.switchCb.func(pFsm->channel, switchingToCrypto,
                                     pCb->u.switchCb.userData, gerr);
            if (gerr) {g_error_free(gerr);}
        }
        break;
    }

    PSL_ASSERT(kPslChanFsmEvtCompletionCbId_none == which);

    /// okay if the FSM gets destroyed now
    psl_chan_fsm_unref(pFsm);
    return;

}//psl_chan_fsm_dispatch_completion_cb



/** ========================================================================
 * =========================================================================
 */
static void
chan_fsm_free(PslChanFsm* const pFsm)
{
    PSL_LOG_INFO("%s (fsm=%p)", __func__, pFsm);

    PSL_ASSERT(pFsm);

    /**
     * If the FSM was successfully started, then we should have been
     * finalized by the channel via psl_chan_fsm_finalize() before 
     * our reference count dropped to zero 
     */
    PSL_ASSERT(!pFsm->fsmStarted || pFsm->fsmFinalized);

    /// Our sock should be closed by the state handlers
    if (pFsm->fd >= 0) {
        PSL_LOG_ERROR("%s: ERROR: pFsm->fd not closed!", __func__);
    }

    if (!pFsm->fsmStarted) {
        chan_fsm_destroy_widgets(pFsm);
    }

    g_free(pFsm);

    PSL_LOG_DEBUGLOW("%s (fsm=%p): LEAVING", __func__, pFsm);
}



/** ========================================================================
 * chan_fsm_destroy_widgets(): Called by chan_fsm_free() and the 
 * PslChanFsmFinalState's kFsmEventEnterScope event handler to 
 * destroy the "widgets" used the the FSM. 
 *  
 * @note See the note about deadlock work-around in 
 *       psl_chan_fsm_finalize() header comments.
 *  
 * @param pFsm 
 * =========================================================================
 */
static void
chan_fsm_destroy_widgets(PslChanFsm* const pFsm)
{
    PSL_LOG_INFO("%s (fsm=%p)", __func__, pFsm);

    PSL_ASSERT(pFsm);

    if (pFsm->fdWatchInfo.fdWatch) {
        /**
         * @note Multi-level GSource arrangements such as ours (a 
         *       GSource that monitors our channel instance and another
         *       GSource owned by the channel instance) are susceptible
         *       to deadlock in glib's gmain code if we're not careful.
         *       We use lots of low-level logging below to help with
         *       debugging should a deadlock be triggered.
         */

        (void)psl_multi_fd_watch_reset(pFsm->fdWatchInfo.fdWatch);

        PSL_LOG_DEBUGLOW("%s (fsm=%p): Detaching multi-fd-watch=%p",
                         __func__, pFsm, pFsm->fdWatchInfo.fdWatch);

        g_source_destroy((GSource*)pFsm->fdWatchInfo.fdWatch);

        PSL_LOG_DEBUGLOW("%s (fsm=%p): Finished detaching multi-fd-watch=%p",
                         __func__, pFsm, pFsm->fdWatchInfo.fdWatch);

        PSL_LOG_DEBUGLOW("%s (fsm=%p): Unref'ing multi-fd-watch=%p",
                         __func__, pFsm, pFsm->fdWatchInfo.fdWatch);

        g_source_unref((GSource*)pFsm->fdWatchInfo.fdWatch);

        PSL_LOG_DEBUGLOW("%s (fsm=%p): Finished unref'ing multi-fd-watch=%p",
                         __func__, pFsm, pFsm->fdWatchInfo.fdWatch);

        pFsm->fdWatchInfo.fdWatch = NULL;
    }

    g_free(pFsm->userSettings.bindAddr.hostStr);
    pFsm->userSettings.bindAddr.hostStr = NULL;
    g_free(pFsm->userSettings.serverAddr.hostStr);
    pFsm->userSettings.serverAddr.hostStr = NULL;

    if (pFsm->userSettings.threadCtx) {
        PmSockThreadCtxUnref(pFsm->userSettings.threadCtx);
        pFsm->userSettings.threadCtx = NULL;
    }

    PSL_LOG_DEBUGLOW("%s (fsm=%p): LEAVING", __func__, pFsm);
}



/** ========================================================================
 * =========================================================================
 */
void
psl_chan_fsm_set_last_error(PslChanFsm*             const fsm,
                            PslChanFsmErrorSource   const errSrc,
                            int                           code)
{
    PSL_ASSERT(fsm);
    PSL_ASSERT(kPslChanFsmErrorSource_errno == errSrc ||
               kPslChanFsmErrorSource_psl == errSrc);
    PSL_ASSERT(code);

    if (kPslChanFsmErrorSource_errno == errSrc) {
        code = psl_err_pslerror_from_errno(code, PSL_ERR_FAILED);
    }

    fsm->lastError = code;
}



/** ========================================================================
 * =========================================================================
 */
PslError
psl_chan_fsm_get_last_error(const PslChanFsm* const fsm)
{
    PSL_ASSERT(fsm);

    return fsm->lastError;
}



/** ========================================================================
 * =========================================================================
 */
void
psl_chan_fsm_reset_last_error(PslChanFsm* const fsm)
{
    PSL_ASSERT(fsm);

    fsm->lastError = 0;
}


/** ========================================================================
 * =========================================================================
 */
void
psl_chan_fsm_set_gerror_from_last_error(
    const PslChanFsm*       const fsm,
    GError**                const pError,
    PslChanFsmGErrorTarget  const targetDomain)
{
    PSL_ASSERT(fsm);


    /// @note We should only be called if an error was indicated
    PSL_ASSERT(fsm->lastError);

    if (!pError) {
        return;
    }

    *pError = NULL;

    switch (targetDomain) {
    case kPslChanFsmGErrorTarget_giochannel:
        *pError = psl_err_giochangerror_from_pslerror(fsm->lastError);
        break;

    case kPslChanFsmGErrorTarget_psl:
        *pError = psl_err_pslgerror_from_pslerror(fsm->lastError);
        break;
    }

    PSL_ASSERT(*pError);
}



/** ========================================================================
 * =========================================================================
 */
const char*
psl_chan_fsm_str_from_giostatus(GIOStatus const giostatus)
{
    switch (giostatus) {
    case G_IO_STATUS_ERROR:     return "G_IO_STATUS_ERROR";
        break;
    case G_IO_STATUS_NORMAL:    return "G_IO_STATUS_NORMAL";
        break;
    case G_IO_STATUS_EOF:       return "G_IO_STATUS_EOF";
        break;
    case G_IO_STATUS_AGAIN:     return "G_IO_STATUS_AGAIN";
        break;
    }

    PSL_LOG_ERROR("ERROR: UNKNOWN GIOStatus value: %ld", (long)giostatus);
    return "ERROR: UNKNOWN GIOStatus value (see log)";
}



/** ========================================================================
 * PslMultiFdWatchSourceCb callback from the multi-fd watch
 * source
 * 
 * @see PslMultiFdWatchSourceCb for arg info
 * 
 * @param userData
 * @param pollrecs
 * @param numrecs
 * 
 * @return gboolean
 * 
 * =========================================================================
 */
static gboolean
chan_fsm_fd_watch_cb(gpointer const userData, const PslMultiFdPollRec* pollrecs,
                     int const numrecs)
{
    PslChanFsm* const pFsm = (PslChanFsm*)userData;

    PSL_ASSERT(!pFsm->fdWatchInfo.inFdWatchCb);

    pFsm->fdWatchInfo.inFdWatchCb = true;

    PslSmeEventStatus const status =
        psl_chan_fsm_evt_dispatch_FD_WATCH(pFsm, pollrecs, numrecs);

    if (kPslSmeEventStatus_errorCatchAll == status ||
        kPslSmeEventStatus_notHandled == status) {
        PSL_LOG_ERROR("%s (fsm=%p): ERROR: FD_WATCH event fell through",
                      __func__, pFsm);
    }

    /// Process external callbacks
    struct PslChanFsmFdWatchCompletion* const cb = &pFsm->fdWatchInfo.completionCb;

    if (kPslChanFsmEvtCompletionCbId_none != cb->cb.which) {

        /// So we don't get destroyed while in callbacks
        (void)psl_chan_fsm_ref(pFsm);

        psl_chan_fsm_dispatch_completion_cb(pFsm, &cb->cb, cb->pslErr,
                                            cb->switchingToCrypto);

        cb->cb.which = kPslChanFsmEvtCompletionCbId_none;

        pFsm->fdWatchInfo.inFdWatchCb = false;

        /// okay if the FSM gets destroyed now
        psl_chan_fsm_unref(pFsm);
        return true;
    }//if user callback scheduled

    else {
        pFsm->fdWatchInfo.inFdWatchCb = false;
    }

    return true; ///< true, so the GSource won't get detached from our gmain ctx
}//chan_fsm_fd_watch_cb




/** ===========================================================================
 *                            STATE HANDLERS
 * ============================================================================
 */

/** ========================================================================
 * =========================================================================
 */
static PslSmeEventStatus
chan_fsm_alive_state_handler(PslChanFsmAliveState*      const pState,
                             PslChanFsm*                const pFsm,
                             PslSmeEventId              const evtId,
                             const PslChanFsmEvtArg*    const evtArg)
{   
    switch (evtId) 
    {
    case kFsmEventEnterScope:
    case kFsmEventExitScope:
    case kFsmEventBegin:
        return kPslSmeEventStatus_success;
        break;

    case PSL_CHAN_FSM_EVT_CLOSE:
        psl_chan_fsm_goto_closed_state(pFsm);
        return kPslSmeEventStatus_success;
        break;

    case PSL_CHAN_FSM_EVT_FINALIZE:
        psl_chan_fsm_goto_final_state(pFsm);
        return kPslSmeEventStatus_success;
        break;

    case PSL_CHAN_FSM_EVT_CHECK_IO:
        return psl_chan_fsm_evt_make_simple_CHECK_IO_response(
            &evtArg->checkIO, kPslChanFsmEvtIOReadyHint_notReady,
            PSL_INVALID_FD);
        break;

    default:
        break;
    }

    if (evtId >= kFsmEventFirstUserEvent) {
        PSL_LOG_ERROR(
            "%s (%p): %s.%s: ERROR: Operation not allowed: evtId=%d",
            __func__, pFsm, FsmDbgPeekMachineName(&pFsm->base.base),
            FsmDbgPeekStateName(&pState->base.base), evtId);

        psl_chan_fsm_set_last_error(pFsm, kPslChanFsmErrorSource_psl,
                                    PSL_ERR_NOT_ALLOWED);
        return kPslSmeEventStatus_errorCatchAll;
    }
    else {
        return kPslSmeEventStatus_success;
    }
}//chan_fsm_alive_state_handler



/** ========================================================================
 * =========================================================================
 */
static PslSmeEventStatus
chan_fsm_init_state_handler(PslChanFsmInitState*    const pState,
                            PslChanFsm*             const pFsm,
                            PslSmeEventId           const evtId,
                            const PslChanFsmEvtArg* const evtArg)
{   
    switch (evtId) 
    {
    case kFsmEventEnterScope:
    case kFsmEventExitScope:
    case kFsmEventBegin:
        return kPslSmeEventStatus_success;
        break;

    case PSL_CHAN_FSM_EVT_CONNECT:
        if (AF_UNSPEC == pFsm->userSettings.serverAddr.addrFamily && pFsm->fd < 0) {
            PSL_LOG_ERROR("%s (fsm=%p): ERROR: PSL_CHAN_FSM_EVT_CONNECT " \
                          "failed: connect address not set", __func__, pFsm);

            psl_chan_fsm_set_last_error(pFsm, kPslChanFsmErrorSource_psl,
                                        PSL_ERR_BAD_SERV_ADDR);
            return kPslSmeEventStatus_error;
        }


        if (pFsm->fd < 0) {
            psl_chan_fsm_goto_plain_lookup_state(pFsm, &evtArg->connect.data);
        }
        else {
            static const struct PslChanFsmEvtInetAddrText addrText = {
                .family = AF_UNSPEC
                };
            psl_chan_fsm_goto_plain_conn_state(pFsm, &evtArg->connect.data, &addrText);
        }
        return kPslSmeEventStatus_success;
        break;

    case PSL_CHAN_FSM_EVT_SET_CONN_FD:
        {
            const struct PslChanFsmEvtArgSetConnFD* const arg =
                &evtArg->setConnFD;

            PSL_ASSERT(arg->fd >= 0);

            if (AF_UNSPEC != pFsm->userSettings.serverAddr.addrFamily) {
                PSL_LOG_ERROR("%s (fsm=%p): SET_CONN_FD ERROR: " \
                              "not allowed when server address is set",
                              __func__, pFsm);
                return kPslSmeEventStatus_passToParent;
            }

            if (AF_UNSPEC != pFsm->userSettings.bindAddr.addrFamily) {
                PSL_LOG_ERROR("%s (fsm=%p): SET_CONN_FD ERROR: " \
                              "not allowed when bind address is set",
                              __func__, pFsm);
                return kPslSmeEventStatus_passToParent;
            }

            if (pFsm->fd >= 0) {
                PSL_LOG_ERROR("%s (fsm=%p): SET_CONN_FD ERROR: connected " \
                              "file descriptor was already set",
                              __func__, pFsm);
                return kPslSmeEventStatus_passToParent;
            }

            pFsm->fd = arg->fd;
            pFsm->userSettings.fdIsUserProvided = true;
            pFsm->userSettings.fdOpts = arg->opts;

            return kPslSmeEventStatus_success;
            break;
        }

    case PSL_CHAN_FSM_EVT_SET_SERVER:
        {
            const struct PslChanFsmEvtArgSetServer* const arg =
                &evtArg->setServer;

            if (pFsm->fd >= 0) {
                PSL_LOG_ERROR("%s (fsm=%p): SET_SERVER ADDR ERROR: not " \
                              "allowed when connected file descriptor is set",
                              __func__, pFsm);
                return kPslSmeEventStatus_passToParent;
            }

            if (AF_UNSPEC != pFsm->userSettings.serverAddr.addrFamily) {
                PSL_LOG_ERROR("%s (fsm=%p): SET_SERVER ADDR ERROR: " \
                              "server address was already set",
                              __func__, pFsm);
                return kPslSmeEventStatus_passToParent;
            }

            PSL_LOG_DEBUG("%s (fsm=%p): SET_SERVER ADDR: server: '%s:%d'/af=%d",
                          __func__, pFsm,
                          PSL_LOG_OBFUSCATE_STR(arg->hostStr),
                          (int)arg->port,
                          (int)arg->addrFamily);

            pFsm->userSettings.serverAddr.addrFamily = arg->addrFamily;
            pFsm->userSettings.serverAddr.port = arg->port;
            pFsm->userSettings.serverAddr.hostStr = g_strdup(arg->hostStr);
            PSL_ASSERT(pFsm->userSettings.serverAddr.hostStr);
        }
        return kPslSmeEventStatus_success;
        break;

    case PSL_CHAN_FSM_EVT_SET_SOCK_BIND:
        {
            const struct PslChanFsmEvtArgSetSockBind* const arg =
                &evtArg->setSockBind;

            if (pFsm->fd >= 0) {
                PSL_LOG_ERROR("%s (fsm=%p): SET_SOCK_BIND ERROR: not " \
                              "allowed when connected file descriptor is set",
                              __func__, pFsm);
                return kPslSmeEventStatus_passToParent;
            }

            if (AF_UNSPEC != pFsm->userSettings.bindAddr.addrFamily) {
                PSL_LOG_ERROR("%s (fsm=%p): SET_SOCK_BIND ERROR: " \
                              "socket bind address was already set",
                              __func__, pFsm);
                return kPslSmeEventStatus_passToParent;
            }

            PSL_LOG_DEBUG("%s (fsm=%p): SET_SOCK_BIND: local addr: '%s:%d'/af=%d",
                          __func__, pFsm,
                          PSL_LOG_MAKE_SAFE_STR(arg->ipAddrStr),
                          (int)arg->port,
                          (int)arg->addrFamily);

            pFsm->userSettings.bindAddr.addrFamily = arg->addrFamily;
            pFsm->userSettings.bindAddr.port = arg->port;
            pFsm->userSettings.bindAddr.hostStr = g_strdup(arg->ipAddrStr);
            PSL_ASSERT(!arg->ipAddrStr || pFsm->userSettings.bindAddr.hostStr);
        }
        return kPslSmeEventStatus_success;
        break;

    default:
        break; ///< allow default processing by parent
    }

    return kPslSmeEventStatus_passToParent;
}//chan_fsm_init_state_handler



/** ========================================================================
 * =========================================================================
 */
static PslSmeEventStatus
chan_fsm_closed_state_handler(PslChanFsmClosedState*    const pState,
                              PslChanFsm*               const pFsm,
                              PslSmeEventId             const evtId,
                              const PslChanFsmEvtArg*   const evtArg)
{   
    switch (evtId) 
    {
    case kFsmEventEnterScope:
        if (pFsm->fsmClosed) {
            PSL_LOG_ERROR("%s (fsm=%p): ERROR: entering CLOSED state *again*",
                          __func__, pFsm);
        }
        if (pFsm->fd >= 0 &&
            !(pFsm->userSettings.fdOpts & kPmSockFileDescOpt_doNotClose)) {
            shutdown(pFsm->fd, SHUT_RDWR);
            if (0 != close(pFsm->fd)) {
                const int   savederrno = errno;
                PSL_LOG_ERROR(
                    "%s (fsm=%p): ERROR closing comms fd: fd=%d, errno=%d (%s)",
                    __func__, pFsm, pFsm->fd, savederrno,
                    strerror(savederrno));
            }
        }
        pFsm->fd = PSL_CHAN_FSM_CLOSED_FD_VALUE;
        pFsm->fsmClosed = true;
        return kPslSmeEventStatus_success;
        break;

    case kFsmEventExitScope:
        return kPslSmeEventStatus_success;
        break;

    case kFsmEventBegin:
        (void)psl_multi_fd_watch_reset(pFsm->fdWatchInfo.fdWatch);
        return kPslSmeEventStatus_success;
        break;

    default:
        break; ///< allow default processing by parent
    }

    return kPslSmeEventStatus_passToParent;
}//chan_fsm_closed_state_handler



/** ========================================================================
 * =========================================================================
 */
static PslSmeEventStatus
chan_fsm_final_state_handler(PslChanFsmFinalState*      const pState,
                             PslChanFsm*                const pFsm,
                             PslSmeEventId              const evtId,
                             const PslChanFsmEvtArg*    const evtArg)
{   
    switch (evtId) 
    {
    case kFsmEventEnterScope:
        PSL_ASSERT(pFsm->fsmClosed); ///< we should have been closed first
        chan_fsm_destroy_widgets(pFsm);
        pFsm->fsmFinalized = true;
        /// FALLTHROUGH
    case kFsmEventExitScope:
        /// FALLTHROUGH
    case kFsmEventBegin:
        return kPslSmeEventStatus_success;
        break;

    default:
        if (evtId >= kFsmEventFirstUserEvent) {
            /// We don't expect any other events in the final state, since
            /// we're supposed to be an ephemeral state used only during
            /// destruction of the FSM instance.
            PSL_LOG_FATAL("%s (fsm=%p): ERROR: %s.%s received unexpected " \
                          "event %d", __func__, pFsm,
                          FsmDbgPeekMachineName(&pFsm->base.base),
                          FsmDbgPeekStateName(&pState->base.base),
                          evtId);
            PSL_ASSERT(false && "unexpected event in 'final' state");
        }
        break;
    }

    return kPslSmeEventStatus_passToParent;
}
