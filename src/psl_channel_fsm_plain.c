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
 * @file psl_channel_fsm_plain.c
 * @ingroup psl_internal 
 * 
 * @brief  Implementation of Plaintext mode states for the
 *         PmSockIOChannel Finite State Machine.
 * 
 * *****************************************************************************
 */
#include "psl_build_config.h"

#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>

#include <glib.h>

#include "palmsocket.h"
#include "palmhostlookup.h"

#include "psl_common.h"
#include "psl_log.h"
#include "psl_error_utils.h"
#include "psl_multi_fd_watch.h"
#include "psl_thread_context.h"

#include "psl_channel_fsm_events.h"
#include "psl_channel_fsm_plain.h"
#include "psl_channel_fsm.h"
#include "psl_channel_fsm_main.h"
#include "psl_inet_utils.h"



static PSL_CHAN_FSM_STATE_HANDLER_DECLARE(plain_mode_state_handler,
                                          PslChanFsmPlainModeState);

static PSL_CHAN_FSM_STATE_HANDLER_DECLARE(plain_fail_state_handler,
                                          PslChanFsmPlainFailState);

static PSL_CHAN_FSM_STATE_HANDLER_DECLARE(plain_lookup_state_handler,
                                          PslChanFsmPlainLookupState);

static PSL_CHAN_FSM_STATE_HANDLER_DECLARE(plain_conn_state_handler,
                                          PslChanFsmPlainConnState);

static PSL_CHAN_FSM_STATE_HANDLER_DECLARE(plain_tcp_state_handler,
                                          PslChanFsmPlainTCPState);

static PSL_CHAN_FSM_STATE_HANDLER_DECLARE(plain_shut_state_handler,
                                          PslChanFsmPlainShutState);


/**
 * Host lookup completion callback.  It's guaranteed to be
 * called from the scope of gmain dispatch, so it's safe to
 * dispatch an FSM event from this callback.
 * 
 * @see PmSockHostLookupCb for description of args.
 * 
 * @param userData
 * @param session
 * @param result
 * @param errorCode
 */
static void
plain_host_lookup_cb(void*                      userData,
                     PmSockHostLookupSession*   session,
                     const struct hostent*      result,
                     PslError                   errorCode);

/**
 * Performs a plaintext 'read' operation conforming to glib's
 * GIOFuncs::io_read() semantics
 * 
 * @param pFsm
 * @param arg
 * 
 * @return PslSmeEventStatus
 */
static PslSmeEventStatus
plain_handle_READ(PslChanFsm*                           pFsm,
                  const struct PslChanFsmEvtArgRead*    arg);

/**
 * Performs a plaintext 'write' operation conforming to glib's
 * GIOFuncs::io_write() semantics
 * 
 * @param pFsm
 * @param arg
 * 
 * @return PslSmeEventStatus
 */
static PslSmeEventStatus
plain_handle_WRITE(PslChanFsm*                          pFsm,
                   const struct PslChanFsmEvtArgWrite*  arg);


/**
 * Shuts down the channel's socket in the requested direction
 * 
 * @param pFsm
 * @param how SHUT_RD, SHUT_WR, or SHUT_RDWR from sys/socket.h
 * 
 * @return PslError
 */
static PslError
plain_shut_sock(PslChanFsm* pFsm,
                int         how);


/**
 * Open a socket, configure it as non-blocking, and bind it 
 *  
 * @param pFsm
 * @param sockFamily AF_INET or AF_INET6
 * @param sock Non-NULL location for returning socket; undefined
 *             on error
 * @return PslError
 */
static PslError
plain_make_and_config_sock(PslChanFsm* pFsm,
                           int         sockFamily,
                           int*        sock);


/** ===========================================================================
 *                            FUNCTIONS
 * ============================================================================
 */


/** ========================================================================
 * =========================================================================
 */
void
psl_chan_fsm_plain_init(PslChanFsm* const fsm, PslSmeStateBase* parentState)
{

    /// Initialize the states
    PslChanFsmPlainModeState*   const plainModeState =
        (PslChanFsmPlainModeState*)psl_chan_fsm_get_plain_mode_state(fsm);

    psl_sme_init_state(
        &plainModeState->base,
        (PslSmeStateHandlerFnType*)&plain_mode_state_handler,
        "PLAIN_MODE");

    psl_sme_init_state(
        &plainModeState->failState.base,
        (PslSmeStateHandlerFnType*)&plain_fail_state_handler,
        "PLAIN_FAIL");

    psl_sme_init_state(
        &plainModeState->lookupState.base,
        (PslSmeStateHandlerFnType*)&plain_lookup_state_handler,
        "LOOKUP");

    psl_sme_init_state(
        &plainModeState->connState.base,
        (PslSmeStateHandlerFnType*)&plain_conn_state_handler,
        "PLAIN_CONN");

    psl_sme_init_state(
        &plainModeState->tcpState.base,
        (PslSmeStateHandlerFnType*)&plain_tcp_state_handler,
        "PLAIN_TCP");

    psl_sme_init_state(
        &plainModeState->shutState.base,
        (PslSmeStateHandlerFnType*)&plain_shut_state_handler,
        "PLAIN_SHUT");


    /// Add our state to the FSM
    psl_sme_insert_state(
        &fsm->base,
        &plainModeState->base,
        parentState);

    psl_sme_insert_state(
        &fsm->base,
        &plainModeState->failState.base,
        &plainModeState->base);

    psl_sme_insert_state(
        &fsm->base,
        &plainModeState->lookupState.base,
        &plainModeState->base);

    psl_sme_insert_state(
        &fsm->base,
        &plainModeState->connState.base,
        &plainModeState->base);

    psl_sme_insert_state(
        &fsm->base,
        &plainModeState->tcpState.base,
        &plainModeState->base);

    psl_sme_insert_state(
        &fsm->base,
        &plainModeState->shutState.base,
        &plainModeState->base);

}// psl_chan_fsm_plain_init


/** ========================================================================
 * =========================================================================
 */
PslSmeEventStatus
psl_chan_fsm_plain_shut_sock_and_goto_shut_on_success(PslChanFsm*   const pFsm,
                                                      int           const how)
{
    PslError const pslErr = plain_shut_sock(pFsm, how);

    if (!pslErr) {
        psl_chan_fsm_goto_plain_shut_state(pFsm);
        return kPslSmeEventStatus_success;
    }
    else {
        psl_chan_fsm_set_last_error(pFsm, kPslChanFsmErrorSource_psl,
                                    pslErr);
        return kPslSmeEventStatus_error;
    }
}



/** ========================================================================
 * =========================================================================
 */
static PslSmeEventStatus
plain_mode_state_handler(PslChanFsmPlainModeState* const pState,
                         PslChanFsm*               const pFsm,
                         PslSmeEventId             const evtId,
                         const PslChanFsmEvtArg*   const evtArg)
{   
    switch (evtId) 
    {
    case kFsmEventEnterScope:
    case kFsmEventExitScope:
    case kFsmEventBegin:
        return kPslSmeEventStatus_success;
        break;

    default:
        break; ///< allow default processing by parent
    }

    return kPslSmeEventStatus_passToParent;
}



/** ========================================================================
 * =========================================================================
 */
static PslSmeEventStatus
plain_fail_state_handler(PslChanFsmPlainFailState* const pState,
                         PslChanFsm*               const pFsm,
                         PslSmeEventId             const evtId,
                         const PslChanFsmEvtArg*   const evtArg)
{   
    switch (evtId) 
    {
    case kFsmEventEnterScope:
    case kFsmEventExitScope:
        return kPslSmeEventStatus_success;
        break;

    case kFsmEventBegin:
        pState->arg = evtArg->begin.plainFail;
        PSL_ASSERT(pState->arg.pslError);
        (void)psl_multi_fd_watch_reset(pFsm->fdWatchInfo.fdWatch);
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
        break; ///< allow default processing by parent
    }

    return kPslSmeEventStatus_passToParent;
}



/** ========================================================================
 * =========================================================================
 */
static PslSmeEventStatus
plain_lookup_state_handler(PslChanFsmPlainLookupState* const pState,
                           PslChanFsm*                 const pFsm,
                           PslSmeEventId               const evtId,
                           const PslChanFsmEvtArg*     const evtArg)
{   
    switch (evtId) 
    {
    case kFsmEventEnterScope:
        pState->lookupSes = NULL;
        return kPslSmeEventStatus_success;
        break;

    case kFsmEventExitScope:
        if (pState->lookupSes) {
            PmSockHostLookupDestroy(pState->lookupSes);
        }
        if (psl_chan_fsm_evt_is_crypto_conn_kind(pState->arg.common.connKind)) {
            PmSockSSLCtxUnref(pState->arg.common.u.crypto.sslCtx);
        }
        return kPslSmeEventStatus_success;
        break;

    case kFsmEventBegin:
        {
            pState->arg = evtArg->begin.plainLookup;

            /**
             * @note The following calls should only fail due to programming
             *       error or if we're out of memory, so the assers should
             *       be appropriate.
             * 
             * @todo look into replacing
             *       the following asserts with a more gentle solution
             *       (perhaps, we should enqueue an event so that we can
             *       make a transition to the error state)
             */
            PslError pslerr = PmSockHostLookupNew(
                &pState->lookupSes,
                pFsm->userSettings.serverAddr.hostStr,
                pFsm->userSettings.serverAddr.addrFamily,
                pFsm,
                &plain_host_lookup_cb,
                "PSL_FSM",
                pFsm->userSettings.threadCtx->gmainCtx);
            PSL_ASSERT(!pslerr && "PmSockHostLookupNew");

            pslerr = PmSockHostLookupStart(pState->lookupSes);
            PSL_ASSERT(!pslerr && "PmSockHostLookupStart");
        }
        return kPslSmeEventStatus_success;
        break;

    case PSL_CHAN_FSM_EVT_LOOKUP_DONE:
        {
            const struct PslChanFsmEvtArgLookupDone*    const arg =
                &evtArg->lookupDone;

            if (arg->errorCode) {
                psl_chan_fsm_set_last_error(pFsm, kPslChanFsmErrorSource_psl,
                                            arg->errorCode);
                psl_chan_fsm_goto_plain_fail_state(pFsm, arg->errorCode);
                return kPslSmeEventStatus_error;
            }

            char* const * const addrs = arg->hosts->h_addr_list;

            struct PslChanFsmEvtInetAddrText addrText;

            addrText.family = arg->hosts->h_addrtype;

            if (!inet_ntop(arg->hosts->h_addrtype, addrs[0],
                           addrText.addr, sizeof(addrText.addr))) {
                int const saverrno = errno;
                PSL_LOG_ERROR("%s (fsm=%p): ERROR: inet_ntop failed; " \
                              "errno=%d (%s)", __func__, pFsm, saverrno,
                              strerror(saverrno));
                psl_chan_fsm_set_last_error(pFsm, kPslChanFsmErrorSource_psl,
                                            PSL_ERR_BAD_SERV_ADDR);
                psl_chan_fsm_goto_plain_fail_state(pFsm, PSL_ERR_BAD_SERV_ADDR);
                return kPslSmeEventStatus_error;
            }

            psl_chan_fsm_goto_plain_conn_state(pFsm, &pState->arg.common, &addrText);
        }
        return kPslSmeEventStatus_success;
        break;

    default:
        break; ///< allow default processing by parent
    }

    return kPslSmeEventStatus_passToParent;
}// plain_lookup_state_handler



/** ========================================================================
 * =========================================================================
 */
static void
plain_host_lookup_cb(void*                      const userData,
                     PmSockHostLookupSession*   const session,
                     const struct hostent*      const hosts,
                     PslError                   const errorCode)
{
    /**
     * @note We're guaranteed to be called from the scope of gmain
     *       dispatch, so it's safe to dispatch an FSM event from
     *       this callback... and it's also safe to call the user's
     *       callback without risking run-to-completion violation of
     *       our FSM.
     */

    PslChanFsm* const pFsm = (PslChanFsm*)userData;
    PslChanFsmPlainLookupState* const pState =
        (PslChanFsmPlainLookupState*)psl_chan_fsm_get_plain_lookup_state(pFsm);

    if (!errorCode) {
        PSL_ASSERT(hosts);
        PSL_ASSERT(AF_INET == hosts->h_addrtype ||
                   AF_INET6 == hosts->h_addrtype);
    }

    /**
     * @note We pass result to FSM before emitting the external
     *       error callback (if any) so that the FSM will be in the
     *       desired error state by the time of the callback.
     */
    (void)psl_chan_fsm_evt_dispatch_LOOKUP_DONE(pFsm, errorCode, hosts);

    /**
     * If lookup failed, let the legacy user know
     * 
     * @note The user may call reentrantly from its callback to
     *       destroy our palmsocket channel instance, and we MUST
     *       handle it gracefully
     */

    if (errorCode) {
        PSL_LOG_ERROR(
            "%s(fsm=%p): ERROR: Requested server not found: PslError=%d (%s)",
            __func__, pFsm, errorCode, PmSockErrStringFromError(errorCode));

        psl_chan_fsm_dispatch_completion_cb(
            pFsm, &pState->arg.common.cb, errorCode,
            psl_chan_fsm_evt_is_crypto_conn_kind(pState->arg.common.connKind));
        
        /// @note The channel/FSM may have been destroyed or closed
        ///       during callback dispatch
        return;
    }
    return;
}// plain_host_lookup_cb



/** ========================================================================
 * =========================================================================
 */
static PslSmeEventStatus
plain_conn_state_handler(PslChanFsmPlainConnState* const pState,
                         PslChanFsm*               const pFsm,
                         PslSmeEventId             const evtId,
                         const PslChanFsmEvtArg*   const evtArg)
{   
    switch (evtId) 
    {
    case kFsmEventEnterScope:
        pState->failPslErr = 0;
        return kPslSmeEventStatus_success;
        break;

    case kFsmEventExitScope:
        /// We use it, so clean up
        (void)psl_multi_fd_watch_reset(pFsm->fdWatchInfo.fdWatch);
        if (psl_chan_fsm_evt_is_crypto_conn_kind(pState->arg.common.connKind)) {
            PmSockSSLCtxUnref(pState->arg.common.u.crypto.sslCtx);
        }
        return kPslSmeEventStatus_success;
        break;

    case kFsmEventBegin:
        {
            pState->arg = evtArg->begin.plainConn;

            (void)psl_multi_fd_watch_reset(pFsm->fdWatchInfo.fdWatch);

            if (pFsm->userSettings.fdIsUserProvided) {
                PSL_LOG_INFO("%s (fsm=%p): Using user-provided, connected fd=%d",
                             __func__, pFsm, pFsm->fd);

                /// We have a user-provided, connected socket: only need
                /// to config it for non-blocking I/O
                pState->failPslErr = psl_inet_make_fd_non_blocking(
                    pFsm->fd, "fsm", pFsm);
            }
            else {
                PSL_LOG_INFO("%s (fsm=%p): Connecting to server '%s:%d'",
                             __func__, pFsm,
                             PSL_LOG_OBFUSCATE_STR(pState->arg.addrText.addr),
                             (int)pFsm->userSettings.serverAddr.port);

                /// Create, bind, and configure socket for non-blocking use
                pState->failPslErr = plain_make_and_config_sock(
                    pFsm, pState->arg.addrText.family, &pFsm->fd);


                /// Start connection-establishment (non-blocking)
                if (!pState->failPslErr) {
                    pState->failPslErr = psl_inet_connect_sock(
                        pFsm->fd, pState->arg.addrText.family,
                        pState->arg.addrText.addr,
                        pFsm->userSettings.serverAddr.port,
                        "fsm", pFsm);
                }
            }

            if (pState->failPslErr) {
                /// Schedule a timer so we can notify user and go to the
                /// failed state
                (void)psl_multi_fd_watch_set_poll_timeout(
                    pFsm->fdWatchInfo.fdWatch, 0);
            }
            else {    
                /// Get notified when the socket finishes connecting (or fails to)
                (void)psl_multi_fd_watch_add_or_update_fd(pFsm->fdWatchInfo.fdWatch,
                                                          pFsm->fd, G_IO_OUT);
            }
        }
        return kPslSmeEventStatus_success; ///< always success for begin
        break;

    case PSL_CHAN_FSM_EVT_FD_WATCH:
        {
            /// Don't need it again here
            (void)psl_multi_fd_watch_reset(pFsm->fdWatchInfo.fdWatch);

            const struct PslChanFsmEvtArgFdWatch* const arg = &evtArg->fdWatch;

            /// Check connection status
            if (!pState->failPslErr) {
                /// We should only get called when G_IO_OUT (or one of the G_IO
                /// error bits) is indicated (besides the 'pState->failPslErr'
                /// case)
                PSL_ASSERT(1 == arg->numrecs && arg->pollrecs[0].fd == pFsm->fd);

                if (!pFsm->userSettings.fdIsUserProvided) {
                    /// Check connection completion status
                    int soerror = 0;
                    socklen_t solen = sizeof(soerror);
                    int rc = getsockopt(pFsm->fd, SOL_SOCKET, SO_ERROR,
                                        &soerror, &solen);
                    PSL_ASSERT(0 == rc);

                    pState->failPslErr =
                        psl_err_pslerror_from_connect_errno(soerror);

                    if (pState->failPslErr) {
                        PSL_LOG_ERROR(
                            "%s (fsm=%p): ERROR: connection attempt " \
                            "failed: SO_ERROR=%d (%s), PslError=%d (%s)",
                            __func__, pFsm, soerror, strerror(soerror),
                            pState->failPslErr,
                            PmSockErrStringFromError(pState->failPslErr));
                    }
                }

                if (!pState->failPslErr) {
                    if (0 == (arg->pollrecs[0].indEvents & G_IO_OUT) ||
                        0 != (arg->pollrecs[0].indEvents & PSL_FAIL_GIOCONDITIONS)) {
                        PSL_LOG_ERROR(
                            "%s (fsm=%p): ERROR: connection attempt " \
                            "failed: glib poll indicates GIOCondition=0x%lX",
                            __func__, pFsm,
                            (unsigned long)arg->pollrecs[0].indEvents);

                        pState->failPslErr = PSL_ERR_TCP_CONNECT;
                    }
                }

            }//check connection status


            /// Is it time for completion callback?
            if (pState->failPslErr ||
                psl_chan_fsm_evt_is_plain_conn_kind(pState->arg.common.connKind)) {
                /// @note The callback will be emitted after state transition
                psl_chan_fsm_sched_fdwatch_completion_cb(
                    pFsm,
                    &pState->arg.common.cb,
                    pState->failPslErr,
                    psl_chan_fsm_evt_is_crypto_conn_kind(pState->arg.common.connKind));
            }

            /// Transition to failed-connection state on error
            if (pState->failPslErr) {
                psl_chan_fsm_set_last_error(pFsm, kPslChanFsmErrorSource_psl,
                                            pState->failPslErr);
                psl_chan_fsm_goto_plain_fail_state(pFsm, pState->failPslErr);
                return kPslSmeEventStatus_error;
            }

            /// Transition to plaintext state if plaintext mode was the goal
            else if (psl_chan_fsm_evt_is_plain_conn_kind(pState->arg.common.connKind)) {
                psl_chan_fsm_goto_plain_tcp_state(pFsm);
            }

            /// Otherwise transition to crypto-connect state to set up SSL/TLS
            else {
                psl_chan_fsm_goto_crypto_conn_state(pFsm, &pState->arg.common);
            }
        }
        return kPslSmeEventStatus_success;
        break;

    default:
        break; ///< allow default processing by parent
    }

    return kPslSmeEventStatus_passToParent;
}// plain_conn_state_handler



/** ========================================================================
 * =========================================================================
 */
static PslSmeEventStatus
plain_tcp_state_handler(PslChanFsmPlainTCPState*   const pState,
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

    case PSL_CHAN_FSM_EVT_CHECK_IO:
        return psl_chan_fsm_evt_make_simple_CHECK_IO_response(
            &evtArg->checkIO, kPslChanFsmEvtIOReadyHint_poll, pFsm->fd);
        break;

    case PSL_CHAN_FSM_EVT_CONNECT:
        if (psl_chan_fsm_evt_is_plain_conn_kind(evtArg->connect.data.connKind)) {
            PSL_LOG_ERROR("%s (fsm=%p): ERROR: PSL_CHAN_FSM_EVT_CONNECT-plain " \
                          "failed: already in plaintext mode", __func__, pFsm);
            return kPslSmeEventStatus_passToParent;
        }

        psl_chan_fsm_goto_crypto_conn_state(pFsm, &evtArg->connect.data);
        return kPslSmeEventStatus_success;
        break;

    case PSL_CHAN_FSM_EVT_READ:
        return plain_handle_READ(pFsm, &evtArg->read);
        break;

    case PSL_CHAN_FSM_EVT_WRITE:
        return plain_handle_WRITE(pFsm, &evtArg->write);
        break;

    case PSL_CHAN_FSM_EVT_SHUT_SOCK:
        return psl_chan_fsm_plain_shut_sock_and_goto_shut_on_success(
            pFsm, evtArg->shutSock.how);
        break;

    default:
        break; ///< allow default processing by parent
    }

    return kPslSmeEventStatus_passToParent;
}// plain_tcp_state_handler



/** ========================================================================
 * =========================================================================
 */
static PslSmeEventStatus
plain_shut_state_handler(PslChanFsmPlainShutState* const pState,
                         PslChanFsm*               const pFsm,
                         PslSmeEventId             const evtId,
                         const PslChanFsmEvtArg*   const evtArg)
{
    switch (evtId) 
    {
    case kFsmEventEnterScope:
    case kFsmEventExitScope:
    case kFsmEventBegin:
        return kPslSmeEventStatus_success;
        break;

    case PSL_CHAN_FSM_EVT_CHECK_IO:
        return psl_chan_fsm_evt_make_simple_CHECK_IO_response(
            &evtArg->checkIO, kPslChanFsmEvtIOReadyHint_poll, pFsm->fd);
        break;

    case PSL_CHAN_FSM_EVT_READ:
        return plain_handle_READ(pFsm, &evtArg->read);
        break;

    case PSL_CHAN_FSM_EVT_WRITE:
        return plain_handle_WRITE(pFsm, &evtArg->write);
        break;

    case PSL_CHAN_FSM_EVT_SHUT_SOCK:
        {
            PslError const pslErr = plain_shut_sock(
                pFsm, evtArg->shutSock.how);
            if (pslErr) {
                psl_chan_fsm_set_last_error(pFsm, kPslChanFsmErrorSource_psl,
                                            pslErr);
                return kPslSmeEventStatus_error;
            }
        }
        return kPslSmeEventStatus_success;
        break;

    default:
        break; ///< allow default processing by parent
    }

    return kPslSmeEventStatus_passToParent;
}// plain_shut_state_handler



/** ========================================================================
 * =========================================================================
 */
static PslSmeEventStatus
plain_handle_READ(PslChanFsm*                          const pFsm,
                  const struct PslChanFsmEvtArgRead*   const arg)
{
    PSL_LOG_DEBUG("%s (fsm=%p): requested cnt=%ld",
                  __func__, pFsm, (long)arg->cnt);

    PslSmeEventStatus evtStatus = kPslSmeEventStatus_success;
    size_t const maxRead = (arg->cnt <= SSIZE_MAX) ? arg->cnt : SSIZE_MAX;

    ssize_t size;

    do {
        size = read(pFsm->fd, arg->buf, maxRead);
    } while (size < 0 && EINTR == errno);

    if (size < 0) {
        int const savederrno = errno;

        *arg->pNumRead = 0;

        switch (savederrno) {
        case EAGAIN:
            *arg->pGioStatus = G_IO_STATUS_AGAIN;
            break;

        default:
            psl_chan_fsm_set_last_error(pFsm, kPslChanFsmErrorSource_errno,
                                        savederrno);
            *arg->pGioStatus = G_IO_STATUS_ERROR;
            PSL_LOG_ERROR("%s (fsm=%p): read(%ld) failed with errno=%d (%s)",
                          __func__, pFsm, (long)maxRead, savederrno,
                          strerror(savederrno));
            evtStatus = kPslSmeEventStatus_error;
            break;
        }
    }

    else {
        *arg->pNumRead = size;

        if (size > 0 || arg->cnt == 0) {
            *arg->pGioStatus = G_IO_STATUS_NORMAL;
        }
        else {
            *arg->pGioStatus = G_IO_STATUS_EOF;
        }
    }


    PSL_LOG_DEBUG(
        "%s (fsm=%p): completed with: GIOStatus=%s, numRead=%u, evtStatus=%d",
        __func__, pFsm, psl_chan_fsm_str_from_giostatus(*arg->pGioStatus),
        (unsigned)*arg->pNumRead, (int)evtStatus);
    if (*arg->pNumRead) {
        PSL_LOG_DATASTREAM_DEBUGLOW(arg->buf, *arg->pNumRead);
    }

    return evtStatus;
}//plain_handle_READ



/** ========================================================================
 * =========================================================================
 */
static PslSmeEventStatus
plain_handle_WRITE(PslChanFsm*                         const pFsm,
                   const struct PslChanFsmEvtArgWrite* const arg)
{
    PSL_LOG_DEBUG("%s (fsm=%p): requested cnt=%ld",
                  __func__, pFsm, (long)arg->cnt);

    PslSmeEventStatus evtStatus = kPslSmeEventStatus_success;
    size_t const maxWrite = (arg->cnt <= SSIZE_MAX) ? arg->cnt : SSIZE_MAX;

    ssize_t size;
    do {
        size = write(pFsm->fd, arg->buf, maxWrite);
    } while (size < 0 && EINTR == errno);

    if (size < 0) {
        int const savederrno = errno;

        *arg->pNumWritten = 0;

        switch (savederrno) {
        case EAGAIN:
            *arg->pGioStatus = G_IO_STATUS_AGAIN;
            break;

        default:
            psl_chan_fsm_set_last_error(pFsm, kPslChanFsmErrorSource_errno,
                                        savederrno);
            *arg->pGioStatus = G_IO_STATUS_ERROR;
            PSL_LOG_ERROR("%s (fsm=%p): ERROR: send(%ld) failed with " \
                          "errno=%d (%s)",
                          __func__, pFsm, (long)maxWrite, savederrno,
                          strerror(savederrno));
            evtStatus = kPslSmeEventStatus_error;
            break;
        }
    }
    else {
        *arg->pNumWritten = size;
        *arg->pGioStatus = G_IO_STATUS_NORMAL;
    }

    PSL_LOG_DEBUG(
        "%s (fsm=%p): completed with: GIOStatus=%s, numWritten=%u, evtStatus=%d",
        __func__, pFsm, psl_chan_fsm_str_from_giostatus(*arg->pGioStatus),
        (unsigned)*arg->pNumWritten, (int)evtStatus);
    if (*arg->pNumWritten) {
        PSL_LOG_DATASTREAM_DEBUGLOW(arg->buf, *arg->pNumWritten);
    }

    return evtStatus;
}//plain_handle_WRITE



/** ========================================================================
 *  how: SHUT_RD, SHUT_WR, or SHUT_RDWR from sys/socket.h
 * =========================================================================
 */
PslError
plain_shut_sock(PslChanFsm* const pFsm,
                int         const how)
{
    int const rc = shutdown(pFsm->fd, how);

    if (rc < 0) {
        int const saverrno = errno;

        PSL_LOG_ERROR("%s (fsm=%p): ERROR: shutdown() failed: errno=%d (%s)",
                      __func__, pFsm, saverrno, strerror(saverrno));
        return psl_err_pslerror_from_errno(saverrno, PSL_ERR_FAILED);
    }

    return 0;
}



/** ========================================================================
 * =========================================================================
 */
static PslError
plain_make_and_config_sock(PslChanFsm* const pFsm,
                           int         const sockFamily,
                           int*        const sock)
{
    PslError    pslErr = PSL_ERR_SOCKET;
    int saverrno;

    /// Create a socket
    int s = socket(sockFamily, SOCK_STREAM, 0);
    if (s < 0) {
        saverrno = errno;
        PSL_LOG_ERROR("%s (fsm=%p): ERROR: socket() failed; " \
                      "family=%d, errno=%d (%s)", __func__, pFsm,
                      sockFamily, saverrno, strerror(saverrno));
        return PSL_ERR_SOCKET;
    }

    PSL_LOG_DEBUG("%s (fsm=%p): socket created: fd=%d, " \
                  "addrfamily=%d", __func__, pFsm, s, sockFamily);

    /**
     * Configure the socket...
     */

    /// Make it non-blocking
    pslErr = psl_inet_make_fd_non_blocking(s, "fsm", pFsm);
    if (pslErr) {
        goto error_cleanup;
    }

    pslErr = PSL_ERR_SOCKET_CONFIG;

    /// Set SO_REUSEADDR, if requested
    if ((pFsm->userSettings.chanOpts & kPmSockOptFlag_sockAddrReuse) != 0) {
        int const on = 1;
        if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
            saverrno = errno;
            PSL_LOG_ERROR("%s (fsm=%p): ERROR: setsockopt(SO_REUSEADDR) " \
                          "failed; errno=%d (%s)",
                          __func__, pFsm, saverrno, strerror(saverrno));
            goto error_cleanup;
        }
    }

    /// Bind it, if needed
    if (PF_UNSPEC != pFsm->userSettings.bindAddr.addrFamily) {

        /// @todo Investigate: do sock 
        ///       addr family and bind addr family have to match?
        
        PSL_LOG_DEBUG("%s (fsm=%p): Binding socket %d to '%s:%d'/addrFamily=%d",
                      __func__, pFsm, s,
                      PSL_LOG_MAKE_SAFE_STR(pFsm->userSettings.bindAddr.hostStr),
                      (int)pFsm->userSettings.bindAddr.port,
                      (int)pFsm->userSettings.bindAddr.addrFamily);
        PslInetGenericSockAddr  ba; ///< bind address
        bool isSuccess = !psl_inet_make_sock_addr(
            pFsm->userSettings.bindAddr.addrFamily,
            pFsm->userSettings.bindAddr.hostStr,
            pFsm->userSettings.bindAddr.port,
            &ba, "fsm", pFsm);
        if (!isSuccess) {
            PSL_LOG_ERROR("%s (fsm=%p): ERROR: invalid local bind address",
                          __func__, pFsm);
            pslErr = PSL_ERR_BAD_BIND_ADDR;
            goto error_cleanup;
        }

        int const bindRes = bind(s, (struct sockaddr*)&ba.sa, ba.addrLength);
        if (bindRes < 0) {
            saverrno = errno;
            PSL_LOG_ERROR("%s (fsm=%p): ERROR: bind() failed; errno=%d (%s)",
                          __func__, pFsm, saverrno, strerror(saverrno));
            switch (saverrno) {
            case EADDRNOTAVAIL: pslErr = PSL_ERR_ADDRNOTAVAIL;
                break;
            case EADDRINUSE:    pslErr = PSL_ERR_ADDRINUSE;
                break;
            default:            pslErr = PSL_ERR_SOCKET_CONFIG;
                break;
            }
            goto error_cleanup;
        }
    }

    *sock = s;
    return 0;

error_cleanup:
    if (s >= 0) {
        close(s);
    }

    return pslErr;
}


