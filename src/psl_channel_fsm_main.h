/* @@@LICENSE
*
*      Copyright (c) 2009-2012 Hewlett-Packard Development Company, L.P.
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
 * @file psl_channel_fsm_main.h
 * @ingroup psl_internal 
 * 
 * @brief  Definitions for the top level of the
 *         PmSockIOChannel FSM implementation.
 * 
 * *****************************************************************************
 */
#ifndef PSL_CHANNEL_FSM_MAIN_H__
#define PSL_CHANNEL_FSM_MAIN_H__

#include "psl_build_config.h"

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <glib.h>

#include <openssl/ssl.h>

#include "palmsocket.h"

#include "psl_common.h"
#include "psl_log.h"
#include "psl_assert.h"
#include "psl_error_utils.h"
#include "psl_refcount.h"
#include "psl_sme.h"
#include "psl_multi_fd_watch.h"
#include "psl_channel_fsm_events.h"
#include "psl_channel_fsm_plain.h"
#include "psl_channel_fsm_crypto.h"
#include "psl_channel_fsm.h"



#if defined(__cplusplus)
extern "C" {
#endif


/**
 * A value that we use to represent closed file descriptors
 * (sockets, etc.)
 */
#define PSL_CHAN_FSM_CLOSED_FD_VALUE        PSL_INVALID_FD


/**
 * Initial state: waiting for the connect command
 */
typedef struct PslChanFsmInitState_ {
    PslSmeStateBase         base; ///< MUST BE FIRST MEMBER
} PslChanFsmInitState;


/**
 * Close channel state: responsible for closing the file 
 * descriptor and cancelling any outstanding callbacks; remains 
 * in this state until the IO Channel is finalized 
 */
typedef struct PslChanFsmClosedState_ {
    PslSmeStateBase         base; ///< MUST BE FIRST MEMBER
} PslChanFsmClosedState;


/**
 * Final state: we transition here when the IO Channel is 
 * finalized (base GIOChannel's reference count hits 0). This 
 * transition causes the previously active state hierachy to 
 * exit and clean-up after itself. The remaining clean-up takes
 * place upon entry to this state.
 */
typedef struct PslChanFsmFinalState_ {
    PslSmeStateBase         base; ///< MUST BE FIRST MEMBER
} PslChanFsmFinalState;



/**
 * Top parent state of all "alive" states (all states except the
 * final state).  This wrapper states provides a set of
 * catch-all handlers that facilitates robust clean-up.
 */
typedef struct PslChanFsmAliveState_ {
    PslSmeStateBase         base; ///< MUST BE FIRST MEMBER

    PslChanFsmInitState         initState;
    PslChanFsmClosedState       closedState;

    PslChanFsmPlainModeState    plainModeState;
    PslChanFsmCryptoModeState   cryptoModeState;
} PslChanFsmAliveState;



typedef struct PslChanFsmHostAddrInfo_ {
    int     addrFamily; ///< AF_INET or AF_INET6

    char*   hostStr;    ///< zero-terminated, ASCII hostname or IP address string 

    int     port;       ///< port number
} PslChanFsmHostAddrInfo;



/**
 * PSL IO Channel's finite state machine
 */
struct PslChanFsm_ {
    PslSmeMachineBase           base; ///< MUST BE FIRST MEMBER

    /// Buffers for kFsmEventBegin arg support provided to psl_sme_init_machine
    struct {
        /// @note The buffers MUST be of the same size
        PslChanFsmEvtBeginStateArg  requestArgBuf;
        PslChanFsmEvtBeginStateArg  dispatchArgBuf;
    } beginEvtArgSupport;

    PslRefcount                 refCount;

    PslChanFsmAliveState        aliveState;
    PslChanFsmFinalState        finalState;

    /// The channel that contains this FSM instance; we need to pass it as
    /// an arg to user's callback functions.
    GIOChannel*                 channel;

    /// multi-fd sock watch-related info
    struct {
        PslMultiFdWatchSource*      fdWatch;

        bool                        inFdWatchCb; ///< for error-checking

        /**
         * Connection or security swtich completed callback info (either
         * success or failure)
         */
        struct PslChanFsmFdWatchCompletion {
            PslChanFsmEvtCompletionCbInfo   cb;

            /// non-zero if failure
            PslError                        pslErr;

            /// switchingToCrypto is meaningful only for the
            /// PmSecureSocketSwitchCb callback, and ignored for other callback
            /// types.
            /// TRUE if user requested switch from plaintext to crypto;
            /// FALSE if user requested switch from crypto to plaintext;
            bool                            switchingToCrypto;
        } completionCb;
    } fdWatchInfo;

    /// TRUE if the CLOSE event has already been processed by the FSM
    bool                        fsmClosed;

    /// TRUE if the FINALIZE event has already been processed by the FSM
    bool                        fsmFinalized;

    /// TRUE if FsmStart() has been called; used by chan_fsm_free()
    /// to decide whether it's okay to dispatch events to the FSM (in
    /// order to properly clean up a partially-initialized FSM instance).
    bool                        fsmStarted;

    /**
     * Set by the channel fsm events module to schedule the
     * HEARTBEAT event.
     */
    bool                        heartbeatPending;

    /**
     * Last error record. Updated when an error occurs; otherwise,
     * remains unchanged.  We map codes to PslError codes before
     * storing in lastError.
     */
    PslError                    lastError;

    /// Our comms file descriptor, or -1 if not open yet or when closed.
    /// May be socket or other type of FD (e.g., pipe, TTY).
    /// If provided by user, then userSettings.fdIsUserProvided is set to true.
    int                         fd;

    /**
     * User settings
     *
     * @note Not all settings are available at initialization time.
     *       States should defer access to these settings until the
     *       FSM transitions into the states that need the info.
     */
    struct {

        /// Local address info for binding the socket.  hostStr MUST be an
        /// IP address.
        PslChanFsmHostAddrInfo      bindAddr;

        /// TRUE if a connected file descriptor was provided by user
        bool                        fdIsUserProvided;

        PmSockFileDescOpts          fdOpts;

        PmSockOptionFlags           chanOpts;

        /// Address info or the server; hostStr may be a hostname or
        /// an IP address 
        PslChanFsmHostAddrInfo      serverAddr;

        PmSockThreadContext*        threadCtx;          ///< refcounted

        void*                       userData;   ///< psl_chan_fsm_set_userdata
    } userSettings;
} /*PslChanFsm*/;


/**
 * We typecast our state handler callbacks in order to get
 * specific state, FSM, and arg typenames in the arg list.  We
 * use this macro for forward declaration of state handlers to
 * ensure correctness and consistency in the declarations and to
 * help us detect at compile-time incompatible changes in the
 * formal FSM callback prototype.
 */
#define PSL_CHAN_FSM_STATE_HANDLER_DECLARE(funcName__, stateTypename__) \
    PSL_CHAN_FSM_STATE_HANDLER(funcName__, stateTypename__, PslChanFsm,     \
                                           PslChanFsmEvtArg);               \
                                                                            \
    /* Validate stateTypename__ */                                          \
    PSL_ASSERT_STATIC(                                                      \
        PSL_CHAN_FSM_VALIDATE_ ## stateTypename__ ## _IN_ ## funcName__,    \
        ((PslSmeStateBase*)0) == &(((stateTypename__ *)0)->base))


#define PSL_CHAN_FSM_STATE_HANDLER(name__, stateTypename__,     \
                                   fsmTypename__, argType__)    \
    PslSmeEventStatus name__ (                  \
        stateTypename__ *   pState,             \
        fsmTypename__ *     pFsm,               \
        PslSmeEventId       evtId,              \
        const argType__ *   evtArg)


/**
 * Make sure that our state handler declaration mechanism
 * (PSL_CHAN_FSM_STATE_HANDLER_TYPE) is compatible with
 * PslSmeStateHandlerFnType
 */
typedef PSL_CHAN_FSM_STATE_HANDLER(
    PSL_CHAN_FSM_STATE_HANDLER_CB_TYPE_TO_VALIDATE,
    PslSmeStateBase,
    PslSmeMachineBase,
    void);

PSL_ASSERT_STATIC(
    PSL_CHAN_FSM_VALIDATE_OUR_STATE_HANDLER_DECLARATION_COMPATIBILITY,
    ((PslSmeStateHandlerFnType*)0) ==
    ((PSL_CHAN_FSM_STATE_HANDLER_CB_TYPE_TO_VALIDATE*)0));


/**
 * Schedules a callback to be emitted from the context of our
 * multi-fd watch callback function chan_fsm_fd_watch_cb. This
 * is necessary because calling an external callback directly
 * from a state handler will result in FSM run-to-completion
 * (RTC) violation if the user calls the palmsock channel API
 * from the scope of the user's callback
 * 
 * If the value of the PslChanFsmEvtCompletionCbInfo::which
 * member is kPslChanFsmEvtCompletionCbId_none, then nothing
 * will be scheduled.
 * 
 * @param fsm
 * @param pCb Non-NULL pointer to callback info
 * @param pslErr 0 if the operation completed successfully;
 *               non-zero PslError code if the operation failed.
 * @param toCrypto For the legacy
 *                 kPslChanFsmEvtCompletionCbId_switch callback
 *                 only (ingored by other callbacks): TRUE if
 *                 the user's request was to switch from
 *                 plaintext to SSL/TLS mode; FALSE if the
 *                 user's request was to switch from SSL/TLS
 *                 mode to plaintext.
 */
PSL_CONFIG_INLINE_FUNC void
psl_chan_fsm_sched_fdwatch_completion_cb(
    PslChanFsm*                           const fsm,
    const PslChanFsmEvtCompletionCbInfo*  const pCb,
    PslError                              const pslErr,
    bool                                  const toCrypto)
{
    PSL_ASSERT(fsm->fdWatchInfo.inFdWatchCb);
    PSL_ASSERT(pCb);

    PSL_ASSERT(kPslChanFsmEvtCompletionCbId_none ==
               fsm->fdWatchInfo.completionCb.cb.which);

    PSL_LOG_DEBUGLOW("%s (fsm=%p): requesting completion callback: cbID=%d, " \
                     "funcAddr=%p, PslError=%d (%s), toCrypto=%d",
                     __func__, fsm, (int)pCb->which, pCb->u.completionCb.func,
                     (int)pslErr, PmSockErrStringFromError(pslErr),
                     (int)toCrypto);


    fsm->fdWatchInfo.completionCb.cb                = *pCb;
    fsm->fdWatchInfo.completionCb.pslErr            = pslErr;
    fsm->fdWatchInfo.completionCb.switchingToCrypto = toCrypto;
}


/**
 * Dispatches the given completion callback
 * 
 * @note increments FSM refcount around callback dispatch so the
 *       FSM doesn't get destroyed while in completion callback
 *       in case user destroys the channel from the scope of his
 *       callback.
 * 
 * @param pFsm
 * @param pCb
 * @param pslErr
 * @param switchingToCrypto TRUE if we were connecting or
 *                          connected to SSL/TLS
 */
void
psl_chan_fsm_dispatch_completion_cb(
    PslChanFsm*                             pFsm,
    const PslChanFsmEvtCompletionCbInfo*    pCb,
    PslError                                pslErr,
    bool                                    switchingToCrypto);


/**
 * Convenience state access methods;
 * 
 * Their use enables us to make state hierarchy changes without
 * disrupting much of the code.
 */

PSL_CONFIG_INLINE_FUNC PslSmeStateBase*
psl_chan_fsm_get_final_state(PslChanFsm* const fsm)
{
    return &fsm->finalState.base;
}

PSL_CONFIG_INLINE_FUNC PslSmeStateBase*
psl_chan_fsm_get_alive_state(PslChanFsm* const fsm)
{
    return &fsm->aliveState.base;
}

PSL_CONFIG_INLINE_FUNC PslSmeStateBase*
psl_chan_fsm_get_init_state(PslChanFsm* const fsm)
{
    return &fsm->aliveState.initState.base;
}


PSL_CONFIG_INLINE_FUNC PslSmeStateBase*
psl_chan_fsm_get_closed_state(PslChanFsm* const fsm)
{
    return &fsm->aliveState.closedState.base;
}


PSL_CONFIG_INLINE_FUNC PslSmeStateBase*
psl_chan_fsm_get_plain_mode_state(PslChanFsm* const fsm)
{
    return &fsm->aliveState.plainModeState.base;
}


PSL_CONFIG_INLINE_FUNC PslSmeStateBase*
psl_chan_fsm_get_plain_fail_state(PslChanFsm* const fsm)
{
    return &fsm->aliveState.plainModeState.failState.base;
}


PSL_CONFIG_INLINE_FUNC PslSmeStateBase*
psl_chan_fsm_get_plain_lookup_state(PslChanFsm* const fsm)
{
    return &fsm->aliveState.plainModeState.lookupState.base;
}


PSL_CONFIG_INLINE_FUNC PslSmeStateBase*
psl_chan_fsm_get_plain_conn_state(PslChanFsm* const fsm)
{
    return &fsm->aliveState.plainModeState.connState.base;
}


PSL_CONFIG_INLINE_FUNC PslSmeStateBase*
psl_chan_fsm_get_plain_tcp_state(PslChanFsm* const fsm)
{
    return &fsm->aliveState.plainModeState.tcpState.base;
}


PSL_CONFIG_INLINE_FUNC PslSmeStateBase*
psl_chan_fsm_get_plain_shut_state(PslChanFsm* const fsm)
{
    return &fsm->aliveState.plainModeState.shutState.base;
}


PSL_CONFIG_INLINE_FUNC PslSmeStateBase*
psl_chan_fsm_get_crypto_mode_state(PslChanFsm* const fsm)
{
    return &fsm->aliveState.cryptoModeState.base;
}


PSL_CONFIG_INLINE_FUNC PslSmeStateBase*
psl_chan_fsm_get_crypto_fail_state(PslChanFsm* const fsm)
{
    return &fsm->aliveState.cryptoModeState.failState.base;
}


PSL_CONFIG_INLINE_FUNC PslSmeStateBase*
psl_chan_fsm_get_crypto_conn_state(PslChanFsm* const fsm)
{
    return &fsm->aliveState.cryptoModeState.connState.base;
}


PSL_CONFIG_INLINE_FUNC PslSmeStateBase*
psl_chan_fsm_get_crypto_ssl_state(PslChanFsm* const fsm)
{
    return &fsm->aliveState.cryptoModeState.sslState.base;
}


PSL_CONFIG_INLINE_FUNC PslSmeStateBase*
psl_chan_fsm_get_crypto_renegotiate_state(PslChanFsm* const fsm)
{
    return &fsm->aliveState.cryptoModeState.renegotiateState.base;
}


PSL_CONFIG_INLINE_FUNC PslSmeStateBase*
psl_chan_fsm_get_crypto_shut_state(PslChanFsm* const fsm)
{
    return &fsm->aliveState.cryptoModeState.shutState.base;
}



/** ========================================================================
 * State transition wrappers
 * 
 * @note State transitions may be requested ONLY:
 * 
 *      * When handling kFsmEventBegin event (for initial
 *        transition to child state)
 * 
 *      * When handling a user-defined event
 * 
 * @note WARNING: do NOT request state transitions under any
 *       other circumstances!
 * 
 * @note WARNING: state transition may be requested at most one
 *       time before returning control to the FSM's dispatcher.
 * 
 * =========================================================================
 */



/** ========================================================================
 * Begin transition to the Closed state
 * @param pFsm
 * 
 * =========================================================================
 */
PSL_CONFIG_INLINE_FUNC void
psl_chan_fsm_goto_closed_state(PslChanFsm* const pFsm)
{
    psl_sme_begin_transition(&pFsm->base, psl_chan_fsm_get_closed_state(pFsm),
                             NULL, 0, __func__);
}


/** ========================================================================
 * Begin transition to the Final state
 * @param pFsm
 * 
 * =========================================================================
 */
PSL_CONFIG_INLINE_FUNC void
psl_chan_fsm_goto_final_state(PslChanFsm* const pFsm)
{
    psl_sme_begin_transition(&pFsm->base, psl_chan_fsm_get_final_state(pFsm),
                             NULL, 0, __func__);
}


/** ========================================================================
 * Begin transition to the Plain-Connect state
 * @param pFsm
 * @param pArgs Non-NULL common connection args 
 * @param addrText Non-NULL connection address info
 * 
 * =========================================================================
 */
PSL_CONFIG_INLINE_FUNC void
psl_chan_fsm_goto_plain_conn_state(
    PslChanFsm*                             const pFsm,
    const PslChanFsmEvtCommonConnectArgs*   const pArgs,
    const struct PslChanFsmEvtInetAddrText* const addrText)
{
    PSL_ASSERT(addrText);
    PSL_ASSERT(pArgs);

    struct PslChanFsmEvtBeginArgPlainConn   const arg = {
        .common         = *pArgs,
        .addrText       = *addrText
    };

    if (psl_chan_fsm_evt_is_crypto_conn_kind(arg.common.connKind)) {
        (void)PmSockSSLCtxRef(arg.common.u.crypto.sslCtx);
    }

    psl_sme_begin_transition(&pFsm->base,
                             psl_chan_fsm_get_plain_conn_state(pFsm),
                             (PslChanFsmEvtBeginStateArg*)&arg,
                             sizeof(arg), __func__);
}


/** ========================================================================
 * Begin transition to the Plain-fail state
 * @param pFsm
 * @param causeCode Non-zero PslError that caused this request
 * 
 * =========================================================================
 */
PSL_CONFIG_INLINE_FUNC void
psl_chan_fsm_goto_plain_fail_state(PslChanFsm*  const pFsm,
                                   PslError     const causeCode)
{
    PSL_ASSERT(causeCode);

    struct PslChanFsmEvtBeginArgPlainFail   const arg = {
        .pslError       = causeCode
    };
    psl_sme_begin_transition(&pFsm->base,
                             psl_chan_fsm_get_plain_fail_state(pFsm),
                             (PslChanFsmEvtBeginStateArg*)&arg,
                             sizeof(arg), __func__);
}


/** ========================================================================
 * Begin transition to the Plain-Lookup state
 * @param pFsm 
 * @param pArgs Non-NULL connection args 
 * 
 * =========================================================================
 */
PSL_CONFIG_INLINE_FUNC void
psl_chan_fsm_goto_plain_lookup_state(
    PslChanFsm*                           const pFsm,
    const PslChanFsmEvtCommonConnectArgs* const pArgs)
{
    PSL_ASSERT(pArgs);

    struct PslChanFsmEvtBeginArgPlainLookup const arg = {
        .common         = *pArgs
    };

    if (psl_chan_fsm_evt_is_crypto_conn_kind(arg.common.connKind)) {
        (void)PmSockSSLCtxRef(arg.common.u.crypto.sslCtx);
    }

    psl_sme_begin_transition(&pFsm->base,
                             psl_chan_fsm_get_plain_lookup_state(pFsm),
                             (PslChanFsmEvtBeginStateArg*)&arg,
                             sizeof(arg), __func__);
}


/** ========================================================================
 * Begin transition to the Plain-Shut state
 * @param pFsm
 * 
 * =========================================================================
 */
PSL_CONFIG_INLINE_FUNC void
psl_chan_fsm_goto_plain_shut_state(PslChanFsm*  const pFsm)
{
    psl_sme_begin_transition(&pFsm->base,
                             psl_chan_fsm_get_plain_shut_state(pFsm),
                             NULL, 0, __func__);
}


/** ========================================================================
 * Begin transition to the Plain-TCP/IP state
 * @param pFsm
 * 
 * =========================================================================
 */
PSL_CONFIG_INLINE_FUNC void
psl_chan_fsm_goto_plain_tcp_state(PslChanFsm* const pFsm)
{
    psl_sme_begin_transition(&pFsm->base,
                             psl_chan_fsm_get_plain_tcp_state(pFsm),
                             NULL, 0, __func__);
}


/** ========================================================================
 * Begin transition to the Crypto-conn state
 * @param pFsm
 * @param pArgs Non-NULL connection args 
 * =========================================================================
 */
PSL_CONFIG_INLINE_FUNC void
psl_chan_fsm_goto_crypto_conn_state(
    PslChanFsm*                           const pFsm,
    const PslChanFsmEvtCommonConnectArgs* const pArgs)
{
    PSL_ASSERT(pArgs);
    PSL_ASSERT(psl_chan_fsm_evt_is_crypto_conn_kind(pArgs->connKind));

    struct PslChanFsmEvtBeginArgCryptoConn  const arg = {
        .common         = *pArgs
    };

    (void)PmSockSSLCtxRef(arg.common.u.crypto.sslCtx);

    psl_sme_begin_transition(&pFsm->base,
                             psl_chan_fsm_get_crypto_conn_state(pFsm),
                             (PslChanFsmEvtBeginStateArg*)&arg,
                             sizeof(arg), __func__);
}


/** ========================================================================
 * Begin transition to the Crypto-Fail state
 * @param pFsm
 * @param causeCode Non-zero PslError that caused this request
 * 
 * =========================================================================
 */
PSL_CONFIG_INLINE_FUNC void
psl_chan_fsm_goto_crypto_fail_state(PslChanFsm*     const pFsm,
                                    PslError        const causeCode)
{
    PSL_ASSERT(causeCode);

    struct PslChanFsmEvtBeginArgCryptoFail  const arg = {
        .pslError       = causeCode
    };
    psl_sme_begin_transition(&pFsm->base,
                             psl_chan_fsm_get_crypto_fail_state(pFsm),
                             (PslChanFsmEvtBeginStateArg*)&arg,
                             sizeof(arg), __func__);
}


PSL_CONFIG_INLINE_FUNC void
psl_chan_fsm_goto_crypto_renegotiate_state(
    PslChanFsm*                               const pFsm,
    const PslChanFsmEvtCryptoRenegotiateArgs* const pArgs)
{
    PSL_ASSERT(pArgs);

    struct PslChanFsmEvtBeginArgCryptoRenegotiate const arg = {
        .data            = *pArgs
    };
    psl_sme_begin_transition(&pFsm->base,
                             psl_chan_fsm_get_crypto_renegotiate_state(pFsm),
                             (PslChanFsmEvtBeginStateArg*)&arg,
                             sizeof(arg), __func__);
}


/** ========================================================================
 * Begin transition to the Crypto-Shut state
 * @param pFsm
 * @param how
 * @param switchCb Legacy callback; may be NULL
 * @param cbArg User arg for legacy callback; may be NULL
 * 
 * =========================================================================
 */
PSL_CONFIG_INLINE_FUNC void
psl_chan_fsm_goto_crypto_shut_state(
    PslChanFsm*                          const pFsm,
    PslChanFsmEvtShutCryptoKind          const how,
    const PslChanFsmEvtCompletionCbInfo* const pCb)
{
    PSL_ASSERT(pCb);

    struct PslChanFsmEvtBeginArgCryptoShut const arg = {
        .how            = how,
        .cb             = *pCb
    };
    psl_sme_begin_transition(&pFsm->base,
                             psl_chan_fsm_get_crypto_shut_state(pFsm),
                             (PslChanFsmEvtBeginStateArg*)&arg,
                             sizeof(arg), __func__);
}


/** ========================================================================
 * Begin transition to the Crypto-SSL state
 * @param pFsm
 * 
 * =========================================================================
 */
PSL_CONFIG_INLINE_FUNC void
psl_chan_fsm_goto_crypto_ssl_state(PslChanFsm*  const pFsm)
{
    psl_sme_begin_transition(&pFsm->base,
                             psl_chan_fsm_get_crypto_ssl_state(pFsm),
                             NULL, 0, __func__);
}


#if defined(__cplusplus)
}
#endif

#endif // PSL_CHANNEL_FSM_MAIN_H__
