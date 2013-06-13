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
 * @file psl_channel_fsm_events.h
 * @ingroup psl_internal 
 * 
 * @brief  Event definitions and primitives for the the
 *         PmSockIOChannel Finite State Machine
 *         implementation.
 * 
 * *****************************************************************************
 */
#ifndef PSL_CHANNEL_FSM_EVENTS_H__
#define PSL_CHANNEL_FSM_EVENTS_H__

#include "psl_build_config.h"

#include <stdbool.h>
#include <string.h>
#include <netdb.h>

#include <PmStateMachineEngine/PalmFsm.h>

#include "palmsocket.h"

#include "psl_assert.h"
#include "psl_sme.h"
#include "psl_multi_fd_watch.h"
//#include "psl_channel.h"
//#include "psl_channel_fsm_fwd.h"
#include "psl_channel_fsm.h"



#if defined(__cplusplus)
extern "C" {
#endif


typedef enum PslChanFsmEvtId_ {
    /**
     * Checks for IO readiness
     * 
     * Prerequisites: N/A.
     * 
     * Event arg: PslChanFsmEvtArg::checkIO
     * 
     * Last/Latched error: sets Last Error on failure;
     * 
     * Source: psl_channel
     */
    PSL_CHAN_FSM_EVT_CHECK_IO                   = kFsmEventFirstUserEvent + 1,

    /**
     * The close event that results in transition to the 'close'
     * state
     * 
     * Event arg: N/A
     * 
     * Source: psl_channel and internal
     */
    PSL_CHAN_FSM_EVT_CLOSE                      = kFsmEventFirstUserEvent + 10,

    /**
     * Initiates connection-establishment
     * 
     * Event arg: PslChanFsmEvtArg::connect
     * 
     * Last/Latched error: sets Last Error on failure;
     * 
     * Source: psl_channel
     */
    PSL_CHAN_FSM_EVT_CONNECT                    = kFsmEventFirstUserEvent + 20,

    /**
     * Event from our PslMultiFdWatchSourceCb callback
     * 
     * Event arg: PslChanFsmEvtArg::fdWatch
     * 
     * Last/Latched error: sets Last Error on failure;
     * 
     * Source: internal
     */
    PSL_CHAN_FSM_EVT_FD_WATCH                   = kFsmEventFirstUserEvent + 30,

    /**
     * The final event that results in transition to the 'final'
     * state, thus exiting (and uninitializing of) the current
     * active state chain;
     * 
     * @note Only for internal use by psl_chan_fsm_finalize
     * 
     * Event arg: N/A
     * 
     * Source: internal
     */
    PSL_CHAN_FSM_EVT_FINALIZE                   = kFsmEventFirstUserEvent + 40,

    /**
     * Obtains peer certificate verification error info 
     * 
     * Scope: crypto-mode
     * 
     * Event arg: N/A
     * 
     * Last/Latched error: sets Last Error on failure;
     * 
     * Source: psl_channel
     */
    PSL_CHAN_FSM_EVT_GET_PEER_CERT_VERIFY_ERR   = kFsmEventFirstUserEvent + 45,

    /**
     * Dispatched in response to psl_chan_fsm_evt_req_heartbeat()
     * 
     * Event arg: N/A
     * 
     * Last/Latched error: N/A;
     * 
     * Source: internal
     */
    PSL_CHAN_FSM_EVT_HEARTBEAT                  = kFsmEventFirstUserEvent + 50,

    /**
     * Signals completion of host lookup
     * 
     * Event arg: PslChanFsmEvtArg::lookupDone
     * 
     * Last/Latched error: sets Last Error on failure;
     * 
     * Source: internal
     */
    PSL_CHAN_FSM_EVT_LOOKUP_DONE                = kFsmEventFirstUserEvent + 60,

    /**
     * Performs the 'read' operation
     * 
     * Prerequisites: successful plaintext or SSL/TLS connection.
     * 
     * Event arg: PslChanFsmEvtArg::read
     * 
     * Last/Latched error: sets Last Error on failure;
     * 
     * Source: psl_channel
     */
    PSL_CHAN_FSM_EVT_READ                       = kFsmEventFirstUserEvent + 70,

    /**
     * Kicks off SSL/TLS renegotiation from crypto-ssl (SSL/TLS 
     * connected) mode 
     * 
     * Scope: crypto-ssl state
     * 
     * Event arg: N/A
     * 
     * Last/Latched error: sets Last Error on failure;
     * 
     * Source: psl_channel
     */
    PSL_CHAN_FSM_EVT_RENEGOTIATE_CRYPTO         = kFsmEventFirstUserEvent + 75,

    /**
     * Resumes plaintext mode from bi-directional crypto-shut mode
     * 
     * Scope: crypto-shut state
     * 
     * Event arg: N/A
     * 
     * Last/Latched error: sets Last Error on failure;
     * 
     * Source: psl_channel
     */
    PSL_CHAN_FSM_EVT_RESUME_PLAINTEXT           = kFsmEventFirstUserEvent + 80,

    /**
     * Sets a connected file descriptor
     * 
     * Scope: init state
     * 
     * Event arg: PslChanFsmEvtArg::setConnFD
     * 
     * Last/Latched error: sets Last Error on failure;
     * 
     * Source: psl_channel
     */
    PSL_CHAN_FSM_EVT_SET_CONN_FD                = kFsmEventFirstUserEvent + 90,

    /**
     * Sets the connection parameters (address family, address, and
     * port)
     * 
     * Scope: init state
     * 
     * Event arg: PslChanFsmEvtArg::setServer
     * 
     * Last/Latched error: sets Last Error on failure;
     * 
     * Source: psl_channel
     */
    PSL_CHAN_FSM_EVT_SET_SERVER                 = kFsmEventFirstUserEvent + 100,

    /**
     * Sets the local socket bind parameters (IP address, and port)
     * 
     * Scope: init state
     * 
     * Event arg: PslChanFsmEvtArg::setSockBind
     * 
     * Last/Latched error: sets Last Error on failure;
     * 
     * Source: psl_channel
     */
    PSL_CHAN_FSM_EVT_SET_SOCK_BIND              = kFsmEventFirstUserEvent + 110,

    /**
     * Initiates shut-down of the SSL session
     * 
     * Prerequisites: In SSL or SSL soft-error state.
     * 
     * Event arg: PslChanFsmEvtArg::shutCrypto
     * 
     * Last/Latched error: sets Last Error on failure;
     * 
     * Source: psl_channel
     */
    PSL_CHAN_FSM_EVT_SHUT_CRYPTO                = kFsmEventFirstUserEvent + 120,

    /**
     * Shuts down the socket in the requested direction and
     * transitions the FSM to the plain-shut state
     * 
     * Prerequisites: successful plaintext TCP/IP connection or
     * already in plain-shut state.
     * 
     * Event arg: PslChanFsmEvtArg::shutSock
     * 
     * Last/Latched error: sets Last Error on failure;
     * 
     * Source: psl_channel
     */
    PSL_CHAN_FSM_EVT_SHUT_SOCK                  = kFsmEventFirstUserEvent + 130,

    /**
     * Performs the 'write' operation
     * 
     * Prerequisites: successful plaintext or SSL/TLS connection.
     * 
     * Event arg: PslChanFsmEvtArg::write
     * 
     * Last/Latched error: sets Last Error on failure;
     * 
     * Source: psl_channel
     */
    PSL_CHAN_FSM_EVT_WRITE                      = kFsmEventFirstUserEvent + 140

} PslChanFsmEvtId;


/**
 * Connection kind: plaintext of SSL/TLS
 */
typedef enum PslChanFsmEvtConnKind_ {
    kPslChanFsmEvtConnKind_plain            = 1,    ///< plaintext
    kPslChanFsmEvtConnKind_cryptoClient     = 2,    ///< SSL/TLS client
    kPslChanFsmEvtConnKind_cryptoServer     = 3    ///< SSL/TLS server
} PslChanFsmEvtConnKind;



/**
 * SSL/TLS shut-down kinds
 */
typedef enum PslChanFsmEvtShutCryptoKind_ {
    /// Permitted by SSL/TLS spec, but not suitable for using the socket
    /// connection afterwards
    kPslChanFsmEvtShutCrypto_oneWay = 1,

    /// Clean, bi-directional SSL/TLS shutdown.  The socket connection may
    /// be used after successful completion of the two-way shut-down
    kPslChanFsmEvtShutCrypto_twoWay = 2
} PslChanFsmEvtShutCryptoKind;


/**
 * Channel I/O readiness hints for readable and writeable
 */
typedef enum PslChanFsmEvtIOReadyHint_ {
    /// forced NOT READY (readable or writeable)
    kPslChanFsmEvtIOReadyHint_notReady  = 0,

    /// forced READY (readable or writeable)
    kPslChanFsmEvtIOReadyHint_ready     = 1,

    /// use select/poll on the FD to find out (readable or writeable)
    kPslChanFsmEvtIOReadyHint_poll      = 2,

    /// forced POLLHUP-equivalent (readable or writeable)
    kPslChanFsmEvtIOReadyHint_hup       = -1,

    /// forced READY and POLLHUP-equivalent (readable or writeable)
    kPslChanFsmEvtIOReadyHint_readyhup  = -2
} PslChanFsmEvtIOReadyHint;


/**
 * Structure for passing completion callbacks in event args
 */
typedef struct PslChanFsmEvtCompletionCallbacks_ {
    /// Union member selection depends on the value 'which'

    enum PslChanFsmEvtCompletionCbId {
        kPslChanFsmEvtCompletionCbId_none,    ///< no callback

        kPslChanFsmEvtCompletionCbId_completion,

        kPslChanFsmEvtCompletionCbId_connect, ///< legacy
        kPslChanFsmEvtCompletionCbId_switch   ///< legacy
    } which;

    union {
        struct {
            PmSockCompletionCb*     func;
            /// @note callback arg for this callback type is settable per
            ///       PmSockIOChannel instance via PmSockSetUserData()
        } completionCb;

        struct {
            PmSocketConnectCb       func;
            void*                   userData;   ///< callback arg
        } connectCb;    ///< legacy connect callback

        struct {
            PmSecureSocketSwitchCb  func;   
            void*                   userData;   ///< callback arg
        } switchCb;     ///< legacy security switch callback

    } u;

} PslChanFsmEvtCompletionCbInfo;



/**
 * Common args for SSL/TLS-specific connection-related 
 * events 
 */
typedef struct PslChanFsmEvtCryptoConnectArgs_ {
    PmSockSSLContext*               sslCtx;
    
    PmSockCryptoConfArgs            conf;
} PslChanFsmEvtCryptoConnectArgs;


/**
 * Common arguments for connection-related events. 
 */
typedef struct PslChanFsmEvtCommonConnectArgs_ {
    PslChanFsmEvtCompletionCbInfo           cb;

    /**
     * Target connection kind; one of the SSL/TLS kinds:
     *
     * kPslChanFsmEvtConnKind_plain, 
     * kPslChanFsmEvtConnKind_cryptoClient, or 
     * kPslChanFsmEvtConnKind_cryptoServer 
     */
    PslChanFsmEvtConnKind                   connKind;

    /// Field selection in this union depends on the value of connKind
    union {
        PslChanFsmEvtCryptoConnectArgs      crypto;

        /// There are no extra args for plaintext request right now, but this
        /// is where they would be added when needed.
        ///PslChanFsmEvtPlainConnectArgs    plain;
    } u;
} PslChanFsmEvtCommonConnectArgs;


/**
 * Common arguments for SSL/TLS renegotiation-related events
 */
typedef struct PslChanFsmEvtCryptoRenegotiateArgs_ {
    PmSockRenegotiateConf                   conf;
    PslChanFsmEvtCompletionCbInfo           cb;
} PslChanFsmEvtCryptoRenegotiateArgs;


/**
 * State-specific kFsmEventBegin args
 * 
 * @see psl_chan_fsm_begin_transition_()
 */
typedef struct PslChanFsmEvtBeginStateArg_ {
    union {
        struct PslChanFsmEvtBeginArgCryptoConn {
            PslChanFsmEvtCommonConnectArgs  common;
        } cryptoConn;


        struct PslChanFsmEvtBeginArgCryptoFail {
            PslError                        pslError; ///< failure cause code
        } cryptoFail;

        struct PslChanFsmEvtBeginArgCryptoRenegotiate {
            PslChanFsmEvtCryptoRenegotiateArgs  data;
        } cryptoRenegotiate;

        struct PslChanFsmEvtBeginArgCryptoShut {
            PslChanFsmEvtCompletionCbInfo   cb;

            PslChanFsmEvtShutCryptoKind     how;
        } cryptoShut;


        struct PslChanFsmEvtBeginArgPlainConn {
            PslChanFsmEvtCommonConnectArgs  common;

            struct PslChanFsmEvtInetAddrText {
                int         family; ///< AF_INET or AF_INET6

                char        addr [(INET6_ADDRSTRLEN > INET_ADDRSTRLEN
                                   ? INET6_ADDRSTRLEN
                                   : INET_ADDRSTRLEN)];
            } addrText;
        } plainConn;


        struct PslChanFsmEvtBeginArgPlainFail {
            PslError    pslError; ///< failure cause code
        } plainFail;


        struct PslChanFsmEvtBeginArgPlainLookup {
            PslChanFsmEvtCommonConnectArgs  common;
        } plainLookup;


    }; ///< anonymous
} PslChanFsmEvtBeginStateArg;


/**
 * Event argument structures
 */
typedef struct PslChanFsmEvtArg_ {
    union {
        /// kFsmEventBegin args
        PslChanFsmEvtBeginStateArg  begin;

        /// PSL_CHAN_FSM_EVT_CHECK_IO
        struct PslChanFsmEvtArgCheckIO {
            PslChanFsmEvtIOReadyHint*             pReadableHint;
            PslChanFsmEvtIOReadyHint*             pWriteableHint;
            int*                            pFD; ///< returns sock fd or -1 if none
        } checkIO;

        /// PSL_CHAN_FSM_EVT_CONNECT
        struct PslChanFsmEvtArgConnect {
            PslChanFsmEvtCommonConnectArgs  data;
        } connect;

        /// PSL_CHAN_FSM_EVT_FD_WATCH
        struct PslChanFsmEvtArgFdWatch {
            int                             numrecs;
            const PslMultiFdPollRec*        pollrecs; ///< may be NULL if none
        } fdWatch;

        /// PSL_CHAN_FSM_EVT_GET_PEER_CERT_VERIFY_ERR
        struct PslChanFsmEvtArgGetPeerCertVerifyErr {
            PmSockPeerCertVerifyErrorInfo*  pRes;
        } getPeerCertVerifyErr;

        /// PSL_CHAN_FSM_EVT_LOOKUP_DONE
        struct PslChanFsmEvtArgLookupDone {
            PslError                        errorCode;  ///< 0 on success
            const struct hostent*           hosts;      ///< non-NULL on success
        } lookupDone;

        /// PSL_CHAN_FSM_EVT_READ
        struct PslChanFsmEvtArgRead {
            void*                           buf; ///<
            gsize                           cnt; ///< Maximum # of bytes to read
            GIOStatus*                      pGioStatus;
            gsize*                          pNumRead;
        } read;

        /// PSL_CHAN_FSM_EVT_RENEGOTIATE_CRYPTO
        struct PslChanFsmEvtArgRenegotiateCrypto {
            PslChanFsmEvtCryptoRenegotiateArgs  data;
        } renegotiateCrypto;

        /// PSL_CHAN_FSM_EVT_SET_CONN_FD
        struct PslChanFsmEvtArgSetConnFD {
            /// Connected file descriptor
            int                             fd;
            /// File descriptor options
            PmSockFileDescOpts              opts;
        } setConnFD;

        /// PSL_CHAN_FSM_EVT_SET_SERVER
        struct PslChanFsmEvtArgSetServer {
            /// Address family: AF_INET or AF_INET6
            int                             addrFamily;
            /// Hostname or IP addr of server: MUST not be INADDR_ANY
            const char*                     hostStr;
            /// Server port number: MUST not be 0 (any port)
            int                             port;
        } setServer;

        /// PSL_CHAN_FSM_EVT_SET_SOCK_BIND
        struct PslChanFsmEvtArgSetSockBind {
            /// Address family: AF_INET or AF_INET6
            int                             addrFamily;

            /// Non-empty IP address or NULL for INADDR_ANY/in6addr_any
            const char*                     ipAddrStr;

            /// Server port number, or 0 (zero) for "any port"
            int                             port;
        } setSockBind;

        /// PSL_CHAN_FSM_EVT_SHUT_CRYPTO
        struct PslChanFsmEvtArgShutCrypto {
            PslChanFsmEvtCompletionCbInfo   cb;

            PslChanFsmEvtShutCryptoKind     how;
        } shutCrypto;

        /// PSL_CHAN_FSM_EVT_SHUT_SOCK
        struct PslChanFsmEvtArgShutSock {
            /// SHUT_RD, SHUT_WR, or SHUT_RDWR from sys/socket.h
            int                             how;
        } shutSock;

        /// PSL_CHAN_FSM_EVT_WRITE
        struct PslChanFsmEvtArgWrite {
            const void*                     buf; ///<
            gsize                           cnt; ///< Maximum # of bytes to write
            GIOStatus*                      pGioStatus;
            gsize*                          pNumWritten;
        } write;

    }; ///< anonymous

} PslChanFsmEvtArg;




/**
 * Returns TRUE if the given PslChanFsmEvtConnKind value is plaintext
 * 
 * @param connKind
 * 
 * @return bool
 */
PSL_CONFIG_INLINE_FUNC bool
psl_chan_fsm_evt_is_plain_conn_kind(PslChanFsmEvtConnKind const connKind)
{
    return kPslChanFsmEvtConnKind_plain == connKind;
}


/**
 * Returns true if the given PslChanFsmEvtConnKind value is one
 * of the SSL/TLS variants
 * 
 * @param connKind
 * 
 * @return bool
 */
PSL_CONFIG_INLINE_FUNC bool
psl_chan_fsm_evt_is_crypto_conn_kind(PslChanFsmEvtConnKind const connKind)
{
    return !psl_chan_fsm_evt_is_plain_conn_kind(connKind);
}



/**
 * Dispatch an event; this is a private function: don't call it
 * directly; use one of the inline event-specific wrapper
 * functions instead.
 * 
 * @param fsm Non-NULL FSM instance
 * @param evtId Event ID
 * @param arg Event-specific argument structure, or NULL if an
 *            arg is not required by the event. MUST be either
 *            the event-specific member PslChanFsmEvtArg cast
 *            to PslChanFsmEvtArg pointer or the
 *            PslChanFsmEvtArg structure itself.
 */
PslSmeEventStatus
psl_chan_fsm_evt_dispatch_full_(struct PslChanFsm_* fsm,
                                PslChanFsmEvtId evtId,
                                const PslChanFsmEvtArg* arg);

/**
 * Request dispatch of PSL_CHAN_FSM_EVT_HEARTBEAT.
 * PSL_CHAN_FSM_EVT_HEARTBEAT will be dispatched as soon as the
 * current dispatch chain and any pending state transitions
 * unwind.
 * 
 * @note MUST be called from the scope of a state event handler
 * 
 * @param fsm Non-NULL FSM instance
 * @param requester Non-NULL state that is making the request
 */
void
psl_chan_fsm_evt_req_heartbeat(struct PslChanFsm_*  const fsm,
                               const FsmState*      const requester);




/**
 * Dispatches PSL_CHAN_FSM_EVT_CHECK_IO
 * 
 * @param fsm
 * @param pReadableHint
 * @param pWriteableHint
 * @param pFD
 * 
 * @return PslSmeEventStatus
 * 
 * @see psl_chan_fsm_evt_make_simple_CHECK_IO_response()
 */
PSL_CONFIG_INLINE_FUNC PslSmeEventStatus
psl_chan_fsm_evt_dispatch_CHECK_IO(struct PslChanFsm_*  const fsm,
                                   PslChanFsmEvtIOReadyHint*  const pReadableHint,
                                   PslChanFsmEvtIOReadyHint*  const pWriteableHint,
                                   int*                 const pFD)
{
    PSL_ASSERT(pReadableHint && pWriteableHint && pFD);

    *pReadableHint = *pWriteableHint = kPslChanFsmEvtIOReadyHint_notReady;
    *pFD = -1;

    struct PslChanFsmEvtArgCheckIO const arg = {
        .pReadableHint  = pReadableHint,
        .pWriteableHint = pWriteableHint,
        .pFD            = pFD
    };

    return psl_chan_fsm_evt_dispatch_full_(fsm, PSL_CHAN_FSM_EVT_CHECK_IO,
                                           (const PslChanFsmEvtArg*)&arg);
}


/**
 * Fill in a PSL_CHAN_FSM_EVT_CHECK_IO response
 * 
 * @param arg Non-NULL pointer to the PSL_CHAN_FSM_EVT_CHECK_IO
 *            to fill in.
 * @param readableHint Readiness hint for readable condition.
 * @param writeableHint Readiness hint for writeable condition.
 * @param fd Socket file descriptor, or -1 if none
 * 
 * @return PslSmeEventStatus  kPslSmeEventStatus_success
 */
PSL_CONFIG_INLINE_FUNC PslSmeEventStatus
psl_chan_fsm_evt_make_full_CHECK_IO_response(
    const struct PslChanFsmEvtArgCheckIO*   const arg,
    PslChanFsmEvtIOReadyHint                      const readableHint,
    PslChanFsmEvtIOReadyHint                      const writeableHint,
    int                                     const fd)
{
    *arg->pReadableHint = readableHint;
    *arg->pWriteableHint = writeableHint;
    *arg->pFD = fd;

    return kPslSmeEventStatus_success;
}


/**
 * Fill in a simple PSL_CHAN_FSM_EVT_CHECK_IO response
 * 
 * @param arg Non-NULL pointer to the PSL_CHAN_FSM_EVT_CHECK_IO
 *            to fill in.
 * @param readinessHint Readiness hint for both readable and
 *                      writable conditions.
 * @param fd Socket file descriptor, or -1 if none
 * 
 * @return PslSmeEventStatus  kPslSmeEventStatus_success
 */
PSL_CONFIG_INLINE_FUNC PslSmeEventStatus
psl_chan_fsm_evt_make_simple_CHECK_IO_response(
    const struct PslChanFsmEvtArgCheckIO*   const arg,
    PslChanFsmEvtIOReadyHint                      const readinessHint,
    int                                     const fd)
{
    return psl_chan_fsm_evt_make_full_CHECK_IO_response(arg, readinessHint,
                                                        readinessHint, fd);
}


/**
 * Dispatches PSL_CHAN_FSM_EVT_CLOSE
 * @param fsm
 * 
 * @return PslSmeEventStatus
 */
PSL_CONFIG_INLINE_FUNC PslSmeEventStatus
psl_chan_fsm_evt_dispatch_CLOSE(struct PslChanFsm_* const fsm)
{
    return psl_chan_fsm_evt_dispatch_full_(
        fsm, PSL_CHAN_FSM_EVT_CLOSE, NULL/*arg*/);
}


/**
 * Dispatches PSL_CHAN_FSM_EVT_CONNECT
 * @param fsm
 * @param connKind
 * @param sslCtx Non-NULL PmSockSSLContext instance for crypto
 *               requests (FSM will acquire its own reference as
 *               needed); NULL for plaintext requests
 * @param pCryptoConf Optional SSL/TLS options; NULL if none; 
 *                    for crypto requests only
 * @param certVerifyOpts Optional certificate verification flags
 *                       for crypto requests only.
 * @param pCb Non-NULL pointer to completion callback info
 * @return PslSmeEventStatus
 */
PSL_CONFIG_INLINE_FUNC PslSmeEventStatus
psl_chan_fsm_evt_dispatch_CONNECT(struct PslChanFsm_*           const fsm,
                                  PslChanFsmEvtConnKind         const connKind,
                                  PmSockSSLContext*             const sslCtx,
                                  const PmSockCryptoConfArgs*   const pCryptoConf,
                                  const PslChanFsmEvtCompletionCbInfo* const pCb)
{
    PSL_ASSERT(psl_chan_fsm_evt_is_crypto_conn_kind(connKind) ||
               (!sslCtx && !pCryptoConf));
    PSL_ASSERT(!psl_chan_fsm_evt_is_crypto_conn_kind(connKind) || sslCtx);
    PSL_ASSERT(pCb);

    PmSockCryptoConfArgs    cryptoConf;
    memset(&cryptoConf, 0, sizeof(cryptoConf));

    /// Process and validate crypto configuration args
    if (pCryptoConf) {
        /**
         * @note We copy manually for backward compatibility
         */
        if (0 != (pCryptoConf->enabledOpts & kPmSockCryptoConfigEnabledOpt_lifecycleCb)) {
            cryptoConf.enabledOpts |= kPmSockCryptoConfigEnabledOpt_lifecycleCb;
            cryptoConf.lifecycleCb = pCryptoConf->lifecycleCb;
        }
    
        if (0 != (pCryptoConf->enabledOpts & kPmSockCryptoConfigEnabledOpt_verifyCb)) {
            cryptoConf.enabledOpts |= kPmSockCryptoConfigEnabledOpt_verifyCb;
            cryptoConf.verifyCb = pCryptoConf->verifyCb;
        }
    
        if (0 != (pCryptoConf->enabledOpts & kPmSockCryptoConfigEnabledOpt_verifyOpts)) {
            cryptoConf.enabledOpts |= kPmSockCryptoConfigEnabledOpt_verifyOpts;
            cryptoConf.verifyOpts = pCryptoConf->verifyOpts;
        }

        if (0 != (pCryptoConf->enabledOpts & ~cryptoConf.enabledOpts)) {
            PSL_LOG_ERROR(
                "%s (fsm=%p): ERROR: unexpected PmSockCryptoConfigEnabledOpts: 0x%X",
                __func__, fsm, pCryptoConf->enabledOpts & ~cryptoConf.enabledOpts);
            psl_chan_fsm_set_last_error(fsm, kPslChanFsmErrorSource_psl,
                                        PSL_ERR_INVAL);
            return kPslSmeEventStatus_error;
        }
    }

    /// Compose and dispatch the event

    struct PslChanFsmEvtArgConnect const arg = {
        .data           = {
            .cb             = *pCb,
            .connKind       = connKind,
    
            .u              = {
                .crypto         = {
                    .sslCtx         = sslCtx,
                    .conf           = cryptoConf
                }
            }
        }
    };

    return psl_chan_fsm_evt_dispatch_full_(fsm, PSL_CHAN_FSM_EVT_CONNECT,
                                           (const PslChanFsmEvtArg*)&arg);
}//psl_chan_fsm_evt_dispatch_CONNECT


/**
 * Dispatches PSL_CHAN_FSM_EVT_FD_WATCH
 * @param fsm
 * @param pollrecs Array of PslMultiFdPollRec; NULL if none
 * @param numrecs Count of PslMultiFdPollRec structures in
 *                pollrecs.
 * @return PslSmeEventStatus
 */
PSL_CONFIG_INLINE_FUNC PslSmeEventStatus
psl_chan_fsm_evt_dispatch_FD_WATCH(struct PslChanFsm_*      const fsm,
                                   const PslMultiFdPollRec* const pollrecs,
                                   int                      const numrecs)
{
    PSL_ASSERT(numrecs || !pollrecs);

    struct PslChanFsmEvtArgFdWatch const arg = {
        .pollrecs       = pollrecs,
        .numrecs        = numrecs
    };

    return psl_chan_fsm_evt_dispatch_full_(fsm, PSL_CHAN_FSM_EVT_FD_WATCH,
                                           (const PslChanFsmEvtArg*)&arg);
}


/**
 * Dispatches PSL_CHAN_FSM_EVT_FINALIZE
 * @param fsm
 * 
 * @return PslSmeEventStatus
 */
PSL_CONFIG_INLINE_FUNC PslSmeEventStatus
psl_chan_fsm_evt_dispatch_FINALIZE(struct PslChanFsm_* const fsm)
{
    return psl_chan_fsm_evt_dispatch_full_(
        fsm, PSL_CHAN_FSM_EVT_FINALIZE, NULL/*arg*/);
}



/**
 * Dispatches PSL_CHAN_FSM_EVT_GET_PEER_CERT_VERIFY_ERR
 * 
 * @param fsm
 * @param pRes Non-NULL pointer to a variable for returning the 
 *             requested info.
 * 
 * @return PslSmeEventStatus
 */
PSL_CONFIG_INLINE_FUNC PslSmeEventStatus
psl_chan_fsm_evt_dispatch_GET_PEER_CERT_VERIFY_ERR(
    struct PslChanFsm_*             const fsm,
    PmSockPeerCertVerifyErrorInfo*  const pRes)
{
    PSL_ASSERT(pRes);

    struct PslChanFsmEvtArgGetPeerCertVerifyErr const arg = {
        .pRes           = pRes
    };

    return psl_chan_fsm_evt_dispatch_full_(
        fsm, PSL_CHAN_FSM_EVT_GET_PEER_CERT_VERIFY_ERR,
        (const PslChanFsmEvtArg*)&arg);
}


/**
 * Dispatches PSL_CHAN_FSM_EVT_LOOKUP_DONE
 * 
 * @param fsm
 * @param errorCode 0 on success
 * @param hosts Host address lookup results: non-NULL on success
 * 
 * @return PslSmeEventStatus
 */
PSL_CONFIG_INLINE_FUNC PslSmeEventStatus
psl_chan_fsm_evt_dispatch_LOOKUP_DONE(struct PslChanFsm_*   const fsm,
                                      PslError              const errorCode,
                                      const struct hostent* const hosts)
{
    struct PslChanFsmEvtArgLookupDone const arg = {
        .errorCode      = errorCode,
        .hosts          = hosts
    };

    return psl_chan_fsm_evt_dispatch_full_(fsm, PSL_CHAN_FSM_EVT_LOOKUP_DONE,
                                           (const PslChanFsmEvtArg*)&arg);
}


/**
 * Performs a 'read' operation conforming to glib's
 * GIOFuncs::io_read() semantics
 * 
 * @param fsm
 * @param buf
 * @param cnt
 * @param pGioStatus
 * @param pNumRead
 * 
 * @return PSL_CONFIG_INLINE_FUNC PslSmeEventStatus
 */
PSL_CONFIG_INLINE_FUNC PslSmeEventStatus
psl_chan_fsm_evt_dispatch_READ(struct PslChanFsm_*  const fsm,
                               void*                const buf,
                               gsize                const cnt,
                               GIOStatus*           const pGioStatus,
                               gsize*               const pNumRead)
{
    /// Pre-init results in case it gets handled by a fall-through handler
    *pGioStatus = G_IO_STATUS_ERROR;
    *pNumRead = 0;

    /// Set up arg and go
    struct PslChanFsmEvtArgRead const arg = {
        .buf            = buf,
        .cnt            = cnt,
        .pGioStatus     = pGioStatus,
        .pNumRead       = pNumRead
    };

    return psl_chan_fsm_evt_dispatch_full_(fsm, PSL_CHAN_FSM_EVT_READ,
                                           (const PslChanFsmEvtArg*)&arg);
}


/**
 * Dispatches PSL_CHAN_FSM_EVT_RENEGOTIATE_CRYPTO
 * @param fsm
 * 
 * @return PslSmeEventStatus
 */
PSL_CONFIG_INLINE_FUNC PslSmeEventStatus
psl_chan_fsm_evt_dispatch_RENEGOTIATE_CRYPTO(struct PslChanFsm_*          const fsm,
                                             const PmSockRenegotiateConf* const pConf,
                                             PmSockCompletionCb*          const cb)
{
    PmSockRenegotiateConf    conf;
    memset(&conf, 0, sizeof(conf));

    /// Process and validate crypto configuration args
    if (pConf) {
        /**
         * @note We copy manually for backward compatibility
         */
        if (0 != (pConf->enabledFlds & kPmSockRenegConfEnabledField_opts)) {
            conf.enabledFlds |= kPmSockRenegConfEnabledField_opts;
            conf.opts = pConf->opts;
        }
    

        if (0 != (pConf->enabledFlds & ~conf.enabledFlds)) {
            PSL_LOG_ERROR(
                "%s (fsm=%p): ERROR: unexpected PmSockRenegConfEnabledFields: 0x%X",
                __func__, fsm, pConf->enabledFlds & ~conf.enabledFlds);
            psl_chan_fsm_set_last_error(fsm, kPslChanFsmErrorSource_psl,
                                        PSL_ERR_INVAL);
            return kPslSmeEventStatus_error;
        }
    }

    struct PslChanFsmEvtArgRenegotiateCrypto const arg = {
        .data           = {
            .conf           = conf,
            .cb             = {
                .which              = (cb
                                       ? kPslChanFsmEvtCompletionCbId_completion
                                       : kPslChanFsmEvtCompletionCbId_none),
    
                .u.completionCb     = {
                    .func       = cb
                }
            }
        }
    };

    return psl_chan_fsm_evt_dispatch_full_(fsm, PSL_CHAN_FSM_EVT_RENEGOTIATE_CRYPTO,
                                           (const PslChanFsmEvtArg*)&arg);
}


/**
 * Dispatches PSL_CHAN_FSM_EVT_RESUME_PLAINTEXT
 * @param fsm
 * 
 * @return PslSmeEventStatus
 */
PSL_CONFIG_INLINE_FUNC PslSmeEventStatus
psl_chan_fsm_evt_dispatch_RESUME_PLAINTEXT(struct PslChanFsm_* const fsm)
{
    return psl_chan_fsm_evt_dispatch_full_(
        fsm, PSL_CHAN_FSM_EVT_RESUME_PLAINTEXT, NULL/*arg*/);
}


/**
 * Dispatches PSL_CHAN_FSM_EVT_SET_CONN_FD
 * 
 * @param fsm
 * @param fd
 * @param opts
 * 
 * @return PSL_CONFIG_INLINE_FUNC PslSmeEventStatus
 */
PSL_CONFIG_INLINE_FUNC PslSmeEventStatus
psl_chan_fsm_evt_dispatch_SET_CONN_FD(struct PslChanFsm_*   const fsm,
                                      int                   const fd,
                                      PmSockFileDescOpts    const opts)
{
    PSL_ASSERT(fd >= 0);
    PSL_ASSERT(!(opts & ~kPmSockFileDescOpt_allValidOpts));

    struct PslChanFsmEvtArgSetConnFD const arg = {
        .fd             = fd,
        .opts           = opts
    };

    return psl_chan_fsm_evt_dispatch_full_(fsm,
                                           PSL_CHAN_FSM_EVT_SET_CONN_FD,
                                           (const PslChanFsmEvtArg*)&arg);
}


/**
 * Dispatches PSL_CHAN_FSM_EVT_SET_SERVER
 * @param fsm
 * @param addrFamily Address family: AF_INET or AF_INET6
 * @param hostStr non-NULL, non-empty hostname or IP addr of
 *                server: MUST not be INADDR_ANY
 * @param port Server port number: MUST not be 0 (any port)
 * @param res
 * 
 * @return PslSmeEventStatus
 */
PSL_CONFIG_INLINE_FUNC PslSmeEventStatus
psl_chan_fsm_evt_dispatch_SET_SERVER(struct PslChanFsm_*    const fsm,
                                     int                    const addrFamily,
                                     const char*            const hostStr,
                                     int                    const port)
{
    PSL_ASSERT(AF_INET == addrFamily || AF_INET6 == addrFamily);
    PSL_ASSERT(hostStr && hostStr[0]);
    PSL_ASSERT(0 != port);

    struct PslChanFsmEvtArgSetServer const arg = {
        .addrFamily     = addrFamily,
        .hostStr        = hostStr,
        .port           = port
    };

    return psl_chan_fsm_evt_dispatch_full_(fsm,
                                           PSL_CHAN_FSM_EVT_SET_SERVER,
                                           (const PslChanFsmEvtArg*)&arg);
}


/**
 * Dispatches PSL_CHAN_FSM_EVT_SET_SOCK_BIND
 * @param fsm
 * @param addrFamily Address family: AF_INET or AF_INET6
 * @param ipAddrStr Non-empty IP address or NULL for INADDR_ANY/in6addr_any
 * @param port Server port number, or 0 (zero) for "any port"
 * 
 * @return PslSmeEventStatus
 */
PSL_CONFIG_INLINE_FUNC PslSmeEventStatus
psl_chan_fsm_evt_dispatch_SET_SOCK_BIND(struct PslChanFsm_* const fsm,
                                          int               const addrFamily,
                                          const char*       const ipAddrStr,
                                          int               const port)
{
    PSL_ASSERT(AF_INET == addrFamily || AF_INET6 == addrFamily);

    PSL_ASSERT(!ipAddrStr || ipAddrStr[0]);

    struct PslChanFsmEvtArgSetSockBind const arg = {
        .addrFamily     = addrFamily,
        .ipAddrStr      = ipAddrStr,
        .port           = port
    };

    return psl_chan_fsm_evt_dispatch_full_(fsm,
                                           PSL_CHAN_FSM_EVT_SET_SOCK_BIND,
                                           (const PslChanFsmEvtArg*)&arg);
}


/**
 * Dispatches PSL_CHAN_FSM_EVT_SHUT_CRYPTO
 * @param fsm
 * @param kind Specifies the kind of shut-down: one-way or
 *             two-way crypto
 * @param pCb Non-NULL pointer to completion callback info
 * @return PslSmeEventStatus
 */
PSL_CONFIG_INLINE_FUNC PslSmeEventStatus
psl_chan_fsm_evt_dispatch_SHUT_CRYPTO(
    struct PslChanFsm_*                  const fsm,
    PslChanFsmEvtShutCryptoKind          const how,
    const PmSockShutCryptoConf*          const pConf,
    const PslChanFsmEvtCompletionCbInfo* const pCb)
{
    PSL_ASSERT(pCb);

    if (pConf) {
        PSL_LOG_ERROR(
            "%s (fsm=%p): ERROR: unexpected non-NULL PmSockShutCryptoConf=%p",
            __func__, fsm, pConf);
        psl_chan_fsm_set_last_error(fsm, kPslChanFsmErrorSource_psl,
                                    PSL_ERR_INVAL);
        return kPslSmeEventStatus_error;
    }

    struct PslChanFsmEvtArgShutCrypto const arg = {
        .how            = how,
        .cb             = *pCb
    };

    return psl_chan_fsm_evt_dispatch_full_(fsm, PSL_CHAN_FSM_EVT_SHUT_CRYPTO,
                                           (const PslChanFsmEvtArg*)&arg);
}


/**
 * Dispatches PSL_CHAN_FSM_EVT_SHUT_SOCK
 * @param fsm
 * @param how Direction of socket shutdown: SHUT_RD, SHUT_WR, or
 *            SHUT_RDWR from sys/socket.h
 * @return PslSmeEventStatus
 */
PSL_CONFIG_INLINE_FUNC PslSmeEventStatus
psl_chan_fsm_evt_dispatch_SHUT_SOCK(struct PslChanFsm_* const fsm,
                                    int                 const how)
{
    struct PslChanFsmEvtArgShutSock const arg = {
        .how            = how
    };

    return psl_chan_fsm_evt_dispatch_full_(fsm, PSL_CHAN_FSM_EVT_SHUT_SOCK,
                                           (const PslChanFsmEvtArg*)&arg);
}


/**
 * Performs a 'write' operation conforming to glib's
 * GIOFuncs::io_write() semantics
 * 
 * @param fsm
 * @param buf
 * @param cnt
 * @param pGioStatus
 * @param pNumWritten
 * 
 * @return PSL_CONFIG_INLINE_FUNC PslSmeEventStatus
 */
PSL_CONFIG_INLINE_FUNC PslSmeEventStatus
psl_chan_fsm_evt_dispatch_WRITE(struct PslChanFsm_* const fsm,
                                const void*         const buf,
                               gsize                const cnt,
                               GIOStatus*           const pGioStatus,
                               gsize*               const pNumWritten)
{
    /// Pre-init results in case it gets handled by a fall-through handler
    *pGioStatus = G_IO_STATUS_ERROR;
    *pNumWritten = 0;

    /// Set up arg and go
    struct PslChanFsmEvtArgWrite const arg = {
        .buf            = buf,
        .cnt            = cnt,
        .pGioStatus     = pGioStatus,
        .pNumWritten    = pNumWritten
    };

    return psl_chan_fsm_evt_dispatch_full_(fsm, PSL_CHAN_FSM_EVT_WRITE,
                                           (const PslChanFsmEvtArg*)&arg);
}



#if defined(__cplusplus)
}
#endif

#endif // PSL_CHANNEL_FSM_EVENTS_H__
