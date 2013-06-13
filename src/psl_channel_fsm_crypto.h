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
 * @file psl_channel_fsm_crypto.h
 * @ingroup psl_internal 
 * 
 * @brief  Crypto state difinitions for the PmSockIOChannel
 *         Finite State Machine.
 * 
 * *****************************************************************************
 */
#ifndef PSL_CHANNEL_FSM_CRYPTO_H__
#define PSL_CHANNEL_FSM_CRYPTO_H__

#include "psl_build_config.h"

#include <stdint.h>
#include <stdbool.h>

#include <PmStateMachineEngine/PalmFsm.h>

#include "palmsocket.h"

#include "psl_channel_fsm_events.h"

#include "psl_io_buf.h"


#if defined(__cplusplus)
extern "C" {
#endif




/**
 * SSL I/O request state for a given I/O direction.
 * 
 * We track the SSL I/O state separately for input (read) and
 * output (write) sub-channels
 */
typedef enum PslChanFsmSSLIOStateId_ {
    /// There is no pending deferred I/O operation and no sticky error
    kPslChanFsmSSLIOState_idle      = 0,

    /// openssl wants us to repeat the operation once sock becomes readable;
    /// @note May apply to both input and output directions
    kPslChanFsmSSLIOState_wantRead,

    /// openssl wants us to repeat the operation once sock becomes writable
    /// @note May apply to both input and output directions
    kPslChanFsmSSLIOState_wantWrite,

    /// There is a permanent error on the given I/O direction
    kPslChanFsmSSLIOState_error
} PslChanFsmSSLIOStateId;



/**
 * openssl input managment info
 */
typedef struct PslChanFsmCryptoInput_ {
    /// Deferred read management: when reading via SSL_read, we prefer to
    /// read directly into the user's buffer to avoid the extra overhead
    /// of buffering.  We can do this as long as SSL_pending() tells us
    /// that data is available for immediate consumption.  However, if there
    /// are no more decoded data records available, SSL_read may not be able
    /// to read the entire record from the socket immediately, necessitating
    /// additional SSL_read call(s) once the WANT_READ or WANT_WRITE condition
    /// is satisfied, and in that case openssl requires that we call SSL_read()
    /// with exactly the same args as when WANT_READ or WANT_WRITE was
    /// indicated.  To comply with this, but still minimize the amount of
    /// bufferred input, we use a tiny one-byte buffer for this purpose.  Once
    /// the deferred write completes, there should be at least one decoded SSL
    /// data record in openssl's own buffer, so subsequent can go directly to
    /// user's buffer.
    uint8_t                 deferredReadOneByteBuf[1];
    bool                    deferredByteAvailable;  ///< FALSE if buf is empty

    /// SSL Input state.  When set to kPslChanFsmSSLIOState_error,
    /// pslErr MUST be set to a non-zero error value.  In
    /// kPslChanFsmSSLIOState_error, no further input is possible.
    /// When set to one of kPslChanFsmSSLIOState_wantRead/wantWrite,
    /// we're waiting to make a deferred SSL_read() call into our
    /// deferredReadOneByteBuf buffer.
    PslChanFsmSSLIOStateId  ioState;

    /// Sticky input error; when non-zero, ioState MUST be
    /// kPslChanFsmSSLIOState_error.  Once set to a non-zero PslError value,
    /// no further input is possible.
    PslError                pslErr;     ///< sticky input error
} PslChanFsmCryptoInput;


/**
 * openssl output managment info
 */
typedef struct PslChanFsmCryptoOutput_ {
    /// internal buffer used for SSL_write deferred processing
    /// @see crypto_handle_WRITE() and read the comments
    PslIOBuf                buf;

    /// SSL output state.  When set to kPslChanFsmSSLIOState_error,
    /// pslErr MUST be set to a non-zero error value.  In
    /// kPslChanFsmSSLIOState_error, no further output is possible
    PslChanFsmSSLIOStateId  ioState;

    /// Sticky output error; when non-zero, ioState MUST be
    /// kPslChanFsmSSLIOState_error.  Once set to a non-zero PslError value,
    /// no further output is possible.
    PslError                pslErr; ///< sticky output error
} PslChanFsmCryptoOutput;



/**
 * Data shared by all Crypto states 
 *  
 * @note Define semantics of the structure's (and 
 *       substructures') members such that initializing the
 *       structure to 0's will give it the correct initial
 *       state.
 *  
 * @see crypto_shared_info() 
 */
typedef struct PslChanFsmCryptoSharedInfo_ {
    PslChanFsmEvtConnKind   connKind;

    /// SSL Channel I/O state
    struct {
        /// Input channel info
        PslChanFsmCryptoInput       in;

        /// Output channel info
        PslChanFsmCryptoOutput      out;
    } io;

    /// Our referenced openssl SSL channel instance, or NULL if none yet or destroyed
    SSL*                    ssl;

    /// Referenced PmSockSSLContext instance, or NULL when unrefeferenced
    PmSockSSLContext*       sslCtx;

    /// Crypto configuration args from user
    PmSockCryptoConfArgs    cryptoConf;

    /// Set to TRUE during SSL/TSL Connect or Accept when it detects end of
    /// the initial handshake, which may have succeeded or failed
    bool                    sslHandshakeFinished;

    /// Peer verify record used by crypto_ssl_peer_verify_callback()
    struct {
        /// Set to TRUE when certificate verification session begins and
        /// to FALSE when it ends.
        bool                        verifyInProgress;

        /// Set to TRUE by crypto_ssl_peer_verify_callback().  Allows us
        /// to determine whether certificate verification was attempted
        bool                        peerVerifyCalled;

        /// If our own peer certificate verification logic detects an error,
        /// verifyFailCode will be set to the corresponding non-zero code. 
        PslError                    verifyFailCode;

    }                       pv;


    /// Last GIOCondition on our multi-fd watch instance; our multi-fd watch
    /// wrapper functions use this field to optimize out unnecessary calls
    /// to psl_multi_fd_watch_add_or_update_fd()
    GIOCondition            lastGIOCondition;

} PslChanFsmCryptoSharedInfo;



/**
 * SSL session 'failed' state: we land here upon SSL connection 
 * attempt or SSL shutdown failure. 
 * 
 * @note In this state, the integrity of data on the socket
 *       connection is unknown (e.g., there may be some SSL/TLS
 *       bits still in input/output stream)
 */
typedef struct {
    PslSmeStateBase         base; ///< MUST BE FIRST MEMBER

    struct PslChanFsmEvtBeginArgCryptoFail  arg; ///< kFsmEventBegin arg
} PslChanFsmCryptoFailState;


/**
 * SSL session connection-establishment state
 */
typedef struct {
    PslSmeStateBase         base; ///< MUST BE FIRST MEMBER

    struct PslChanFsmEvtBeginArgCryptoConn  arg;

    /// Non-zero PslError error code set if hard failure
    PslError                failPslErr;

    /// Set to TRUE once calls to SSL_connect begin
    bool                    started;
} PslChanFsmCryptoConnState;


/**
 * SSL Session state: we enter this state once we have
 * established an SSL session.
 */
typedef struct {
    PslSmeStateBase         base; ///< MUST BE FIRST MEMBER
} PslChanFsmCryptoSSLState;


/**
 * Phases of SSL/TLS renegotiation used by 
 * PslChanFsmCryptoRenegotiateState 
 */
typedef enum PslChanFsmCryptoRenegPhase_ {
    kPslChanFsmCryptoRenegPhase_init,

    kPslChanFsmCryptoRenegPhase_flushOut,

    /// The "requestHello" phase is for server side only: during this phase, the server
    /// side sends the HelloRequest messsage to the client side.  The client side
    /// may or may not honor the request.
    kPslChanFsmCryptoRenegPhase_requestHello,

    /// The "handshake" phase is mandatory for client and optional for server; it
    /// may be turned on for the server side via the waitForClientHandshake
    /// renegotiation option.
    kPslChanFsmCryptoRenegPhase_handshake,

    /// The "done" phase indicates either successful or failed completion
    kPslChanFsmCryptoRenegPhase_done
} PslChanFsmCryptoRenegPhase;


/**
 * SSL/TLS renegotiation state: we enter this state following 
 * renegotiation request. Upon successful completion, we return 
 * to PslChanFsmCryptoSSLState.
 */
typedef struct {
    PslSmeStateBase         base; ///< MUST BE FIRST MEMBER

    struct PslChanFsmEvtBeginArgCryptoRenegotiate   arg;

    PslChanFsmCryptoRenegPhase    phase;

    /// pslerr is meaningful only when phase is
    /// kPslChanFsmCryptoRenegPhase_done;  PSL_ERR_NONE indicates success.
    PslError                            pslerr;

} PslChanFsmCryptoRenegotiateState;


/**
 * SSL Shutdown phases; used by PslChanFsmCryptoShutState
 */
typedef enum PslChanFsmCryptoShutPhase_ {
    kPslChanFsmCryptoShutPhase_init,

    kPslChanFsmCryptoShutPhase_flushOut,

    /// sending "close  notify" to peer
    kPslChanFsmCryptoShutPhase_shut1,

    /// waiting for peer's "close notify"
    kPslChanFsmCryptoShutPhase_shut2,

    /// Completed successfully
    kPslChanFsmCryptoShutPhase_success,

    /// Failed
    kPslChanFsmCryptoShutPhase_failed
} PslChanFsmCryptoShutPhase;


/**
 * SSL Shutdown handshake state: handles one-way and two-way SSL
 * Shutdown handshakes
 */
typedef struct {
    PslSmeStateBase         base; ///< MUST BE FIRST MEMBER

    struct PslChanFsmEvtBeginArgCryptoShut  arg;

    PslChanFsmCryptoShutPhase       phase;
} PslChanFsmCryptoShutState;



/**
 * SSL mode parent state
 */
typedef struct {
    PslSmeStateBase         base; ///< MUST BE FIRST MEMBER

    /**
     * Child states
     */
    PslChanFsmCryptoConnState           connState;
    PslChanFsmCryptoFailState           failState;
    PslChanFsmCryptoRenegotiateState    renegotiateState;
    PslChanFsmCryptoShutState           shutState;
    PslChanFsmCryptoSSLState            sslState;


    /**
     * Data shared by all Crypto states
     */
    PslChanFsmCryptoSharedInfo      sslInfo;
} PslChanFsmCryptoModeState;


/**
 * Initialize crypto mode states and and insert them into the FSM
 * 
 * @param fsm
 * @param parent The state that should be the parent state for
 *               our states (NULL if root)
 */
void
psl_chan_fsm_crypto_init(struct PslChanFsm_* fsm, PslSmeStateBase* parent);

#if defined(__cplusplus)
}
#endif

#endif // PSL_CHANNEL_FSM_CRYPTO_H__
