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
 * @file palmsocket.h
 * @ingroup psl_palmsocket
 * 
 * @brief Public API for Palmsocket GIOChannel and GSource
 *        abstraction.  Supports plaintext and SSL/TLS modes.
 *
 * @{
 * *****************************************************************************
 */
#ifndef PALMSOCKET_H__
#define PALMSOCKET_H__

#include <stdint.h>
#include <glib.h>

#include "palmsockerror.h"          ///< our public error codes/utilities
#include "palmsocklog.h"            ///< our public logging control API
#include "palmsockopensslutils.h"   ///< our public openssl utilities



#if defined(__cplusplus)
extern "C" {
#endif





/** 
 * *****************************************************************************
 *       PUBLIC API
 * 
 * @note The legacy API definitions are at the bottom of this
 *       file
 * 
 * @note The result of using both legacy and the new API on the
 *       SAME channel instance is undefined and unsupported.
 *  
 * Helpful Usage Info this module is in palmsocket.dox
 *  
 * See @ref palmsocket_usage_info and 
 * @ref palmsocket_comms_client_server
 *
 * *****************************************************************************
 */ 


/**
 * PmSockIOChannel options that may be bitwise-or'ed together
 */
typedef enum PmSockOptionFlags_ {

    /**
     * Allows socket address re-use.  This option may be needed when
     * also specifying a local socket bind address to avoid EADDRINUSE.
     * 
     * @note WARNING: However, you really need to know what you're
     *       doing, as the use of this option may lead to corruption
     *       of the TCP/IP stream due to stale, wondering packets
     *       from previous session finding their way to the
     *       destination.
     * 
     * @see SO_REUSEADDR
     */
    kPmSockOptFlag_sockAddrReuse    = 0x01,

    /**
     * Causes operations that might cause SIGPIPE to be wrapped in
     * code that suppresses SIGPIPE.
     *
     * @note This option is less efficient than having the user
     *       disable SIGPIPE at process or thread level.  It's
     *       provided for users (such as other shared libraries)
     *       that don't have control over their process or thread of
     *       execution.
     * 
     * @todo NOT IMPLEMENTED YET; Implement this option
     */
    kPmSockOptFlag_sigpipeGuard     = 0x02,

    /**
     * This value MUST contain all valid PmSockOptionFlags values
     * bitwise-or'ed together. It is used for error-checking by
     * PmSockIOChannel implementation.
     */
    kPmSockOptFlag_allValidOpts     = (kPmSockOptFlag_sockAddrReuse |
                                       kPmSockOptFlag_sigpipeGuard),

    /// So we get at least 32-bit width for this enum
    kPmSockOptFlag_reserved         = 0xFFFFFFFF
} PmSockOptionFlags;


/**
 * Opaque definition of PSL thread context for use by PalmSocket
 * instances.  The thread context represents thread-specific
 * state.
 * 
 * The thread context is reference-counted; all libpalmsocket
 * constructors that accept it as an argument (e.g.,
 * PmSockCreateChannel) will acquire and hold reference as long
 * as they need the thread context, and release reference when
 * no longer needed.
 * 
 * A thread context instance is freed by libpalmsocket when the
 * instance's reference count drops to 0
 * 
 * @see PmSockThreadCtxNewFromGMain,
 *      PmSockThreadCtxUnref
 */
typedef struct PmSockThreadContext_ PmSockThreadContext;


/**
 * Opaque definition of SSL Context.  An SSL Context represents
 * cached SSL data that may be shared by multiple SSL
 * GIOChannels.
 * 
 * A single SSL Context may be shared by multiple SSL
 * GIOChannels executing on different threads.
 * 
 * The SSL Context is reference-counted; all libpalmsocket
 * constructors that accept it as an argument (e.g.,
 * PmSockCreateChannel) will acquire and hold reference as long
 * as they need the SSL Context, and release reference when no
 * longer needed.
 * 
 * An SSL Context instance is freed by libpalmsocket when the
 * instance's reference count drops to 0
 * 
 * @see PmSockSSLCtxNew, PmSockSSLCtxUnref
 */
typedef struct PmSockSSLContext_ PmSockSSLContext;


/**
 * Opaque definition of Palm Socket IO Channel.  A pointer to
 * PmSockIOChannel may be cast to the GIOChannel point for
 * passing to g_io_* functions that take a GIOchannel pointer.
 * 
 * @note Access to a specific instance of PmSockIOChannel is
 *       NOT thread-safe.
 */
typedef struct PmSockIOChannel_ PmSockIOChannel;

                                   

/**
 * PmSockCompletionCb: User's callback function type that
 * may be passed to PmSockConnectPlain(), PmSockConnectCrypto(),
 * etc.
 * 
 * If requested, this callback will be called upon completion of
 * the requested operation, indicating the operation's success
 * or failure.
 * 
 * @note This callback is called only from the scope of
 *       palmsocket's own GSource dispatch, and never from the
 *       scope of an PmSockIOChannel or g_io_channel API
 *       function call.
 * 
 * @note The given PmSockIOChannel instance is fully re-entrant
 *       from the scope of this callback (i.e., any permitted
 *       g_io_channel_* and any PmSockIOChannel function may be
 *       called)
 * 
 * @param channel PmSockIOChannel instance associated with the
 *                completed operation.
 * 
 * @param userData User data that was associated with this
 *                 PmSockIOChannel instance via
 *                 PmSockSetUserData() or NULL if none was set.
 * @param errorCode 0 if the operation completed successfully;
 *                  non-zero PslError code if the operation
 *                  failed.
 */
typedef void PmSockCompletionCb(PmSockIOChannel*    channel,
                                void*               userData,
                                PslError            errorCode);


/**
 * File descriptor options that may be passed to
 * PmSockSetConnectedFD()
 * 
 * @see PmSockSetConnectedFD
 */
typedef enum PmSockFileDescOpts_ {

    /**
     * If set, prevents the palmsocket instance from closing the
     * file descriptor that was provided it via
     * PmSockSetConnectedFD()
     */
    kPmSockFileDescOpt_doNotClose       = 0x4000,

    kPmSockFileDescOpt_allValidOpts     = 
        (kPmSockFileDescOpt_doNotClose)


} PmSockFileDescOpts;



/**
 * Peer certificate verification result structure for 
 * PmSockGetPeerCertVerifyError() 
 */
typedef struct PmSockPeerCertVerifyErrorInfo_ {
    /**
     * An error code that would be returned by openssl's 
     * SSL_get_verify_result() (X509_V_ERR_CERT_HAS_EXPIRED, etc.) 
     * or X509_V_OK if none was detected or if peer certificate 
     * verification was not performed due to an earlier error or 
     * because peer certificate verification was not required (or if 
     * user's peer-verify callback improperly reset it during 
     * verification) 
     */
    long                opensslx509_v_err;

    /**
     * A certificate verification error detected by libpalmsocket's 
     * extended certificate verification logic, or PSL_ERR_NONE if 
     * certificate verification succeeded.  If psl_v_err is
     * PSL_ERR_SSL_CERT_VERIFY, then opensslx509_v_err may contain a
     * more precise X509_V_ERR_* cause code. 
     */
    PslError            psl_v_err;
} PmSockPeerCertVerifyErrorInfo;


/**
 * PmSockPeerVerifyCbInfo: extended info structure passed to 
 * PmSockOpensslPeerVerifyCb 
 *  
 * @see PmSockOpensslPeerVerifyCb 
 * @see PmSockCertVerifyOpts 
 * @see X509_STORE_CTX_get_error()
 */
typedef struct PmSockPeerVerifyCbInfo_ {
    const PmSockIOChannel*          channel;

    /**
     * User data that was associated with this PmSockIOChannel 
     * instance via PmSockSetUserData() or NULL if none was set
     */
    void*                           userData;

    /**
     * Pointer to hostname or address string that was set as the 
     * "serverAddress" via PmSockSetConnectAddress(); NULL or empty 
     * string if none was set.
     */
    const char*                     hostname;

    /**
     * A certificate verification error detected by libpalmsocket's 
     * extended certificate verification logic (extended 
     * verification features are controlled via 
     * PmSockCertVerifyOpts). If the verify callback's preverifyOK 
     * arg is FALSE, the user needs to check both this field as well
     * as the value returned by X509_STORE_CTX_get_error() for the 
     * given x509_store_ctx_st instance in order to determine the 
     * actual cause. If this field is PSL_ERR_SSL_CERT_VERIFY, then 
     * X509_STORE_CTX_get_error() may provide a more specific cause.
     */
    PslError                        pslVerifyError;

    /// The reserved field is set to zero by libpalmsocket;
    /// It's intended to be used as a flags field to indicate which additional
    /// fields are present when the structure is expanded in the future.
    uint32_t                        reserved;
} PmSockPeerVerifyCbInfo;


/**
 * PmSockOpensslPeerVerifyCb: User's callback function type that
 * may be passed to PmSockConnectCrypto() and 
 * PmSockAcceptCrypto() via PmSockCryptoConfArgs. 
 * 
 * @note _WARNING_: The PmSockIOChannel instance for which the
 *       verification callback is emitted is NOT re-entrant from
 *       the scope of this callback. The user MUST NOT call any
 *       PmSockIOChannel (including g_io_channel) API on the
 *       given PmSockIOChannel instance from the scope
 *       of this callback function (in order to avoid
 *       run-to-completion violation in libpalmsocket FSM).
 *       Instead, you may schedule a gmain timeout or make use
 *       of PmSockCompletionCb (if one is pending) to take the
 *       necessary action.
 * 
 * @note This callback is called only from the scope of
 *       palmsocket's own GSource dispatch, and never from the
 *       scope of the user's function call to a PmSockIOChannel
 *       or g_io_channel API.
 * 
 * This callback may be called _multiple_ times during the SSL 
 * handshake as openssl performs its own pre-verification of 
 * a given certificate in certificate chain. It may be called
 * one or more times for each certificate in the certificate 
 * chain being validated. (it may be called more than once for a 
 * given certificate in the chain if multiple errors are present 
 * in the certificate, but the prior error(s) were suppressed by 
 * user's callback. 
 * 
 * @todo Verify whether this callback may also be called after 
 *       initial SSL/TLS connection establishment whenever
 *       SSL/TLS re-negotiation is subsequently requested by
 *       either server or client.
 * 
 * This callback provides the user with the opportunity to
 * augment and/or override openssl's and palmsocket's peer 
 * certificate verification during the negotiation process. You 
 * may call openssl API functions directly to accomplish this. 
 * 
 * If user returns FALSE from this callback, the SSL certificate
 * verification will be deemed a failure, and a failure alert
 * will be sent to the peer.  If this failure  occurs during an 
 * explicit SSL session establishment procedure (requested via 
 * PmSockConnectCrypto, etc.) and a PmSockCompletionCb callback
 * is associated with that request, that PmSockCompletionCb
 * function will be called shortly with the PslError code value
 * reflecting the cause of failure.  If the failure is due to 
 * the user's own assessment, the user may wish to note this by 
 * setting the X509_V_ERR_APPLICATION_VERIFICATION error code on 
 * the given x509_store_ctx_st instance via 
 * X509_STORE_CTX_set_error(), and note the exact failure reason
 * in the user's own data structures. 
 *  
 * @param preverifyOK TRUE if peer certificate pre-verification
 *                    performed by openssl on the current
 *                    certificate in the chain was successful.
 *                    FALSE if openssl determined this
 *                    certificate to be invalid.  The value
 *                    returned by X509_STORE_CTX_get_error()
 *                    applies to the current invocation of the
 *                    callback _only_ when preverifyOK is FALSE,
 *                    otherwise it may reflect a prior
 *                    (suppressed) invocation of the callback
 * 
 * @param x509_ctx Pointer to openssl's X509_STORE_CTX instance
 *                 corresponding to the current certificate
 *                 being validated. (interpret as
 *                 X509_STORE_CTX*)
 *  
 * @param pInfo Non-NULL pointer to extended verification 
 *              information.
 * 
 * @return bool TRUE to allow the certificate chain verification
 *         process to continue (regardless of preverifyOK);
 *         FALSE to force the SSL verification process to fail
 *         (regardless of preverifyOK)
 *  
 * @see PmSockConnectCrypto() 
 * @see PmSockAcceptCrypto() 
 * @see SSL_set_verify() ('man SSL_set_verify') for openssl's
 *      semantics of this operation
 * @see PmSockCryptoConfArgs 
 * @see PmSockOpensslVerifyHostname() 
 * @see PmSockX509CheckCertHostNameMatch() 
 */
typedef bool PmSockOpensslPeerVerifyCb(bool                           preverifyOK,
                                       struct x509_store_ctx_st*      x509_ctx,
                                       const PmSockPeerVerifyCbInfo*  pInfo);


/**
 * Lifecycle phases for the underlying openssl SSL instance used
 * with PmSockOpensslLifecycleCb
 */
typedef enum PmSockOpensslLifecyclePhase_ {
    /**
     * After a libpalmsocket channel instantiates and initializes
     * the underlying openssl SSL instance.
     * 
     * @note Users MUST be careful when performing additional SSL
     *       initialization from this callback so as not to conflict
     *       with palmsocket implementation.  Over time, we will
     *       likely add sufficient abstraction API whereby direct
     *       configuration of the underlying implementation by user
     *       would become unnecessary.
     * 
     *       In particular, palmsocket makes use of
     *       SSL_set_app_data, SSL_set_verify, SSL_set_mode, and
     *       SSL_set_fd, among others.
     */
    kPmSockOpensslLifecyclePhase_init       = 0


    /**
     * @note We don't support ssl 'destroy' phase notification
     *       because destruction happens synchronously with
     *       PmSockIOChannel API calls, and such callback would have
     *       to be emitted from the scope of a user's
     *       PmSockIOChannel API call, which is often error-prone.
     */

} PmSockOpensslLifecyclePhase;



/**
 * PmSockOpensslLifecycleCb: User's callback function type that
 * may be passed to PmSockConnectCrypto and PmSockAcceptCrypto 
 * via PmSockCryptoConfArgs. 
 * 
 * This callback may be useful for performing additional
 * initialization procedures on the underlying openssl SSL
 * instance.
 * 
 * In particular, it may be used to optimize SSL/TLS negotiation
 * handshake performance by re-using a previously-established
 * SSL/TLS session as follows: cache a previously-established
 * SSL/TLS session for a given server/port combination from
 * PmSockOpensslPeerVerifyCb (you will want to acquire your own
 * reference to the session via SSL_get1_session); then use
 * SSL_set_session() to set the SSL session during
 * kPmSockOpensslLifecyclePhase_init when re-connecting to the
 * same server/port.
 * 
 * @note _WARNING_: The PmSockIOChannel instance for which the
 *       PmSockOpensslLifecycleCb callback is emitted is NOT
 *       re-entrant from the scope of this callback. The user
 *       MUST NOT call any PmSockIOChannel (including
 *       g_io_channel) API on the given PmSockIOChannel
 *       instance from the scope of this callback function (in
 *       order to avoid run-to-completion violation in
 *       libpalmsocket FSM).
 * 
 * @note This callback is called only from the scope of
 *       palmsocket's own GSource dispatch, and never from the
 *       scope of a PmSockIOChannel or g_io_channel API
 *       function call.
 * 
 * @param channel PmSockIOChannel instance associated with this
 *                callback.  See the _WARNING_ above
 *                regarding not accessing any
 *                PmSockIOChannel/g_io_channel API for this
 *                instance.
 * 
 * @param userData User data that was associated with this
 *                 PmSockIOChannel instance via
 *                 PmSockSetUserData() or NULL if none was set.
 * 
 * @param ssl Pointer to the openssl SSL instance whose
 *            lifecycle is being reported (interpret as SSL*).
 * 
 * @param phase The lifecycle phase of the given SSL instance.
 */
typedef void PmSockOpensslLifecycleCb(const struct PmSockIOChannel_* channel,
                                      void*                          userData,
                                      struct ssl_st*                 ssl,
                                      PmSockOpensslLifecyclePhase    phase);


/**
 * PmSockCertVerifyOpts: Certificate verification options to
 * be performed in addition to the standard certificate chain 
 * validation of the underlying SSL/TLS implementation; multiple
 * compatible non-zero kPmSockCertVerifyOpt_* flags may be 
 * bitwise-or'ed together. 
 *  
 * @see PmSockOpensslPeerVerifyCb 
 * @{
 */
typedef uint32_t    PmSockCertVerifyOpts;
enum {
    /**
     * Indicates that no special verification options are requested 
     * beyond the standard certification chain validation performed 
     * by the underlying SSL/TLS implementation. 
     */
    kPmSockCertVerifyOpt_none                       = 0,

    /**
     * Perform hostname/ipaddress match against the 
     * dNSName/ipAddress/CN fields of the peer certificate per 
     * RFC-2595, RFC-2818, and accepted practices
     */
    kPmSockCertVerifyOpt_checkHostname              = 0x01,

    /**
     * When peer certificate chain verification process detects an 
     * error, this option causes palmsocket to fall-back to a check 
     * of whether a matching certificate with the peer certificate's
     * subject name is installed in the device's default certificate
     * store; if an exact match is found (exact comparison between 
     * certs), the verification is allowed to succeed regardless of 
     * any other errors that were detected during the certificate 
     * chain verification process. 
     */
    kPmSockCertVerifyOpt_fallbackToInstalledLeaf    = 0x02

};
/**@}*/



/**
 * PmSockCryptoConfigEnabledOpts: These flags may be
 * bitwise-or'ed together to select the desired fields in the 
 * PmSockCryptoConfArgs structure. 
 *  
 * @{
 */
typedef uint32_t        PmSockCryptoConfigEnabledOpts;
enum {
    kPmSockCryptoConfigEnabledOpt_lifecycleCb          = 0x00000001,

    kPmSockCryptoConfigEnabledOpt_verifyCb             = 0x00000002,

    kPmSockCryptoConfigEnabledOpt_verifyOpts           = 0x00000004

};
/**@}*/


/** 
 * PmSockCryptoConfArgs: SSL configuration arguments for
 * PmSockConnectCrypto() and PmSockAcceptCrypto().
 */
typedef struct PmSockCryptoConfigArgs_ {
    /// For backward and forward compatibility: indicates which of the following
    /// fields are set.  If a flag is not enabled, the corresponding field below
    /// will be ignored.
    PmSockCryptoConfigEnabledOpts      enabledOpts;

    /// enabled by kPmSockCryptoConfigEnabledOpt_lifecycleCb
    PmSockOpensslLifecycleCb*   lifecycleCb;

    /// enabled by kPmSockCryptoConfigEnabledOpt_verifyCb
    /// @note verifyCb may co-exist with verifyOpts
    PmSockOpensslPeerVerifyCb*  verifyCb;

    /// enabled by kPmSockCryptoConfigEnabledOpt_verifyOpts
    PmSockCertVerifyOpts        verifyOpts;
} PmSockCryptoConfArgs;



/**
 * PmSockRenegOpts: SSL/TLS rengegotiation options; individual 
 * flags may be bitwise-or'ed together 
 *  
 * @see PmSockRenegotiateConf 
 * @{ 
 */
typedef uint32_t        PmSockRenegOpts;
enum {
    /**
     * Server-side-only option: forces wait for completion of
     * handshake after sending the "RequestHello" message to the
     * client.  This forces further server writes to be postponed
     * until the session is renegotiated.  This option is _invalid_ 
     * for the client side. 
     * 
     * @note When the client recieves a "RequestHello" message 
     *       from the server, the client may choose to honor the
     *       request or ignore it.  If the client chooses to ignore
     *       it, this option will result in an indefinite suspension
     *       of writes from the server.
     *  
     * @note EXPERIMENTAL: FOR TESTING ONLY: this option allows our
     *       test code to discern whether the renegotiation
     *       handshake has actually been performed
     */
    kPmSockRenegOpt_waitForClientHandshake      = 0x01
};
/**@}*/


/**
 * PmSockRenegConfEnabledFields: flags are used to indicate 
 * which fields are enabled when passing PmSockRenegotiateConf 
 * structure to PmSockRenegotiateCrypto().  Multiple flags may 
 * be bitwise-or'ed together 
 * @{ 
 */
typedef uint32_t        PmSockRenegConfEnabledFields;
enum {
    /// Enables the PmSockRenegotiateConf::opts field
    kPmSockRenegConfEnabledField_opts           = 0x01
};
/**@}*/


/**
 * PmSockRenegotiateConf: PmSockRenegotiateCrypto() 
 * configuration parameters 
 *  
 * Future: add timeout suport 
 *  
 * @note For implementation convenience, define the fields such 
 *       that the value of 0/NULL will have the default
 *       semantics.
 *  
 * @see PmSockRenegotiateCrypto() 
 */
typedef struct PmSockRenegotiateConf_ {
    /// For backward and forward compatibility: indicates which of the following
    /// fields are set.  If a flag is not set, the corresponding field below
    /// will be ignored.
    PmSockRenegConfEnabledFields    enabledFlds;


    /// Enabled by kPmSockRenegConfEnabledField_opts
    PmSockRenegOpts                 opts;
} PmSockRenegotiateConf;



/**
 * PmSockCreateChannel(): Creates a new PSL GIOChannel instance 
 * with a reference count of 1. 
 * 
 * A connect address (PmSockSetConnectAddress) or connected file
 * descriptor (PmSockSetConnectedFD) MUST be set before 
 * requesting connection-establishment. 
 * 
 * @note Access to a specific instance of PmSockIOChannel is
 *       NOT thread-safe!
 * 
 * @note GIOChannel buffered IO and encoding is not supported
 *       (because GIOChannel buffer flushing relies on blocking
 *       writes, which we don't support).
 * 
 * @note A write to PmSockIOChannel may result in a portion of
 *       the output data getting bufferred (in response
 *       to SSL_ERROR_WANT_READ and SSL_ERROR_WANT_WRITE from
 *       SSL_write()) and sent at a later time by PmSockIOChannel
 *       implementation.  Calling either
 *       PmSockShutCryptoOneWay() or PmSockShutCryptoTwoWay()
 *       will flush bufferred output data (if any) before
 *       starting the requested SSL shutdown handshake.
 * 
 * @note A PmSockIOChannel instance in SSL mode must be
 *       monitored for readability and the incoming data must be
 *       read in order to release system resources and prevent a
 *       stalled connection (e.g., openssl sometimes needs to
 *       perform internal reads from the socket in order to
 *       satisfy a data SSL_write() request, such as during
 *       re-negotiation, so data should be promptly removed from
 *       openssl's buffers).
 * 
 * @note A GSource watch created from a specific instance of
 *       PmSockIOChannel MUST be attached to the same gmain
 *       context that is associated with the corresponding
 *       instance of PmSockIOChannel via threadCtx, and accessed
 *       only from the SAME thread!
 * 
 * @note Calling g_io_channel_close guarantees to cancel any
 *       pending activities and callbacks from the channel.
 * 
 * 
 * @param threadCtx A PmSockThreadContext instance to associate
 *                  with this channel. Upon successful return,
 *                  this function acquires its own reference to
 *                  the given PmSockThreadContext instance and
 *                  holds it as long as needed by the
 *                  implementation.  If NULL is passed, this
 *                  PmSockIOChannel instance will use the
 *                  default gmain context.  The caller is still
 *                  responsible for running the gmain loop
 *                  associated with the underlying gmain
 *                  context.
 * 
 * @param options Values from PmSockOptionFlags bitwise-or'ed
 *                together, or 0 if none. @note In the future,
 *                the options might be used to select a specific
 *                underlying SSL/TLS implementation.
 * 
 * @param userLabel: An OPTIONAL (may be NULL) short,
 *                 zero-terminated string that will be displayed
 *                 in logs associated with this channel;
 *                 this string is copied;
 * 
 * @param channel Non-NULL location for returning a pointer to
 *                the PmSockIOChannel instance; undefined on
 *                error. The newly-created instance has a
 *                reference count of 1 (one) that is owned by
 *                the caller. When done with the channel, use
 *                g_io_channel_unref() to free your reference to
 *                the returned channel instance. Once your
 *                reference is freed, you MUST NOT make any
 *                further accesses or perform operatios on that
 *                channel instance.
 * 
 * @return PslError 0 on success; non-zero PslError code on
 *         failure
 * 
 * @see PmSockSetConnectAddress
 * @see PmSockSetSocketBindAddress
 * @see PmSockSetUserData
 * @see PmSockCreateWatch()
 */
PslError
PmSockCreateChannel(PmSockThreadContext* threadCtx,
                    PmSockOptionFlags    options,
                    const char*          userLabel,
                    PmSockIOChannel**    channel);


/**
 * PmSockGetLastError(): Returns the last recorded PslError
 * value for the given PmSockIOChannel instance. It's only
 * meaningful to call this function immediately after another
 * PmSockIOChannel API returned with an indication of failure or
 * when g_io_channel_read_chars or g_io_channel_write_chars
 * returns G_IO_STATUS_ERROR.
 * 
 * @note The error value is meaningful ONLY IMMEDIATELY after a
 *       PmSockIOChannel API function call that RETURNED
 *       AN INDICATION OF FAILURE (typically, a
 *       G_IO_STATUS_ERROR from g_io_channel_read/write calls);
 *       the value is undefined, otherwise (e.g., in other
 *       cases, it might represent an internal intermediate
 *       error, which might not be an actual error)
 * 
 * @note PmSockIOChannel's GIOChannel methods
 *       (g_io_channel_xxxx()) return GError instances with
 *       GIOChannelError values in the G_IO_CHANNEL_ERROR domain
 *       that are mapped from libpalmsocket's internal error
 *       representation. However, PmSockGetLastError() will
 *       return PslError codes in the PmSockErrGErrorDomain() domain.
 * 
 * @param channel Non-NULL PmSockIOChannel instance to which you
 *                hold a reference.
 * 
 * @return PslError A non-zero error code that represents the
 *         error from the just-called PmSockIOChannel API
 *         function that *returned an indication of failure*.
 *         The error value is undefined under all other
 *         circumstances (including successful return from a
 *         PmSockIOChannel API function).
 */
PslError
PmSockGetLastError(const PmSockIOChannel* channel);


/**
 * Peek the PmSockThreadContext instance associated with the
 * given palmsocket instance.
 * 
 * This function does NOT increment the PmSockThreadContext's reference
 * count, so the returned PmSockThreadContext pointer is valid
 * only as long as you're holding a valid reference count to the
 * corresponding PmSockIOChannel instance. You may call
 * PmSockThreadCtxRef() if you need your own reference to it.
 * 
 * @param channel Non-NULL PmSockIOChannel instance to which you
 *                hold a reference.
 * 
 * @return PmSockThreadContext*
 */
PmSockThreadContext*
PmSockPeekThreadContext(const PmSockIOChannel* channel);


/**
 * PmSockSetUserData(): Associates an arbitrary pointer value
 * with the given PmSockIOChannel instance.  This value may be
 * retrieved via PmSockGetUserData()
 * 
 * @param channel Non-NULL PmSockIOChannel instance to which you
 *                hold a reference.
 * 
 * @param userData An arbitrary pointer value that you wish to
 *                 associate with this PmSockIOChannel instance.
 * 
 * @see PmSockGetUserData()
 */
void
PmSockSetUserData(PmSockIOChannel* channel, void* userData);


/**
 * PmSockGetUserData(): Returns the user data pointer value that
 * was associated with the given PmSockIOChannel instance via
 * PmSockSetUserData()
 * 
 * @param channel Non-NULL PmSockIOChannel instance to which you
 *                hold a reference.
 * 
 * @return void* User data pointer value that was associated
 *         with the given PmSockIOChannel instance via
 *         PmSockSetUserData(); NULL if none was associated.
 * 
 * @note There is no way to discern between a NULL value set by
 *       user and the case where no value was set by user: NULL
 *       would be returned in both cases.
 */
void*
PmSockGetUserData(const PmSockIOChannel* channel);


/**
 * PmSockSetConnectAddress(): Sets the server address (or
 * hostname) and port for the given PmSockIOChannel instance.
 * This function MUST be called before initiating connection
 * establishment.
 * 
 * @note PmSockSetConnectAddress may only be called once on a
 *       given PmSockIOChannel instance, and only before
 *       PmSockConnect*()
 * 
 * @param channel Non-NULL PmSockIOChannel instance to which you
 *                hold a reference.
 * 
 * @param addrFamily Address family: Only AF_INET is presently
 *                   supported (AF_INET6 support to be added
 *                   later)
 * 
 * @param serverAddress Non-NULL, non-empty ASCII (IA5),
 *                      zero-terminated string representing IP
 *                      address or hostname of the server; the
 *                      string is copied.
 * 
 * @param serverPort Non-zero port number of the server
 * 
 * @return PslError 0 on success; non-zero PslError code on
 *         failure
 *  
 * @todo For IDNA support, may need to accept cert name and 
 *       hostname args in UTF8 format. (UTF8 is backward
 *       compatible with IA5)
 */
PslError
PmSockSetConnectAddress(PmSockIOChannel*    channel,
                        int                 addrFamily,
                        const char*         serverAddress,
                        int                 serverPort);

/**
 * PmSockSetSocketBindAddress(): Sets the local bind address and
 * port for the given channel.  If a bind address/port is needed
 * for the connection socket, this function MUST be called
 * before initiating connection establishment.
 * 
 * @note PmSockSetSocketBindAddress may only be called once on a
 *       given PmSockIOChannel instance, and only before
 *       PmSockConnect*()
 * 
 * @param channel Non-NULL PmSockIOChannel instance to which you
 *                hold a reference.
 * 
 * @param addrFamily Address family: Only AF_INET is presently
 *                   supported (AF_INET6 support to be added
 *                   later)
 * 
 * @param bindAddress ASCII, zero-terminated, non-empty address
 *                    string for binding the connection socket;
 *                    or NULL for INADDR_ANY/in6addr_any; the
 *                    string is copied.
 * 
 * @param bindPort Port number for binding the connection
 *                 socket, or 0 for "any"
 * 
 * @param error: optional pointer to location for returning a
 *             GError value; if the pointer is non-NULL, a
 *             GError will be returned in the pointed-to
 *             location if and only if the function call returns
 *             with error. The pointed-to location may be
 *             unaltered or set to NULL on success. The caller
 *             is responsible for freeing the returned GError
 *             (if any) via g_error_free().
 * 
 * @return PslError 0 on success; non-zero PslError code on
 *         failure
 */
PslError
PmSockSetSocketBindAddress(PmSockIOChannel* channel,
                           int              addrFamily,
                           const char*      bindAddress,
                           int              bindPort);


/**
 * PmSockSetConnectedFD(): Associates a _connected_ file
 * descriptor with the PmSockIOChannel instance.
 * 
 * @note You may call this function ONLY BEFORE initiating
 *       connection establishment.
 * 
 * @note Setting of the connected file descriptor is
 *       MUTUALLY-EXCLUSIVE with PmSockSetConnectAddress and
 *       PmSockSetSocketBindAddress.
 * 
 * On success, the given PmSockIOChannel instance takes
 * ownership of the passed file descriptor and will close the
 * file descriptor when PmSockIOChannel instance is closed
 * (g_io_channel_close or equivalent) or destroyed.
 * kPmSockFileDescOpt_doNotClose may be used to override this
 * behavior.
 * 
 * On failure, the passed file descriptor is not associated with
 * the given PmSockIOChannel instance, and the _caller_ retains
 * responsibility for closing the file descriptor. 
 *  
 * To enable communication over the channel after associating it
 * with a connected file descriptor, you need to call one of the 
 * connection-establishment API functions: for plaintext 
 * communications, call PmSockConnectPlain(); to perform the 
 * client-side SSL/TLS handshake, call PmSockConnectCrypto(); 
 * for the server-side SSL/TLS handshake, call 
 * PmSockAcceptCrypto().  Refer to documentation of those 
 * functions. 
 * 
 * @param channel Non-NULL PmSockIOChannel instance to which you
 *                hold a reference.
 * 
 * @param fd A valid (>= 0), connected file descriptor; may be a
 *           connected TCP/IP socket, a TTY fd, or another type
 *           of fd suitable for bi-directinal transfer of binary
 *           data. libpalmsocket will configure this
 *           file descriptor for non-blocking operation before
 *           using it for I/O.
 * 
 * @param opts One or more PmSockFileDescOpts flags
 *             bitwise-or'ed together.
 * 
 * @return PslError
 * 
 * @see PmSockFileDescOpts 
 * @see PmSockConnectPlain 
 * @see PmSockConnectCrypto
 * @see PmSockAcceptCrypto() 
 */
PslError
PmSockSetConnectedFD(PmSockIOChannel* channel, int fd, PmSockFileDescOpts opts);


/**
 * PmSockConnectPlain(): Initiates plaintext connection
 * establishment on the given channel.  This operation completes
 * asynchronously.
 * 
 * @note In order to connect, the channel must have previously
 *       been configured either with a connection address
 *       (PmSockSetConnectAddress) or with a connected file
 *       descriptor (PmSockSetConnectedFD)
 * 
 * A channel that has been configured with a connected file
 * descriptor (PmSockSetConnectedFD) will advance to the
 * plaintext mode upon successful completion of this operation
 * (see below for success/failure indications)
 * 
 * If a connection address was configured on the channel
 * (PmSockSetConnectAddress), the address will be resolved
 * asynchronously (if it's a hostname), followed by the
 * establishment of a TCP/IP connection.
 * 
 * Successful completion of connection establishment will be
 * indicated by the completionCb callback with PslError code of
 * 0. Attempts to read/write the channel prematurely will 
 * result in error. G_IO_OUT will be set upon successful
 * completion of the requested connection establishment; G_IO_IN
 * will become set when incoming data becomes available.
 * 
 * Subsequent failures of the connection will result in both
 * G_IO_IN and G_IO_OUT corresponding to the failure being set,
 * and g_io_channel_read_chars and/or g_io_channel_write_chars
 * would return the error status, and PmSockGetLastError may
 * also be used immediately after such failed calls (those that
 * return G_IO_STATUS_ERROR) to retrieve more specific error
 * info.
 * 
 * If connection-establishment fails, the channel will indicate
 * both G_IO_ERR and G_IO_HUP, and completionCb callback will
 * indicate a non-zero PslError code. An attempt to call
 * g_io_channel_read_chars or g_io_channel_write_chars would
 * return G_IO_STATUS_ERROR.
 * 
 * @param channel Non-NULL pointer to a PmSockIOChannel instance
 *                to which you hold a reference and that has not
 *                attempted to connect yet.
 * 
 * @param completionCb Optional (may be NULL) completion
 *                     callback function to be called upon
 *                     successful or failed completion of the
 *                     operation; the callback will not be
 *                     called if PmSockConnectPlain() returns
 *                     with a non-zero error code.
 *                      
 * 
 * @return PslError 0 on success: plaintext
 *         connection-establishment is in progress and
 *         completionCb will be called at successful or failed
 *         completion; non-zero PslError code on failure
 *         (completionCb will not be called)
 * 
 * @see PmSockCompletionCb
 */
PslError
PmSockConnectPlain(PmSockIOChannel*     channel,
                   PmSockCompletionCb*  completionCb);


/**
 * PmSockConnectCrypto(): Initiates client-specific SSL/TLS
 * connection establishment on the given channel. This operation
 * completes asynchronously.
 * 
 * @note In order to connect, the channel must have previously
 *       been configured either with a connection address
 *       (PmSockSetConnectAddress) or with a connected file
 *       descriptor (PmSockSetConnectedFD)
 * 
 * For a channel that has not been connected at all yet,
 * establishes a TCP/IP connection followed by
 * SSL/TLS connection.
 * 
 * For a channel that's already connected and in plaintext mode,
 * establishes an SSL/TLS connection.
 * 
 * Success and failure will be indicated exactly as for
 * PmSockConnectPlain()
 * 
 * 
 * @param channel Non-NULL pointer to a PmSockIOChannel instance
 *                to which you hold a reference and is either in
 *                init mode (created, congigured, but not
 *                connected) or in plaintext mode.
 * 
 * @param sslCtx A PmSockSSLContext instance to which you
 *               hold a reference.  Upon successful return, this
 *               function acquires its own reference to the
 *               given PmSockSSLContext instance and holds it
 *               for the duration of SSL mode (until SSL mode is
 *               exited).  This enables a single SSL context to
 *               be shared across multiple PmSockIOChannel SSL
 *               session.  If NULL is passed, this
 *               PmSockIOChannel instance will create its own
 *               PmSockSSLContext (not shared with others).
 *  
 * @param pConf SSL/TLS configuration options or NULL if none. 
 * 
 * @param completionCb Optional (may be NULL) completion
 *                     callback function to be called upon
 *                     successful or failed completion of the
 *                     operation; the callback will not be
 *                     called if PmSockConnectCrypto() returns
 *                     with a non-zero error code.
 * 
 * @return PslError 0 on success: SSL/TLS
 *         connection-establishment is in progress and
 *         completionCb will be called at successful or failed
 *         completion; non-zero PslError code on failure (
 *         completionCb, PmSockOpensslLifecycleCb, and
 *         PmSockOpensslPeerVerifyCb will not be called)
 * 
 * @see PmSockOpensslPeerVerifyCb
 * @see PmSockOpensslLifecycleCb
 * @see PmSockCompletionCb
 */
PslError
PmSockConnectCrypto(PmSockIOChannel*              channel,
                    PmSockSSLContext*             sslCtx,
                    const PmSockCryptoConfArgs*   pConf,
                    PmSockCompletionCb*           completionCb);


/**
 * PmSockAcceptCrypto(): Initiates server-specific SSL/TLS
 * connection establishment on the given channel. This operation
 * completes asynchronously.
 * 
 * @note EXPERIMENTAL API; used for testing
 * 
 * @note In order to connect, the channel must have previously
 *       been configured either with a connection address
 *       (PmSockSetConnectAddress) or with a connected file
 *       descriptor (PmSockSetConnectedFD)
 *  
 * @note In order to associate a certificate and the 
 *       corresponding private key with the channel, the user
 *       needs to do so using openssl API. The cert and key may
 *       be associated either with the SSL instance or with the
 *       SSL_CTX instance. You may get access to the SSL
 *       instance by requesting PmSockOpensslLifecycleCb via
 *       PmSockCryptoConfArgs; or you may get access to the
 *       SSL_CTX instance via PmSockSSLCtxPeekOpensslContext().
 *       For example, you may use the combination of
 *       SSL_CTX_use_RSAPrivateKey_file(),
 *       SSL_CTX_use_certificate_file(), and
 *       SSL_CTX_check_private_key() to associate a private key
 *       with an SSL_CTX instance (obtained from
 *       PmSockSSLContext), and then pass the PmSockSSLContext
 *       instance to PmSockAcceptCrypto().
 * 
 * @param channel Non-NULL pointer to a PmSockIOChannel instance
 *                to which you hold a reference and is either in
 *                init mode and associated with a connected file
 *                descriptor or in plaintext mode.
 * 
 * @param sslCtx A PmSockSSLContext instance to which you
 *               hold a reference.  Upon successful return, this
 *               function acquires its own reference to the
 *               given PmSockSSLContext instance and holds it
 *               for the duration of SSL mode (until SSL mode is
 *               exited).  This enables a single SSL context to
 *               be shared across multiple PmSockIOChannel SSL
 *               sessions.  If NULL is passed, this
 *               PmSockIOChannel instance will create its own
 *               PmSockSSLContext (not shared with others).
 *  
 * @param pConf SSL/TLS configuration options or NULL if none. 
 * 
 * @param completionCb Optional (may be NULL) completion
 *                     callback function to be called upon
 *                     successful or failed completion of the
 *                     operation; the callback will not be
 *                     called if PmSockAcceptCrypto() returns
 *                     with a non-zero error code.
 * 
 * @return PslError 0 on success: SSL/TLS 'accept' handshake is
 *         in progress and completionCb will be called at
 *         successful or failed completion; non-zero PslError
 *         code on failure (completionCb,
 *         PmSockOpensslLifecycleCb, and
 *         PmSockOpensslPeerVerifyCb will not be called)
 * 
 * @see PmSockSetConnectedFD
 * @see PmSockOpensslPeerVerifyCb
 * @see PmSockOpensslLifecycleCb
 * @see PmSockCompletionCb
 */
PslError
PmSockAcceptCrypto(PmSockIOChannel*              channel,
                   PmSockSSLContext*             sslCtx,
                   const PmSockCryptoConfArgs*   pConf,
                   PmSockCompletionCb*           completionCb);


/**
 * PmSockGetPeerCertVerifyError(): Returns the last cached peer
 * certificate verification error snapshot. 
 *  
 * @note Calling this function is meaningful only after 
 *       an SSL/TLS establishment attempt completes with success
 *       or fails with PSL_ERR_SSL_CERT_VERIFY, but is still in
 *       SSL mode. The result of calling this function at any
 *       other time is undefined.
 *  
 * @note It's possible for this function to return non-zero 
 *       error codes in PmSockPeerCertVerifyErrorInfo even
 *       though the SSL connection completed successfully.  This
 *       is because the transient verification errors may have
 *       been suppressed either by user's peer-verify callback
 *       or by libpalmsocket's extended peer verification logic.
 *       Therefore, the info returned by this function must be
 *       correlated with the outcome of the _completed_ SSL/TLS
 *       session-establishment attempt.
 *  
 * @note While the underlying SSL implementation (e.g., openssl) 
 *       and libpalmsocket's extended certificate verification
 *       logic can generate multiple verification errors during
 *       certificate chain verification, this functions returns
 *       only the last recorded verification error set.
 * 
 * @param channel Non-NULL pointer to a PmSockIOChannel instance
 *                to which you hold a reference
 *  
 * @param pRes Non-NULL pointer to a variable for returning the 
 *             requested error info; the contents are undefined
 *             on failure.
 * 
 * @return PslError 0 on success (the function was able to 
 *         obtain the requested info); non-zero PslError code on
 *         failure.
 *  
 * @see PmSockPeerCertVerifyErrorInfo 
 */
PslError
PmSockGetPeerCertVerifyError(PmSockIOChannel*               channel,
                             PmSockPeerCertVerifyErrorInfo* pRes);


/**
 * PmSockRenegotiateCrypto(): Kicks off SSL/TLS renegotiation. 
 * Renegotiation completes asynchronously by piggy-backing on 
 * subsequent I/O (explicit and/or deferred read/write 
 * requests). 
 *  
 * Once renegotiation is started, applications SHOULD continue 
 * reading from the PmSockIOChannel instance normally in order 
 * to prevent stalling of the renegotiation procedure (openssl's
 * internal RX buffer needs to be available in order to receive 
 * additional records, including the SSL/TLS handshake records).
 *  
 * Writing will be suppressed until renegotiation completes 
 * (e.g., g_io_write_chars() would return G_IO_STATUS_AGAIN) 
 * 
 * @note EXPERIMENTAL API; used for testing 
 *  
 * @note The underlying openssl 0.9.8 implementation (and likely
 *       later versions) have a bug that results in failed
 *       renegotiation whenever a data record is received
 *       instead of the expected handshake record; this can
 *       happen with full-duplex protocols.  When this happens,
 *       the SSL/TLS session dies with "error:140940F5:SSL
 *       routines:SSL3_READ_BYTES:unexpected record" being
 *       reported to the initiator of renegotiation.  The other
 *       side may see something like "error:140943F2:SSL
 *       routines:SSL3_READ_BYTES:sslv3 alert unexpected
 *       message" and "error:140940E5:SSL
 *       routines:SSL3_READ_BYTES:ssl handshake failure" in the
 *       log when libpalmsocket's log level is set to "debug"
 *       via PmLogCtrl or the corresponding config file. The
 *       _ONLY_ reliable scenario occurs with the half-duplex
 *       model: peer A initiates the renegotiation handshake,
 *       while peer B is reading and no data records are
 *       received by peer A until the renegotiation is
 *       completed; this implies that there also MUST NOT be any
 *       data records in transit from peer B to peer A (in
 *       socket buffer(s) or on the network) during the
 *       renegotiation procedure.
 * 
 * @param channel Non-NULL pointer to a PmSockIOChannel instance
 *                to which you hold a reference and that has a
 *                valid SSL/TLS connection already
 *                established.
 *  
 * @param pConf Optional configuration options for 
 *              renegotiation.  Pass NULL to ignore.
 * 
 * @param completionCb Optional (may be NULL) completion
 *                     callback function to be called upon
 *                     successful or failed completion of the
 *                     operation; the callback will not be
 *                     called if PmSockRenegotiateCrypto()
 *                     returns with a non-zero error code.
 * 
 * @return PslError 0 on success: SSL/TLS renegotiation kicked 
 *         off successfully and will attempt to complete by
 *         piggy-backing on subsequent I/O (read and/or write
 *         requests); non-zero PslError code on failure.
 *  
 * @see PmSockRenegotiateConf 
 * @see PmSockCompletionCb 
 */
PslError
PmSockRenegotiateCrypto(PmSockIOChannel*             channel,
                        const PmSockRenegotiateConf* pConf,
                        PmSockCompletionCb*          completionCb);


/**
 * PmSockShutCryptoConf: reserved for future 
 * PmSockShutCryptoOneWay() and PmSockShutCryptoTwoWay() 
 * configuration parameters (e.g., timeout) 
 *  
 * @note Model it on PmSockRenegotiateConf 
 *  
 * @see PmSockShutCryptoOneWay() 
 * @see PmSockShutCryptoTwoWay() 
 */
typedef struct PmSockShutCryptoConf_ PmSockShutCryptoConf;

/**
 * PmSockShutCryptoOneWay(): Kicks off uni-directional SSL/TLS
 * shut-down.  Completes sending of pending output data (if any)
 * to the remote peer, then sends the 'Close notify' alert to
 * the peer.
 * 
 * During the operation, the channel will indicate "not
 * writable", and writing is not allowed; the 'readable'
 * indication will track the channel's readability.
 * 
 * User may NOT write data to the channel in this mode.
 * 
 * User may monitor the channel for readability and read all
 * incoming data until g_io_channel_read_chars() indicates
 * orderly input shutdown (G_IO_STATUS_EOF) or error
 * (G_IO_STATUS_ERROR).
 * 
 * The combination of successful completion of the
 * uni-directional SSL shutdown procedure and receiving
 * G_IO_STATUS_EOF from read is equivalent to a successful
 * bi-directional SSL shutdown.  In this case, calling 
 * PmSockResumePlain() is allowed. 
 * 
 * Upon completion of the uni-directional SSL shutdown operation
 * (both successful and failed), the channel will indicate
 * 'writeable', and completionCb will be called with the
 * errorCode arg indicating success or failure.  Success
 * indicated by the callback means that 'Close notify' has been
 * sent to the peer on the underlying socket (however, this does
 * not guarantee that it has been received by the peer yet).
 * 
 * If uni-directional SSL/TLS shut-down completes successfully,
 * the channel will remain in the SSL Shutdown mode until some
 * explicit action by the user (e.g., PmSockShutSocket()).
 * 
 * Upon failure, the channel will transition into SSL failure
 * mode, making it unsuitable for further communication of any
 * kind; in this case, viable options are: TCP/IP socket
 * shut-down (PmSockShutSocket()) and/or g_io_channel_close
 * should be performed.
 * 
 * An app that wishes only to wait long enough for the 'close
 * notify' alert to be sent (i.e., enqueued in transmit buffers
 * of the local TCP/IP stack), may close the palmsocket instance
 * as soon as shutdown completion is indicated (completionCb is
 * called).
 * 
 * The user may follow in-progress or successfully-completed
 * uni-directional SSL shutdown with a bi-directional
 * shut-down request (@see PmSockShutCryptoTwoWay), which will
 * complete sending the 'close notify' alert (if necessary) and
 * wait to receive the peer's 'close notify' alert (if it hasn't
 * arrived alredy), while discarding any incoming user-layer
 * data from the peer.
 * 
 * @note During the uni-directional SSL shutdown procedure, user
 *       needs to monitor this palmsocket instance for
 *       readability and read all incoming data in order to
 *       avoid a stalled connection.
 * 
 * @note Uni-directional SSL/TLS shutdown handshake makes the
 *       underlying socket connection potentially unsuitable for
 *       further communication because a proper transport data
 *       sync-up is not performed, so unexpected data may linger
 *       on the input of the connection. Following
 *       uni-directional SSL/TLS shutdown (either successful or
 *       failed), a TCP socket shutdown (e.g., graceful TCP/IP
 *       shut-down via PmSockShutSocket()) and/or
 *       g_io_channel_close should be performed.
 * 
 * @param channel Non-NULL pointer to a PmSockIOChannel instance
 *                to which you hold a reference and that has an
 *                encrypted connection.
 *  
 * @param pConf This optional arg is reserved for features to be
 *              added in the future (e.g., timeout).  Users
 *              _MUST_ pass NULL for this arg.
 * 
 * @param completionCb Optional (may be NULL) completion
 *                     callback function to be called upon
 *                     successful or failed completion of the
 *                     operation; the callback will not be
 *                     called if PmSockShutCryptoOneWay()
 *                     returns with a non-zero error code.
 * 
 * @return PslError 0 on success: SSL/TLS shut-down is
 *         in progress and completionCb will be called at
 *         successful (as soon as 'Close notify' is sent) or
 *         failed completion; non-zero PslError code on failure
 *         (completionCb will not be called)
 * 
 * @see PmSockShutCryptoTwoWay
 * @see PmSockShutSocket
 */
PslError
PmSockShutCryptoOneWay(PmSockIOChannel*            channel,
                       const PmSockShutCryptoConf* pConf,
                       PmSockCompletionCb*         completionCb);


/**
 * PmSockShutCryptoTwoWay(): Kicks off bi-directional SSL/TLS
 * shut-down.  Completes sending of pending output data (if any)
 * to the remote peer, then sends the 'Close notify' alert to
 * the peer and waits for the 'Close notify' alert from the
 * peer, while discarding any incoming user-layer data from the
 * peer.
 *  
 * Any incoming data will be automatically discarded.  Use 
 * PmSockShutCryptoOneWay() if you need to read incoming data 
 * while performing graceful SSL shutdown. 
 * 
 * User may NOT write data to the channel in this mode.
 * 
 * During the operation, the channel will indicate 'not
 * writable'; and 'not readable'.
 * 
 * Upon completion of the operation (both successful and
 * failed), the channel will indicate 'writeable' and 
 * 'readable', and PmSockCompletionCb will be called to indicate
 * success/failure. 
 * 
 * Upon successful completion of bi-directional SSL/TLS 
 * shut-down, the channel will remain in the SSL Shutdown mode 
 * until some explicit action by the user (e.g., 
 * PmSockResumePlain() or PmSockShutSocket()).
 *  
 * Upon successful completion, an attempt to read data from the 
 * channel via g_io_channel_read_chars() will always return 
 * G_IO_STATUS_EOF;
 * 
 * Upon failure, the channel will transition into SSL failure
 * mode, making it unsuitable for further communication of any
 * kind; in this case, viable options are: TCP/IP socket
 * shut-down (PmSockShutSocket()) and/or g_io_channel_close
 * should be performed.
 * 
 * @param channel Non-NULL pointer to a PmSockIOChannel instance
 *                to which you hold a reference and that has an
 *                encrypted connection.
 *  
 * @param pConf This optional arg is reserved for features to be
 *              added in the future (e.g., timeout).  Users
 *              _MUST_ pass NULL for this arg.
 * 
 * @param completionCb Optional (may be NULL) completion
 *                     callback function to be called upon
 *                     successful or failed completion of the
 *                     operation; the callback will not be
 *                     called if PmSockShutCryptoOneWay()
 *                     returns with a non-zero error code.
 * 
 * @return PslError 0 on success: SSL/TLS shut-down is
 *         in progress and completionCb will be called at
 *         successful (as soon as 'Close notify' is sent to the
 *         peer and a 'Close Notify' is received from the peer)
 *         or failed completion; non-zero PslError code on
 *         failure (completionCb will not be called)
 * 
 * @see PmSockShutCryptoOneWay
 * @see PmSockShutSocket
 */
PslError
PmSockShutCryptoTwoWay(PmSockIOChannel*            channel,
                       const PmSockShutCryptoConf* pConf,
                       PmSockCompletionCb*         completionCb);


/**
 * Resumes plaintext mode operation following successful
 * completion of bi-directional SSL/TLS shutdown.  This
 * operation completes immediately and synchronously.
 * 
 * @note PmSockIOChannel implementation does not automatically
 *       advance to the plaintext mode following successful
 *       bi-directional SSL/TLS shutdown in order to avoid
 *       accidental sending of private data in plaintext mode.
 * 
 * Successful bi-directional SSL/TLS shut-down is achieved
 * either through:
 * 
 *   1. A successfully-completed 'two-way shutdown' procedure
 *      (initiated via PmSockShutCryptoTwoWay), during which a
 *      'Close notify' alert was sent to the peer and 'Close
 *      notify' alert was also received from the peer; or
 * 
 *   2. The combination of a successfully-completed 'one-way
 *      shutdown' procedure (initiated via
 *      PmSockShutCryptoOneWay) combined with the receipt of the
 *      SSL/TLS 'Close notify' alert from the peer (indicated by
 *      G_IO_STATUS_EOF result from g_io_channel_read_chars).
 * 
 * @param channel Non-NULL pointer to a PmSockIOChannel instance
 *                to which you hold a reference and that has an
 *                encrypted connection.
 * 
 * @return PslError
 */
PslError
PmSockResumePlain(PmSockIOChannel* channel);


/**
 * PmSockShutSocket(): Performs the Unix socket shutdown
 * operation on the channel's socket in the direction(s)
 * specified by 'how' and transitions the channel to plaintext
 * TCP/IP socket shut-down state.  This operation compeltes
 * immediately and synchronously.
 * 
 * This enables the user to implement the graceful TCP/IP
 * shutdown algorithm, if needed.
 * 
 * @note This function is intended for shutting down a TCP/IP
 *       socket.  If the connection was set up by associating a
 *       file descriptor with the given PmSockIOChannel instance
 *       (via PmSockSetConnectedFD), but that file descriptor is
 *       not a socket, then the result is undefined.
 * 
 * @note If the socket was in secure connection mode (SSL/TLS)
 *       at the time of the call, then this call is equivalent
 *       to an unfriendly SSL/TLS shutdown (neither Tx flush nor
 *       goodbye handshake will take place, and pending SSL/TLS
 *       completion callback, if any, will not be called). In
 *       this case, the channel will begin to function as a
 *       direct socket connection, bypassing the SSL/TLS
 *       processing, and the data on the channel will be of
 *       unknown type/integrity.
 * 
 * @note The direction(s) that is/are shutdown become
 *       permanently indicated (readable or writable), and the
 *       user should disable all watch sources for that/those
 *       direction(s) in order to prevent an inifinite spin of
 *       the underlying poll/select loop.
 * 
 * @param channel Non-NULL pointer to a PmSockIOChannel instance
 *                to which you hold a reference and that has any
 *                kind of connection established on it.
 * @param how Exactly one of: SHUT_RD, SHUT_WR, or SHUT_RDWR
 *            values defined in sys/socket.h.
 * 
 * @return PslError 0 on success (shutdown() was successfully
 *         called on the underlying socket with the specified
 *         'how' value); non-zero PslError code on failure
 * 
 * @see PmSockShutCryptoOneWay,
 *      PmSockShutCryptoTwoWay
 */
PslError
PmSockShutSocket(PmSockIOChannel* channel, int how);


/**
 * Returns TRUE if the channel is now closed (e.g., via
 * g_io_channel_close() or equivalent)
 * 
 * @param channel Non-NULL pointer to a PmSockIOChannel instance
 *                to which you hold a reference
 * 
 * @return bool
 */
bool
PmSockIsClosed(const PmSockIOChannel* channel);


/**
 * palmsocket watch type.  Instances of this type are
 * instantiated via PmSockCreateWatch().  A pointer to
 * PmSockWatch may be cast to GSource pointer for use with
 * certain g_source functions;
 * 
 * @see PmSockCreateWatch
 * 
 */
typedef struct PmSockWatch_ PmSockWatch;


/**
 * PmSockCreateWatch(): Creates a watch source instance to
 * monitor the given palmsocket channel for readability and
 * writeability.
 * 
 * The source has an initial reference count of 1, which is
 * owned by the user.  When you no longer
 * need this reference, call g_source_unref() on the source
 * instance.
 * 
 * @note This IO watch uses GIOFunc as the callback function
 *       type that you set via g_source_set_callback().
 * 
 * @note The resulting source instance MUST be attached to the
 *       same gmain context as the one used by the given channel
 *       instance. The communication betwee the source and
 *       corresponding channel is NOT thread-safe.
 * 
 * @note The resulting watch instance pointer may be type-cast
 *       to GSource pointer when a pointer to GSource is needed.
 * 
 * @note When the corresponding PmSockIOChannel instance is
 *       closed (g_io_channel_close() or equivalent), an active
 *       watch with non-zero condition set will indicate
 *       G_IO_NVAL.
 * 
 * @param channel Non-NULL pointer to a PmSockIOChannel instance
 *                to which you hold a reference and that you
 *                wish to monitor.
 * 
 * @param conditions The initial conditions to monitor. You may pass
 *                   zero (typecast to GIOCondition) to suppress
 *                   monitoring. Conditions may be changed later
 *                   via PmSockWatchUpdate()
 * 
 * @note If conditions arg is non-zero, any of the following
 *       failure conditions may be indicated as results via the
 *       GIOFunc notification callback independent of the
 *       requested conditions: G_IO_ERR, G_IO_HUP, and
 *       G_IO_NVAL. _WARNING_: once they occur, these failure
 *       conditions are permanent; so, in order to avoid an
 *       infinite loop, the watch instance MUST be destroyed.
 * 
 * @param pWatch Non-NULL pointer to location for returning the
 *               newly-allocated PmSockWatch instance; undefined
 *               on failure.
 * 
 * @return PslError 0 on success; non-zero PslError code on
 *         failure
 * 
 * @see PmSockWatchUpdate()
 */
PslError
PmSockCreateWatch(PmSockIOChannel*  channel,
                  GIOCondition      conditions,
                  PmSockWatch**     pWatch);


/**
 * PmSockWatchUpdate(): Replaces conditions that the palmsocket
 * channel source is monitoring.
 * 
 * @note Access to a given palmsocket channel source instance is
 *       NOT thread-safe.  You MUST call this function from the
 *       SAME thread that corresponds to the gmain context that
 *       the source is attached to.
 * 
 * @param watch Non-NULL PmSockWatch instance.
 * 
 * @param conditions New conditions to monitor.  These will
 *                   replace the prior conditions.  You may pass
 *                   zero (typecast to GIOCondition) to suspend
 *                   monitoring without having to destroy the
 *                   watch.
 * 
 * @note If conditions arg is non-zero, any of the following
 *       failure conditions may be indicated as results via the
 *       GIOFunc notification callback independent of the
 *       requested conditions: G_IO_ERR, G_IO_HUP, and
 *       G_IO_NVAL. _WARNING_: once they occur, these failure
 *       conditions are permanent; so, in order to avoid an
 *       infinite loop, the watch instance MUST be destroyed.
 * 
 * @return PslError 0 on success; non-zero PslError code on
 *         failure
 * 
 * @note This function operates on the watch object (not on the
 *       channel), so PmSockGetLastError() does not apply in
 *       this case.
 */
PslError
PmSockWatchUpdate(PmSockWatch* watch, GIOCondition conditions);



/**
 * Creates a PSL thread context instance from a GMain Context;
 * the reference count of the newly-created instance is 1.
 * 
 * @note The initial reference count of 1 is owned by the user
 *       and MUST be released before the thread exits by
 *       calling PmSockThreadCtxUnref().
 * 
 * @note THREAD-SAFETY = NONE: WARNING: Access to a given
 *       instance of PSL thread context is NOT thread-safe.
 * 
 * 
 * @param gmainCtx: GMainLoop Context that the returned thread
 *                context should use; pass NULL for the default
 *                gmainloop context.
 * @param userLabel: An OPTIONAL (may be NULL) short,
 *                 zero-terminated string that will be displayed
 *                 in logs associated with this PSL Thread
 *                 Context; this string is copied;
 * @param pThreadCtx Non-NULL location for returning the PSL
 *                  thread context on success; undefined on
 *                  failure.
 * 
 * @return PslError 0 on success; non-zero PslError code on
 *         failure
 */
PslError
PmSockThreadCtxNewFromGMain(GMainContext*           gmainCtx,
                            const char*             userLabel,
                            PmSockThreadContext**   pThreadCtx);

/**
 * Peek the GMainContext instance pointer from a
 * PmSockThreadContext instance that was created via
 * PmSockThreadCtxNewFromGMain.
 * 
 * This function does NOT increment the GMainContext's reference
 * count, so the returned GMainContext pointer is valid only as
 * long as you're holding a valid reference count to the
 * corresponding PmSockThreadContext instance. You should call
 * g_main_context_ref() if you need your own reference to it.
 * 
 * @param ctx A non-NULL, valid thread context instance.
 * 
 * @return GMainContext* Pointer to the thread context's
 *         GMainContext instance or NULL if none (i.e., was not
 *         created from a GMainContext)
 */
GMainContext*
PmSockThreadCtxPeekGMainContext(PmSockThreadContext* ctx);


/**
 * Increments the reference count of the given thread context
 * instance by 1.
 * 
 * @note A newly created Thread Context instance has an initial
 *       reference count of 1, which is owned by the user code
 *       that requested its creation.
 * 
 * @param ctx A non-NULL, valid thread context instance.
 * 
 * @return the value of the passed-in ctx arg
 * 
 * @see PmSockThreadCtxUnref
 */
PmSockThreadContext*
PmSockThreadCtxRef(PmSockThreadContext* ctx);


/**
 * Decrements the reference count of the given instance of PSL
 * thread context by 1, and destroys it when its reference count
 * drops to 0.
 * 
 * @note A newly created Thread Context instance has an initial
 *       reference count of 1, which is owned by the user code
 *       that requested its creation.
 * 
 * @note Access to an individual Thread Context instance is NOT
 *       thread-safe!
 * 
 * @param ctx Non-NULL thread context instance to which you own
 *            a reference.
 */
void
PmSockThreadCtxUnref(PmSockThreadContext* ctx);


/**
 * PmSockSSLCtxNew(): Creates an SSL Context instance; the 
 * reference count of the newly-created instance is 1. 
 * 
 * Default settings:
 *      Compatibility modes: by default, SSLv3 and TLSv1 are
 *      enabled, and SSLv2 is disabled.
 * 
 *      Also, see DEFAULT_CIPHER_LIST, DEFAULT_CAFILE_PATH,
 *      DEFAULT_CAPATH, and DEFAULT_CERT_VERIFY_DEPTH in
 *      libpalmsocket sources.
 * 
 * @note The initial reference count of 1 is owned by the user
 *       and MUST be released before the process exits by
 *       calling PmSockSSLCtxUnref().
 * 
 * @note THREAD-SAFETY = OPTIONAL: Access to a given instance of
 *       the SSL Context is NOT thread-safe by default.  It may
 *       be made thread-safe only if openssl has been
 *       initialized for thread-safety.
 * 
 * @param userLabel: An OPTIONAL (may be NULL) short,
 *                 zero-terminated string that will be displayed
 *                 in logs associated with this SSL Context;
 *                 this string is copied;
 * @param pThreadCtx Non-NULL location for returning the SSL
 *                  Context on success; undefined on
 *                  failure.
 * 
 * @return PslError 0 on success; non-zero PslError code on
 *         failure
 */
PslError
PmSockSSLCtxNew(const char* userLabel, PmSockSSLContext** pSSLCtx);


/**
 * PmSockSSLCtxPeekOpensslContext(): Peek the openssl SSL_CTX
 * instance pointer from a PmSockSSLContext instance that was 
 * created via PmSockSSLCtxNew. 
 *  
 * This function does NOT increment the SSL_CTX instance's 
 * reference count, so the returned SSL_CTX pointer is valid 
 * only as long as you're holding a valid reference count to the 
 * corresponding PmSockSSLContext instance. 
 *  
 * @note At the time of this writing, openssl 0.9.8 did not 
 *       provide an explicit SSL_CTX API for incrementing the
 *       reference count of SSL_CTX instances.
 * 
 * @param sslCtx A non-NULL, valid PmSockSSLContext instance.
 * 
 * @return struct ssl_ctx_st* SSL_CTX-equivalent pointer to the 
 *         PmSockSSLContext's SSL_CTX instance or
 *         NULL if none (i.e., PmSockSSLContext was not created
 *         from an openssl context)
 */
struct ssl_ctx_st*
PmSockSSLCtxPeekOpensslContext(PmSockSSLContext* sslCtx);


/**
 * Increments the reference count of the given SSL Context
 * instance by 1.
 * 
 * @note A newly created SSL Context instance has an initial
 *       reference count of 1, which is owned by the user code
 *       that requested its creation.
 * 
 * @param sslCtx Non-NULL SSL Context instance.
 * 
 * @see PmSockSSLCtxUnref
 * 
 * @return The value of the passed-in sslCtx arg
 */
PmSockSSLContext*
PmSockSSLCtxRef(PmSockSSLContext* sslCtx);


/**
 * Decrements the reference count of the given instance of SSL
 * Context by 1, and destroys it when its reference count
 * drops to 0.
 * 
 * @note A newly created SSL Context instance has an initial
 *       reference count of 1, which is owned by the user code
 *       that requested its creation.
 * 
 * @param sslCtx Non-NULL SSL Context instance to which you own
 *               a reference
 */
void
PmSockSSLCtxUnref(PmSockSSLContext* sslCtx);




/*******************************************************************************
 *       Legacy API
 ******************************************************************************/


/** ========================================================================
 *  @note Deprecated... superceded by the new API
 * 
 *  @note There appears to be
 *        no meaning to the boolean return values of these two
 *        callback types.
 *  
 * =========================================================================
 * @{
 */
typedef gboolean (*PmSocketConnectCb)(GIOChannel *gio , gpointer data,
                                      const GError *error);
typedef gboolean (*PmSecureSocketSwitchCb)(GIOChannel *gio,
                                           gboolean isSocketEncrypted,
                                           gpointer data, const GError *error);
/**@}*/

/** ========================================================================
 *  @note Legacy API: Deprecated... superceded by the new API 
 * =========================================================================
 */
GIOChannel*
PmNewIoChannel(const char* address, gint port, const char* bindAddress,
               gint bindPort, GError **error);

/** ========================================================================
 *  @note Legacy API: Deprecated... superceded by the new API
 * ========================================================================= 
 */
gint
PmSocketConnect(GIOChannel* channel, gpointer context, PmSocketConnectCb cb,
                GError **error);

/** ========================================================================
 *  @note Legacy API: Deprecated... superceded by the new API
 * ========================================================================= 
 */
gint
PmSslSocketConnect(GIOChannel* channel, gpointer context, PmSocketConnectCb cb,
                   GError **error);

/** ========================================================================
 *  @note Legacy API: Deprecated... superceded by the new API
 * ========================================================================= 
 */
gint
PmSetSocketEncryption(GIOChannel* channel, gboolean doSwitchToEncryptedMode,
                      gpointer app_data, PmSecureSocketSwitchCb cb,
                      GError **error);


#if defined(__cplusplus)
}
#endif



#endif //PALMSOCKET_H__

/**@}*/

