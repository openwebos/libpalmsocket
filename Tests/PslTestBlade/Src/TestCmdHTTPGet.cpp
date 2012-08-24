/** 
 * *****************************************************************************
 * @file TestCmdHTTPGet.cpp
 * @ingroup psl_test
 * 
 * @brief  Test Command Handler for testing libplamsocket's
 *         PmSock API via HTTP GET requests.  Supports parallel
 *         HTTP GET requests on the same thread.  Tests new and
 *         legacy API
 * 
 * *****************************************************************************
 */

#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdio.h>

#include <string>
#include <vector>
#include <sstream>

#include <openssl/ssl.h> ///< for X509_verify_cert_error_string()

#include <glib.h>

#include <uriparser/Uri.h>

#include <stdexcept>

#include <PmWirelessSystemFramework/Utils/RuntimeDispatcher/RuntimeDispatcher.h>
#include <RuntimeDispatcher/Glib/GlibRuntimeDispatcher.h>
#include <PmWirelessSystemFramework/Utils/RuntimeDispatcher/RdAsyncBridge.h>
#include <PmWirelessSystemFramework/Utils/Uncopyable.h>

#include <PmWsfTestUtils/CommandShell.h>
#include <PmWsfTestUtils/ProgressReporter.h>

#include <palmsocket.h>


#include "PslTestCmdShell.h"
#include "CommonUtils.h"


namespace { /// anonymous

    class HTTP_1_0_Trans : private wsf::Uncopyable {
    private:

        enum Phase {
            kPhase_init,
            kPhase_connectingPlain,
            kPhase_connectingCrypto,
            kPhase_sendingRequest,
            kPhase_reapingResponse,
            kPhase_doneSuccess,
            kPhase_doneError
        };

    public:

        enum ConnKind {
            kConnKind_unspecified,
            kConnKind_plaintext,
            kConnKind_crypto,
            kConnKind_cryptoIndirect ///< first to plaintext, then crypto
        };

        enum InetKind {
            kInetKind_ipv4,
            kInetKind_ipv6
        };


        /**
         * @note pSSLCtx and pThreadCtx will be NULL when legacy
         *       palmsocket API use is requested.
         * 
         * @param userLabel
         * @param pSSLCtx
         * @param pThreadCtx
         * @param servername
         * @param path
         * @param serverport
         * @param inetKind
         * @param verbose
         */
        HTTP_1_0_Trans(const std::string&             userLabel,
                             PmSockSSLContext*      const   pSSLCtx,
                             PmSockThreadContext*   const   pThreadCtx,
                             const std::string&             servername,
                             const std::string&             path,
                             int                    const   serverport,
                             InetKind               const   inetKind,
                             const bool                     verbose)
        :   userLabel_(userLabel),
            servername_(servername),
            path_(path),
            pSSLCtx_(pSSLCtx ? PmSockSSLCtxRef(pSSLCtx) : NULL),
            serverport_(serverport),
            inetKind_(inetKind),
            verbose_(verbose),
            useLegacyAPI_(!pSSLCtx && !pThreadCtx),
            requestMsg_(),
            reqConsumedCnt_(0),
            pDoneEvt_(NULL),
            phase_(kPhase_init),
            pSock_(NULL),
            //pGChan_(NULL),
            pSockWatch_(NULL),
            //pSockGSource_(NULL),
            connectKind_(kConnKind_unspecified),
            inWatchCallback_(false),
            destroyWatchPending_(false),
            totalReadSoFar_(0)
        {
            /// Both should be either non-NULL or NULL
            assert(!pSSLCtx == !pThreadCtx);


            std::ostringstream oss;
            oss << "GET " << path << " HTTP/1.0\r\n";
            oss << "User-Agent: test/0.9\r\n";
            oss << "Host: " << servername << "\r\n";
            oss << "Accept: text/plain\r\n";
            oss << "\r\n";

            requestMsg_ = oss.str();

            if (verbose_) {
                printf("%s: request msg=<%s>\n",
                       userLabel_.c_str(),
                       requestMsg_.c_str());
            }



            if (useLegacyAPI_) { /// Using legacy palmsocket API
                GError* pGerror = NULL;

                if (verbose_) {
                    printf("%s: NOTE: Using legacy palmsocket API\n",
                           userLabel_.c_str());
                }

                pGChan_ = PmNewIoChannel(servername_.c_str(),
                                         serverport_,
                                         NULL/*bindAddress*/,
                                         0/*any bindPort*/,
                                         &pGerror);
                if (pGChan_) {
                    assert(!pGerror);
                }
                else {
                    assert(pGerror);
                    g_prefix_error(&pGerror, "FATAL: PmNewIoChannel failed: ");
                    const std::string errorMsg(pGerror->message);
                    g_clear_error(&pGerror);
                    UTIL_THROW_FATAL(userLabel_.c_str(), errorMsg.c_str());
                }

                pSockGSource_ = g_io_create_watch(pGChan_, (GIOCondition)0);
                if (!pSockGSource_) {
                    UTIL_THROW_FATAL(userLabel_.c_str(), "g_io_create_watch failed");
                }

                assert(!pGerror);
            }//Using legacy palmsocket API

            else { /// Using new palmsocket API
                if (verbose_) {
                    printf("%s: NOTE: Using new palmsocket API\n",
                           userLabel_.c_str());
                }
                PslError pslErr = PmSockCreateChannel(
                    pThreadCtx,
                    (PmSockOptionFlags)0/*options*/,
                    userLabel.c_str(),
                    &pSock_);
                if (!pslErr) {
                    assert(pSock_);
                }
                else {
                    const std::string errorMsg(
                        std::string("PmSockCreateChannel failed: ") +
                        PmSockErrStringFromError(pslErr));
                    UTIL_THROW_FATAL(userLabel_.c_str(), errorMsg.c_str());
                }

                PmSockSetUserData(pSock_, this);

                pslErr = PmSockSetConnectAddress(
                    pSock_,
                    inetKind_ == kInetKind_ipv4 ? AF_INET : AF_INET6,
                    servername_.c_str(),
                    serverport_);
                if (pslErr) {
                    const std::string errorMsg(
                        std::string("PmSockSetConnectAddress failed: ") +
                        PmSockErrStringFromError(pslErr));
                    UTIL_THROW_FATAL(userLabel_.c_str(), errorMsg.c_str());
                }

                /**
                 * Create a watch to monitor our palmsocket
                 */
                pslErr = PmSockCreateWatch(pSock_, (GIOCondition)0, &pSockWatch_);
                if (pslErr) {
                    const std::string errorMsg(
                        std::string("PmSockCreateWatch failed: ") +
                        PmSockErrStringFromError(pslErr));
                    UTIL_THROW_FATAL(userLabel_.c_str(), errorMsg.c_str());
                }
            }//Using new palmsocket API


            GMainContext* const pGMainCtx = PmSockThreadCtxPeekGMainContext(
                PmSockPeekThreadContext(pSock_));
            assert(pGMainCtx);


            g_source_set_can_recurse(pSockGSource_, false);
            g_source_set_callback(pSockGSource_,
                                  (GSourceFunc)&SockWatchCallback,
                                  this, NULL);
            g_source_attach(pSockGSource_, pGMainCtx);
        }


        /**
         * Destructor
         */
        ~HTTP_1_0_Trans()
        {
            DestroySockAndWatch(false);

            if (pSSLCtx_) {
                PmSockSSLCtxUnref(pSSLCtx_);
            }
        }

        /**
         * Kick off connection establishment
         * 
         * @param connectKind
         * @param pDoneEvt
         */
        void Start(ConnKind const connectKind, wsf::RdAsyncBridge* pDoneEvt)
        {
            assert(kPhase_init == phase_);
            assert(pSock_);
            assert(pGChan_);

            assert(kConnKind_unspecified != connectKind);

            assert(pDoneEvt), pDoneEvt_ = pDoneEvt;

            connectKind_ = connectKind;

            /**
             * Kick off connection establishment
             */
            bool        legacyStartSuccess = false;
            PslError    pslErr = PSL_ERR_NONE;
            GError*     pGerror = NULL;

            switch (connectKind_) {
            case kConnKind_plaintext: ///< FALLTHROUGH
            case kConnKind_cryptoIndirect:
                phase_ = kPhase_connectingPlain;

                if (useLegacyAPI_) {
                    legacyStartSuccess = !PmSocketConnect(
                        pGChan_,
                        this,
                        &HTTP_1_0_Trans::LegacySocketConnectCb,
                        &pGerror);
                    if (pGerror) {
                        pslErr = (PslError)pGerror->code;
                    }
                }
                else {
                    pslErr = PmSockConnectPlain(pSock_,
                                                &ConnectPlainCompletionCb);
                }
                break;

            case kConnKind_crypto:
                phase_ = kPhase_connectingCrypto;

                if (useLegacyAPI_) {
                    legacyStartSuccess = !PmSslSocketConnect(
                        pGChan_,
                        this,
                        &HTTP_1_0_Trans::LegacySocketConnectCb,
                        &pGerror);
                    if (pGerror) {
                        pslErr = (PslError)pGerror->code;
                    }
                }
                else {
                    pslErr = PmSockConnectCrypto(pSock_, pSSLCtx_,
                                                 &cryptoConfArgs_,
                                                 &ConnectCryptoCompletionCb);
                }
                break;

            case kConnKind_unspecified:
                break;
            }


            assert(kPhase_init != phase_);

            if ((useLegacyAPI_ && legacyStartSuccess) ||
                (!useLegacyAPI_ && !pslErr)) {
                assert(!pGerror);
            }
            else {
                assert((useLegacyAPI_ && pGerror) || (!useLegacyAPI_ && pslErr));

                std::string errorMsg;

                if (useLegacyAPI_) {
                    g_prefix_error(&pGerror, "%s: FATAL: PmSockConnect* failed: ",
                                   userLabel_.c_str());
                    errorMsg = pGerror->message;
                    g_clear_error(&pGerror);
                }
                else {
                    errorMsg =
                        std::string("PmSockConnect* failed: ") +
                        PmSockErrStringFromError(pslErr);
                }
                UTIL_THROW_FATAL(userLabel_.c_str(), errorMsg.c_str());
            }

            if (useLegacyAPI_) {
                UpdateSockWatch(G_IO_NVAL); /// So we can find out if channel is closed
            }
            else {
                UpdateSockWatch(G_IO_OUT);
            }
        }//Start


        /**
         * Returns TRUE if operation completed successfully; FALSE if it
         * completed with failure.  May be called ONLY after the
         * operation completes.
         * 
         * @return bool
         */
        bool IsSuccess()
        {
            return kPhase_doneSuccess == phase_;
        }

        bool IsDone()
        {
            return kPhase_doneSuccess == phase_ || kPhase_doneError == phase_;
        }

    private:
        /**
         * @see PmSockOpensslPeerVerifyCb 
         *  
         * @note _WARNING_: The PmSockIOChannel instance for which the 
         *       verification callback is emitted is NOT re-entrant from
         *       the scope of this callback. The user MUST NOT call any
         *       PmSockIOChannel (including g_io_channel) API on the
         *       given PmSockIOChannel instance from the scope of this
         *       callback function (in order to avoid run-to-completion
         *       violation in libpalmsocket FSM). Instead, you may
         *       schedule a gmain timeout or make use of
         *       PmSockCompletionCb (if one is pending) to take the
         *       necessary action.
         * 
         * @param preverifyOK 
         * @param x509_ctx 
         * @param pInfo 
         * 
         * @return bool 
         */
        static bool
        OpensslPeerVerifyCb(bool                          const preverifyOK,
                            struct x509_store_ctx_st*     const x509_ctx,
                            const PmSockPeerVerifyCbInfo* const pInfo)
        {
            HTTP_1_0_Trans* const me = (HTTP_1_0_Trans*)pInfo->userData;

            if (me->verbose_) {
                printf("%s/%s: PmSockOpensslPeerVerifyCb reports: " \
                       "ch=%p, userData=%p, preverifyOk=%d, x509_ctx=%p, " \
                       "hostname='%s', PslError=%d (%s)\n",
                       me->userLabel_.c_str(), __func__, pInfo->channel,
                       pInfo->userData, (int)preverifyOK, x509_ctx,
                       pInfo->hostname, pInfo->pslVerifyError,
                       PmSockErrStringFromError(pInfo->pslVerifyError));
            }

            return preverifyOK;
        }


        /**
         * @see PmSockOpensslLifecycleCb
         * 
         * @param channel 
         * @param userData 
         * @param ssl 
         * @param phase 
         * 
         * @return bool 
         */
        static void
        OpensslLifecycleCb(const struct PmSockIOChannel_* const ch,
                           void*                          const userData,
                           struct ssl_st*                 const ssl,
                           PmSockOpensslLifecyclePhase    const phase)
        {
            HTTP_1_0_Trans* const me = (HTTP_1_0_Trans*)userData;

            if (me->verbose_) {
                printf("%s/%s: PmSockOpensslLifecycleCb reports: " \
                       "ch=%p, userData=%p, SSL=%p, phase=%d\n",
                       me->userLabel_.c_str(), __func__, ch, userData,
                       ssl, phase);
            }
        }


        /**
         * PmSockCompletionCb for PmSockConnectPlain
         * @param channel
         * @param userData
         * @param errorCode
         */
        static void
        ConnectPlainCompletionCb(PmSockIOChannel*   const ch,
                                 void*              const userData,
                                 PslError           const errorCode)
        {
            HTTP_1_0_Trans* const me = (HTTP_1_0_Trans*)userData;

            if (me->verbose_) {
                printf("%s: ConnectPlainCompletionCb reports: " \
                       "ch=%p, userData=%p, PslError=%d (%s)\n",
                       me->userLabel_.c_str(), ch, userData, (int)errorCode,
                       ::PmSockErrStringFromError(errorCode));
            }
        }


        /**
         * PmSockCompletionCb for PmSockConnectCrypto
         * @param channel
         * @param userData
         * @param errorCode
         */
        static void
        ConnectCryptoCompletionCb(PmSockIOChannel*  const ch,
                                 void*              const userData,
                                 PslError           const errorCode)
        {
            HTTP_1_0_Trans* const me = (HTTP_1_0_Trans*)userData;

            if (me->verbose_) {
                ::printf("%s/%s: ConnectCryptoCompletionCb reports: " \
                         "ch=%p, userData=%p, PslError=%d (%s)\n",
                         me->userLabel_.c_str(), __func__, ch, userData, (int)errorCode,
                         PmSockErrStringFromError(errorCode));

                me->DumpPeerVerifyErrorInfo();
            }
        }


        /**
         * PmSockCompletionCb for PmSockShutCryptoOneWay
         * @param channel
         * @param userData
         * @param errorCode
         */
        static void
        ShutCryptoOneWayCompletionCb(PmSockIOChannel* const ch,
                                     void*            const userData,
                                     PslError         const errorCode)
        {
            HTTP_1_0_Trans* const me = (HTTP_1_0_Trans*)userData;

            if (me->verbose_) {
                printf("%s: ShutCryptoOneWayCompletionCallback reports: " \
                       "ch=%p, userData=%p, PslError=%d (%s)\n",
                       me->userLabel_.c_str(), ch, userData, (int)errorCode,
                       PmSockErrStringFromError(errorCode));
            }
        }


        /**
         * PmSockCompletionCb for PmSockShutCryptoTwoWay
         * @param channel
         * @param userData
         * @param errorCode
         */
        static void
        ShutCryptoTwoWayCompletionCb(PmSockIOChannel* const ch,
                                     void*            const userData,
                                     PslError         const errorCode)
        {
            HTTP_1_0_Trans* const me = (HTTP_1_0_Trans*)userData;

            if (me->verbose_) {
                printf("%s: ShutCryptoTwoWayCompletionCb reports: " \
                       "ch=%p, userData=%p, PslError=%d (%s)\n",
                       me->userLabel_.c_str(), ch, userData, (int)errorCode,
                       PmSockErrStringFromError(errorCode));
            }

            if (!errorCode) {
                if (me->verbose_) {
                    printf("%s: Two-Way SSL/TLS shutdown " \
                           "completed successfully; resuming plaintext and " \
                           "terminating transaction.\n",
                           me->userLabel_.c_str());
                }
                PslError const pslErr = PmSockResumePlain(me->pSock_);
                if (pslErr) {
                    const std::string errorMsg =
                        std::string("PmSockResumePlain failed: ") +
                        PmSockErrStringFromError(pslErr);
                    UTIL_THROW_FATAL(me->userLabel_.c_str(), errorMsg.c_str());
                }

                g_io_channel_close(me->pGChan_);
            }

            else {
                if (me->verbose_) {
                    printf("%s: ERROR: Two-Way SSL/TLS shutdown failed; " \
                           "terminating transaction\n",
                           me->userLabel_.c_str());
                }

                me->phase_ = kPhase_doneError;

                g_io_channel_close(me->pGChan_);
            }
        }


        static gboolean LegacySocketConnectCb(
            GIOChannel*     const gio ,
            gpointer        const userdata,
            const GError*   const pGerror)
        {
            HTTP_1_0_Trans* const me = (HTTP_1_0_Trans*)userdata;

            if (pGerror) {
                if (me->verbose_) {
                    printf("%s: ERROR: legacy %s connection attempt " \
                           "failed: %d (%s); terminating transaction\n",
                           me->userLabel_.c_str(),
                           (kPhase_connectingCrypto == me->phase_
                            ? "SSL"
                            : "plaintext"),
                           (int)pGerror->code, pGerror->message);

                    if (kPhase_connectingCrypto == me->phase_) {
                        me->DumpPeerVerifyErrorInfo();
                    }
                }

                g_io_channel_close(me->pGChan_);
            }

            else { /// Successful plaintext or SSL connection
                if (me->verbose_) {
                    printf("%s: Legacy %s connection attempt " \
                           "completed successfully\n",
                           me->userLabel_.c_str(),
                           (kPhase_connectingCrypto == me->phase_
                            ? "SSL"
                            : "plaintext"));

                    if (kPhase_connectingCrypto == me->phase_) {
                        me->DumpPeerVerifyErrorInfo();
                    }
                }

                /// Get ready to start writing
                me->UpdateSockWatch(G_IO_OUT);
            }

            return true;
        }

        static gboolean LegacySecureSocketSwitchCb(
            GIOChannel*     const gio,
            gboolean        const toCrypto,
            gpointer        const userdata,
            const GError*   const pGerror)
        {
            HTTP_1_0_Trans* const me = (HTTP_1_0_Trans*)userdata;

            if (pGerror) {
                if (me->verbose_) {
                    printf("%s: ERROR: legacy security switch to %s mode " \
                           "failed: %d (%s); terminating transaction\n",
                           me->userLabel_.c_str(),
                           toCrypto ? "SSL" : "plaintext",
                           (int)pGerror->code, pGerror->message);
                }

                me->phase_ = kPhase_doneError;

                g_io_channel_close(me->pGChan_);
            }

            else if (toCrypto) { /// Successful 
                if (me->verbose_) {
                    printf("%s: Legacy security switch to SSL mode " \
                           "completed successfully\n", me->userLabel_.c_str());
                }

                /// Get ready to start writing
                me->UpdateSockWatch(G_IO_OUT);
            }

            else { /// Successful return back to plaintext mode
                if (me->verbose_) {
                    printf("%s: Legacy security switch to plaintext mode " \
                           "completed successfully; terminating transaction.\n",
                           me->userLabel_.c_str());
                }
                g_io_channel_close(me->pGChan_);
            }

            return true;
        }


        void DumpPeerVerifyErrorInfo()
        {
            psl_test_blade::UtilDumpPeerVerifyErrorInfo(pSock_, userLabel_.c_str());
        }//DumpPeerVerifyErrorInfo


        /**
         * Handle GIOCondition event from our palsocket watch instance.
         * 
         * @note dispatched by SockWatchCallback()
         * 
         * @param condition
         */
        void HandleSockWatchEvent(GIOCondition const condition)
        {
            /// Handle termination
            if (0 != (condition & G_IO_NVAL)) {
                if (verbose_) {
                    printf("%s: Transaction completed; terminating...\n",
                           userLabel_.c_str());
                }

                assert(PmSockIsClosed(pSock_));

                DestroySockAndWatch(true);
                return;
            }

            /// Perform transaction processing
            switch (phase_) {
            case kPhase_connectingPlain:
                assert(kConnKind_plaintext == connectKind_ ||
                       kConnKind_cryptoIndirect == connectKind_);
                /// Assume connection succeeded; we'll find out if it didn't
                /// on the subsequent operation.
                if (kConnKind_plaintext == connectKind_) {
                    phase_ = kPhase_sendingRequest;
                }
                else if (kConnKind_cryptoIndirect == connectKind_) {
                    phase_ = kPhase_connectingCrypto;

                    /// Assume it was successful; we'll find out if it failed
                    /// on the subsequent operation
                    
                    if (verbose_) {
                        printf("%s: Connection to plaintext mode " \
                               "completed successfully; upgrading to SSL...\n",
                               userLabel_.c_str());
                    }

                    GError* pGerror = NULL;
                    PslError pslErr = PSL_ERR_NONE;
                    bool startSuccess = false;
                    if (useLegacyAPI_) {
                        startSuccess = !PmSetSocketEncryption(
                            pGChan_,
                            true/*doSwitchToEncryptedMode*/,
                            this,
                            &HTTP_1_0_Trans::LegacySecureSocketSwitchCb,
                            &pGerror);
                    }
                    else {
                        pslErr = PmSockConnectCrypto(pSock_, pSSLCtx_,
                                                     &cryptoConfArgs_,
                                                     &ConnectCryptoCompletionCb);
                        startSuccess = !pslErr;
                    }
                    if (startSuccess) {
                        assert(!pGerror);
                    }
                    else {
                        assert((useLegacyAPI_ && pGerror) ||
                               (!useLegacyAPI_ && pslErr));

                        std::string errorMsg;

                        if (useLegacyAPI_) {
                            g_prefix_error(
                                &pGerror,
                                "%s: FATAL: PmSetSocketEncryption failed: ",
                                userLabel_.c_str());
                            errorMsg = pGerror->message;
                            g_clear_error(&pGerror);
                        }
                        else {
                            errorMsg =
                                std::string("PmSockConnectCrypto failed: ") +
                                PmSockErrStringFromError(pslErr);
                        }
                        UTIL_THROW_FATAL(userLabel_.c_str(), errorMsg.c_str());
                    }
                }
                break;

            case kPhase_connectingCrypto:
                assert(kConnKind_crypto == connectKind_ ||
                       kConnKind_cryptoIndirect == connectKind_);
                /// Assume connection succeeded; we'll find out if it didn't
                /// on the subsequent operation.
                phase_ = kPhase_sendingRequest;
                break;

            case kPhase_sendingRequest:
                phase_ = SendRequest();
                if (kPhase_reapingResponse == phase_) {
                    /// Start monitoring input events
                    UpdateSockWatch(G_IO_IN);

                #if 0
                    /// If it's a non-legacy crypto connection, initiate one-way
                    /// SSL shut-down; we will keep reading until SSL_EOF
                    if (!useLegacyAPI_ &&
                        (kConnKind_crypto == connectKind_ ||
                        kConnKind_cryptoIndirect == connectKind_)) {

                        PslError const shutErr = PmSockShutCryptoOneWay(
                            pSock_, &ShutCryptoOneWayCompletionCb);
                        if (shutErr) {
                            const std::string errorMsg =
                                std::string("PmSockShutCryptoOneWay failed: ") +
                                PmSockErrStringFromError(shutErr);
                            UTIL_THROW_FATAL(userLabel_.c_str(), errorMsg.c_str());
                        }
                    }
                #endif
                }
                else if (kPhase_doneError == phase_) {
                    g_io_channel_close(pGChan_);
                }
                else {
                    assert(kPhase_sendingRequest == phase_);
                    /// Will continue sending when the palmsocket instance
                    /// becomes writeable again...
                }
                break;

            case kPhase_reapingResponse:
                phase_ = ReapResponse();
                if (kPhase_doneSuccess == phase_) {

                    UpdateSockWatch(G_IO_NVAL);

                    if (kConnKind_plaintext != connectKind_) {
                        if (useLegacyAPI_) {
                            GError* pGerror = NULL;
                            bool const shutSuccess = !PmSetSocketEncryption(
                                pGChan_,
                                false/*doSwitchToEncryptedMode*/,
                                this,
                                &HTTP_1_0_Trans::LegacySecureSocketSwitchCb,
                                &pGerror);
                            if (shutSuccess) {
                                assert(!pGerror);
                            }
                            else {
                                assert(pGerror);
                                g_prefix_error(
                                    &pGerror,
                                    "PmSetSocketEncryption to plaintext failed: ");
                                const std::string errorMsg(pGerror->message);
                                g_clear_error(&pGerror);
                                UTIL_THROW_FATAL(userLabel_.c_str(), errorMsg.c_str());
                            }
                        }
                        else {
                            PslError const shutErr = PmSockShutCryptoTwoWay(
                                pSock_, NULL/*pConf*/, &ShutCryptoTwoWayCompletionCb);
                            if (shutErr) {
                                const std::string errorMsg =
                                    std::string("PmSockShutCryptoTwoWay failed: ") +
                                    PmSockErrStringFromError(shutErr);
                                UTIL_THROW_FATAL(userLabel_.c_str(), errorMsg.c_str());
                            }
                        }
                    }
                    else {
                        g_io_channel_close(pGChan_);
                    }
                }
                else if (kPhase_doneError == phase_) {
                    g_io_channel_close(pGChan_);
                }
                else {
                    assert(kPhase_reapingResponse == phase_);
                    /// Will continue reaping when the palmsocket instance
                    /// becomes readable again...
                }
                break;

            case kPhase_init:
                assert(false && "MUST NOT be called in kPhase_init");
                break;
            case kPhase_doneSuccess:
                assert(false && "MUST NOT be called in kPhase_doneSuccess");
                break;
            case kPhase_doneError:
                assert(false && "MUST NOT be called in kPhase_doneError");
                break;
            }
        }//HandleSockWatchEvent


        /**
         * Incrementally write HTTP request
         * 
         * @return Phase HTTP request phase: kPhase_sendingRequest,
         *         kPhase_doneError
         */
        Phase SendRequest()
        {
            assert(kPhase_sendingRequest == phase_);

            GIOStatus giostatus = G_IO_STATUS_NORMAL;

            while (G_IO_STATUS_NORMAL == giostatus) {
                int const charsToWrite = requestMsg_.length() - reqConsumedCnt_;
                assert(charsToWrite > 0);

                const char* pSrc = requestMsg_.c_str() + reqConsumedCnt_;

                GError* pGerror = NULL;
                gsize   charsWritten = 0;
                giostatus = g_io_channel_write_chars(
                    pGChan_, pSrc, charsToWrite, &charsWritten, &pGerror);

                reqConsumedCnt_ += charsWritten;

                if (verbose_) {
                    printf(
                        "%s: g_io_channel_write_chars(%d) completed with: " \
                        "GIOStatus=%s, charsWritten=%d, so far: %d/%d\n",
                        userLabel_.c_str(), charsToWrite,
                        psl_test_blade::UtilStringFromGIOStatus(giostatus,
                                                            userLabel_.c_str()),
                        (int)charsWritten, (int)reqConsumedCnt_,
                        (int)requestMsg_.length());
                }

                assert(charsWritten >= 0);
                assert((int)charsWritten <= charsToWrite);


                if (G_IO_STATUS_ERROR == giostatus) {
                    assert(pGerror);

                    if (verbose_) {
                        printf("%s: ERROR from g_io_channel_write_chars(%d): " \
                               "%d (%s) after writing %d of %d request bytes\n",
                               userLabel_.c_str(), charsToWrite,
                               (int)pGerror->code, pGerror->message,
                               (int)reqConsumedCnt_, (int)requestMsg_.length());
                    }
                    g_clear_error(&pGerror);

                    /// Test PmSockGetLastError
                    PslError const lastErr = PmSockGetLastError(pSock_);
                    assert(lastErr);
                    if (verbose_) {
                        printf("%s: ERROR from g_io_channel_write_chars " \
                               "(PmSockGetLastError): %d (%s)\n",
                               userLabel_.c_str(), (int)lastErr,
                               PmSockErrStringFromError(lastErr));
                    }

                    return kPhase_doneError;
                }

                else {
                    assert(!pGerror);
                    /// @note We shouldn't see G_IO_STATUS_EOF when writing
                    assert(G_IO_STATUS_EOF != giostatus);
                    assert(G_IO_STATUS_NORMAL == giostatus ||
                           G_IO_STATUS_AGAIN == giostatus);

                    if ((int)requestMsg_.length() == reqConsumedCnt_) {
                        if (verbose_) {
                            printf("%s: HTTP request write is complete, " \
                                   "switching to kPhase_reapingResponse\n",
                                   userLabel_.c_str());
                        }
                        return kPhase_reapingResponse;
                    }
                }
            }//while (G_IO_STATUS_NORMAL)

            return kPhase_sendingRequest;
        }//SendRequest


        /**
         * Incrementally read and process HTTP response
         * 
         * @return Phase HTTP request phase: kPhase_reapingResponse,
         *         kPhase_doneSuccess or kPhase_doneError
         */
        Phase ReapResponse()
        {
            assert(kPhase_reapingResponse == phase_);

            GIOStatus giostatus = G_IO_STATUS_NORMAL;

            while (G_IO_STATUS_NORMAL == giostatus) {
                gchar  readbuf[1024];

                GError* pGerror = NULL;
                gsize   const bytesToRead = sizeof(readbuf);
                gsize   bytesRead = 0;
                giostatus = g_io_channel_read_chars(
                    pGChan_, readbuf, bytesToRead, &bytesRead, &pGerror);

                totalReadSoFar_ += bytesRead;

                if (verbose_) {
                    printf(
                        "%s: g_io_channel_read_chars(%d) completed with: " \
                        "GIOStatus=%s, bytesRead=%d, totalReadSoFar=%u\n",
                        userLabel_.c_str(), (int)bytesToRead,
                        psl_test_blade::UtilStringFromGIOStatus(giostatus,
                                                            userLabel_.c_str()),
                        (int)bytesRead, totalReadSoFar_);
                }

                assert(bytesToRead >= 0);
                assert(bytesRead <= bytesToRead);

                if (verbose_ && bytesRead) {
                    /// @todo Handle unprintable chars properly
                    fwrite(readbuf, 1, bytesRead, stdout);
                }

                switch (giostatus) {
                case G_IO_STATUS_ERROR:
                    {
                        assert(pGerror);

                        if (verbose_) {
                            printf("%s: ERROR from g_io_channel_read_chars: " \
                                   "%d (%s)\n", userLabel_.c_str(),
                                   (int)pGerror->code, pGerror->message);
                        }
                        g_clear_error(&pGerror);

                        /// Test PmSockGetLastError
                        PslError const lastErr = PmSockGetLastError(pSock_);
                        assert(lastErr);
                        if (verbose_) {
                            printf("%s: ERROR from g_io_channel_read_chars " \
                                   "(PmSockGetLastError): %d (%s)\n",
                                   userLabel_.c_str(), (int)lastErr,
                                   PmSockErrStringFromError(lastErr));
                        }
                    }
                    return kPhase_doneError;
                    break;

                case G_IO_STATUS_NORMAL:
                    continue;
                    break;
                case G_IO_STATUS_EOF:
                    return kPhase_doneSuccess;  ///< clean EOF
                    break;
                case G_IO_STATUS_AGAIN:
                    break;
                }
            }//while (G_IO_STATUS_NORMAL)

            return kPhase_reapingResponse;
        }//ReapResponse


        /**
         * Update our palmsocket watch conditions; throw an exception on
         * error.
         * 
         * @param condition
         */
        void UpdateSockWatch(GIOCondition const condition)
        {
            /// Suppress our sock watch
            PslError const watchErr = PmSockWatchUpdate(
                pSockWatch_, condition);
            if (watchErr) {
                const std::string errorMsg =
                    std::string("PmSockWatchUpdate failed: ") +
                    PmSockErrStringFromError(watchErr);
                UTIL_THROW_FATAL(userLabel_.c_str(), errorMsg.c_str());
            }
        }


        /**
         * Close our palmsocket channel
         */
        void DestroySockAndWatch(bool doneNotify)
        {
            if (0 && verbose_) {
                printf("%s/%s: ENTERING\n", __func__, userLabel_.c_str());
            }

            if (pSockGSource_) {

                if (0 && verbose_) {
                    printf(
                        "%s/%s: Destroying watch now (before g_source_destroy)\n",
                        __func__, userLabel_.c_str());
                }
                assert(pSockGSource_->context);

                g_source_destroy(pSockGSource_);

                if (0 && verbose_) {
                    printf(
                        "%s/%s: Destroying watch now (before " \
                        "g_source_unfref): source ref=%u\n",
                        __func__, userLabel_.c_str(),
                        (unsigned)pSockGSource_->ref_count);
                }

                g_source_unref(pSockGSource_);
                pSockGSource_ = NULL;

            }

            if (pGChan_) {
                if (0 && verbose_) {
                    printf("%s/%s: destroying palmsocket.\n",
                           __func__, userLabel_.c_str());
                }
                if (!PmSockIsClosed(pSock_)) {
                    g_io_channel_close(pGChan_);
                }
                g_io_channel_unref(pGChan_);
                pGChan_ = NULL;
            }

            if (doneNotify) {
                if (0 && verbose_) {
                    printf("%s/%s: triggering DoneEvt.\n",
                           __func__, userLabel_.c_str());
                }
                pDoneEvt_->Trigger();
            }

            if (0 && verbose_) {
                printf("%s/%s: LEAVING\n", __func__, userLabel_.c_str());
            }
        }


        /**
         * GIOFunc type callback for our PmSockWatch instance.
         * 
         * @param pSourceBase
         * @param condition
         * @param userData Pointer to our HTTP_1_0_Trans instance.
         * 
         * @return gboolean
         */
        static gboolean SockWatchCallback(GIOChannel*   const pSourceBase,
                                          GIOCondition  const condition,
                                          gpointer      const userData)
        {
            HTTP_1_0_Trans* me = (HTTP_1_0_Trans*)userData;

            SetReset    guard(&me->inWatchCallback_);

            me->HandleSockWatchEvent(condition);

            return true;        ///< remain attached to our gmain context
        }

    private:

        class SetReset {
        public:
            explicit SetReset(bool* pBool)
            :   pBool_(pBool)
            {
                assert(pBool);

                *pBool_ = true;
            }
            ~SetReset()
            {
                *pBool_ = false;
            }
        private:
            bool*   const pBool_;
        };

        const std::string       userLabel_;
        const std::string       servername_;
        const std::string       path_;
        PmSockSSLContext* const pSSLCtx_;
        const int               serverport_;
        const InetKind          inetKind_;
        const bool              verbose_;

        const bool              useLegacyAPI_;


        std::string             requestMsg_;
        int                     reqConsumedCnt_;

        wsf::RdAsyncBridge*     pDoneEvt_;

        Phase                   phase_;

        union {
            PmSockIOChannel*        pSock_;
            GIOChannel*             pGChan_; ///< pSock_ cast to (GIOChannel*)
        };///< anonymous

        union {
            PmSockWatch*            pSockWatch_;
            GSource*                pSockGSource_; ///< pSockWatch_ cast to (GSource*)
        };///< anonymous

        ConnKind                connectKind_;

        bool                    inWatchCallback_;
        bool                    destroyWatchPending_;

        unsigned int            totalReadSoFar_;

        class CryptoConfArgs : public ::PmSockCryptoConfArgs {
        public:
            CryptoConfArgs()
            {
                enabledOpts = 0;

                enabledOpts |= kPmSockCryptoConfigEnabledOpt_lifecycleCb;
                lifecycleCb = &HTTP_1_0_Trans::OpensslLifecycleCb;

                verifyCb = &HTTP_1_0_Trans::OpensslPeerVerifyCb;
                enabledOpts |= kPmSockCryptoConfigEnabledOpt_verifyCb;

                verifyOpts = kPmSockCertVerifyOpt_checkHostname;
                enabledOpts |= kPmSockCryptoConfigEnabledOpt_verifyOpts;
            }
        };
        static const CryptoConfArgs cryptoConfArgs_;

    };//class HTTP_1_0_Trans


    const HTTP_1_0_Trans::CryptoConfArgs HTTP_1_0_Trans::cryptoConfArgs_;


    /**
     * Transaction manager class
     */
    class HttpTransMgr {
    public:
        /**
         * @note pSSLCtx and pThreadCtx will be NULL when legacy
         *       palmsocket API use is requested.
         * 
         * @param userLabel
         * @param pRd
         * @param pSSLCtx
         * @param pThreadCtx
         * @param servername
         * @param uripath
         * @param serverport
         * @param inetKind
         * @param connKind
         * @param verbose
         */
        HttpTransMgr(const std::string&                 userLabel,
                     wsf::RuntimeDispatcher*    const   pRd,
                     PmSockSSLContext*          const   pSSLCtx,
                     PmSockThreadContext*       const   pThreadCtx,
                     const std::string&                 servername,
                     const std::string&                 uripath,
                     int                        const   serverport,
                     HTTP_1_0_Trans::InetKind   const   inetKind,
                     HTTP_1_0_Trans::ConnKind   const   connKind,
                     const bool                         verbose)
        :   userLabel_(userLabel),
            rd_(*pRd),
            pSSLCtx_(pSSLCtx ? PmSockSSLCtxRef(pSSLCtx) : NULL),
            pThreadCtx_(pThreadCtx ? PmSockThreadCtxRef(pThreadCtx) : NULL),
            servername_(servername),
            uripath_(uripath),
            serverport_(serverport),
            inetKind_(inetKind),
            connKind_(connKind),
            verbose_(verbose),
            loops_(0),
            pLoopsDoneEvt_(NULL),
            pTrans_(NULL),
            completedCnt_(0),
            successCnt_(0),
            transDoneEvt_(this, &HttpTransMgr::OnTransDoneEvent,
                          (void*)NULL, *pRd),
            progress_(0, 1, userLabel.c_str())
        {
        }

        ~HttpTransMgr()
        {
            progress_.Final();

            delete pTrans_;

            if (pThreadCtx_) {
                PmSockThreadCtxUnref(pThreadCtx_);
            }

            if (pSSLCtx_) {
                PmSockSSLCtxUnref(pSSLCtx_);
            }
        }

        void Start(unsigned int loops, wsf::RdAsyncBridge* const pLoopsDoneEvt)
        {
            assert(loops > 0);
            assert(pLoopsDoneEvt);
            assert(!loops_);
            assert(!pTrans_);


            progress_.SetTotal(loops);

            loops_ = loops;
            pLoopsDoneEvt_ = pLoopsDoneEvt;

            NextTrans();
        }

        bool IsDone()
        {
            assert(loops_);

            return completedCnt_ == loops_;
        }


        void PrintStatus()
        {
            printf("%s: completedCnt=%u/%u, successCnt=%u.\n",
                   userLabel_.c_str(), completedCnt_, loops_, successCnt_);
        }

    private:
        void OnTransDoneEvent(wsf::RdAsyncBridge*/*ignore*/, void*/*ignore CXT*/)
        {
            assert(pTrans_);

            progress_.Tick();

            ++completedCnt_;
            if (pTrans_->IsSuccess()) {
                ++successCnt_;

                if (verbose_) {
                    printf("%s[%u] completed with SUCCESS: successCnt=%u/%u.\n",
                           userLabel_.c_str(), completedCnt_-1, successCnt_,
                           completedCnt_);
                }
            }
            else {
                if (verbose_) {
                    printf("%s[%u] completed with FAILURE: successCnt=%u/%u.\n",
                           userLabel_.c_str(), completedCnt_-1, successCnt_,
                           completedCnt_);
                }
            }

            if (completedCnt_ == loops_) {
                pLoopsDoneEvt_->Trigger();

                if (verbose_) {
                    printf("%s: all loops completed: successCnt=%u/%u.\n",
                           userLabel_.c_str(), successCnt_, completedCnt_);
                }
            }
            else {
                assert(completedCnt_ < loops_);
                NextTrans();
            }
        }

        void NextTrans()
        {
            if (pTrans_) {
                assert(pTrans_->IsDone());

                delete pTrans_;
                pTrans_ = NULL;
            }

            std::ostringstream oss;
            oss << userLabel_ << "[" << completedCnt_ << "]";

            pTrans_ = new HTTP_1_0_Trans(oss.str(), pSSLCtx_, pThreadCtx_,
                                         servername_, uripath_, serverport_,
                                         inetKind_, verbose_);
            pTrans_->Start(connKind_, &transDoneEvt_);
        }


    private:
        std::string                 const   userLabel_;
        wsf::RuntimeDispatcher&             rd_;
        /// @note pSSLCtx_ and pThreadCtx_ will be NULL when legacy palmsocket
        ///       API use is requested.
        PmSockSSLContext*           const   pSSLCtx_;
        PmSockThreadContext*        const   pThreadCtx_;
        std::string                 const   servername_;
        std::string                 const   uripath_;
        int                         const   serverport_;
        HTTP_1_0_Trans::InetKind    const   inetKind_;
        HTTP_1_0_Trans::ConnKind    const   connKind_;
        bool                        const   verbose_;

        unsigned int                        loops_;
        wsf::RdAsyncBridge*                 pLoopsDoneEvt_;

        HTTP_1_0_Trans*                     pTrans_;

        unsigned int                        completedCnt_;
        unsigned int                        successCnt_;

        wsf::RdAsyncBridge                  transDoneEvt_;

        wtu::ProgressReporter               progress_;

    };//class HttpTransMgr

} // end of anonymous namespace





namespace psl_test_blade {
const char kTestCmdHTTPGet[] = "http.get";



/**
 * libpalmsocket HTTP/HTTPS-based test
 */
class TestCmdHTTPGet {
private:


private:
    explicit TestCmdHTTPGet(const MyCmdShell::ArgsType &args)
    :   args_(args),
        addrFamily_(AF_INET),
        force_(false),
        useLegacyAPI_(false),
        loopMax_(1),
        parallelCnt_(1),
        stagedConn_(false),
        uri_(),
        verbose_(false),
        crypto_(false),
        serverName_(),
        serverPath_(),
        serverPort_(0),
        rd_(IsLegacyRequest(args) ? g_main_context_default() : NULL),
        endTestEvt_(this, &TestCmdHTTPGet::OnEndTestEvent,
                      (void*)NULL, rd_),
        checkDoneEvt_(this, &TestCmdHTTPGet::OnCheckDoneEvent,
                      (void*)NULL, rd_),
        cmdShellInterruptMon_(
            &args.PeekShell(), &rd_,
            std::tr1::bind(&TestCmdHTTPGet::OnCmdShellInterruptCb, this,
                           std::tr1::placeholders::_1))
    {
    }

    ~TestCmdHTTPGet()
    {
        /// @note may be less than parallelCnt_ if Execute failed.
        unsigned int const transCnt = transactions_.size();
        for (unsigned int i=0; i < transCnt; ++i) {
            delete transactions_[i];
        }
        transactions_.clear();

    }

    void OnCheckDoneEvent(wsf::RdAsyncBridge*/*ignore*/, void*/*ignore CXT*/)
    {
        bool    done = true;

        assert(transactions_.size() == parallelCnt_);

        for (unsigned int i=0; i < parallelCnt_; ++i) {
            if (!transactions_[i]->IsDone()) {
                done = false;
                break;
            }
        }

        if (done) {
            endTestEvt_.Trigger();
        }
    }

    void OnEndTestEvent(wsf::RdAsyncBridge*/*ignore*/, void*/*ignore CXT*/)
    {
        rd_.RequestStop();
    }

    void OnCmdShellInterruptCb(wtu::CommandShellInterruptMonitor* pMon)
    {
        printf("%s: INTERRUPTED.\n", args_[0]);
        rd_.RequestStop();
    }


    /** Executes a command
     * 
     * @param args
     * 
     * @return bool true on success; false on failure
     */
    bool Execute()
    {
        if (!ParseArgs()) {
            return false;
        }

        assert(parallelCnt_ > 0);
        assert(loopMax_ > 0);

        class ExecuteRaii {
        public:
            ExecuteRaii()
            :   pThreadCtx(NULL),
                pSslCtx(NULL)
            {
            }

            ~ExecuteRaii()
            {
                if (pThreadCtx) {
                    PmSockThreadCtxUnref(pThreadCtx);
                }

                if (pSslCtx) {
                    PmSockSSLCtxUnref(pSslCtx);
                }
            }
        public:
            PmSockThreadContext*    pThreadCtx;
            PmSockSSLContext*       pSslCtx;
        };

        ExecuteRaii raii;


        if (!useLegacyAPI_) {
            GMainLoop* const gmainloop =
                (GMainLoop*)wsf::RuntimeDispatcher::GetInternalLoop(rd_);
            assert(gmainloop);

            /// Create a palmsocket thread context
            PslError pslErr = PmSockThreadCtxNewFromGMain(
                g_main_loop_get_context(gmainloop), args_[0],
                &raii.pThreadCtx);
            if (pslErr) {
                const std::string errorMsg =
                    std::string("PmSockThreadCtxNewFromGMain failed: ") +
                    PmSockErrStringFromError(pslErr);
                UTIL_THROW_FATAL(args_[0], errorMsg.c_str());
            }


            /// Create a palmsocket SSL context
            pslErr = PmSockSSLCtxNew(args_[0], &raii.pSslCtx);
            if (pslErr) {
                const std::string errorMsg =
                    std::string("PmSockSSLCtxNew failed: ") +
                    PmSockErrStringFromError(pslErr);
                UTIL_THROW_FATAL(args_[0], errorMsg.c_str());
            }
        }



        /// Instantiate and start up HTTP Transaction manager(s)
        HTTP_1_0_Trans::InetKind const inetKind =
            (addrFamily_ == AF_INET
             ? HTTP_1_0_Trans::kInetKind_ipv4
             : HTTP_1_0_Trans::kInetKind_ipv6);

        HTTP_1_0_Trans::ConnKind const connKind =
            (!crypto_
             ? HTTP_1_0_Trans::kConnKind_plaintext
             : (stagedConn_
                ? HTTP_1_0_Trans::kConnKind_cryptoIndirect
                : HTTP_1_0_Trans::kConnKind_crypto));

        for (unsigned int i=0; i < parallelCnt_; ++i) {
            std::ostringstream oss;
            oss << "httpMgr[" << i << "]";

            HttpTransMgr* const pMgr = new HttpTransMgr(
                oss.str(), &rd_, raii.pSslCtx, raii.pThreadCtx, serverName_,
                serverPath_, serverPort_, inetKind, connKind, verbose_);

            pMgr->Start(loopMax_, &checkDoneEvt_);

            transactions_.push_back(pMgr);
        }

        /// Run until all transactions complete or we get a stop request
        rd_.Run();


        /// Output status of each transaction
        for (unsigned int i=0; i < parallelCnt_; ++i) {
            transactions_[i]->PrintStatus();
        }

        return true;
    } // Execute()


    bool IsLegacyRequest(const MyCmdShell::ArgsType &args)
    {
        if (args_.Count() < 3) {
            return false;
        }

        for (int i=2; i < args_.Count(); ++i) {
            if (0 == strcmp("-legacy", args_[i])) {
                return true;
            }
        }

        return false;
    }


    bool ParseArgs()
    {
        if (args_.Count() < 2) {
            printf("%s: ERROR: Expected at least one arg (URI), " \
                   "but got %d\n", args_[0], args_.Count() - 1);
            return false;
        }


        uri_ = args_[1];

        for (int i=2; i < args_.Count(); ++i) {
            if (0 == strcmp("-force", args_[i])) {
                force_ = true;
            }
            else if (0 == strcmp("-inet4", args_[i])) {
                addrFamily_ = AF_INET;
            }
            else if (0 == strcmp("-inet6", args_[i])) {
                addrFamily_ = AF_INET6;
            }
            else if (0 == strcmp("-legacy", args_[i])) {
                useLegacyAPI_ = true;
            }
            else if (0 == strcmp("-loop", args_[i])) {
                ++i;
                if (i >= args_.Count()) {
                    printf("%s: ERROR: expected a loop count " \
                           "after %s, but got none\n", args_[0], args_[i-1]);
                    return false;
                }

                sscanf(args_[i], "%u", &loopMax_);
                if (loopMax_ <= 0) {
                    printf("%s: ERROR: expected a loop count > 0, but got" \
                           "%s, which evaluated to to %u\n",
                           args_[0], args_[i], loopMax_);
                    return false;
                }
            }
            else if (0 == strcmp("-parallel", args_[i])) {
                ++i;
                if (i >= args_.Count()) {
                    printf("%s: ERROR: expected a parallel count " \
                           "after %s, but got none\n", args_[0], args_[i-1]);
                    return false;
                }

                sscanf(args_[i], "%u", &parallelCnt_);
                if (parallelCnt_ <= 0) {
                    printf("%s: ERROR: expected a parallel count > 0, but got" \
                           "%s, which evaluated to to %u\n",
                           args_[0], args_[i], parallelCnt_);
                    return false;
                }
            }
            else if (0 == strcmp("-stagedconn", args_[i])) {
                stagedConn_ = true;
            }
            else if (0 == strcmp("-verbose", args_[i])) {
                verbose_ = true;
            }
            else {
                printf("%s: ERROR: Unexpected command-line arg: <%s>\n",
                       args_[0], args_[i]);
                return false;
            }
        }

        /// Make sure we don't trigger an accidental denial-of-service attack
        double totalCnt = loopMax_ * parallelCnt_;
        if ((totalCnt > kMaxTotalRequests_) && !force_) {
            printf("%s: ERROR: too many requests may constitute a " \
                   "Denial-of-Service attack:\n" \
                   "   (loop=%u x parallel=%u) = %f requests.\n" \
                   "maximum allowed total is %u. Use '-force' to override\n",
                   args_[0], loopMax_, parallelCnt_, totalCnt,
                   kMaxTotalRequests_);
            return false;
        }




        /**
         * If '://' is not present in the URI, insert 'http://'
         * 
         * uriparser won't correctly parse a malformed URI that's
         * missing a scheme.
         * 
         * @note This is not a bulletproof technique to use in
         *       production code, but is fine for the purposes of our
         *       test command.
         */
        if (!strcasestr(uri_.c_str(), "://")) {
            if (verbose_) {
                printf("%s: missing scheme specifier, assuming 'http'\n",
                       args_[0]);
            }

            uri_.insert(0, "http://");
        }

        /**
         * Parse the URI
         */

        UriParserStateA state;
        UriUriA         uri;

        class UriRAIIType {
        public:
            UriUriA* pUri;

            UriRAIIType() : pUri(NULL) {}

            ~UriRAIIType()
            {
                if (pUri) {
                    uriFreeUriMembersA(pUri);
                }
            }
        }; 

        UriRAIIType uriraii;

        state.uri = uriraii.pUri = &uri;

        if (uriParseUriA(&state, uri_.c_str()) != URI_SUCCESS) {
            /* Failure */

            printf("%s: ERROR parsing uri string '%s' at position '%s\n",
                   args_[0], uri_.c_str(), state.errorPos);
            return false;
        }

        /**
         * Scheme
         */
        if (uri.scheme.first && uri.scheme.afterLast) {
            std::string schemeText(uri.scheme.first,
                                   uri.scheme.afterLast - uri.scheme.first);

            if (0 == strcasecmp("http", schemeText.c_str())) {
                crypto_ = false;
            }
            else if (0 == strcasecmp("https", schemeText.c_str())) {
                     crypto_ = true;
            }
            else {
                printf("%s: ERROR: unexpected scheme: '%s'\n",
                       args_[0], schemeText.c_str());
                return false;
            }

            if (verbose_) {
                printf("%s: scheme='%s'\n", args_[0], schemeText.c_str());
            }
        }
        else {
            if (verbose_) {
                printf("%s: Scheme name not specified explicitly; " \
                       "assuming http.\n", args_[0]);
            }
            crypto_ = false;
        }


        /**
         * servername
         */
        if (uri.hostText.first && uri.hostText.afterLast &&
            (uri.hostText.afterLast - uri.hostText.first) > 0) {
            serverName_.append(uri.hostText.first,
                               uri.hostText.afterLast - uri.hostText.first);

            if (verbose_) {
                printf("%s: serverName is '%s'\n",
                       args_[0], serverName_.c_str());
            }
        }
        else {
            printf("%s: uri.hostText.first=%p, uri.hostText.afterLast=%p\n",
                   args_[0], uri.hostText.first, uri.hostText.afterLast);
            printf("%s: ERROR: missing host name.\n", args_[0]);
            return false;
        }


        /// port number
        if (uri.portText.first && uri.portText.afterLast) {
            std::string portText(uri.portText.first,
                                 uri.portText.afterLast - uri.portText.first);
            sscanf(portText.c_str(), "%d", &serverPort_);

            if (verbose_) {
                printf("%s: port number=%d (%s)\n",
                       args_[0], serverPort_, portText.c_str());
            }
        }
        else {
            serverPort_ = crypto_ ? 443 : 80;

            if (verbose_) {
                printf(
                    "%s: port number not specified explicitly; assuming %d " \
                    "based on scheme.\n", args_[0], serverPort_);
            }
        }

        /// URI path
        for (UriPathSegmentA* pSeg=uri.pathHead; pSeg; pSeg = pSeg->next) {
            serverPath_.append("/", 1);
            if (pSeg->text.first && pSeg->text.afterLast) {
                serverPath_.append(pSeg->text.first,
                                   pSeg->text.afterLast - pSeg->text.first);
            }
        }

        if (serverPath_.empty()) {
            serverPath_.append("/", 1);

            if (verbose_) {
                printf("%s: uri path was empty, defaulting to '/'\n",
                       args_[0]);
            }
        }

        if (verbose_) {
            printf("%s: uripath is '%s'\n",
                   args_[0], serverPath_.c_str());
        }

        if (stagedConn_ && !crypto_) {
            printf("%s: ERROR: -stagedconn arg specified, but scheme is not " \
                   "HTTPS.\n", args_[0]);
            return false;
        }

        return true;
    }//ParseArgs


private:
    static bool Register()
    {
        MyCmdShellHost::CmdRegInfo info;
        info.pName = kTestCmdHTTPGet;
        info.pHelp =
            "Performs an HTTP or HTTPS GET request; " \
            "args: " \
            "<uri> " \
            "[-force] " \
            "[-inet4 | -inet6] " \
            "[-legacy] "
            "[-loop number-of-times] " \
            "[-parallel number-of-parallel-requests] " \
            "[-stagedconn] " \
            "[-verbose] " \
            "\n\n" \
            "uri         E.g., 'HTTP://palm.com', 'https://login.yahoo.com'\n" \
            "[-force]    A large number of continuous requests constitutes\n" \
            "            a Denial of Service attack.  By default, this\n" \
            "            command will fail if a large total GET count\n" \
            "            is requested.  However, if you're testing in a\n" \
            "            lab environment on your own network, you may\n" \
            "            use the -force argument to override this\n" \
            "            restriction.\n" \
            "-inet4      Selects IPv4 address family. (DEFAULT)\n" \
            "-inet6      Selects IPv6 address family.\n" \
            "-legacy     Forces use of legacy palmsocket API (DEFAULT=use\n" \
            "            new palmsocket API).\n" \
            "-loop       Number of times to repeat the GET (DEFAULT=1).\n" \
            "            total requests=(loop-count x parallel-count).\n" \
            "-parallel   Number of parallel requests to perform " \
            "(DEFAULT=1)\n" \
            "-stagedconn For HTTPS only: connect to plaintext, then SSL.\n" \
            "\n";

        info.handlerCb = &Handler;

        RegisterCmdHandler(info);
        return true;
    }


    /**
     * The command handler callback function that we register with
     * our command shell
     * 
     * @param args
     * 
     * @return bool
     */
    static bool Handler(const MyCmdShell::ArgsType &args)
    {
        TestCmdHTTPGet   handler(args);
        return handler.Execute();
    }

private:
    const MyCmdShell::ArgsType& args_;

    /**
     * If (loopMax_ x parallelCnt_) exceed kMaxTotalRequests_, then
     * the request will be rejected unless the '-force' option is
     * also specified.  This is intended to prevent an accidental
     * (unintended) denial of service attack.
     */
    static const unsigned int   kMaxTotalRequests_ = 200;

    int                         addrFamily_;    ///< AF_INET or AF_INET6
    bool                        force_;         ///< override max requests
    bool                        useLegacyAPI_;
    unsigned int                loopMax_;
    unsigned int                parallelCnt_;   ///< # of parallell transactions
    bool                        stagedConn_;
    std::string                 uri_;
    bool                        verbose_;

    bool                        crypto_;        ///< FALSE=plaintext; TRUE=SSL
    std::string                 serverName_;
    std::string                 serverPath_;
    int                         serverPort_;

    std::vector<HttpTransMgr*>  transactions_;

    wsf::GlibRuntimeDispatcher  rd_;
    wsf::RdAsyncBridge          endTestEvt_;
    wsf::RdAsyncBridge          checkDoneEvt_;

    wtu::CommandShellInterruptMonitor   cmdShellInterruptMon_;

    static const bool           registered_;
}; // class TestCmdHTTPGet

const bool TestCmdHTTPGet::registered_ = Register();

} /// End of namespace
