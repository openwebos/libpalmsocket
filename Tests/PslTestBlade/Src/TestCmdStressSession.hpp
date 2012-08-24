/** 
 * *****************************************************************************
 * @file TestCmdStressSession.hpp
 * @ingroup psl_test
 * 
 * @brief  StressSession class implementation shared by both
 *         client and server-side classes for the libplamsocket
 *         Stress test command handler for stress-testing
 *         libpalmsocket's PmSock API in a multi-threaded
 *         environment.  Also used by the SSL shutdown test.
 * 
 * *****************************************************************************
 */
#ifndef PSL_TEST_CMD_STRESS_SESSION_HPP
#define PSL_TEST_CMD_STRESS_SESSION_HPP


#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <time.h>

#if 0
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//#include <unistd.h>


#include <algorithm>
#include <string>
#include <sstream>
//#include <vector>
//#include <memory>
//#include <map>

#include <glib.h>

#include <stdexcept>

#include <PmWirelessSystemFramework/Utils/RuntimeDispatcher/RuntimeDispatcher.h>
#include <PmWirelessSystemFramework/Utils/RuntimeDispatcher/RdAsyncBridge.h>
#include <PmWirelessSystemFramework/Utils/RuntimeDispatcher/RdDescriptorMonitor.h>
#include <PmWirelessSystemFramework/Utils/Thread.h>
#include <PmWirelessSystemFramework/Utils/Uncopyable.h>

#include <PmWsfTestUtils/ProgressReporter.h>

#include <palmsocket.h>


#include "SockUtils.h"
#include "CommonUtils.h"

#include "TestCmdStressCommon.hpp"


namespace { /// anonymous



class StressSession : private wsf::Uncopyable {
public:
    class StressSessionArg {
    public:
        StressSessionArg()
        :   isServer(false), pChan(NULL), groupIndex(0), loopIndex(0),
            progressBytePeriod(0), pRd(NULL), pSessDoneEvt(NULL), pSSLCtx(NULL),
            sslRenegotiate(false), targetRxBytes(0), targetTxBytes(0),
            ioSliceThreashold(0), maxWriteByteCnt(0), paceWriteMillisec(0),
            testKind(kStressTestKind_none), useCrypto(false)
        {
            ::memset(&sslConfig, 0, sizeof(sslConfig));
        }

        bool                isServer;      ///< true if server; otherwise client
        PmSockIOChannel*    pChan;         ///< does not convey ownership
        uint32_t            groupIndex;    ///< for identification
        uint32_t            loopIndex;     ///< for identification
        unsigned int        progressBytePeriod; ///< 0=none
        wsf::RuntimeDispatcher* pRd;       ///< does not convey ownership
        wsf::RdAsyncBridge* pSessDoneEvt;  ///< does not convey ownership
        PmSockCryptoConfArgs sslConfig;    ///< crypto config args
        PmSockSSLContext*   pSSLCtx;       ///< may pass NULL for default CTX
        bool                sslRenegotiate;/// TRUE = invoke SSL/TLS renegotiation
        uint32_t            targetRxBytes; ///< number of data Rx bytes to expect
        uint32_t            targetTxBytes; ///< number of data bytes to transmit
        /// # of rx/tx bytes before yielding control; 0 = default
        unsigned int        ioSliceThreashold;
        /// max bytes per write call; 0 = default
        unsigned int        maxWriteByteCnt;
        unsigned int        paceWriteMillisec; ///< delay between writes; 0=none
        StressTestKind      testKind;      ///< type of test to be performed
        bool                useCrypto;     ///< true for SSL/TLS; false for plaintext
        bool                isVerbose;
    };

    StressSession(const StressSessionArg& arg)
    :   arg_(ApplyDefaultsToArg(arg)),
        isSuccess_(false),
        phase_(kSessionPhase_idle),
        stopPhase_(kSessionPhase_idle),
        name_(MakeName(arg_)),
        paceWriteTS_(psl_test_blade::UtilTimespecFromMillisec(arg_.paceWriteMillisec)),
        pRxProgress_(
            (arg_.progressBytePeriod
             ? new wtu::ProgressReporter(arg_.targetRxBytes, arg_.progressBytePeriod,
                                         (name_ + "-Rx-bytes").c_str())
             : NULL)
            ),
        pTxProgress_(
            (arg_.progressBytePeriod
             ? new wtu::ProgressReporter(arg_.targetTxBytes, arg_.progressBytePeriod,
                                         (name_ + "-Tx-bytes").c_str())
             : NULL)
            ),
        pChanWatch_(psl_test_blade::UtilCreatePmSockWatch(arg_.pChan, (GIOCondition)0,
                                                      &ChannelWatchCb, this,
                                                      name_.c_str())),
        rx_(arg_.targetRxBytes),
        tx_(arg_.targetTxBytes),
        sslHandshakeStopwatch_()
    {
        assert(arg_.targetRxBytes || arg_.targetTxBytes);

        if (arg_.isVerbose) {
            UTIL_PRINT_LINE("%s/%s (this=%p): Created.",
                       name_.c_str(), __func__, this);
        }
    }

    ~StressSession()
    {

        if (arg_.isVerbose) {
            UTIL_PRINT_LINE("%s/%s (this=%p): Destroying pChanWatch...",
                       name_.c_str(), __func__, this);
        }

        psl_test_blade::UtilDestroyPmSockWatch(pChanWatch_);

        if (arg_.isVerbose) {
            UTIL_PRINT_LINE("%s/%s (this=%p): Destroyed pChanWatch",
                       name_.c_str(), __func__, this);
        }
    }


    void Start()
    {
        assert(kSessionPhase_idle == phase_);

        if (arg_.isServer && arg_.useCrypto) {
            assert(arg_.pSSLCtx && "SSL Server requires non-NULL server SSL Context");
        }

        if (arg_.sslConfig.enabledOpts) {
            assert(!arg_.sslConfig.enabledOpts || arg_.useCrypto);
        }

        if (arg_.sslRenegotiate) {
            assert(!arg_.sslRenegotiate || arg_.useCrypto);
        }

        ::PmSockSetUserData(arg_.pChan, this);

        if (arg_.useCrypto) {
            sslHandshakeStopwatch_.Start();
            PslError pslerr;
            if (arg_.isServer) {
                pslerr = ::PmSockAcceptCrypto(arg_.pChan, arg_.pSSLCtx,
                                              &arg_.sslConfig,
                                              &CryptoHandshakeCompletionCb);
                if (pslerr) {
                    const std::string errorMsg =
                        std::string("PmSockAcceptCrypto failed: ") +
                        ::PmSockErrStringFromError(pslerr);
                    UTIL_THROW_FATAL(name_.c_str(), errorMsg.c_str());
                }
            }
            else {
                PmSockCryptoConfArgs    sslConfigArgs = arg_.sslConfig;
                if (!sslConfigArgs.enabledOpts) {
                    /// Set default SSL config options
                    sslConfigArgs.enabledOpts = kPmSockCryptoConfigEnabledOpt_verifyOpts;
                    sslConfigArgs.verifyOpts = kPmSockCertVerifyOpt_checkHostname;
                }
                pslerr = ::PmSockConnectCrypto(arg_.pChan, arg_.pSSLCtx,
                                               &sslConfigArgs,
                                               &CryptoHandshakeCompletionCb);
                if (pslerr) {
                    const std::string errorMsg =
                        std::string("PmSockConnectCrypto failed: ") +
                        ::PmSockErrStringFromError(pslerr);
                    UTIL_THROW_FATAL(name_.c_str(), errorMsg.c_str());
                }
            }


            phase_ = kSessionPhase_sslHandshake;
        }

        else {
            BeginDataExchange();
        }

    }//Start


    void Stop()
    {
        if (arg_.isVerbose) {
            UTIL_PRINT_LINE("%s/%s: External Stop requested...",
                       name_.c_str(), __func__);
        }

        if (kSessionPhase_done == phase_) {
            if (arg_.isVerbose) {
                UTIL_PRINT_LINE("%s/%s: stress-session was already stopped.",
                           name_.c_str(), __func__);
            }
            return;
        }

        StopInternal();
    }


    const char* GetName()
    {
        return name_.c_str();
    }


    bool IsSuccess()
    {
        assert(kSessionPhase_done == phase_);

        return isSuccess_;
    }


    /** 
     * Returns SSL connection duration 
     *  
     * @note Don't call this when IsSuccess() evaluates to FALSE 
     * @note Don't call this if the session was not operating in 
     *       SSL/TLS mode
     * 
     * @return const struct timespec 
     */
    const struct timespec GetSSLHandshakeDuration()
    {
        assert(IsSuccess());
        assert(arg_.useCrypto);

        return sslHandshakeStopwatch_.GetElapsedTime();
    }


    /** 
     * Returns the amount of time it took the session to receive 
     * expected data from the remote peer 
     *  
     * @note Don't call this when IsSuccess() evaluates to FALSE
     * @note May only call this for the data-exchange and 
     *       uni-directional SSL shutdown tests.  Don't call this
     *       for the bi-directional SSL shutdown test.
     * 
     * @return const struct timespec 
     */
    const struct timespec GetRxDuration()
    {
        assert(IsSuccess());
        assert(kStressTestKind_SSLShutOneWay == arg_.testKind ||
               kStressTestKind_dataExg == arg_.testKind);

        if (rx_.maxDataRxCnt) {
            return rx_.dataStopwatch.GetElapsedTime();
        }
        else {
            static const struct timespec zerotime = {0, 0};
            return zerotime;
        }
    }


    /** 
     * Returns the amount of time it took the remote peer to receive
     * the expected data from this session instance 
     *  
     * @note Don't call this when IsSuccess() evaluates to FALSE 
     * 
     * @return const struct timespec 
     */
    const struct timespec GetTxDuration()
    {
        assert(IsSuccess());

        struct timespec duration;
        duration.tv_sec     = rx_.PeekReport()->rxDuration.sec;
        duration.tv_nsec    = rx_.PeekReport()->rxDuration.nanosec;

        return duration;
    }

    static unsigned int DataPatternSize()
    {
        return TxInfo::DataPattern::DataPatternSize();
    }


    void PrintStats()
    {
        assert(kSessionPhase_done == phase_);


        UTIL_PRINT_LINE("%s/%s: %s, stopPhase=%d, target/actualRxCnt=%u/%u, " \
                   "target/actualTxCnt=%u/%u", 
                   name_.c_str(), __func__, IsSuccess() ? "SUCCESS" : "FAILURE",
                   stopPhase_, rx_.maxDataRxCnt, rx_.numDataRxCnt,
                   tx_.maxDataTxCnt, tx_.numDataTxCnt);
    }

private:

    static const StressSessionArg
    ApplyDefaultsToArg(const StressSessionArg& arg)
    {
        StressSessionArg res = arg;

        if (!res.ioSliceThreashold) {
            unsigned const oldSlice = res.ioSliceThreashold;

            res.ioSliceThreashold = 50000;

            if (arg.isVerbose) {
                UTIL_PRINT_LINE("%s/%s: Adjusted ioSliceThreashold from %u to %u", 
                                MakeName(arg).c_str(), __func__, oldSlice,
                                res.ioSliceThreashold);
            }
        }

        if (!res.maxWriteByteCnt || res.maxWriteByteCnt > DataPatternSize()) {
            unsigned const oldCnt = res.maxWriteByteCnt;

            res.maxWriteByteCnt = DataPatternSize();

            if (arg.isVerbose) {
                UTIL_PRINT_LINE("%s/%s: Adjusted maxWriteByteCnt from %u to %u", 
                                MakeName(arg).c_str(), __func__,
                                oldCnt, res.maxWriteByteCnt);
            }
        }

        if (arg.isVerbose) {
            UTIL_PRINT_LINE("%s/%s: Using: ioSliceThreashold=%u, maxWriteByteCnt=%u", 
                            MakeName(arg).c_str(), __func__,
                            res.ioSliceThreashold, res.maxWriteByteCnt);
        }

        return res;
    }//ApplyDefaultsToArg


    void
    StopInternal()
    {
        if (arg_.isVerbose) {
            UTIL_PRINT_LINE("%s/%s: TERMINATING...", name_.c_str(), __func__);
        }

        assert(kSessionPhase_idle != phase_);
        assert(kSessionPhase_done != phase_);


        UpdateChannelWatch((GIOCondition)0);

        stopPhase_ = phase_;
        phase_ = kSessionPhase_done;

        arg_.pSessDoneEvt->Trigger();
    }



    /**
     * Callback function associated with the StressSession's channel watch
     * 
     * @param pChanBase
     * @param condition
     * @param userData
     * 
     * @return gboolean
     */
    static gboolean
    ChannelWatchCb(GIOChannel*   const pChanBase,
                   GIOCondition  const condition,
                   gpointer      const userData)
    {
        StressSession* const me = (StressSession*)userData;

        assert(!(condition & G_IO_NVAL));

        switch (me->phase_) {
        case kSessionPhase_idle:
            //FALLTHROUGH
        case kSessionPhase_sslHandshake:
            //FALLTHROUGH
        case kSessionPhase_sslShutdown:
            //FALLTHROUGH
        case kSessionPhase_done:
            break;

        case kSessionPhase_dataIO:
            me->DoDataIO(condition);
            return true;
            break;
        case kSessionPhase_reportIO:
            me->DoReportIO(condition);
            return true;
            break;
        case kSessionPhase_tcpShutdown:
            me->DoGracefulTCPShutdown(condition);
            return true;
            break;
        }

        const std::string errorMsg =
            std::string("FATAL ERROR: UNEXPECTED SESSION PHASE=") +
            StringFromSessionPhase(me->phase_);
        UTIL_PRINT_ERROR("%s: %s", me->name_.c_str(), errorMsg.c_str());
        assert(false && "UNEXPECTED SESSION PHASE");

        return true;        ///< remain attached to our gmain context
    }//ChannelWatchCb


    void
    DoDataIO(GIOCondition const condition)
    {
        assert(tx_.numDataTxCnt < tx_.maxDataTxCnt ||
               rx_.numDataRxCnt < rx_.maxDataRxCnt);

        /// We use this constant to limit the total amount of data written
        /// and total amount of data read on any one dispatch in order to
        /// prevent starvation of reads versus writes (which is particularly
        /// pronounced when Debug logging is enabled), as well as I/O versus
        /// other "asynchronous" activities

        uint32_t    writtenSoFar = 0;
        while (writtenSoFar < arg_.ioSliceThreashold &&
               tx_.numDataTxCnt < tx_.maxDataTxCnt &&
               UTIL_IS_BIT_SET(condition, G_IO_OUT | G_IO_HUP | G_IO_NVAL)) {
            uint32_t    const totalRemCnt = tx_.maxDataTxCnt - tx_.numDataTxCnt;
            unsigned    const patternSize = sizeof(tx_.txPattern.data);
            uint32_t    const srcOffset = tx_.numDataTxCnt % patternSize;
            uint32_t    const srcRemCnt = patternSize - srcOffset;
            uint32_t    const maxWriteCnt = std::min(arg_.maxWriteByteCnt,
                                                     std::min(totalRemCnt, srcRemCnt));
            assert(maxWriteCnt > 0);

            uint32_t    numWritten = 0;
            ::GIOStatus const giostatus = psl_test_blade::UtilTxPmSockBytes(
                arg_.pChan, &(tx_.txPattern.data[srcOffset]),
                maxWriteCnt, &numWritten,
                arg_.isVerbose, name_.c_str()
                );

            writtenSoFar += numWritten;
            tx_.numDataTxCnt += numWritten;
            assert(tx_.numDataTxCnt <= tx_.maxDataTxCnt);

            if (pTxProgress_.get()) {
                pTxProgress_->Tick(numWritten);
            }

            if (::G_IO_STATUS_ERROR == giostatus) {
                UTIL_PRINT_ERROR(
                    "%s/%s: I/O ERROR detected after writing %u bytes: " \
                    "PslError=%d (%s)",
                    name_.c_str(), __func__, tx_.numDataTxCnt,
                    ::PmSockGetLastError(arg_.pChan),
                    ::PmSockErrStringFromError(::PmSockGetLastError(arg_.pChan)));

                if (0) {
                    /**
                     * This is a bit of test code for confirming that a particular 
                     * bug is caused by openssl and not by Palm's kernel patch that 
                     * destroys sockets associated with a shut-down network 
                     * interface: openssl appears to have a bug whereby whenever we 
                     * have both pending write and a pending read, and a pending 
                     * G_IO_HUP condition on the channel, SSL_write would return 
                     * ECONNRESET, but the immediately following SSL_read would 
                     * return SSL_WANT_READ (instead of ECONNRESET) 
                     *  
                     * @note Interestingly, when write() failed with ECONNRESET, the 
                     *       subsequent read() failed with ENOTCONN.
                     */
                    char buf[100];
                    uint32_t numRead;
                    psl_test_blade::UtilRxPmSockBytes(
                        arg_.pChan, buf,
                        sizeof(buf), &numRead,
                        arg_.isVerbose, name_.c_str()
                        );
                }//if (0)

                StopInternal();
                return;
            }

            if (arg_.sslRenegotiate && numWritten &&
                tx_.numDataTxCnt < tx_.maxDataTxCnt) {
                TriggerSSLRenegotiation();
            }

            if (::G_IO_STATUS_NORMAL != giostatus) {
                break;
            }

            //#if 0
            /// For reproducing NOV-119272 (libpalmsocket: receipt of a final
            /// 1-byte SSL record (immediately followed by EOF) as deferred I/O
            /// will cause g_io_channel_read_chars to return the byte along with
            /// G_IO_STATUS_EOF instead of G_IO_STATUS_NORMAL)
            /// cmd: shut -how ud -client rx=10001 -maxwrite 10000 -ioslice 10000
            ///  -addr localhost -port 30999 -server -key star.kruglikov.castle.com.key.pem
            if (arg_.paceWriteMillisec && tx_.numDataTxCnt != tx_.maxDataTxCnt) {
                (void)nanosleep(&paceWriteTS_, NULL);
            }
            //#endif
        }//while (more data to tx)


        uint32_t    readSoFar = 0;
        while (readSoFar < arg_.ioSliceThreashold &&
               rx_.numDataRxCnt < rx_.maxDataRxCnt &&
               UTIL_IS_BIT_SET(condition, G_IO_IN | G_IO_HUP | G_IO_NVAL)) {

            uint8_t     rxBuf[1024 * 8];

            uint32_t    numRead = 0;
            ::GIOStatus const giostatus = psl_test_blade::UtilRxPmSockBytes(
                arg_.pChan, rxBuf,
                sizeof(rxBuf), &numRead,
                arg_.isVerbose, name_.c_str()
                );

            uint32_t    const totalRemCnt = rx_.maxDataRxCnt - rx_.numDataRxCnt;
            uint32_t    const dataRxCnt = std::min(totalRemCnt, numRead);

            if (::G_IO_STATUS_NORMAL != giostatus && numRead > 0) {
                UTIL_PRINT_ERROR(
                    "%s/%s: UNEXPECTED non-zero numRead=%u with non-NORMAL GIOStatus=%s " \
                    "after reading %u data bytes",
                    name_.c_str(), __func__, numRead,
                    psl_test_blade::UtilStringFromGIOStatus(giostatus, name_.c_str()), 
                    rx_.numDataRxCnt);
                StopInternal();
                return;
            }

            if (::G_IO_STATUS_ERROR == giostatus) {
                UTIL_PRINT_ERROR(
                    "%s/%s: UNEXPECTED G_IO_STATUS_ERROR after reading %u data bytes",
                    name_.c_str(), __func__, rx_.numDataRxCnt);
                StopInternal();
                return;
            }

            if (::G_IO_STATUS_EOF == giostatus) {
                // During two-way SSL shutdown test, the client side will get an
                // incomplete read after SSL shutdown completes
                if (!arg_.isServer && kStressTestKind_SSLShutTwoWay == arg_.testKind &&
                    tx_.numDataTxCnt == tx_.maxDataTxCnt) {
                    BeginGracefulTCPShutdown();
                }
                else {
                    UTIL_PRINT_ERROR(
                        "%s/%s: UNEXPECTED G_IO_STATUS_EOF after reading %u data bytes\n",
                        name_.c_str(), __func__, rx_.numDataRxCnt);
                    StopInternal();
                }
                return;
            }

            if (::G_IO_STATUS_NORMAL != giostatus) {
                break;
            }

            if (numRead > dataRxCnt) {
                if (kStressTestKind_dataExg != arg_.testKind) {
                    UTIL_PRINT_ERROR(
                        "%s/%s: FATAL ERROR: UNEXPECTED rx bytes after complete " \
                        "input stream: num rx bytes=%u",
                        name_.c_str(), __func__, numRead - dataRxCnt);
                    assert(false && "UNEXPECTED rx bytes after complete input stream");
                }

                rx_.AppendReportBytes(rxBuf + dataRxCnt, numRead - dataRxCnt,
                                      name_.c_str());
            }


            /// Validate the data
            for (uint32_t i=0; i < dataRxCnt; i++, rx_.nextExpectedDataByte++) {
                if (rxBuf[i] != rx_.nextExpectedDataByte) {
                    UTIL_PRINT_ERROR("%s/%s: FATAL ERROR: unexpected Rx data byte: " \
                             "exptected %u, but got %u at offset %u.",
                             name_.c_str(), __func__, 
                             (unsigned)rx_.nextExpectedDataByte,
                             (unsigned)rxBuf[i], rx_.numDataRxCnt + i);
                    assert(false && "UNEXPECTED RX DATA BYTE VALUE");
                }
            }

            readSoFar += dataRxCnt;
            rx_.numDataRxCnt += dataRxCnt;

            if (pRxProgress_.get()) {
                pRxProgress_->Tick(dataRxCnt);
            }

            if (rx_.numDataRxCnt == rx_.maxDataRxCnt && rx_.dataStopwatch.IsRunning()) {
                rx_.dataStopwatch.Stop();
            }
        }//while (more data to rx)


        // Are we done already ?
        if (tx_.numDataTxCnt == tx_.maxDataTxCnt &&
            rx_.numDataRxCnt == rx_.maxDataRxCnt) {

            if (arg_.isServer && (kStressTestKind_SSLShutOneWay == arg_.testKind ||
                                  kStressTestKind_SSLShutTwoWay == arg_.testKind)) {
                BeginGracefulTwoWayShutdown();
            }
            else if (!arg_.isServer && (kStressTestKind_SSLShutOneWay == arg_.testKind ||
                                        kStressTestKind_SSLShutTwoWay == arg_.testKind)) {
                BeginGracefulTwoWayShutdown();
            }
            else {
                BeginReportExchange();
            }
        }

        else {
            if (writtenSoFar > 0 && tx_.numDataTxCnt == tx_.maxDataTxCnt &&
                !arg_.isServer && (kStressTestKind_SSLShutOneWay == arg_.testKind ||
                                   kStressTestKind_SSLShutTwoWay == arg_.testKind)) {
                BeginClientSSLShutdownForSSLShutTest();
            }


            ::GIOCondition    cond = (::GIOCondition)0;

            if (rx_.numDataRxCnt < rx_.maxDataRxCnt) {
                cond = (::GIOCondition)(cond | ::G_IO_IN);
            }

            if (tx_.numDataTxCnt < tx_.maxDataTxCnt) {
                cond = (::GIOCondition)(cond | ::G_IO_OUT);
            }

            /// @todo Performance optimization: save the previously-set cond
            ///       and update only when different

            UpdateChannelWatch(cond);
        }
    }//DoDataIO


    void
    DoReportIO(GIOCondition const condition)
    {
        assert(tx_.numReportTxCnt < sizeof(tx_.report) ||
               rx_.RemainingReportByteCnt() > 0);


        if (tx_.numReportTxCnt < sizeof(tx_.report) &&
            UTIL_IS_BIT_SET(condition, G_IO_OUT | G_IO_HUP | G_IO_NVAL)) {
            uint32_t    const totalRemCnt = sizeof(tx_.report) - tx_.numReportTxCnt;
            const void* const p = (uint8_t*)&tx_.report + tx_.numReportTxCnt;

            uint32_t    numWritten = 0;
            ::GIOStatus const giostatus = psl_test_blade::UtilTxPmSockBytes(
                arg_.pChan, p, totalRemCnt, &numWritten,
                arg_.isVerbose, name_.c_str()
                );

            tx_.numReportTxCnt += numWritten;
            assert(tx_.numReportTxCnt <= sizeof(tx_.report));

            if (::G_IO_STATUS_ERROR == giostatus) {
                UTIL_PRINT_ERROR("%s/%s: I/O ERROR detected after writing %u bytes\n",
                            name_.c_str(), __func__, tx_.numReportTxCnt);
                StopInternal();
                return;
            }

        }

        if (rx_.RemainingReportByteCnt() > 0 &&
            UTIL_IS_BIT_SET(condition, G_IO_IN | G_IO_HUP | G_IO_NVAL)) {

            uint8_t rxBuf[sizeof(PeerReport)];
            assert(rx_.RemainingReportByteCnt() <= sizeof(rxBuf));

            uint32_t    numRead = 0;
            ::GIOStatus const giostatus = psl_test_blade::UtilRxPmSockBytes(
                arg_.pChan, rxBuf, rx_.RemainingReportByteCnt(), &numRead,
                arg_.isVerbose, name_.c_str()
                );

            rx_.AppendReportBytes(rxBuf, numRead, name_.c_str());

            if (::G_IO_STATUS_ERROR == giostatus) {
                UTIL_PRINT_ERROR("%s/%s: I/O ERROR detected after reading %u bytes\n",
                            name_.c_str(), __func__, rx_.ReceivedReportByteCnt());
                StopInternal();
                return;
            }

            if (::G_IO_STATUS_EOF == giostatus && rx_.RemainingReportByteCnt() > 0) {
                UTIL_PRINT_ERROR(
                    "%s/%s: UNEXPECTED EOF detected after reading %u report bytes\n",
                    name_.c_str(), __func__, rx_.ReceivedReportByteCnt());
                StopInternal();
                return;
            }
        }


        if (tx_.numReportTxCnt == sizeof(tx_.report) &&
            0 == rx_.RemainingReportByteCnt()) {

            const PeerReport* const pRxReport = rx_.PeekReport();

            if (PEER_REPORT_SIGNATURE != pRxReport->signature) {
                UTIL_PRINT_ERROR(
                    "%s/%s: FATAL ERROR: invalid report signature: expected 0x%X, " \
                    "but got signature=0x%X, groupIndex=%u, loopIndex=%u.\n",
                    name_.c_str(), __func__, (unsigned)PEER_REPORT_SIGNATURE,
                    (unsigned)pRxReport->signature, pRxReport->groupIndex,
                    pRxReport->loopIndex);
                assert(false && "INVALID REPORT SIGNATURE");
            }
            assert(arg_.groupIndex == pRxReport->groupIndex);
            assert(arg_.loopIndex == pRxReport->loopIndex);

            if (pRxReport->numRxBytes != tx_.numDataTxCnt) {
                UTIL_PRINT_ERROR("%s/%s: FATAL ERROR: unexpected rx_.report.numRxBytes: " \
                         "expected %u, but got %u.\n",
                         name_.c_str(), __func__,
                         tx_.numDataTxCnt,
                         pRxReport->numRxBytes);
                assert(false && "INVALID REPORT SIGNATURE");
            }

            BeginGracefulTwoWayShutdown();
        }

        else {
            ::GIOCondition    cond = (::GIOCondition)0;

            if (rx_.RemainingReportByteCnt() > 0) {
                cond = (::GIOCondition)(cond | ::G_IO_IN);
            }

            if (tx_.numReportTxCnt < sizeof(tx_.report)) {
                cond = (::GIOCondition)(cond | ::G_IO_OUT);
            }

            UpdateChannelWatch(cond);
        }
    }//DoReportIO



    void
    DoGracefulTCPShutdown(GIOCondition const condition)
    {
        uint8_t     rxBuf[1024];
        uint32_t    numRead = 0;
        ::GIOStatus const giostatus = psl_test_blade::UtilRxPmSockBytes(
            arg_.pChan, rxBuf, sizeof(rxBuf), &numRead,
            arg_.isVerbose, name_.c_str()
            );

        /**
         * @note Since we already reaped all the expected incoming data
         *       as well as the peer's report, there shouldn't be any
         *       more data coming in.  We're simply waiting for clean
         *       EOF.
         */

        if (numRead) {
            UTIL_PRINT_ERROR(
                "%s/%s: ERROR: unexpected Rx of %u bytes, terminating session\n",
                name_.c_str(), __func__, numRead);
            StopInternal();
            return;
        }

        if (::G_IO_STATUS_ERROR == giostatus) {
            UTIL_PRINT_ERROR("%s/%s: I/O ERROR detected, terminating session\n",
                        name_.c_str(), __func__);
            StopInternal();
            return;
        }

        if (::G_IO_STATUS_EOF == giostatus) {
            if (arg_.isVerbose) {
                UTIL_PRINT_LINE("%s/%s: SUCCESS: EOF detected, terminating session",
                           name_.c_str(), __func__);
            }

            isSuccess_ = true;
            StopInternal();
            return;
        }

        assert(::G_IO_STATUS_NORMAL != giostatus);
    }//DoGracefulTCPShutdown


    void
    TriggerSSLRenegotiation()
    {
        if (arg_.isVerbose) {
            UTIL_PRINT_LINE("%s/%s: triggering SSL/TLS renegotiation",
                       name_.c_str(), __func__);
        }
        PmSockRenegOpts const opts = (arg_.isServer
                                      ? kPmSockRenegOpt_waitForClientHandshake
                                      : 0);
        psl_test_blade::UtilTriggerSSLRenegotiation(arg_.pChan, opts, name_.c_str());
    }


    void
    BeginDataExchange()
    {
        assert(arg_.targetRxBytes || arg_.targetTxBytes);

        if (arg_.isVerbose) {
            UTIL_PRINT_LINE("%s: Beginning Data Exchange...", name_.c_str());
        }

        ::GIOCondition    cond = (::GIOCondition)0;

        if (rx_.maxDataRxCnt &&
            (kStressTestKind_SSLShutOneWay == arg_.testKind ||
             kStressTestKind_dataExg == arg_.testKind)) {

            cond = (::GIOCondition)(cond | ::G_IO_IN);
            rx_.dataStopwatch.Start();
        }

        else {
            if (0) {
                /**
                 * This is a bit of test code for debugging an openssl 
                 * workaround in libpalmsocket whereby whenever we have both 
                 * pending write and a pending read, and a pending G_IO_HUP 
                 * condition on the channel, SSL_write would return ECONNRESET, 
                 * but the immediately following SSL_read would return 
                 * SSL_WANT_READ (instead of ECONNRESET) 
                 */
                char buf[100];
                uint32_t rxcnt;
                GIOStatus const giostatus =
                    psl_test_blade::UtilRxPmSockBytes(arg_.pChan,
                                                      buf,
                                                      sizeof(buf),
                                                      &rxcnt,
                                                      arg_.isVerbose,
                                                      name_.c_str());
                assert(G_IO_STATUS_NORMAL != giostatus);
            }
        }

        if (tx_.maxDataTxCnt) {
            cond = (::GIOCondition)(cond | ::G_IO_OUT);
        }

        UpdateChannelWatch(cond);

        phase_ = kSessionPhase_dataIO;
    }//BeginDataExchange


    /**
     * 
     */
    void
    BeginReportExchange()
    {
        if (arg_.isVerbose) {
            UTIL_PRINT_LINE("%s: Beginning Report Exchange...", name_.c_str());
        }

        tx_.report.groupIndex   = arg_.groupIndex;
        tx_.report.loopIndex    = arg_.loopIndex;
        tx_.report.numRxBytes   = rx_.numDataRxCnt;
        tx_.report.signature    = PEER_REPORT_SIGNATURE;

        if (rx_.dataStopwatch.IsStarted()) {
            assert(!rx_.dataStopwatch.IsRunning());
            
            struct timespec const ts = rx_.dataStopwatch.GetElapsedTime();
            tx_.report.rxDuration.sec = ts.tv_sec;
            tx_.report.rxDuration.nanosec = ts.tv_nsec;
        }

        UpdateChannelWatch((GIOCondition)(::G_IO_IN | ::G_IO_OUT));

        phase_ = kSessionPhase_reportIO;
    }


    /**
     * 
     */
    void
    BeginGracefulTwoWayShutdown()
    {

        if (arg_.useCrypto) {
            if (arg_.isVerbose) {
                UTIL_PRINT_LINE("%s: Beginning bi-directional SSL/TLS shutdown...",
                           name_.c_str());
            }

            UpdateChannelWatch((GIOCondition)0);

            PslError const pslerr = ::PmSockShutCryptoTwoWay(
                arg_.pChan, NULL/*pConf*/, &CryptoShutdownCompletionCb);
            if (pslerr) {
                const std::string errorMsg =
                    std::string("PmSockShutCryptoTwoWay failed: ") +
                    ::PmSockErrStringFromError(pslerr);
                UTIL_THROW_FATAL(name_.c_str(), errorMsg.c_str());
            }

            phase_ = kSessionPhase_sslShutdown;

        }

        else {
            BeginGracefulTCPShutdown();
        }
    }


    /**
     * 
     */
    void
    BeginGracefulTCPShutdown()
    {
        if (arg_.isVerbose) {
            UTIL_PRINT_LINE("%s: Beginning Graceful TCP/IP shutdown...", name_.c_str());
        }

        PslError const pslerr = ::PmSockShutSocket(arg_.pChan, SHUT_WR);
        if (pslerr) {
            const std::string errorMsg =
                std::string("PmSockShutSocket(SHUT_WR) failed: ") +
                ::PmSockErrStringFromError(pslerr);
            UTIL_PRINT_ERROR("%s: %s", name_.c_str(), errorMsg.c_str());

            StopInternal();
        }
        else {
            UpdateChannelWatch((GIOCondition)::G_IO_IN);

            phase_ = kSessionPhase_tcpShutdown;
        }

    }

    /**
     * 
     */
    void
    BeginClientSSLShutdownForSSLShutTest()
    {
        if (kStressTestKind_SSLShutOneWay == arg_.testKind) {
            if (arg_.isVerbose) {
                UTIL_PRINT_LINE(
                    "%s: Beginning uni-directional SSL/TLS shutdown for " \
                    "SSL-SHUT test", name_.c_str());
            }

            PslError const pslerr = ::PmSockShutCryptoOneWay(
                arg_.pChan, NULL/*pConf*/, NULL);
            if (pslerr) {
                const std::string errorMsg =
                    std::string("PmSockShutCryptoOneWay failed: ") +
                    ::PmSockErrStringFromError(pslerr);
                UTIL_THROW_FATAL(name_.c_str(), errorMsg.c_str());
            }

        }//kStressTestKind_SSLShutOneWay

        else if (kStressTestKind_SSLShutTwoWay == arg_.testKind) {
            if (arg_.isVerbose) {
                UTIL_PRINT_LINE(
                    "%s: Beginning bi-directional SSL/TLS shutdown for " \
                    "SSL-SHUT test", name_.c_str());
            }

            PslError const pslerr = ::PmSockShutCryptoTwoWay(
                arg_.pChan, NULL/*pConf*/, NULL);
            if (pslerr) {
                const std::string errorMsg =
                    std::string("PmSockShutCryptoTwoWay failed: ") +
                    ::PmSockErrStringFromError(pslerr);
                UTIL_THROW_FATAL(name_.c_str(), errorMsg.c_str());
            }
        }//kStressTestKind_SSLShutTwoWay
    }


    /**
     * PmSockCompletionCb for the initial SSL/TLS handshake
     * @param channel
     * @param userData
     * @param errorCode
     */
    static void
    CryptoHandshakeCompletionCb(PmSockIOChannel*    const ch,
                                void*               const userData,
                                PslError            const errorCode)
    {
        StressSession* const me = (StressSession*)userData;

        me->sslHandshakeStopwatch_.Stop();

        if (me->arg_.isVerbose) {
            UTIL_PRINT_LINE("%s: SSL Handshake attempt completed: %s: PslError=%d(%s)",
                       me->name_.c_str(), errorCode ? "ERROR" : "SUCCESS",
                       errorCode, ::PmSockErrStringFromError(errorCode));

            psl_test_blade::UtilDumpPeerVerifyErrorInfo(ch, me->name_.c_str());
        }

        if (errorCode) {
            me->StopInternal();
        }
        else {
            if (me->arg_.sslRenegotiate && me->tx_.maxDataTxCnt > 0) {
                me->TriggerSSLRenegotiation();
            }

            if (!me->arg_.isServer && 0 == me->arg_.targetTxBytes &&
                (kStressTestKind_SSLShutOneWay == me->arg_.testKind ||
                 kStressTestKind_SSLShutTwoWay == me->arg_.testKind)) {

                me->BeginClientSSLShutdownForSSLShutTest();
            }//!me->arg_.isServer

            me->BeginDataExchange();
        }
    }//CryptoHandshakeCompletionCb


    /**
     * PmSockCompletionCb for the initial SSL/TLS shutdown
     * @param channel
     * @param userData
     * @param errorCode
     */
    static void
    CryptoShutdownCompletionCb(PmSockIOChannel*    const ch,
                               void*               const userData,
                               PslError            const errorCode)
    {
        StressSession* const me = (StressSession*)userData;

        if (me->arg_.isVerbose) {
            UTIL_PRINT_LINE("%s: bi-directional SSL Shutdown attempt completed: " \
                       "%s: PslError=%d(%s)",
                       me->name_.c_str(), errorCode ? "ERROR" : "SUCCESS",
                       errorCode, ::PmSockErrStringFromError(errorCode));
        }

        if (errorCode) {
            me->StopInternal();
        }
        else {
            me->BeginGracefulTCPShutdown();
        }
    }//CryptoShutdownCompletionCb


    /**
     * UpdateChannelWatch():
     * 
     * @param cond
     */
    void UpdateChannelWatch(GIOCondition const cond)
    {
        psl_test_blade::UtilUpdatePmSockWatch(pChanWatch_, cond, name_.c_str());
    }//UpdateChannelWatch



    /**
     * 
     */
    static const std::string
    MakeName(const StressSessionArg& arg)
    {
        std::ostringstream oss;
        oss << (arg.isServer ? "SERVER-SESS" : "CLIENT-SESS");
        oss << "[" << arg.groupIndex << "]" << "[" << arg.loopIndex << "]";
        return oss.str();
    }


    enum SessionPhase {
        kSessionPhase_idle,
        kSessionPhase_sslHandshake,
        kSessionPhase_dataIO,
        kSessionPhase_reportIO,
        kSessionPhase_sslShutdown,
        kSessionPhase_tcpShutdown,
        kSessionPhase_done
    };


    /**
     * 
     * @param phase 
     * 
     * @return const char* 
     */
    static const char*
    StringFromSessionPhase(enum SessionPhase const phase)
    {
        switch (phase) {
        case kSessionPhase_idle:            return "kSessionPhase_idle";
            break;
        case kSessionPhase_sslHandshake:    return "kSessionPhase_sslHandshake";
            break;
        case kSessionPhase_dataIO:          return "kSessionPhase_dataIO";
            break;
        case kSessionPhase_reportIO:        return "kSessionPhase_reportIO";
            break;
        case kSessionPhase_sslShutdown:     return "kSessionPhase_sslShutdown";
            break;
        case kSessionPhase_tcpShutdown:     return "kSessionPhase_tcpShutdown";
            break;
        case kSessionPhase_done:            return "kSessionPhase_done";
            break;
        }

        assert(false && "UNEXPECTED SessionPhase value");
        return "UNEXPECTED";
    }


private:


    class RxInfo : private wsf::Uncopyable {
    public:
        RxInfo(uint32_t const targetRxBytes)
        :   maxDataRxCnt(targetRxBytes),
            nextExpectedDataByte(0),
            numDataRxCnt(0),
            dataStopwatch(),
            report_(),
            numReportRxCnt_(0)
        {
            ::memset(&report_, 0, sizeof(report_));
        }

        void AppendReportBytes(const void* const src,
                               uint32_t    const cnt,
                               const char* const label)
        {
            if (cnt > RemainingReportByteCnt()) {
                UTIL_PRINT_ERROR(
                    "%s/%s: FATAL ERROR: report overflow: expected only %u " \
                    "more bytes, but got %u bytes",
                    label, __func__, RemainingReportByteCnt(), cnt);
                assert(false && "Incoming report overflow");
            }

            ::memcpy(((uint8_t*)&report_) + numReportRxCnt_, src, cnt);
            numReportRxCnt_ += cnt;
        }

        uint32_t ReceivedReportByteCnt()
        {
            return numReportRxCnt_;
        }

        uint32_t RemainingReportByteCnt()
        {
            return (sizeof(report_) - numReportRxCnt_);
        }

        const PeerReport* PeekReport()
        {
            return &report_;
        }

    public:
        uint32_t const      maxDataRxCnt;  ///< max total bytes to send
        uint8_t             nextExpectedDataByte;
        uint32_t            numDataRxCnt;  ///< number of data bytes sent so far
        psl_test_blade::Stopwatch dataStopwatch;   ///< for measuring data rx duration

    private:
        PeerReport          report_;
        uint32_t            numReportRxCnt_;
    };//class RxInfo


    class TxInfo : private wsf::Uncopyable {
    public:
        TxInfo(uint32_t const targetTxBytes)
        :   maxDataTxCnt(targetTxBytes),
            numDataTxCnt(0),
            report(),
            numReportTxCnt(0)            
        {
            ::memset(&report, 0, sizeof(report));
        }

    public:
        class DataPattern : private wsf::Uncopyable {
        public:
            DataPattern()
            {
                uint8_t val = 0;
                for (unsigned i=0; i < sizeof(data); i++, val++) {
                    data[i] = val;
                }
            }

            static unsigned int
            DataPatternSize() {return kPatternSize;}

            static const unsigned int kPatternSize = 1024 * 31;

            /// Pre-initialized data buffer for transmitting
            uint8_t             data[kPatternSize];
        };//class DataPattern


        static DataPattern  txPattern;
        uint32_t const      maxDataTxCnt;  ///< max total bytes to send
        uint32_t            numDataTxCnt;  ///< number of data bytes sent so far
                                           /// 
        PeerReport          report;
        uint32_t            numReportTxCnt;
    };//class TxInfo

    StressSessionArg const      arg_;

    bool                        isSuccess_;

    SessionPhase                phase_;
    SessionPhase                stopPhase_; ///< phase when stopped

    std::string const           name_;

    struct timespec const       paceWriteTS_;

    std::auto_ptr<wtu::ProgressReporter>    pRxProgress_;
    std::auto_ptr<wtu::ProgressReporter>    pTxProgress_;

    ::PmSockWatch*              pChanWatch_;

    RxInfo                      rx_;
    TxInfo                      tx_;

    /// For measuring SSL/TLS handshake duration
    psl_test_blade::Stopwatch sslHandshakeStopwatch_;

};//class StressSession

StressSession::TxInfo::DataPattern  StressSession::TxInfo::txPattern;




} // end of anonymous namespace



#endif //PSL_TEST_CMD_STRESS_SESSION_HPP
