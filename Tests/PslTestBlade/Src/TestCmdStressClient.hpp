/** 
 * *****************************************************************************
 * @file TestCmdStressClient.hpp
 * @ingroup psl_test
 * 
 * @brief  Client-side implementation for the libplamsocket
 *         Stress test command handler for stress-testing
 *         libpalmsocket's PmSock API in a multi-threaded
 *         environment. Supports parallel requests.  Also used
 *         by the SSL shutdown test.
 * 
 * *****************************************************************************
 */
#ifndef PSL_TEST_CMD_STRESS_CLIENT_HPP
#define PSL_TEST_CMD_STRESS_CLIENT_HPP

#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <time.h>

#include <sys/socket.h>

#if 0
#include <netdb.h>
#include <sys/types.h>
#include <arpa/inet.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <string>
#include <sstream>
#include <vector>
#include <memory>
//#include <algorithm>
//#include <map>

#include <glib.h>

#include <stdexcept>

#include <PmWirelessSystemFramework/Utils/RuntimeDispatcher/RuntimeDispatcher.h>
#include <PmWirelessSystemFramework/Utils/RuntimeDispatcher/RdAsyncBridge.h>
#include <PmWirelessSystemFramework/Utils/Thread.h>
#include <PmWirelessSystemFramework/Utils/Uncopyable.h>

#include <PmWsfTestUtils/ProgressReporter.h>

#include <palmsocket.h>


#include "CommonUtils.h"

#include "TestCmdStressCommon.hpp"
#include "TestCmdStressSession.hpp"


namespace { /// anonymous


class StressClientPeerArg {
public:
    StressClientPeerArg()
    :   addr(),
        ioSliceThreashold(0),
        maxWriteByteCnt(0),
        paceWriteMillisec(0),
        port(0),
        progressBytePeriod(0),
        progressLoopPeriod(0),
        sslRenegFlags(0),
        targetRxBytes(0),
        targetTxBytes(0),
        testKind(kStressTestKind_none),
        useCrypto(false)
    {
        ::memset(&sslConfig, 0, sizeof(sslConfig));
    }

    std::string             addr;
    /// # of rx/tx bytes before yielding control; 0 = default
    unsigned int            ioSliceThreashold;
    /// max bytes per write call; 0 = default
    unsigned int            maxWriteByteCnt;
    unsigned int            paceWriteMillisec; ///< delay between writes; 0=none
    int                     port;
    unsigned int            progressBytePeriod; ///< 0 = none
    unsigned int            progressLoopPeriod; ///< 0 = none
    PmSockCryptoConfArgs    sslConfig;
    StressSSLRenegFlags     sslRenegFlags;
    unsigned int            targetRxBytes;
    unsigned int            targetTxBytes;
    StressTestKind          testKind;
    bool                    useCrypto;
};//class StressClientPeerArg


/**
 * CreateClientChannel()
 * @param arg
 * @param pRd
 * @param userLabel
 * 
 * @return ::PmSockIOChannel*
 */
inline ::PmSockIOChannel*
CreateClientChannel(const StressClientPeerArg&  arg,
                    wsf::RuntimeDispatcher*     pRd,
                    const char*                 userLabel);


class StressClientPeer
:   public psl_test_blade::PeerBase,
    private wsf::Uncopyable {
public:
    StressClientPeer(unsigned int               const groupIndex,
                     unsigned int               const loopIndex,
                     const StressClientPeerArg&       arg,
                     ::PmSockSSLContext*        const pSSLCtx,
                     wsf::RdAsyncBridge*        const pPeerDoneEvt,
                     bool                       const isVerbose)
    :   psl_test_blade::PeerBase(MakeMyName(__func__, groupIndex, loopIndex).c_str(),
                                 isVerbose),
        arg_(arg),
        pChan_(CreateClientChannel(arg, GetRd(), MyName())),
        pChanWatch_(psl_test_blade::UtilCreatePmSockWatch(pChan_, (GIOCondition)0,
                                                      &ChannelWatchCb, this,
                                                      MyName())),
        cmd_(),
        cmdBytesTx_(0),
        groupIndex_(groupIndex),
        loopIndex_(loopIndex),
        isDone_(false),
        isSuccess_(false),
        isVerbose_(isVerbose),
        rPeerDoneEvt_(*pPeerDoneEvt),
        sessDoneEvt_(this, &StressClientPeer::OnSessDoneEvt, 0, *(GetRd())),
        pSSLCtx_(NULL),
        pStressSession_(),
        thread_(std::string(__func__), this,
                &StressClientPeer::ClientPeerThreadFunc, (void*)NULL)
    {
        pSSLCtx_ = pSSLCtx ? ::PmSockSSLCtxRef(pSSLCtx) : NULL;

        /// Prepare command contents for sending to the remote peer
        ::memset(&cmd_, 0, sizeof(cmd_));
        cmd_.testKind       = arg_.testKind;
        cmd_.groupIndex     = groupIndex_;
        cmd_.loopIndex      = loopIndex_;
        cmd_.targetRxBytes  = arg_.targetTxBytes; ///< @note our tx is peer's rx
        cmd_.targetTxBytes  = arg_.targetRxBytes;
        cmd_.useCrypto      = arg_.useCrypto;
        cmd_.sslReneg       = (arg_.sslRenegFlags & kStressSSLRenegFlag_server);
        cmd_.signature      = SERVER_PEER_CMD_SIGNATURE;

        if (isVerbose_) {
            UTIL_PRINT_LINE("%s/%s (this=%p): created", MyName(), __func__, this);
        }
    }//StressClientPeer

    ~StressClientPeer()
    {
        psl_test_blade::UtilDestroyPmSockWatch(pChanWatch_);

        ::g_io_channel_unref((GIOChannel*)pChan_);

        if (pSSLCtx_) {
            ::PmSockSSLCtxUnref(pSSLCtx_);
        }

        if (isVerbose_) {
            UTIL_PRINT_LINE("%s/%s (this=%p): destroyed", MyName(), __func__, this);
        }
    }

    void Start()
    {
        if (isVerbose_) {
            UTIL_PRINT_LINE("%s/%s (this=%p): Starting...", MyName(), __func__, this);
        }

        thread_.Start();
    }

    void Stop()
    {
        RequestStop();

        if (isVerbose_) {
            UTIL_PRINT_LINE("%s/%s (this=%p): Joining thread...",
                            MyName(), __func__, this);
        }

        thread_.Join();

        if (isVerbose_) {
            UTIL_PRINT_LINE("%s/%s (this=%p): Thread Join completed.",
                            MyName(), __func__, this);
        }
    }

    bool IsDone()
    {
        return isDone_;
    }

    /**
     * @note DO NOT call this if IsDone() returns false
     * 
     * @return bool
     */
    bool IsSuccess()
    {
        assert(IsDone());

        return isSuccess_;
    }


    /** 
     * Returns SSL connection duration 
     *  
     * @note Don't call this when IsSuccess() evaluates to FALSE
     * @note Don't call this if the session was not operating in 
     * 
     * @return const struct timespec 
     */
    const struct timespec GetSSLConnectionDuration()
    {
        assert(IsSuccess());
        return pStressSession_->GetSSLHandshakeDuration();
    }


    /** 
     * Returns the amount of time it took the client to receive 
     * expected data from the server 
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
        return pStressSession_->GetRxDuration();
    }


    /** 
     * Returns the amount of time it took the server to receive the 
     * expected data from the client 
     *  
     * @note Don't call this when IsSuccess() evaluates to FALSE
     * @note May only call this for the data-exchange test. 
     * 
     * @return const struct timespec 
     */
    const struct timespec GetTxDuration()
    {
        assert(IsSuccess());
        assert(kStressTestKind_dataExg == arg_.testKind);
        return pStressSession_->GetTxDuration();
    }


    /**
     * @note DO NOT call this if IsDone() returns false
     * 
     */
    void PrintStats()
    {
        assert(IsDone());

        UTIL_PRINT_LINE("%s/%s (this=%p): %s", MyName(), __func__, this,
                        IsSuccess() ? "SUCCESS" : "FAILED");

        if (pStressSession_.get()) {
            pStressSession_->PrintStats();
        }
    }

private:
    /**
     * 
     */
    void ClientPeerThreadFunc(void* /*CXT*/)
    {
        if (isVerbose_) {
            UTIL_PRINT_LINE(
                "%s/%s (this=%p): thread started, connecting to server...",
                MyName(), __func__, this);
        }

        PslError pslerr;

        pslerr = ::PmSockConnectPlain(pChan_, NULL/*completionCb*/);
        if (pslerr) {
            const std::string errorMsg =
                std::string("PmSockConnectPlain failed: ") +
                ::PmSockErrStringFromError(pslerr);
            UTIL_THROW_FATAL(MyName(), errorMsg.c_str());
        }


        /**
         * @note The client peer expects to send instructions to the
         *       server peer, so we set our channel watch to wait for
         *       writeable; it will also alert us if the connection
         *       failed.
         */
        UpdateChannelWatch(::G_IO_OUT);

        psl_test_blade::PeerBase::Run();

        if (pStressSession_.get()) {
            pStressSession_->Stop();

            isSuccess_ = pStressSession_->IsSuccess();
        }

        ::g_io_channel_close((::GIOChannel*)pChan_);

        isDone_ = true;

        if (isVerbose_) {
            UTIL_PRINT_LINE("%s/%s (this=%p): shut-down complete, terminating",
                            MyName(), __func__, this);
        }

        rPeerDoneEvt_.Trigger();

        if (arg_.useCrypto) {
            ::PslError const pslerr = ::PmSockOpensslThreadCleanup();
            assert(!pslerr);
        }
    }//ClientPeerThreadFunc


    /**
     * UpdateChannelWatch():
     * 
     * @param cond
     */
    void UpdateChannelWatch(GIOCondition const cond)
    {
        psl_test_blade::UtilUpdatePmSockWatch(pChanWatch_, cond, MyName());
    }//UpdateChannelWatch


    /**
     * Callback function associated with the StressClientPeer's
     * channel watch
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
        StressClientPeer* const me = (StressClientPeer*)userData;

        assert(me->cmdBytesTx_ < sizeof(me->cmd_));

        uint32_t const maxTx = sizeof(me->cmd_) - me->cmdBytesTx_;
        uint32_t    numTx = 0;
        ::GIOStatus const giostatus = psl_test_blade::UtilTxPmSockBytes(
            me->pChan_, ((uint8_t*)&me->cmd_) + me->cmdBytesTx_,
            maxTx, &numTx, me->isVerbose_, me->MyName()
            );

        me->cmdBytesTx_ += numTx;
        assert(me->cmdBytesTx_ <= sizeof(me->cmd_));

        if (::G_IO_STATUS_ERROR == giostatus) {
            UTIL_PRINT_ERROR("%s/%s: I/O ERROR detected after writing %u bytes",
                             me->MyName(), __func__, me->cmdBytesTx_);
            me->RequestStop();
            me->UpdateChannelWatch((GIOCondition)0);
            return true; ///< remain attached
        }


        if (me->cmdBytesTx_ == sizeof(me->cmd_)) {
            /**
             * Sent the entire command!
             */

            if (me->isVerbose_) {
                UTIL_PRINT_LINE(
                    "%s/%s: sent cmd to server: client=[%u][%u], " \
                    "targetRxBytes=%u, targetTxBytes=%u, useCrypto=%u",
                    me->MyName(), __func__, me->groupIndex_, me->cmd_.loopIndex,
                    me->cmd_.targetRxBytes, me->cmd_.targetTxBytes,
                    me->cmd_.useCrypto);
            }

            /**
             * We're not going to be using our channel watch any more
             */
            me->UpdateChannelWatch((GIOCondition)0);

            /**
             * Create StressPeer and put it to work
             */
            StressSession::StressSessionArg    arg;

            arg.isServer        = false;
            arg.testKind        = me->arg_.testKind;
            arg.pChan           = me->pChan_;
            arg.groupIndex      = me->groupIndex_;
            arg.loopIndex       = me->loopIndex_;
            arg.progressBytePeriod = me->arg_.progressBytePeriod;
            arg.pRd             = me->GetRd();
            arg.pSessDoneEvt    = &me->sessDoneEvt_;
            arg.sslConfig       = me->arg_.sslConfig;
            arg.pSSLCtx         = me->pSSLCtx_;
            arg.sslRenegotiate  = (me->arg_.sslRenegFlags & kStressSSLRenegFlag_client);
            arg.targetRxBytes   = me->arg_.targetRxBytes;
            arg.targetTxBytes   = me->arg_.targetTxBytes;
            arg.ioSliceThreashold = me->arg_.ioSliceThreashold;
            arg.maxWriteByteCnt   = me->arg_.maxWriteByteCnt;
            arg.paceWriteMillisec = me->arg_.paceWriteMillisec;
            arg.useCrypto       = me->arg_.useCrypto;
            arg.isVerbose       = me->isVerbose_;

            me->pStressSession_.reset(
                new StressSession(arg)
                );
            me->pStressSession_->Start();
        }


        return true;        ///< remain attached to our gmain context
    }//ChannelWatchCb


    /**
     * OnSessDoneEvt(): Called when our StressSession instance
     * signals completion; called as a callback function from
     * wsf::RdAscynBridge
     */
    void OnSessDoneEvt(wsf::RdAsyncBridge*, int)
    {
        RequestStop();
    }


    /**
     * 
     * @param baseLabel
     * @param groupIndex
     * @param loopIndex
     * 
     * @return const std::string
     */
    static const std::string
    MakeMyName(const char*  const baseLabel,
               unsigned int const groupIndex,
               unsigned int const loopIndex)
    {
        std::ostringstream oss;
        oss << baseLabel << "[" << groupIndex << "]" << "[" << loopIndex << "]";
        return oss.str();
    }


private:
    StressClientPeerArg             const arg_;
    ::PmSockIOChannel*                    pChan_;
    ::PmSockWatch*                        pChanWatch_;
    ServerPeerCmd                         cmd_; ///< to be sent to server peer
    unsigned int                          cmdBytesTx_;
    unsigned int                          groupIndex_;
    unsigned int                          loopIndex_;
    bool                                  isDone_;
    bool                                  isSuccess_;
    bool                            const isVerbose_;
    wsf::RdAsyncBridge&                   rPeerDoneEvt_; ///< for signaling parent
    wsf::RdAsyncBridge                    sessDoneEvt_;  ///< session signals when done
    PmSockSSLContext*                     pSSLCtx_;
    std::auto_ptr<StressSession>          pStressSession_;
    wsf::Thread                           thread_;
};//class StressClientPeer



/**
 * 
 */
class StressClientGroup : private wsf::Uncopyable {
public:
    StressClientGroup(const char*             const userLabel,
                      const StressClientPeerArg&    arg,
                      unsigned int            const groupIndex,
                      unsigned int            const maxLoopCnt,
                      PmSockSSLContext*       const pSSLCtx,
                      wsf::RuntimeDispatcher* const pRd,
                      wsf::RdAsyncBridge*     const groupDoneEvt,
                      bool                    const isVerbose)
    :   arg_(arg),
        completedCnt_(),
        pCurrentPeer_(NULL),
        rGroupDoneEvt_(*groupDoneEvt),
        groupIndex_(groupIndex),
        isDone_(false),
        isRunning_(false),
        isVerbose_(isVerbose),
        loopIndex_(0),
        maxLoopCnt_(maxLoopCnt),
        name_(userLabel),
        pProgress_(
            (arg.progressLoopPeriod
             ? new wtu::ProgressReporter(maxLoopCnt, arg.progressLoopPeriod,
                                         (name_ + "-loop").c_str())
             : NULL)
            ),
        rd_(*pRd),
        pSSLCtx_(NULL),
        successCnt_(0),
        sslConnectThroughput_(),
        rxThroughput_(),
        txThroughput_()
    {
        assert(maxLoopCnt_);

        pSSLCtx_ = pSSLCtx ? ::PmSockSSLCtxRef(pSSLCtx) : NULL;

        if (isVerbose_) {
            UTIL_PRINT_LINE("%s/%s (this=%p): created",
                            name_.c_str(), __func__, this);
        }
    }

    ~StressClientGroup()
    {
        delete pCurrentPeer_;

        if (pSSLCtx_) {
            ::PmSockSSLCtxUnref(pSSLCtx_);
        }

        if (isVerbose_) {
            UTIL_PRINT_LINE("%s/%s (this=%p): destroyed",
                            name_.c_str(), __func__, this);
        }
    }

    void Start()
    {
        assert(!isRunning_ && !isDone_);

        isRunning_ = true;

        StartNextPeer();
    }

    bool IsRunning()
    {
        return isRunning_;
    }

    void Stop()
    {
        assert(isRunning_);

        isRunning_ = false;
        isDone_ = true;

        if (pCurrentPeer_) {
            ReapCurrentPeer();
        }
    }

    bool IsDone()
    {
        return isDone_;
    }

    bool IsSuccess()
    {
        assert(IsDone());

        return (maxLoopCnt_ == successCnt_);
    }


    void PrintStats()
    {

        if (IsDone()) {
            UTIL_PRINT_LINE(
                "%s/%s: completedCnt=%u, successCnt=%u, failedCnt=%u, requested_loops=%u,\n" \
                "sslConnect=%f sec/conn, rxThroughput=%f bytes/sec, txThroughput=%f bytes/sec",
                name_.c_str(), __func__, completedCnt_, successCnt_,
                completedCnt_ - successCnt_, maxLoopCnt_,
                sslConnectThroughput_.GetSecondsPerUnit(),
                rxThroughput_.GetUnitsPerSecond(),
                txThroughput_.GetUnitsPerSecond());
        }
        else {
            UTIL_PRINT_LINE("%s/%s: WARNING: either not done, or never started!",
                            name_.c_str(), __func__);
        }
    }

private:
    class ClientPeerRecord : private wsf::Uncopyable {
    public:
        std::auto_ptr<StressClientPeer>     pPeer;
        std::auto_ptr<wsf::RdAsyncBridge>   pPeerDoneEvt;
    };

private:
    void StartNextPeer()
    {
        assert(loopIndex_ < maxLoopCnt_);

        if (pCurrentPeer_) {
            ReapCurrentPeer();
            loopIndex_++;
        }

        if (loopIndex_ >= maxLoopCnt_) {
            /**
             * All loops are done
             */
            if (isVerbose_) {
                UTIL_PRINT_LINE("%s/%s: Group is done: all loops completed.",
                                name_.c_str(), __func__);
            }
            isDone_ = true;
            rGroupDoneEvt_.Trigger();
            return;
        }

        /**
         * Create the next client peer
         */
        if (isVerbose_) {
            UTIL_PRINT_LINE("%s/%s (this=%p): creating client peer [%u][%u]",
                            name_.c_str(), __func__, this, groupIndex_, loopIndex_);
        }

        std::auto_ptr<ClientPeerRecord> pClientPeerRec(new ClientPeerRecord);

        std::auto_ptr<wsf::RdAsyncBridge> pPeerDoneEvt(
            new wsf::RdAsyncBridge(this, &StressClientGroup::OnPeerDone,
                                   pClientPeerRec.get(), rd_)
            );

        std::auto_ptr<StressClientPeer> pClientPeer(
            new StressClientPeer(groupIndex_, loopIndex_, arg_, pSSLCtx_,
                                 pPeerDoneEvt.get(), isVerbose_)
            );

        pClientPeer->Start();

        pClientPeerRec->pPeer = pClientPeer;
        pClientPeerRec->pPeerDoneEvt = pPeerDoneEvt;

        assert(!pCurrentPeer_);
        pCurrentPeer_ = pClientPeerRec.release();
    }//StartNextPeer


    /**
     * 
     */
    void ReapCurrentPeer()
    {
        assert(pCurrentPeer_);

        if (isVerbose_) {
            UTIL_PRINT_LINE("%s/%s (this=%p): reaping client peer [%u][%u]",
                            name_.c_str(), __func__, this, groupIndex_, loopIndex_);
        }

        pCurrentPeer_->pPeer->Stop();

        completedCnt_++;

        /**
         * Reap stats from the old peer before deleting it
         */
        if (pCurrentPeer_->pPeer->IsSuccess()) {
            successCnt_++;

            if (arg_.useCrypto) {
                sslConnectThroughput_.AddSample(
                    1, pCurrentPeer_->pPeer->GetSSLConnectionDuration());
            }

            if (kStressTestKind_dataExg == arg_.testKind ||
                kStressTestKind_SSLShutOneWay == arg_.testKind) {
                rxThroughput_.AddSample(
                    arg_.targetRxBytes, pCurrentPeer_->pPeer->GetRxDuration());
            }

            if (kStressTestKind_dataExg == arg_.testKind) {
                txThroughput_.AddSample(
                    arg_.targetTxBytes, pCurrentPeer_->pPeer->GetTxDuration());
            }
        }

        delete pCurrentPeer_;
        pCurrentPeer_ = NULL;

        if (pProgress_.get()) {
            pProgress_->Tick();
        }
    }//ReapCurrentPeer


    /**
     * 
     * @param pPeerRec
     */
    void OnPeerDone(wsf::RdAsyncBridge*, ClientPeerRecord* const pPeerRec)
    {
        assert(pPeerRec == pCurrentPeer_);

        StartNextPeer();
    }


private:
    StressClientPeerArg     const   arg_;
    unsigned int                    completedCnt_;
    ClientPeerRecord*               pCurrentPeer_;
    wsf::RdAsyncBridge&             rGroupDoneEvt_; ///< signal when group is done
    unsigned int            const   groupIndex_;
    bool                            isDone_;
    bool                            isRunning_;
    bool                    const   isVerbose_;
    unsigned int                    loopIndex_;
    unsigned int            const   maxLoopCnt_;
    std::string             const   name_;
    std::auto_ptr<wtu::ProgressReporter>    pProgress_;
    wsf::RuntimeDispatcher&         rd_;
    ::PmSockSSLContext*             pSSLCtx_;
    unsigned int                    successCnt_;

    psl_test_blade::Throughput      sslConnectThroughput_;
    psl_test_blade::Throughput      rxThroughput_;
    psl_test_blade::Throughput      txThroughput_;

};//class StressClientGroup




/**
 * 
 */
class StressClientMgr
:   public psl_test_blade::PeerBase,
    private wsf::Uncopyable {

public:

    StressClientMgr(unsigned int                const parallelSize,
                    unsigned int                const loopMax,
                    const StressClientPeerArg&        peerArg,
                    StressHostIface*            const pHost,
                    bool                        const isVerbose)
    :   psl_test_blade::PeerBase(__func__, isVerbose),
        checkDoneEvt_(this, &StressClientMgr::OnCheckDoneEvt, 0, *(GetRd())),
        pControlChan_(CreateClientChannel(peerArg, GetRd(), MyName())),
        pControlChanWatch_(
            psl_test_blade::UtilCreatePmSockWatch(pControlChan_, (GIOCondition)0,
                                              &ControlChannelWatchCb, this,
                                              MyName())
            ),
        groups_(),
        isDone_(false),
        rHost_(*pHost),
        isRunning_(false),
        isSuccess_(false),
        isVerbose_(isVerbose),
        peerArg_(peerArg),
        pSSLCtx_(peerArg.useCrypto ? MakeSSLCtx(__func__) : NULL),
        thread_(std::string(__func__), this,
                &StressClientMgr::ClientMgrThreadFunc, (void*)NULL)
    {

        for (unsigned int i=0; i < parallelSize; ++i) {
            std::ostringstream oss;
            oss << "StressClientGroup[" << i << "]";

            StressClientGroup* const pGroup = new StressClientGroup(
                oss.str().c_str(), peerArg, i, loopMax, pSSLCtx_, GetRd(),
                &checkDoneEvt_, isVerbose_);

            groups_.push_back(pGroup);
        }

    }

    ~StressClientMgr()
    {
        assert(!isRunning_);

        psl_test_blade::UtilDestroyPmSockWatch(pControlChanWatch_);

        ::g_io_channel_unref((GIOChannel*)pControlChan_);

        unsigned int const groupCnt = groups_.size();
        for (unsigned int i=0; i < groupCnt; ++i) {
            delete groups_[i];
        }
        groups_.clear();


        if (pSSLCtx_) {
            PmSockSSLCtxUnref(pSSLCtx_);
        }

    }


    /**
     * Parse sub-arguments of the "-client" argument
     * 
     * @param pParam The sub-argument string
     * @param pNumRxBytes 
     * @param pNumTxBytes 
     * 
     * @return bool TRUE on success; FALSE on failure
     */
    static bool ParseClientSubArgs(const char*       pParam,
                                   uint32_t*   const pNumRxBytes,
                                   uint32_t*   const pNumTxBytes,
                                   const char* const label)
    {
        *pNumRxBytes = *pNumTxBytes = 0;

        while (*pParam) {
            unsigned long numBytesValue = 0;
            int numBytesLen = 0;
            int numArgsConverted = 0;
            const char* ptok;
            const char* startNumBytesStr;
            if ((ptok = strstr(pParam, "rx=")) && ptok == pParam) {
                startNumBytesStr = ptok + 3;
                numArgsConverted = sscanf(startNumBytesStr, "%lu%n",
                                          &numBytesValue,
                                          &numBytesLen);
                if (EOF == numArgsConverted) {
                    printf("%s: ERROR: invalid rx= num-bytes value " \
                           "in -client arg: '%s'\n",
                           label, startNumBytesStr);
                    return false;
                }

                pParam = startNumBytesStr + numBytesLen;

                *pNumRxBytes = numBytesValue;
            }
            else if ((ptok = strstr(pParam, "tx=")) && ptok == pParam) {
                startNumBytesStr = ptok + 3;
                numArgsConverted = sscanf(startNumBytesStr, "%lu%n",
                                          &numBytesValue,
                                          &numBytesLen);
                if (EOF == numArgsConverted) {
                    printf("%s: ERROR: invalid tx= num-bytes value " \
                           "in -cient arg: '%s'\n",
                           label, startNumBytesStr);
                    return false;
                }

                pParam = startNumBytesStr + numBytesLen;

                *pNumTxBytes = numBytesValue;
            }
            else if ((ptok = strstr(pParam, "rxtx=")) && ptok == pParam) {
                startNumBytesStr = ptok + 5;
                numArgsConverted = sscanf(startNumBytesStr, "%lu%n",
                                          &numBytesValue,
                                          &numBytesLen);
                if (EOF == numArgsConverted) {
                    printf("%s: ERROR: invalid tx= num-bytes value " \
                           "in -client arg: '%s'\n",
                           label, startNumBytesStr);
                    return false;
                }

                pParam = startNumBytesStr + numBytesLen;

                *pNumRxBytes = *pNumTxBytes = numBytesValue;
            }
            else {
                printf("%s: ERROR: invalid sub-token in -client arg: '%s'\n",
                       label, pParam);
                return false;
            }

            // Advance to next sub-arg past separator, if any
            if (*pParam) {
                if (',' == *pParam) {
                    pParam++;
                }
                else {
                    printf("%s: ERROR: expected ',' separator in -client arg, " \
                           "but got: '%s'\n",
                           label, pParam);
                    return false;
                }
            }
        };//convert -client sub-args

        if (0 == *pNumRxBytes && 0 == *pNumTxBytes) {
            printf("%s: ERROR: both rx and tx bytes counts in -client arg " \
                   "are 0; at _least_ one of them MUST greater than 0\n",
                   label);
            return false;
        }

        return true;
    }//ParseClientSubArgs

public: // psl_test_blade::PeerBase virtual overrides
    void Start()
    {
        assert(!isRunning_);
        assert(!isDone_);

        thread_.Start();
        isRunning_ = true;
    }

    void Stop()
    {
        assert(isRunning_);

        RequestStop();

        if (isVerbose_) {
            UTIL_PRINT_LINE("%s/%s (this=%p): Joining thread...",
                            MyName(), __func__, this);
        }
        thread_.Join();

        if (isVerbose_) {
            UTIL_PRINT_LINE("%s/%s (this=%p): Thread Join completed.",
                            MyName(), __func__, this);
        }

        isRunning_ = false;
    }

    bool IsDone()
    {
        return isDone_;
    }

    /**
     * @note DO NOT call this if IsDone() returns false
     * 
     * @return bool
     */
    bool IsSuccess()
    {
        assert(IsDone());

        return isSuccess_;
    }

    /**
     * @note DO NOT call this if IsDone() returns false
     * 
     */
    void PrintStats()
    {
        UTIL_PRINT_LINE("%s/%s:>>>>>>>>>>>>>>>>>>>>>>>>>>>", MyName(), __func__);

        assert(IsDone());

        unsigned int const groupCnt = groups_.size();
        for (unsigned int i=0; i < groupCnt; ++i) {
            groups_[i]->PrintStats();
        }

        UTIL_PRINT_LINE("%s/%s:<<<<<<<<<<<<<<<<<<<<<<<<<<<", MyName(), __func__);
    }


private:
    /**
     * 
     */
    void
    ClientMgrThreadFunc(void* /*CXT*/)
    {
        /**
         * Initiate creation of a control connection to the server
         */
        ::PmSockSetUserData(pControlChan_, this);
        PslError const pslerr = ::PmSockConnectPlain(pControlChan_,
                                                     &ControlChannelCompletionCb);
        if (pslerr) {
            const std::string errorMsg =
                std::string("PmSockConnectPlain failed: ") +
                ::PmSockErrStringFromError(pslerr);
            UTIL_THROW_FATAL(MyName(), errorMsg.c_str());
        }


        /**
         * Run our main loop
         */
        psl_test_blade::PeerBase::Run();


        /**
         * Stop all our client groups
         */
        unsigned int const groupCnt = groups_.size();
        for (unsigned int i=0; i < groupCnt; ++i) {
            if (groups_[i]->IsRunning()) {
                groups_[i]->Stop();
            }
        }


        /**
         * Close the control channel to force the server to shut down
         */
        ::g_io_channel_close((::GIOChannel*)pControlChan_);

        /**
         * Inform our parent instance
         */
        isDone_ = true;
        rHost_.StressHostSubserviceIsDone();


        if (peerArg_.useCrypto) {
            ::PslError const pslerr = ::PmSockOpensslThreadCleanup();
            assert(!pslerr);
        }
    }


    /**
     * 
     */
    void
    OnCheckDoneEvt(wsf::RdAsyncBridge*, int)
    {
        unsigned int const groupCnt = groups_.size();

        for (unsigned int i=0; i < groupCnt; ++i) {
            if (!groups_[i]->IsDone()) {
                return;
            }
        }

        UTIL_PRINT_LINE("%s/%s: All groups are done, terminating...",
                        MyName(), __func__);

        RequestStop();
    }


    /**
     * Completion callback for Control channel connection request
     * 
     * @param chanBase
     * @param userData
     * @param errorCode
     * 
     * @see PmSockCompletionCb
     */
    static void
    ControlChannelCompletionCb(PmSockIOChannel* const chanBase,
                               void*            const userData,
                               PslError         const errorCode)
    {
        StressClientMgr* const me = (StressClientMgr*)userData;

        assert(chanBase == me->pControlChan_);

        UTIL_PRINT_LINE("%s/%s: Control channel connection attempt completed: " \
                        "%s: PslError=%d(%s)",
                        me->MyName(), __func__, errorCode ? "ERROR" : "SUCCESS",
                        errorCode, ::PmSockErrStringFromError(errorCode));


        if (errorCode) {
            me->RequestStop();
        }
        else {
            /**
             * Start all client groups
             */
            unsigned int const groupCnt = me->groups_.size();
            for (unsigned int i=0; i < groupCnt; ++i) {
                me->groups_[i]->Start();
            }

            /**
             * Start monitoring our control channel for failure
             */
            psl_test_blade::UtilUpdatePmSockWatch(me->pControlChanWatch_,
                                                  ::G_IO_IN, me->MyName());
        }
    }


    /**
     * Callback function associated with the StressClientMgr's
     * control channel watch
     * 
     * @param chanBase
     * @param condition
     * @param userData
     * 
     * @return gboolean
     * 
     * @see GIOFunc
     */
    static gboolean
    ControlChannelWatchCb(GIOChannel*   const chanBase,
                          GIOCondition  const condition,
                          gpointer      const userData)
    {
        StressClientMgr* const me = (StressClientMgr*)userData;

        assert(chanBase == (GIOChannel*)me->pControlChan_);

        /**
         * @note this call signals failure of the control channel
         */

        UTIL_PRINT_ERROR(
            "%s/%s: ERROR: Control channel connection failed, shutting down...",
            me->MyName(), __func__);

        me->RequestStop();

        return true;        ///< remain attached to our gmain context
    }//ControlChannelWatchCb


    /**
     * 
     * @param userLabel
     * 
     * @return PmSockSSLContext*
     */
    static PmSockSSLContext*
    MakeSSLCtx(const char* const userLabel)
    {
        /// Create a palmsocket SSL context
        PmSockSSLContext*       pSSLCtx = NULL;
        PslError const pslerr = ::PmSockSSLCtxNew(userLabel, &pSSLCtx);
        if (pslerr) {
            const std::string errorMsg =
                std::string("PmSockSSLCtxNew failed: ") +
                ::PmSockErrStringFromError(pslerr);
            UTIL_THROW_FATAL(userLabel, errorMsg.c_str());
        }

        assert(pSSLCtx);

        return pSSLCtx;
    }

private:
    wsf::RdAsyncBridge          checkDoneEvt_; ///< triggers check of finished groups
    ::PmSockIOChannel*  const   pControlChan_; ///< control channel to server peer
    ::PmSockWatch*      const   pControlChanWatch_;
    std::vector<StressClientGroup*>   groups_;
    bool                        isDone_;
    StressHostIface&            rHost_;
    bool                        isRunning_;
    bool                        isSuccess_;
    bool                const   isVerbose_;
    StressClientPeerArg const   peerArg_;
    PmSockSSLContext*   const   pSSLCtx_;

    wsf::Thread                 thread_;
};//class StressClientMgr





/**
 * CreateClientChannel()
 * 
 * @param arg
 * @param pRd
 * @param userLabel
 * 
 * @return PmSockIOChannel*
 */
inline ::PmSockIOChannel*
CreateClientChannel(const StressClientPeerArg&        arg,
                    wsf::RuntimeDispatcher*     const pRd,
                    const char*                 const userLabel)
{
    ::GMainLoop* const loop = ((GMainLoop*)
                               wsf::RuntimeDispatcher::GetInternalLoop(*pRd)
                               );

    PslError pslerr;

    PmSockThreadContext*    pThreadCtx = NULL;
    pslerr = ::PmSockThreadCtxNewFromGMain(::g_main_loop_get_context(loop),
                                           userLabel, &pThreadCtx);
    if (pslerr) {
        const std::string errorMsg =
            std::string("PmSockThreadCtxNewFromGMain failed: ") +
            ::PmSockErrStringFromError(pslerr);
        UTIL_THROW_FATAL(userLabel, errorMsg.c_str());
    }

    PmSockIOChannel* pChan = NULL;
    pslerr = ::PmSockCreateChannel(pThreadCtx,
                                   (PmSockOptionFlags)0,
                                   userLabel,
                                   &pChan);
    /// Release our reference to thread ctx
    ::PmSockThreadCtxUnref(pThreadCtx);

    if (pslerr) {
        const std::string errorMsg =
            std::string("PmSockCreateChannel failed: ") +
            ::PmSockErrStringFromError(pslerr);
        UTIL_THROW_FATAL(userLabel, errorMsg.c_str());
    }

    assert(pChan);

    pslerr = ::PmSockSetConnectAddress(pChan, AF_INET,
                                       arg.addr.c_str(), arg.port);
    if (pslerr) {
        const std::string errorMsg =
            std::string("PmSockSetConnectAddress failed: ") +
            ::PmSockErrStringFromError(pslerr);
        UTIL_THROW_FATAL(userLabel, errorMsg.c_str());
    }

    return pChan;
}//CreateClientChannel

} // end of anonymous namespace


#endif //PSL_TEST_CMD_STRESS_CLIENT_HPP


