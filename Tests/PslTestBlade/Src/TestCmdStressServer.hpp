/** 
 * *****************************************************************************
 * @file TestCmdStressServer.hpp
 * @ingroup psl_test
 * 
 * @brief  Server-side implementation for the libplamsocket
 *         Stress test command handler for stress-testing
 *         libpalmsocket's PmSock API in a multi-threaded
 *         environment. Supports parallel requests. Also used
 *         by the SSL shutdown test.
 * 
 * *****************************************************************************
 */
#ifndef PSL_TEST_CMD_STRESS_SERVER_HPP
#define PSL_TEST_CMD_STRESS_SERVER_HPP


#include <stdint.h>
#include <errno.h>
#include <assert.h>

#if 0
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pthread.h>

#include <string>
#include <memory>
#include <map>
//#include <algorithm>
//#include <sstream>
//#include <vector>

#include <glib.h>

#include <stdexcept>
#include <string>

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
#include "TestCmdStressSession.hpp"


namespace { /// anonymous



class StressServerPeerArg {
public:
    StressServerPeerArg()
    :   ioSliceThreashold(0),
        maxWriteByteCnt(0),
        paceWriteMillisec(0),
        listenPort(0),
        privkeyPath()
    {
    }

    /// # of rx/tx bytes before yielding control; 0 = default
    unsigned int            ioSliceThreashold;
    /// max bytes per write call; 0 = default
    unsigned int            maxWriteByteCnt;
    unsigned int            paceWriteMillisec; ///< delay between writes; 0=none
    int                     listenPort;  ///< listening TCP port #
    std::string             privkeyPath; ///< private RSA/CA PEM file path
};//class StressServerPeerArg



/**
 * class ServerPeer
 * 
 * 
 * @param pSSLCtx SSL Context configured for server use (private key),
 *                or NULL if we don't support SSL requests 
 *
 * A ServerPeer instance is responsible for receiving
 * instructions from ClientPeer, and instantiating the
 * corresponding StressPeer instance.
 */
class ServerPeer
:   public psl_test_blade::PeerBase,
    private wsf::Uncopyable {
public:
    ServerPeer(const StressServerPeerArg& arg,
               int                  const sock,
               ::PmSockSSLContext*  const pSSLCtx,
               wsf::RdAsyncBridge*  const pPeerDoneEvt,
               bool                 const isVerbose)
    :   psl_test_blade::PeerBase(__func__, isVerbose),
        arg_(arg),
        pChan_(CreateServerChannel(sock, GetRd(), MyName())),
        pChanWatch_(psl_test_blade::UtilCreatePmSockWatch(pChan_, (GIOCondition)0,
                                                      &ChannelWatchCb, this,
                                                      MyName())),
        cmd_(),
        cmdBytesRx_(0),
        isDone_(false),
        isSuccess_(false),
        isVerbose_(isVerbose),
        rPeerDoneEvt_(*pPeerDoneEvt),
        sessDoneEvt_(this, &ServerPeer::OnSessDoneEvt, 0, *(GetRd())),
        pSSLCtx_(NULL),
        pStressSession(),
        thread_(std::string(__func__), this,
                &ServerPeer::ServerPeerThreadFunc, (void*)NULL),
        usedCrypto_(false)
    {
        pSSLCtx_ = (pSSLCtx ? PmSockSSLCtxRef(pSSLCtx) : NULL);

        if (isVerbose_) {
            UTIL_PRINT_LINE("%s/%s (this=%p): created", MyName(), __func__, this);
        }
    }//ServerPeer


    ~ServerPeer()
    {
        psl_test_blade::UtilDestroyPmSockWatch(pChanWatch_);

        ::g_io_channel_unref((GIOChannel*)pChan_);

        if (pSSLCtx_) {
            PmSockSSLCtxUnref(pSSLCtx_);
        }

        if (isVerbose_) {
            UTIL_PRINT_LINE("%s/%s (this=%p): destroyed", MyName(), __func__, this);
        }
    }

public: /// psl_test_blade::PeerBase virtual overrides
    void Start()
    {
        thread_.Start();
    }

    void Stop()
    {
        if (isVerbose_) {
            UTIL_PRINT_LINE("%s/%s (this=%p): External stop requested.",
                   MyName(), __func__, this);
        }

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
     * @note DO NOT call this if IsDone() returns false
     * 
     */
    void PrintStats()
    {
        assert(IsDone());

        UTIL_PRINT_LINE("%s/%s (this=%p): %s", MyName(), __func__, this,
                   IsSuccess() ? "SUCCESS" : "FAILED");

        if (pStressSession.get()) {
            pStressSession->PrintStats();
        }
    }

private:
    void ServerPeerThreadFunc(void* /*CXT*/)
    {
        if (isVerbose_) {
            UTIL_PRINT_LINE("%s/%s (this=%p): thread started, waiting for command",
                           MyName(), __func__, this);
        }

        PslError pslerr;

        /**
         * @note We already supplied a connected socket to the channel,
         *       so this just gets it into the plaintext state
         */
        pslerr = ::PmSockConnectPlain(pChan_, NULL/*completionCb*/);
        if (pslerr) {
            const std::string errorMsg =
                std::string("PmSockConnectPlain failed: ") +
                ::PmSockErrStringFromError(pslerr);
            UTIL_THROW_FATAL(MyName(), errorMsg.c_str());
        }


        /**
         * @note The server peer expects to get instructions from the
         *       client peer, so we set our channel watch to wait for
         *       readable; it will also alert us if the connection
         *       failed.
         */
        UpdateChannelWatch(::G_IO_IN);

        psl_test_blade::PeerBase::Run();

        if (pStressSession.get()) {

            if (isVerbose_) {
                UTIL_PRINT_LINE("%s/%s (this=%p): stopping stress session %s",
                                MyName(), __func__, this, pStressSession->GetName());
            }

            pStressSession->Stop();

            if (isVerbose_) {
                UTIL_PRINT_LINE("%s/%s (this=%p): stress session %s stopped",
                                MyName(), __func__, this, pStressSession->GetName());
            }

            isSuccess_ = pStressSession->IsSuccess();
        }

        if (isVerbose_) {
            UTIL_PRINT_LINE("%s/%s (this=%p): calling g_io_channel_close",
                            MyName(), __func__, this);
        }

        ::g_io_channel_close((::GIOChannel*)pChan_);

        if (isVerbose_) {
            UTIL_PRINT_LINE("%s/%s (this=%p): returned from g_io_channel_close",
                            MyName(), __func__, this);
        }

        if (usedCrypto_) {
            if (isVerbose_) {
                UTIL_PRINT_LINE("%s/%s (this=%p): calling PmSockOpensslThreadCleanup",
                                MyName(), __func__, this);
            }

            ::PslError const pslerr = ::PmSockOpensslThreadCleanup();
            assert(!pslerr);

            if (isVerbose_) {
                UTIL_PRINT_LINE("%s/%s (this=%p): after PmSockOpensslThreadCleanup",
                                MyName(), __func__, this);
            }
        }

        if (isVerbose_) {
            UTIL_PRINT_LINE("%s/%s (this=%p): calling rPeerDoneEvt_.Trigger()",
                            MyName(), __func__, this);
        }

        isDone_ = true;
        rPeerDoneEvt_.Trigger();

        if (isVerbose_) {
            UTIL_PRINT_LINE("%s/%s (this=%p): returned from rPeerDoneEvt_.Trigger()",
                            MyName(), __func__, this);
        }

        if (isVerbose_) {
            UTIL_PRINT_LINE("%s/%s (this=%p): shut-down complete, exiting thread",
                            MyName(), __func__, this);
        }

    }//ServerPeerThreadFunc


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
     * Callback function associated with the ServerPeer's channel
     * watch
     * 
     * @param pChanBase
     * @param condition
     * @param userData
     * 
     * @return gboolean
     * 
     * @see GIOFunc
     */
    static gboolean
    ChannelWatchCb(GIOChannel*   const pChanBase,
                   GIOCondition  const condition,
                   gpointer      const userData)
    {
        ServerPeer* const me = (ServerPeer*)userData;

        assert(me->cmdBytesRx_ < sizeof(me->cmd_));

        uint32_t const maxRx = sizeof(me->cmd_) - me->cmdBytesRx_;
        uint32_t numRx = 0;
        ::GIOStatus const giostatus = psl_test_blade::UtilRxPmSockBytes(
            me->pChan_,
            ((uint8_t*)&me->cmd_) + me->cmdBytesRx_,
            maxRx, &numRx, me->isVerbose_, me->MyName()
            );
        me->cmdBytesRx_ += numRx;
        assert(me->cmdBytesRx_ <= sizeof(me->cmd_));

        switch (giostatus) {
        case G_IO_STATUS_ERROR:
            {
                UTIL_PRINT_LINE(
                    "%s/%s (this=%p): I/O ERROR detected after reading %u bytes",
                    me->MyName(), __func__, me, me->cmdBytesRx_);

                me->RequestStop();
                me->UpdateChannelWatch((GIOCondition)0);
            }
            return true; ///< remain attached
            break;

        case G_IO_STATUS_NORMAL:
            break;
        case G_IO_STATUS_EOF:
            if (me->cmdBytesRx_ < sizeof(me->cmd_)) {
                UTIL_PRINT_LINE(
                    "%s/%s (this=%p): ERROR: Premature EOF from " \
                    "g_io_channel_read_chars: " \
                    "only %u/%u ServerPeerCmd bytes received",
                    me->MyName(), __func__, me, me->cmdBytesRx_, sizeof(me->cmd_));
                me->RequestStop();
                me->UpdateChannelWatch((GIOCondition)0);
                return true; ///< remain attached
            }
            break;
        case G_IO_STATUS_AGAIN:
            break;
        }


        if (me->cmdBytesRx_ == sizeof(me->cmd_)) {
            if (SERVER_PEER_CMD_SIGNATURE != me->cmd_.signature) {
                UTIL_PRINT_LINE(
                    "%s/%s (this=%p): invalid command signature: expected 0x%X, but " \
                    "got 0x%X; groupIndex=%u, loopIndex=%u.",
                    me->MyName(), __func__, me,
                    (unsigned)SERVER_PEER_CMD_SIGNATURE,
                    (unsigned)me->cmd_.signature, me->cmd_.groupIndex,
                    me->cmd_.loopIndex);
                ::fflush(::stdout);
                assert(false && "INVALID COMMAND SIGNATURE");
            }

            /**
             * Got the entire command!
             */

            if (me->isVerbose_) {
                UTIL_PRINT_LINE(
                    "%s (this=%p): got cmd from client: testKind=%d, " \
                    "client=[%u][%u], " \
                    "targetRxBytes=%u, targetTxBytes=%u, useCrypto=%u, " \
                    "sslRenegotiate=%d",
                    __func__, me, (int)me->cmd_.testKind,
                    me->cmd_.groupIndex, me->cmd_.loopIndex,
                    me->cmd_.targetRxBytes, me->cmd_.targetTxBytes,
                    me->cmd_.useCrypto, !!me->cmd_.sslReneg);
            }

            /**
             * We're not going to be using our channel watch any more
             */
            me->UpdateChannelWatch((GIOCondition)0);

            /**
             * Create StressPeer and put it to work
             */
            StressSession::StressSessionArg    arg;

            arg.isServer            = true;
            arg.testKind            = me->cmd_.testKind;
            arg.pChan               = me->pChan_;
            arg.groupIndex          = me->cmd_.groupIndex;
            arg.loopIndex           = me->cmd_.loopIndex;
            arg.pRd                 = me->GetRd();
            arg.pSessDoneEvt        = &me->sessDoneEvt_;
            arg.pSSLCtx             = me->cmd_.useCrypto ? me->pSSLCtx_ : NULL;
            arg.sslRenegotiate      = !!me->cmd_.sslReneg;
            arg.targetRxBytes       = me->cmd_.targetRxBytes;
            arg.targetTxBytes       = me->cmd_.targetTxBytes;
            arg.ioSliceThreashold   = me->arg_.ioSliceThreashold;
            arg.maxWriteByteCnt     = me->arg_.maxWriteByteCnt;
            arg.paceWriteMillisec   = me->arg_.paceWriteMillisec;
            arg.useCrypto           = me->cmd_.useCrypto;
            arg.isVerbose           = me->isVerbose_;

            if (arg.useCrypto) {
                me->usedCrypto_ = true;
            }

            me->pStressSession.reset(
                new StressSession(arg)
                );
            me->pStressSession->Start();
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
        if (isVerbose_) {
            UTIL_PRINT_LINE("%s/%s (this=%p): stress-session is done",
                   MyName(), __func__, this);
        }

        RequestStop();
    }


    /**
     * CreateServerChannel():
     * 
     * @param sock
     * @param pRd
     * @param userLabel
     * 
     * @return PmSockIOChannel*
     */
    static ::PmSockIOChannel*
    CreateServerChannel(int const sock, wsf::RuntimeDispatcher* const pRd,
                        const char* const userLabel)
    {
        ::GMainLoop* const loop = ((GMainLoop*)
                                   wsf::RuntimeDispatcher::GetInternalLoop(
                                       *pRd)
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
        pslerr = PmSockCreateChannel(pThreadCtx,
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

        pslerr = ::PmSockSetConnectedFD(pChan, sock, (PmSockFileDescOpts)0);
        if (pslerr) {
            const std::string errorMsg =
                std::string("PmSockSetConnectedFD failed: ") +
                ::PmSockErrStringFromError(pslerr);
            UTIL_THROW_FATAL(userLabel, errorMsg.c_str());
        }

        return pChan;
    }//CreateServerChannel

private:
    StressServerPeerArg     const   arg_;
    ::PmSockIOChannel*      const   pChan_;
    ::PmSockWatch*          const   pChanWatch_;
    ServerPeerCmd                   cmd_; ///< to be received from client peer
    unsigned int                    cmdBytesRx_;
    bool                            isDone_;
    bool                            isSuccess_;
    bool                    const   isVerbose_;
    wsf::RdAsyncBridge&             rPeerDoneEvt_; ///< for signaling parent
    wsf::RdAsyncBridge              sessDoneEvt_;  ///< session signals when done
    ::PmSockSSLContext*             pSSLCtx_;      ///< may be NULL
    std::auto_ptr<StressSession>    pStressSession;
    wsf::Thread                     thread_;
    bool                            usedCrypto_;
};//class ServerPeer






/**
 * class StressServerMgr
 *
 * Listens for incoming TCP/IP connections on listenPort that's
 * passed to the constructor.
 *
 * The first incoming connection is assumed to be the 'control'
 * connection, and is treated specially: When this connection is
 * subsequently broken, the StressServerMgr instance shuts down
 * the server.
 *
 * Subsequent incoming connections are assumed to be peer
 * connections and DiscardServerPeer instance will be spawend on
 * a separate thread for each such incoming connection.
 */
class StressServerMgr
:   public psl_test_blade::PeerBase,
    private wsf::Uncopyable {

public:
    StressServerMgr(const StressServerPeerArg& peerArg,
                    StressHostIface*     const pHost,
                    bool                 const isVerbose)
    :   psl_test_blade::PeerBase(__func__, isVerbose),
        activePeers_(),
        controlSock_(kSockUtilInvalidFD),
        pControlSockMon_(),
        exitPending_(false),
        isDone_(false),
        rHost_(*pHost),
        isRunning_(false),
        isSuccess_(false),
        isVerbose_(isVerbose),
        listenSock_(MakeListeningSock(peerArg.listenPort)),
        listenSockMon_(listenSock_, this,
                       &StressServerMgr::ListenSockMonitorFunc,
                       (void*)NULL, *(GetRd())),
        peerArg_(peerArg),
        pSSLCtx_(NULL),
        thread_(std::string(__func__), this,
                &StressServerMgr::ServerMgrThreadFunc, (void*)NULL)
    {
        if (isVerbose_) {
            UTIL_PRINT_LINE("%s/%s (this=%p): created", MyName(), __func__, this);
        }
    }

    ~StressServerMgr()
    {
        assert(!isRunning_);

        if (controlSock_ >= 0) {
            close(controlSock_);
        }
        if (listenSock_ >= 0) {
            close(listenSock_);
        }

        if (isVerbose_) {
            UTIL_PRINT_LINE("%s/%s (this=%p): destroyed", MyName(), __func__, this);
        }
    }

public: /// psl_test_blade::PeerBase virtual overrides
    void Start()
    {
        assert(!isRunning_);
        assert(!IsDone());

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
        assert(IsDone());
    }


private:
    class ServerPeerRecord : private wsf::Uncopyable {
    public:
        std::auto_ptr<ServerPeer>           pPeer;
        std::auto_ptr<wsf::RdAsyncBridge>   pPeerDoneEvt;
    };


private:
    void StopInternal()
    {

        RequestStop();

        if (pControlSockMon_.get()) {
            pControlSockMon_->SetEventMask(false, false, false);
        }

        listenSockMon_.SetEventMask(false, false, false);
    }


    void ServerMgrThreadFunc(void* /*CXT*/)
    {
        if (!peerArg_.privkeyPath.empty()) {
            psl_test_blade::UtilInitOpenssl(MyName());

            pSSLCtx_ = psl_test_blade::UtilMakeServerSSLCtx(peerArg_.privkeyPath,
                                                            MyName());
        }

        listenSockMon_.SetEventMask(true, false, false);

        psl_test_blade::PeerBase::Run();

        /**
         * Shut down and delete all remaining server peers
         */
        ActivePeersMap::iterator        it;
        ActivePeersMap::iterator const  end = activePeers_.end();
        for (it = activePeers_.begin(); it != end; ++it) {
            it->first->pPeer->Stop();
            delete it->first;
        }
        activePeers_.clear();

        isDone_ = true;
        rHost_.StressHostSubserviceIsDone();


        if (!peerArg_.privkeyPath.empty()) {
            if (pSSLCtx_) {
                ::PmSockSSLCtxUnref(pSSLCtx_);
                pSSLCtx_ = NULL;
            }

            ::PslError pslerr = ::PmSockOpensslThreadCleanup();
            assert(!pslerr);
            pslerr = ::PmSockOpensslUninit();
            assert(!pslerr);
        }

        UTIL_PRINT_LINE("%s/%s: shut-down complete, exiting thread.",
                        MyName(), __func__);
    }//ServerMgrThreadFunc


    void ListenSockMonitorFunc(wsf::RdDescriptorMonitor* /*pRd*/,
                               int  const listenSock,
                               bool const readReady,
                               bool /*writeReady*/,
                               bool /*exceptionReady*/,
                               void* /*CXT*/)
    {
        assert(readReady);

        int newSock = accept(listenSock, NULL/*addr*/, 0/*addrlen*/);
        if (newSock < 0) {
            ::perror("accept(listenSock, NULL/*addr*/, 0/*addrlen*/) FAILED");
            return;
        }

        int err = sock_util_make_fd_non_blocking(newSock);
        if (err) {
            goto error_exit;
        }

        if (controlSock_ < 0) {
            controlSock_ = newSock;
            pControlSockMon_.reset(
                new wsf::RdDescriptorMonitor(controlSock_, this,
                       &StressServerMgr::ControlSockMonitorFunc,
                       (void*)NULL, *(GetRd()))
            );
            pControlSockMon_->SetEventMask(true/*readReady*/, false, false);
        }
        else {


            std::auto_ptr<ServerPeerRecord> pServerPeerRec(new ServerPeerRecord);

            std::auto_ptr<wsf::RdAsyncBridge> pPeerDoneEvt(
                new wsf::RdAsyncBridge(this, &StressServerMgr::OnPeerDone,
                                       pServerPeerRec.get(), *(GetRd()))
                );

            std::auto_ptr<ServerPeer> pServerPeer(
                new ServerPeer(peerArg_, newSock, pSSLCtx_, pPeerDoneEvt.get(),
                               isVerbose_)
                );

            newSock = kSockUtilInvalidFD; ///< so it won't get closed twice

            pServerPeer->Start();

            std::pair<ActivePeersMap::iterator, bool> const ret =
                activePeers_.insert(
                    ActivePeersMap::value_type(pServerPeerRec.get(),
                                               pServerPeerRec.get())
                    );
            assert(ret.second);

            pServerPeerRec->pPeer = pServerPeer;
            pServerPeerRec->pPeerDoneEvt = pPeerDoneEvt;

            pServerPeerRec.release();
        }


        return; ///< SUCCESS

    error_exit:
        if (newSock >= 0) {
            close(newSock);
        }
    }//ListenSockMonitorFunc


    void OnPeerDone(wsf::RdAsyncBridge*, ServerPeerRecord* const pPeerRec)
    {
        if (isVerbose_) {
            UTIL_PRINT_LINE("%s/%s: Stopping server peer...", MyName(), __func__);
        }

        pPeerRec->pPeer->Stop();

        if (isVerbose_) {
            UTIL_PRINT_LINE("%s/%s: returned from pPeerRec->pPeer->Stop()",
                       MyName(), __func__);
        }

        /// Clean up
        ActivePeersMap::iterator const it = activePeers_.find(pPeerRec);
        assert(it != activePeers_.end());
        assert(it->first == pPeerRec);

        if (isVerbose_) {
            UTIL_PRINT_LINE("%s/%s: Deleting server peer record @%p...",
                       MyName(), __func__, pPeerRec);
        }

        delete pPeerRec;

        if (isVerbose_) {
            UTIL_PRINT_LINE("%s/%s: returned from delete pPeerRec  @%p...",
                       MyName(), __func__, pPeerRec);
        }

        activePeers_.erase(it);

        if (isVerbose_) {
            UTIL_PRINT_LINE("%s/%s: returned from activePeers_.erase(it) of " \
                       "pPeerRec @%p...",
                       MyName(), __func__, pPeerRec);
        }

        if (exitPending_ && activePeers_.empty()) {
            UTIL_PRINT_LINE(
                "%s/%s: exit is pending and there are no more server peers: " \
                "stopping...", MyName(), __func__);
            StopInternal();
        }
    }


    void ControlSockMonitorFunc(wsf::RdDescriptorMonitor* /*pRd*/,
                                int controlSock,
                                bool readReady,
                                bool /*writeReady*/,
                                bool /*exceptionReady*/,
                                void* /*CXT*/)
    {
        assert(readReady);

        /**
         * Being called is an indicator that the control stream has been
         * closed, and it's time for the server to shut down
         */
        UTIL_PRINT_LINE(
            "%s/%s: Control socket has become readable; preparing to exit...",
            MyName(), __func__);

        exitPending_ = true;

        if (activePeers_.empty()) {
            StopInternal();
        }
        else {
            pControlSockMon_->SetEventMask(false, false, false);
            listenSockMon_.SetEventMask(false, false, false);
        }


    }//ControlSockMonitorFunc


    static int MakeListeningSock(int const port)
    {
        int s = kSockUtilInvalidFD;

        int const rc = sock_util_make_nb_listening_sock(AF_INET,
                                                        NULL/*addrStr*/,
                                                        port,
                                                        100/*listenQueueSize*/,
                                                        &s);
        if (rc) {
            const std::string errorMsg(
                std::string("sock_util_make_nb_listening_sock: ") + ::strerror(rc));
            UTIL_THROW_FATAL(__func__, errorMsg.c_str());
        }

        return s;
    }


private:

    typedef std::map<ServerPeerRecord*, ServerPeerRecord*> ActivePeersMap;

    ActivePeersMap                              activePeers_;
    int                                         controlSock_;
    std::auto_ptr<wsf::RdDescriptorMonitor>     pControlSockMon_;
    bool                        exitPending_;
    bool                        isDone_;
    StressHostIface&            rHost_;
    bool                        isRunning_;
    bool                        isSuccess_;
    bool const                  isVerbose_;
    int  const                  listenSock_;
    wsf::RdDescriptorMonitor    listenSockMon_;
    StressServerPeerArg const   peerArg_;
    ::PmSockSSLContext*         pSSLCtx_;
    wsf::Thread                 thread_;
};//class StressServerMgr



} // end of anonymous namespace



#endif //PSL_TEST_CMD_STRESS_SERVER_HPP
