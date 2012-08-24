/** 
 * *****************************************************************************
 * @file TestCmdShutSSL.cpp
 * @ingroup psl_test
 * 
 * @brief  Test Command Handler for testing libplamsocket's SSL 
 *         shutdown functionality; implements both client and
 *         server sides.
 * 
 * *****************************************************************************
 */

#include <stdint.h>
#include <errno.h>
#include <assert.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <string>

#include <stdexcept>

#include <PmWirelessSystemFramework/Utils/RuntimeDispatcher/RuntimeDispatcher.h>
#include <PmWirelessSystemFramework/Utils/RuntimeDispatcher/RdAsyncBridge.h>
#include <PmWirelessSystemFramework/Utils/Uncopyable.h>

#include <PmWsfTestUtils/CommandShell.h>
#include <PmWsfTestUtils/ProgressReporter.h>

#include <palmsocket.h>


#include "PslTestCmdShell.h"
#include "SockUtils.h"
#include "CommonUtils.h"

#include "TestCmdStressCommon.hpp"
#include "TestCmdStressClient.hpp"
#include "TestCmdStressServer.hpp"

namespace psl_test_blade {


static const char kTestCmdName[] = "shut.ssl";


/**
 * libpalmsocket chargen/discard-like test
 */
class TestCmdShutSSL :
    public TestCmdMgr::CommandIface,
    public StressHostIface,
    private wsf::Uncopyable {

public:
    /**
     * virtual method overrides for class StressHostIface 
     * @{ 
     */
    void StressHostSubserviceIsDone()
    {
        cmdMgr_.CommandIsDone();
    }
    /**@}*/

private:
    explicit TestCmdShutSSL(const MyCmdShell::ArgsType &args)
    :   args_(args),
        clientInfo_(),
        serverInfo_(),
        verbose_(false),
        opensslInitialized_(false),
        cmdMgr_(&args.PeekShell()),
        pClientMgr_(),
        pServerMgr_()
    {
    }

    ~TestCmdShutSSL()
    {

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

        if (verbose_) {
            printf("%s: Starting: numRxBytes=%u, numTxBytes=%u\n",
                   args_[0], clientInfo_.numRxBytes, clientInfo_.numTxBytes);
        }

        cmdMgr_.Run(this);

        return true;
    } // Execute()


    /**
     * wtu::TestCmdMgr::CommandIface virtual member function 
     * overrides 
     * @{ 
     */

    /**
     * GetName(): returns name of the command
     * 
     * @return const std::string 
     */
    const std::string GetName()
    {
        return args_[0];
    }


    /**
     * CommandIfaceStartNB(): _non-blocking_ start request
     * 
     * @param pMgr Pointer to the parent test command manager (e.g.,
     *             for stopping test execution)
     * @param pMgrRd Command Manager's RuntimeDispatcher instance; 
     *               the command handler may use it for running its
     *               own logic, if needed.
     */
    void CommandIfaceStartNB(TestCmdMgr* pMgr,
                             wsf::RuntimeDispatcher* pMgrRd)
    {
        UtilInitOpenssl(args_[0]);
        opensslInitialized_ = true;

        if (serverInfo_.create) {
            StressServerPeerArg peerArg;

            peerArg.ioSliceThreashold   = serverInfo_.ioSliceThreashold;
            peerArg.maxWriteByteCnt     = serverInfo_.maxWriteByteCnt;
            peerArg.paceWriteMillisec   = serverInfo_.paceWriteMillisec;
            peerArg.listenPort          = serverInfo_.listenPort;
            peerArg.privkeyPath         = serverInfo_.privkeyPath;

            pServerMgr_.reset(new StressServerMgr(peerArg, this, verbose_));
            pServerMgr_->Start();
        }

        if (clientInfo_.create) {
            StressClientPeerArg peerArg;

            PmSockCryptoConfArgs cryptoConf;
            cryptoConf.enabledOpts = kPmSockCryptoConfigEnabledOpt_verifyOpts;
            cryptoConf.verifyOpts  = kPmSockCertVerifyOpt_none;

            peerArg.testKind            = clientInfo_.how;
            peerArg.addr                = clientInfo_.sa;
            peerArg.ioSliceThreashold   = clientInfo_.ioSliceThreashold;
            peerArg.maxWriteByteCnt     = clientInfo_.maxWriteByteCnt;
            peerArg.paceWriteMillisec   = clientInfo_.paceWriteMillisec;
            peerArg.port                = clientInfo_.serverPort;
            peerArg.progressBytePeriod  = 0;
            peerArg.progressLoopPeriod  = clientInfo_.progressLoopPeriod;
            peerArg.sslConfig           = cryptoConf;
            peerArg.sslRenegFlags       = 0;
            peerArg.targetRxBytes       = clientInfo_.numRxBytes;
            peerArg.targetTxBytes       = clientInfo_.numTxBytes;
            peerArg.useCrypto           = true;

            pClientMgr_.reset(new StressClientMgr(clientInfo_.parallelCnt,
                                                 clientInfo_.loopCnt,
                                                 peerArg,
                                                 this,
                                                 verbose_)
                             );
            pClientMgr_->Start();
        }

    }

    /**
     * CommandIfaceStopBL(): _blocking_ stop request; MUST stop all 
     * test activity and return _after_ all activity is stopped. 
     *  
     * @note May be called _after_ command has already stopped or if 
     *       it failed to start.  Command implementation is expected
     *       to handle this gracefully.
     */
    void CommandIfaceStopBL()
    {
        // Stop, print status, and destroy command objects

        if (pClientMgr_.get()) {
            pClientMgr_->Stop();
        }

        if (pServerMgr_.get()) {
            pServerMgr_->Stop();
        }

        if (pClientMgr_.get()) {
            pClientMgr_->PrintStats();
        }

        pClientMgr_.reset();
        pServerMgr_.reset();


        if (opensslInitialized_) {
            ::PslError pslerr = ::PmSockOpensslThreadCleanup();
            assert(!pslerr);
            pslerr = ::PmSockOpensslUninit();
            assert(!pslerr);
        }
    }
    /**@}*/ //wtu::TestCmdMgr::CommandIface virtual member function overrides


    bool ParseArgs()
    {
        for (int i=1; i < args_.Count(); ++i) {
            const char* const pArgName = args_[i];

            if (0 == strcmp("-client", pArgName)) {
                clientInfo_.create = true;

                ++i;
                if (i >= args_.Count()) {
                    printf("%s: ERROR: expected rx= and/or tx= or rxtx= " \
                           "after %s, but got none\n", args_[0], pArgName);
                    return false;
                }

                if (!StressClientMgr::ParseClientSubArgs(args_[i],
                                                         &clientInfo_.numRxBytes,
                                                         &clientInfo_.numTxBytes,
                                                         args_[0])) {
                    return false;
                }
            }//-client

            else if (0 == strcmp("-how", pArgName)) {
                ++i;
                if (i >= args_.Count()) {
                    printf("%s: ERROR: expected {bd | ud} " \
                           "after %s, but got none\n", args_[0], pArgName);
                    return false;
                }

                const char* const howStr = args_[i];
                if (0 == strcmp("bd", howStr)) {
                    clientInfo_.how = kStressTestKind_SSLShutTwoWay;
                }
                else if (0 == strcmp("ud", howStr)) {
                    clientInfo_.how = kStressTestKind_SSLShutOneWay;
                }
                else {
                    printf("%s: ERROR: expected a valid %s option value, " \
                           "but got '%s'\n", args_[0], pArgName, howStr);
                    return false;
                }
            }//-how

            else if (0 == strcmp("-addr", pArgName)) {
                ++i;
                if (i >= args_.Count()) {
                    printf("%s: ERROR: expected an IP addr or hostname " \
                           "after %s, but got none\n", args_[0], pArgName);
                    return false;
                }

                clientInfo_.sa = args_[i];
            }

            else if (0 == strcmp("-port", pArgName)) {
                ++i;
                if (i >= args_.Count()) {
                    printf("%s: ERROR: expected a port number " \
                           "after %s, but got none\n", args_[0], pArgName);
                    return false;
                }

                int serverPort = 0;
                sscanf(args_[i], "%d", &serverPort);
                if (serverPort <= 0) {
                    printf("%s: ERROR: expected a server port > 0, but got" \
                           "%s, which evaluated to to %d\n",
                           args_[0], args_[i], serverPort);
                    return false;
                }

                clientInfo_.serverPort = serverInfo_.listenPort = serverPort;
            }

            else if (0 == strcmp("-ioslice", pArgName)) {
                ++i;
                if (i >= args_.Count()) {
                    printf("%s: ERROR: expected a byte count " \
                           "after %s, but got none\n", args_[0], pArgName);
                    return false;
                }

                sscanf(args_[i], "%u", &clientInfo_.ioSliceThreashold);
                if (!(clientInfo_.ioSliceThreashold > 0)) {
                    printf("%s: ERROR: expected a byte count > 0 after %s, but got" \
                           "%s, which evaluated to to %u\n",
                           args_[0], pArgName, args_[i], clientInfo_.ioSliceThreashold);
                    return false;
                }

                serverInfo_.ioSliceThreashold = clientInfo_.ioSliceThreashold;
            }

            else if (0 == strcmp("-pacewrite", pArgName)) {
                ++i;
                if (i >= args_.Count()) {
                    printf("%s: ERROR: expected a millisecond count " \
                           "after %s, but got none\n", args_[0], pArgName);
                    return false;
                }

                sscanf(args_[i], "%u", &clientInfo_.paceWriteMillisec);

                serverInfo_.paceWriteMillisec = clientInfo_.paceWriteMillisec;
            }

            else if (0 == strcmp("-maxwrite", pArgName)) {
                ++i;
                if (i >= args_.Count()) {
                    printf("%s: ERROR: expected a byte count " \
                           "after %s, but got none\n", args_[0], pArgName);
                    return false;
                }

                sscanf(args_[i], "%u", &clientInfo_.maxWriteByteCnt);
                if (!(clientInfo_.maxWriteByteCnt > 0 &&
                      clientInfo_.maxWriteByteCnt <= StressSession::DataPatternSize())) {
                    printf("%s: ERROR: expected a byte count [1..%u] after %s, but got " \
                           "%s, which evaluated to to %u\n",
                           args_[0], StressSession::DataPatternSize(), pArgName, args_[i],
                           clientInfo_.maxWriteByteCnt);
                    return false;
                }

                serverInfo_.maxWriteByteCnt = clientInfo_.maxWriteByteCnt;
            }

            else if (0 == strcmp("-key", pArgName)) {
                ++i;
                if (i >= args_.Count()) {
                    printf("%s: ERROR: expected a private key file path " \
                           "after %s, but got none\n", args_[0], pArgName);
                    return false;
                }

                serverInfo_.privkeyPath = args_[i];
            }

            else if (0 == strcmp("-loop", pArgName)) {
                ++i;
                if (i >= args_.Count()) {
                    printf("%s: ERROR: expected a loop count " \
                           "after %s, but got none\n", args_[0], pArgName);
                    return false;
                }

                sscanf(args_[i], "%u", &clientInfo_.loopCnt);
                if (clientInfo_.loopCnt <= 0) {
                    printf("%s: ERROR: expected a loop count > 0, but got" \
                           "%s, which evaluated to to %u\n",
                           args_[0], args_[i], clientInfo_.loopCnt);
                    return false;
                }
            }

            else if (0 == strcmp("-parallel", pArgName)) {
                ++i;
                if (i >= args_.Count()) {
                    printf("%s: ERROR: expected a parallel count " \
                           "after %s, but got none\n", args_[0], pArgName);
                    return false;
                }

                sscanf(args_[i], "%u", &clientInfo_.parallelCnt);
                if (clientInfo_.parallelCnt <= 0) {
                    printf("%s: ERROR: expected a parallel count > 0, but got" \
                           "%s, which evaluated to to %u\n",
                           args_[0], args_[i], clientInfo_.parallelCnt);
                    return false;
                }
            }

            else if (0 == strcmp("-server", pArgName)) {
                serverInfo_.create = true;
            }

            else if (0 == strcmp("-progressloop", pArgName)) {
                ++i;
                if (i >= args_.Count()) {
                    printf("%s: ERROR: expected a %s period " \
                           "after %s, but got none\n",
                           args_[0], pArgName, pArgName);
                    return false;
                }

                unsigned int period = 0;
                sscanf(args_[i], "%u", &period);
                if (period <= 0) {
                    printf("%s: ERROR: expected a %s period > 0, " \
                           "but got '%s', which evaluated to to %u\n",
                           args_[0], pArgName, args_[i], period);
                    return false;
                }

                clientInfo_.progressLoopPeriod = period;
            }
            else if (0 == strcmp("-verbose", args_[i])) {
                verbose_ = true;
            }
            else {
                printf("%s: ERROR: Unexpected command-line arg: <%s>.\n",
                       args_[0], args_[i]);
                return false;
            }
        }

        /**
         * Validate relationships between args
         */

        if (!clientInfo_.create && !serverInfo_.create) {
            printf("%s: ERROR: At least one of -client or -server MUST be " \
                   "specified.\n", args_[0]);
            return false;
        }

        if (clientInfo_.create) {
            if (kStressTestKind_none == clientInfo_.how) {
                printf("%s: ERROR: A -how arg MUST be " \
                       "specified when using the -client arg.\n", args_[0]);
                return false;
            }

            if (clientInfo_.sa.empty()) {
                printf("%s: ERROR: A -addr arg MUST be " \
                       "specified when using the -client arg.\n", args_[0]);
                return false;
            }

            if (0 == clientInfo_.serverPort) {
                printf("%s: ERROR: A non-zero connection port number MUST be " \
                       "specified via the -port arg.\n", args_[0]);
                return false;
            }
        }
        else {
            if (kStressTestKind_none != clientInfo_.how) {
                printf("%s: ERROR: A -how arg MAY NOT be " \
                       "used without the -client arg.\n", args_[0]);
                return false;
            }

            if (!clientInfo_.sa.empty()) {
                printf("%s: ERROR: A -addr arg MAY NOT be " \
                       "used without the -client arg.\n", args_[0]);
                return false;
            }
        }

        if (serverInfo_.create) {
            if (0 == serverInfo_.listenPort) {
                printf("%s: ERROR: A non-zero connection port number MUST be " \
                       "specified via the -port arg.\n", args_[0]);
                return false;
            }

            if (serverInfo_.privkeyPath.empty()) {
                printf("%s: ERROR: The -key arg is required " \
                       "with the -server arg.\n", args_[0]);
                return false;
            }
        }
        else {
            if (!serverInfo_.privkeyPath.empty()) {
                printf("%s: ERROR: The -key arg is meaningful only with " \
                       "with the -server arg.\n", args_[0]);
                return false;
            }
        }

        return true;
    }//ParseArgs


private:
    static bool Register()
    {
        MyCmdShellHost::CmdRegInfo info;
        info.pName = kTestCmdName;
        info.pHelp =
            "Tests uni-directional and bi-directional SSL/TLS shutdown " \
            "initiated by client before it finishes reading all data " \
            "from the Server; client and server may run in the same process, " \
            "different processes on the same device, or on different devices.\n" \
            "args: " \
            "-client [rx=<num-rx-bytes>][,tx=<num-tx-bytes>][,rxtx=<num-rxtx-bytes>] " \
            "-how ud|bd " \
            "-addr <server's IP addr or hostname> " \
            "-port <IP port number> " \
            "[-maxwrite <max-write-byte-cnt> " \
            "[-ioslice <io-slice-byte-cnt> " \
            "[-pacewrite <milliseconds>] " \
            "-server " \
            "-key <private-key-path> " \
            "[-parallel <parallel-count>] " \
            "[-loop <loop-count>] " \
            "[-progressloop period] " \
            "[-verbose] " \
            "\n\n" \
            "-client     Presence of the '-client' arg creates a chargen and/or\n" \
            "            discard-like client. The client will initiate SSL/TLS\n" \
            "            shut-down after transmitting <num-tx-bytes> number of bytes,\n" \
            "            if any, and concurrently receive the amount of data from\n" \
            "            the server as indicated by <num-rx-bytes>. If uni-directional\n" \
            "            shutdown is requested, the client will validate the\n" \
            "            incoming data stream until it receives EOF from server. If bi-directional\n" \
            "            shutdown is requested, the client will validate incomding\n" \
            "            data until it finishes transmitting all requested bytes\n" \
            "            and issues a bi-directional shut-down request, after which all\n" \
            "            subsequent incoming data will be discarded by libpalmsocket's\n" \
            "            SSL/TLS shutdown handler. At least one of num-rx-bytes or\n" \
            "            num-tx-bytes must be greater than zero.  rxtx is a shortcut\n" \
            "            for assigning the same number to both num-rx-bytes and num-tx-bytes\n" \
            "            An appropriate RSA CA certificate chain that matches the server's\n" \
            "            private key must be installed in the devices default certificate store.\n" \
            "-how        ud = uni-directional and bd = bi-directional shutdown\n" \
            "            Applies only to -client arg. An appropriate\n" \
            "            RSA CA certificate that matches the server's private key must\n" \
            "            be installed in the devices default certificate store.\n" \
            "            _MUST_ be specified with the -client arg.\n" \
            "-addr       Hostname or address of the server. Must be specfied with the -client arg.\n" \
            "-port       Must be specified with both -client and -server; it\n" \
            "            indicates the connection port number.\n" \
            "-maxwrite   Optional. Places a limit on the number of data bytes that\n" \
            "            may be written in a single call to g_io_channel_write_chars.\n" \
            "            Applies to both client and server.\n" \
            "-ioslice    Optional. Defines a threashold on iterative read and write\n" \
            "            operations expressed in number of bytes for each operatio type. \n" \
            "            Once that threshold is reached or crossed, control is yielded\n" \
            "            so that other opersions may be performed.\n"
            "            may be written in a single call to g_io_channel_write_chars.\n" \
            "            Applies to both client and server.\n" \
            "-pacewrite  Optional. Delay in milliseconds to insert between writes.\n"
            "            Applies to both client and server.\n" \
            "-server     Presence of the '-server' arg creates a discard-like\n" \
            "            server. '-server' may be specified on the same\n" \
            "            command line with '-client' or separately in another\n" \
            "            instance of the test either on the same or different device.\n" \
            "-key        Path to a PEM file containing the _unencrypted_ RSA private key\n" \
            "            _and_ the corresponding CA certificate to be used by the server\n" \
            "            side for SSL/TLS communication with the client side.\n" \
            "            _MUST_ be specified with the -server arg.\n" \
            "-parallel   Number of parallel client groups (DEFAULT=1)\n" \
            "-loop       Number of times to loop within each group (DEFAULT=1).\n" \
            "            total requests=(loop-count x parallel-count).\n" \
            "-progressloop Report loop progress to standard out (DEFAULT=don't report).\n" \
            "            period is specified in number of loops per parallel session.\n" \
            "-verbose    Causes detailed output of session information and rx/tx\n" \
            "            data rx/tx stats.\n" \
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
        TestCmdShutSSL   handler(args);
        return handler.Execute();
    }

private:
    const MyCmdShell::ArgsType& args_;

    class ClientInfo {
    public:
        ClientInfo()
        :   create(false),
            how(kStressTestKind_none),
            loopCnt(1),
            parallelCnt(1),
            numRxBytes(0),
            numTxBytes(0),
            sa(),
            serverPort(0),
            ioSliceThreashold(0),
            maxWriteByteCnt(0),
            paceWriteMillisec(0),
            progressLoopPeriod(0)
        {
        }

        ~ClientInfo()
        {
        }

        bool                    create;    ///< whether client should be created

        /// isTwoWay: TRUE=bi-directional;FALSE=uni-directional SSL shutdown
        StressTestKind          how;

        unsigned int            loopCnt;        ///< # of loops
        unsigned int            parallelCnt;    ///< # of parallell sessions
        unsigned int            numRxBytes;
        unsigned int            numTxBytes;
        std::string             sa; ///< server's IP address or hostname string
        int                     serverPort;
        unsigned int            ioSliceThreashold; ///< # of rx/tx bytes before yielding
        unsigned int            maxWriteByteCnt;   ///< max bytes per write call
        unsigned int            paceWriteMillisec; ///< delay between writes
        unsigned int            progressLoopPeriod;
    };

    class ServerInfo {
    public:
        ServerInfo()
        :   create(false),
            listenPort(0),
            privkeyPath(),
            ioSliceThreashold(0),
            maxWriteByteCnt(0),
            paceWriteMillisec(0)
        {
        }


        ~ServerInfo()
        {
        }

        bool                    create;         ///< whether server should be created
        int                     listenPort;
        std::string             privkeyPath;
        unsigned int            ioSliceThreashold; ///< # of rx/tx bytes before yielding
        unsigned int            maxWriteByteCnt;   ///< max bytes per write call
        unsigned int            paceWriteMillisec; ///< delay between writes
    };

    ClientInfo                  clientInfo_;
    ServerInfo                  serverInfo_;
    bool                        verbose_;

    bool                        opensslInitialized_;

    TestCmdMgr                  cmdMgr_;

    std::auto_ptr<StressClientMgr>  pClientMgr_;
    std::auto_ptr<StressServerMgr>  pServerMgr_;

    static const bool           registered_;
}; // class TestCmdShutSSL

const bool TestCmdShutSSL::registered_ = Register();

} /// End of namespace
