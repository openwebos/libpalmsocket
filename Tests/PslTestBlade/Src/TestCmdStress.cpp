/** 
 * *****************************************************************************
 * @file TestCmdStress.cpp
 * @ingroup psl_test
 * 
 * @brief  Test Command Handler for stress-testing
 *         libplamsocket's PmSock API in a multi-threaded
 *         environment.  Implements both client and server
 *         sides.  Supports parallel requests.
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


static const char kTestCmdName[] = "stress";


/**
 * libpalmsocket chargen/discard-like test
 */
class TestCmdStress : public StressHostIface {

public:
    /**
     * virtual method overrides for class StressHostIface 
     * @{ 
     */
    void StressHostSubserviceIsDone()
    {
        subserviceDoneEvt_.Trigger();
    }
    /**@}*/

private:
    explicit TestCmdStress(const MyCmdShell::ArgsType &args)
    :   args_(args),
        clientInfo_(),
        serverInfo_(),
        verbose_(false),
        rd_(),
        endTestEvt_(this, &TestCmdStress::OnEndTestEvent, (void*)NULL, rd_),
        subserviceDoneEvt_(this, &TestCmdStress::OnSubserviceDoneEvent,
                           (void*)NULL, rd_),
        cmdShellInterruptMon_(
            &args.PeekShell(), &rd_,
            std::tr1::bind(&TestCmdStress::OnCmdShellInterruptCb, this,
                           std::tr1::placeholders::_1))
    {
    }

    ~TestCmdStress()
    {

    }

    void OnSubserviceDoneEvent(wsf::RdAsyncBridge*/*ignore*/, void*/*ignore CXT*/)
    {
        bool    done = true;

        if (done) {
            endTestEvt_.Trigger();
        }
    }

    void OnCmdShellInterruptCb(wtu::CommandShellInterruptMonitor* pMon)
    {
        printf("%s: INTERRUPTED.\n", args_[0]);
        endTestEvt_.Trigger();
    }

    void OnEndTestEvent(wsf::RdAsyncBridge*/*ignore*/, void*/*ignore CXT*/)
    {
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

        if (verbose_) {
            printf("%s: Starting: numRxBytes=%u, numTxBytes=%u\n",
                   args_[0], clientInfo_.numRxBytes, clientInfo_.numTxBytes);
        }

        bool opensslInitialized = false;

        /// Placing the execution code in its own block allows us to control
        /// destruction of clientMgr and serverMgr, thus allowing us to
        /// uninitialize openssl thread-specific data properly
        {
            std::auto_ptr<StressClientMgr> pClientMgr;
            std::auto_ptr<StressServerMgr> pServerMgr;

            if (serverInfo_.create) {
                /**
                 * We always need openssl initialized for the server since a 
                 * stand-alone server won't know that it needs SSL until it gets 
                 * a "use crypto" request 
                 */
                if (!opensslInitialized) {
                    UtilInitOpenssl(args_[0]);
                    opensslInitialized = true;
                }

                StressServerPeerArg peerArg;

                peerArg.ioSliceThreashold   = serverInfo_.ioSliceThreashold;
                peerArg.maxWriteByteCnt     = serverInfo_.maxWriteByteCnt;
                peerArg.paceWriteMillisec   = serverInfo_.paceWriteMillisec;
                peerArg.listenPort          = serverInfo_.listenPort;
                peerArg.privkeyPath         = serverInfo_.privkeyPath;

                pServerMgr.reset(new StressServerMgr(peerArg, this, verbose_));
                pServerMgr->Start();
            }

            if (clientInfo_.create) {

                if (clientInfo_.crypto && !opensslInitialized) {
                    UtilInitOpenssl(args_[0]);
                    opensslInitialized = true;
                }

                StressClientPeerArg peerArg;
                
                peerArg.testKind            = kStressTestKind_dataExg;
                peerArg.addr                = clientInfo_.sa;
                peerArg.ioSliceThreashold   = clientInfo_.ioSliceThreashold;
                peerArg.maxWriteByteCnt     = clientInfo_.maxWriteByteCnt;
                peerArg.paceWriteMillisec   = clientInfo_.paceWriteMillisec;
                peerArg.port                = clientInfo_.serverPort;
                peerArg.progressBytePeriod  = clientInfo_.progressBytePeriod;
                peerArg.progressLoopPeriod  = clientInfo_.progressLoopPeriod;
                peerArg.sslConfig           = clientInfo_.sslConfig;
                peerArg.sslRenegFlags       = clientInfo_.sslRengFlags;
                peerArg.targetRxBytes       = clientInfo_.numRxBytes;
                peerArg.targetTxBytes       = clientInfo_.numTxBytes;
                peerArg.useCrypto           = clientInfo_.crypto;

                pClientMgr.reset(new StressClientMgr(clientInfo_.parallelCnt,
                                                     clientInfo_.loopCnt,
                                                     peerArg,
                                                     this,
                                                     verbose_)
                                 );
                pClientMgr->Start();
            }

            /// Run until all transactions complete or we get a stop request
            rd_.Run();

            /// Make sure client and server are fully stopped
            if (pClientMgr.get()) {
                pClientMgr->Stop();
            }

            if (pServerMgr.get()) {
                pServerMgr->Stop();
            }


            /// Output status
            if (pClientMgr.get()) {
                pClientMgr->PrintStats();
            }
        } ///< clientMgr and serverMgr should be destroyed after exiting this block


        if (opensslInitialized) {
            ::PslError pslerr = ::PmSockOpensslThreadCleanup();
            assert(!pslerr);
            pslerr = ::PmSockOpensslUninit();
            assert(!pslerr);
        }

        return true;
    } // Execute()


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

            else if (0 == strcmp("-ssl", pArgName)) {
                clientInfo_.crypto = true;
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

            else if (0 == strcmp("-pv", pArgName)) {
                ++i;
                if (i >= args_.Count()) {
                    printf("%s: ERROR: expected {none | hn,fblc} " \
                           "after %s, but got none\n", args_[0], pArgName);
                    return false;
                }

                const char* optStr = args_[i];
                if (!optStr[0]) {
                    printf("%s: ERROR: expected -pv option value(s) after " \
                           "%s, but got empty string\n", args_[0], pArgName);
                    return false;
                }

                PmSockCertVerifyOpts    opts = 0;

                while (*optStr) {
                    int optLen = 0;
                    if (0 == strncmp("none", optStr, 4)) {
                        opts = 0;
                        optLen = 4;
                    }
                    else if (0 == strncmp("hn", optStr, 2)) {
                        opts |= kPmSockCertVerifyOpt_checkHostname;
                        optLen = 2;
                    }
                    else if (0 == strncmp("fblc", optStr, 4)) {
                        opts |= kPmSockCertVerifyOpt_fallbackToInstalledLeaf;
                        optLen = 4;
                    }
                    else {
                        printf("%s: ERROR: expected a valid %s option value, " \
                               "but got '%s'\n", args_[0], pArgName, optStr);
                        return false;
                    }

                    optStr += optLen;
                    if (',' == optStr[0]) {
                        optStr++;

                        if ('\0' == optStr[0]) {
                            printf("%s: ERROR: expected a valid %s option value " \
                                   "after comman, but got empty string\n", args_[0],
                                   pArgName);
                            return false;
                        }
                    }
                }

                clientInfo_.sslConfig.enabledOpts |= kPmSockCryptoConfigEnabledOpt_verifyOpts;
                clientInfo_.sslConfig.verifyOpts = opts;
            }//-pv

            else if (0 == strcmp("-renegotiate", pArgName)) {
                ++i;
                if (i >= args_.Count()) {
                    printf("%s: ERROR: expected {client | server | both} " \
                           "after %s, but got none\n", args_[0], pArgName);
                    return false;
                }

                const char* const howStr = args_[i];
                if (0 == strcmp("client", howStr)) {
                    clientInfo_.sslRengFlags |= kStressSSLRenegFlag_client;
                }
                else if (0 == strcmp("server", howStr)) {
                    clientInfo_.sslRengFlags |= kStressSSLRenegFlag_server;
                }
                else if (0 == strcmp("both", howStr)) {
                    clientInfo_.sslRengFlags |= kStressSSLRenegFlag_client;
                    clientInfo_.sslRengFlags |= kStressSSLRenegFlag_server;
                }
                else {
                    printf("%s: ERROR: expected a valid %s option value, " \
                           "but got '%s'\n", args_[0], pArgName, howStr);
                    return false;
                }
            }//-renegotiate

            else if (0 == strcmp("-loop", pArgName)) {
                ++i;
                if (i >= args_.Count()) {
                    printf("%s: ERROR: expected a loop count " \
                           "after %s, but got none\n", args_[0], pArgName);
                    return false;
                }

                sscanf(args_[i], "%u", &clientInfo_.loopCnt);
                if (clientInfo_.loopCnt <= 0) {
                    printf("%s: ERROR: expected a loop count > 0 for %s, but got" \
                           "%s, which evaluated to to %u\n",
                           args_[0], pArgName, args_[i], clientInfo_.loopCnt);
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
                    printf("%s: ERROR: expected a parallel count > 0 for %s, but got" \
                           "%s, which evaluated to to %u\n",
                           args_[0], pArgName, args_[i], clientInfo_.parallelCnt);
                    return false;
                }
            }

            else if (0 == strcmp("-server", pArgName)) {
                serverInfo_.create = true;
            }

            else if (0 == strcmp("-progressbyte", pArgName)) {
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

                clientInfo_.progressBytePeriod = period;
            }

            else if (0 == strcmp("-progressloop", pArgName)) {
                ++i;
                if (i >= args_.Count()) {
                    printf("%s: ERROR: expected a %s period " \
                           "after %s, but got none\n",
                           args_[0], args_[i-1], pArgName);
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
            else if (0 == strcmp("-verbose", pArgName)) {
                verbose_ = true;
            }

            else {
                printf("%s: ERROR: Unexpected command-line arg: <%s>.\n",
                       args_[0], pArgName);
                return false;
            }
        }


        /**
         * Validate options
         */

        if (!clientInfo_.create && !serverInfo_.create) {
            printf("%s: ERROR: At least one of -client or -server MUST be " \
                   "specified.\n", args_[0]);
            return false;
        }

        if (clientInfo_.create) {
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

            if (clientInfo_.sslRengFlags && !clientInfo_.crypto) {
                printf("%s: ERROR: A -renegotiate arg MAY NOT be " \
                       "used without the -ssl arg.\n", args_[0]);
                return false;
            }
        }
        else {
            if (!clientInfo_.sa.empty()) {
                printf("%s: ERROR: A -addr arg MAY NOT be " \
                       "used without the -client arg.\n", args_[0]);
                return false;
            }

            if (clientInfo_.crypto) {
                printf("%s: ERROR: A -ssl arg MAY NOT be " \
                       "used without the -client arg.\n", args_[0]);
                return false;
            }

            if (clientInfo_.sslRengFlags) {
                printf("%s: ERROR: A -renegotiate arg MAY NOT be " \
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
        }
        else {
            if (!serverInfo_.privkeyPath.empty()) {
                printf("%s: ERROR: The -key arg is meaningful only with " \
                       "the -server arg.\n", args_[0]);
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
            "Performs a chargen/discard-like operation(s) with " \
            "data validation; supports multiple parallell sessions with " \
            "multi-threading;  server and client may run in the same process, " \
            "different processes on the same device, or on different devices.\n" \
            "args: " \
            "-client [rx=<num-rx-bytes>][,tx=<num-tx-bytes>][,rxtx=<num-rxtx-bytes>] " \
            "-addr <server's IP addr or hostname> " \
            "-port <IP port number> " \
            "[-maxwrite <max-write-byte-cnt> " \
            "[-ioslice <io-slice-byte-cnt> " \
            "[-pacewrite <milliseconds>] " \
            "[-ssl] " \
            "-server " \
            "[-key <private-key-path>] " \
            "[-pv none|hn,fblc] " \
            "[-renegotiate client | server | both] " \
            "[-parallel <parallel-count>] " \
            "[-loop <loop-count>] " \
            "[-progressbyte period] " \
            "[-progressloop period] " \
            "[-verbose] " \
            "\n\n" \
            "-client     Presence of the '-client' arg creates a chargen-like\n" \
            "            client. rx instructs the client to receive the given\n" \
            "            number of bytes; tx instructs the client to transmit\n" \
            "            the given number of bytes; rxtx instructs the\n" \
            "            client to both receive and transmit the given\n" \
            "            number of bytes. num-bytes data bytes will be\n" \
            "            transmitted in each requested direction per session.\n" \
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
            "-ssl        Triggers use of SSL/TLS for data comms (DEFAULT=\n" \
            "            plaintext). Applies only to -client arg. An appropriate\n" \
            "            RSA CA certificate that matches the server's private key must\n" \
            "            be installed in the devices default certificate store.\n" \
            "-server     Presence of the '-server' arg creates a discard-like\n" \
            "            server. '-server' may be specified on the same\n" \
            "            command line with '-client' or separately in another\n" \
            "            instance of the test.\n" \
            "-key        Path to a PEM file containing the _unencrypted_ RSA private key\n" \
            "            _and_ the corresponding CA certificate to be used by the server\n" \
            "            side for SSL/TLS communication. with the client side.\n" \
            "            Applies only to the -server arg.\n" \
            "-pv         Sets peer certificate verification options: either 'none' or\n" \
            "            one or more of 'hn', 'fblc', separated by comma (no spaces).\n" \
            "            'hn' = hostname MUST match certificate; 'fblc' = fall back\n" \
            "            to local cert match in device's default cert store if peer\n" \
            "            verification would fail otherwise.  Applies only to -ssl\n" \
            "            arg. (DEFAULT=hn)\n" \
            "-renegotiate Enables SSL/TLS renegotiation testing.  Applies only to\n" \
            "            -ssl arg client=client-initiated; server=server-initiated;\n" \
            "            both=client and server-initiated. (DEFAULT=no renegotiation)\n" \
            "-parallel   Number of parallel client groups (DEFAULT=1)\n" \
            "-loop       Number of times to loop within each group (DEFAULT=1).\n" \
            "            total requests=(loop-count x parallel-count).\n" \
            "-progressbyte Report data byte Rx/Tx progress to standard out " \
            "(DEFAULT=don't report).\n" \
            "            period is specified in number of bytes.\n" \
            "-progressloop Report loop progress to standard out (DEFAULT=don't report).\n" \
            "            period is specified in number of loops per parallel session.\n" \
            "-verbose    Causes detailed output of session information and rx/tx\n" \
            "            stats.\n" \
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
        TestCmdStress   handler(args);
        return handler.Execute();
    }

private:
    const MyCmdShell::ArgsType& args_;

    class ClientInfo {
    public:
        ClientInfo()
        :   create(false),
            crypto(false),
            sslRengFlags(false),
            loopCnt(1),
            parallelCnt(1),
            numRxBytes(0),
            numTxBytes(0),
            sa(),
            serverPort(0),
            ioSliceThreashold(0),
            maxWriteByteCnt(0),
            paceWriteMillisec(0),
            progressBytePeriod(0),
            progressLoopPeriod(0)
        {
            memset(&sslConfig, 0, sizeof(sslConfig));
        }

        ~ClientInfo()
        {
        }

        bool                    create;         ///< whether client should be created
        bool                    crypto;         ///< FALSE=plaintext; TRUE=SSL
        PmSockCryptoConfArgs    sslConfig;
        StressSSLRenegFlags     sslRengFlags;
        unsigned int            loopCnt;        ///< # of loops
        unsigned int            parallelCnt;    ///< # of parallell sessions
        unsigned int            numRxBytes;
        unsigned int            numTxBytes;
        std::string             sa; ///< server's IP address or hostname string
        int                     serverPort;
        unsigned int            ioSliceThreashold; ///< # of rx/tx bytes before yielding
        unsigned int            maxWriteByteCnt;   ///< max bytes per write call
        unsigned int            paceWriteMillisec; ///< delay between writes
        unsigned int            progressBytePeriod;
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

    wsf::RuntimeDispatcher      rd_;
    wsf::RdAsyncBridge          endTestEvt_;
    wsf::RdAsyncBridge          subserviceDoneEvt_;

    wtu::CommandShellInterruptMonitor   cmdShellInterruptMon_;

    static const bool           registered_;
}; // class TestCmdStress

const bool TestCmdStress::registered_ = Register();

} /// End of namespace
