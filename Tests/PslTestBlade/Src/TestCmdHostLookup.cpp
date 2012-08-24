/** 
 * *****************************************************************************
 * @file HostLookupTestCmd.cpp
 * @ingroup psl_test
 * 
 * @brief  Test Command Handler for testing libplamsocket's
 *         HostLookup.
 * 
 * *****************************************************************************
 */

#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <glib.h>

#include <PmWirelessSystemFramework/Utils/RuntimeDispatcher/RuntimeDispatcher.h>
#include <PmWirelessSystemFramework/Utils/RuntimeDispatcher/RdAsyncBridge.h>

#include <PmWsfTestUtils/CommandShell.h>
#include <PmWsfTestUtils/ProgressReporter.h>

#include <palmhostlookup.h>


#include "PslTestCmdShell.h"
#include "CommonUtils.h"


namespace psl_test_blade {
const char kCmdTestHostLookup[] = "host.resolve";



/**
 * Non-blocking IP address DNS resolution test
 */
class HostLookupTestCmd {
private:


private:
    explicit HostLookupTestCmd(const MyCmdShell::ArgsType &args)
    :   args_(args),
        hostname_(NULL),
        addrFamily_(AF_INET),
        loopMax_(1),
        verbose_(false),
        completedCnt_(0),
        successCnt_(0),
        resolver_(NULL),
        progress_(0, 100, args[0]),
        rd_(),
        endTestEvt_(this, &HostLookupTestCmd::OnEndTestEvent,
                      (void*)NULL, rd_),
        cmdShellInterruptMon_(
            &args.PeekShell(), &rd_,
            std::tr1::bind(&HostLookupTestCmd::OnCmdShellInterruptCb, this,
                           std::tr1::placeholders::_1))
    {
    }

    ~HostLookupTestCmd()
    {
        progress_.Final();

        if (resolver_) {
            PmSockHostLookupDestroy(resolver_);
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

        if (args_.Count() < 2) {
            printf("%s: ERROR: Expected at least one arg (hostname), " \
                   "but got %d\n", args_[0], args_.Count() - 1);
            return false;
        }


        hostname_ = args_[1];

        for (int i=2; i < args_.Count(); ++i) {
            if (0 == strcmp("-inet4", args_[i])) {
                addrFamily_ = AF_INET;
            }
            else if (0 == strcmp("-inet6", args_[i])) {
                addrFamily_ = AF_INET6;
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

            else if (0 == strcmp("-verbose", args_[i])) {
                verbose_ = true;
            }

            else {
                printf("%s: ERROR: Unexpected command-line arg: <%s>\n",
                       args_[0], args_[i]);
                return false;
            }
        }


        progress_.SetTotal(loopMax_);


        printf("%s: Starting: hostname='%s', loopCnt=%u ...\n",
               args_[0], hostname_, loopMax_);

        if (!StartNewSession()) {
            return false;
        }

        rd_.Run();

        progress_.Final();

        printf("\n\n%s: DONE: completedCnt=%u, successCnt=%u.\n",
               args_[0], completedCnt_, successCnt_);



        return true;
    } // Execute()


    /**
     * Destroy the old resolver, if any, creates a new resolver
     * instance, and starts it
     * 
     * @return bool TRUE on success, FALSE on failure
     */
    bool StartNewSession()
    {
        if (resolver_) {
            if (verbose_) {
                printf("%s: Destroying old resolver...\n", args_[0]);
            }
            PmSockHostLookupDestroy(resolver_);
            resolver_ = NULL;
        }

        /// Create it
        GMainLoop* const loop =
            (GMainLoop*)wsf::RuntimeDispatcher::GetInternalLoop(rd_);
        assert(loop);

        PslError const createErr = PmSockHostLookupNew(
            &resolver_,
            hostname_,
            addrFamily_,
            this,
            &HostLookupDoneCb,
            args_[0],
            g_main_loop_get_context(loop));

        if (createErr) {
            printf("%s: ERROR: unable to create resolver PslError=%d (%s)\n",
                   args_[0], createErr, PmSockErrStringFromError(createErr));
            return false;
        }

        /// Start lookup
        PslError const startErr = PmSockHostLookupStart(resolver_);

        if (startErr) {
            printf("%s: ERROR: unable to start resolver PslError=%d (%s)\n",
                   args_[0], startErr, PmSockErrStringFromError(startErr));

            PmSockHostLookupDestroy(resolver_);
            resolver_ = NULL;
        }

        return !createErr && !startErr;
    }


    /**
     * Called by the non-blocking resolver when DNS resolution
     * completes with success or failure (@see PmSockHostLookupCb in
     * palmhostlookup.h)
     * 
     * @param userData
     * @param ses
     * @param result
     * @param errorCode
     * 
     * @see @see PmSockHostLookupCb
     */
    static void HostLookupDoneCb(void*                          userData,
                                 PmSockHostLookupSession* const ses,
                                 const struct hostent*    const hosts,
                                 PslError                 const errorCode)
    {
        HostLookupTestCmd*  const me = (HostLookupTestCmd*)userData;

        me->progress_.Tick();

        /// Initiate destruction of this resolver.  It will complete once
        /// the callback returns.
        assert(ses == me->resolver_);
        PmSockHostLookupDestroy(me->resolver_);
        me->resolver_ = NULL;

        me->completedCnt_++;
        if (!errorCode) {
            me->successCnt_++;
        }

        if (me->verbose_) {
            printf("%s: =====Lookup %u resulted in %s: code = %d (%s)=====\n",
                   me->args_[0], me->completedCnt_,
                   errorCode ? "FAILURE" : "SUCCESS",
                   errorCode,
                   PmSockErrStringFromError(errorCode));

            if (hosts) {
                printf("%s: address family=%d (%s), length=%d\n",
                       me->args_[0],
                       hosts->h_addrtype,
                       (hosts->h_addrtype == AF_INET
                        ? "AF_INET"
                        : (hosts->h_addrtype == AF_INET6
                           ? "AF_INET6"
                           : "other")),
                       hosts->h_length);

                const char * const * const addrlist = hosts->h_addr_list;
                int i = 0;
                const char* addr;
                while((addr = addrlist[i++])) {
                    char        addrtext [(INET6_ADDRSTRLEN > INET_ADDRSTRLEN
                                           ? INET6_ADDRSTRLEN
                                           : INET_ADDRSTRLEN)];

                    if (!inet_ntop(hosts->h_addrtype, addr,
                                   addrtext, sizeof(addrtext))) {
                        int const saverrno = errno;
                        printf("%s: ERROR: inet_ntop failed; errno=%d (%s)\n",
                               me->args_[0], saverrno, strerror(saverrno));
                        me->endTestEvt_.Trigger();
                        return;
                    }

                    printf("%s: addrlist[%d]='%s'\n",
                           me->args_[0], i-1, addrtext);
               }//print all addresses
            }//if (hosts)

        }//if (verbose)

        /// Create a new one if needed
        if (me->completedCnt_ < me->loopMax_) {
            if (!me->StartNewSession()) {
                me->endTestEvt_.Trigger();
                return;
            }

        }
        else { /// Done looping
            me->endTestEvt_.Trigger();
        }
    }//HostLookupDoneCb


private:
    static bool Register()
    {
        MyCmdShellHost::CmdRegInfo info;
        info.pName = kCmdTestHostLookup;
        info.pHelp =
            "Resolve the given hostname; " \
            "args: " \
            "<hostname|ip-address> " \
            "[-inet4 | -inet6]" \
            "[-loop number-of-times] " \
            "[-verbose] " \
            "\n\n" \
            "-inet4    Selects IPv4 address family. (DEFAULT)\n" \
            "-inet6    Selects IPv6 address family.\n" \
            "-loop     Number of times to repeat the lookup (DEFAULT=1).\n" \
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
        HostLookupTestCmd   handler(args);
        return handler.Execute();
    }

private:
    const MyCmdShell::ArgsType& args_;

    const char*                 hostname_;
    int                         addrFamily_; ///< AF_INET or AF_INET6
    unsigned int                loopMax_;
    bool                        verbose_;


    unsigned int                completedCnt_;  ///< # of lookups completed
    unsigned int                successCnt_;    ///< # of successful lookups
    PmSockHostLookupSession*    resolver_;

    wtu::ProgressReporter       progress_;

    wsf::RuntimeDispatcher      rd_;
    wsf::RdAsyncBridge          endTestEvt_;

    wtu::CommandShellInterruptMonitor   cmdShellInterruptMon_;

    static const bool           registered_;
}; // class HostLookupTestCmd

const bool HostLookupTestCmd::registered_ = Register();

} /// End of namespace
