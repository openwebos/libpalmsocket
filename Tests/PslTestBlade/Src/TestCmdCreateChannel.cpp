/** 
 * *****************************************************************************
 * @file TestCmdCreateChannel.cpp
 * @ingroup psl_test
 * 
 * @brief  Test Command Handler for testing libplamsocket's 
 *         Channel Creation functionality.  Simply creates a
 *         channel and runs mainloop (no connection is
 *         attempted) to make sure this case does do anything
 *         unexpected.
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


static const char kTestCmdName[] = "createchannel";


/**
 * libpalmsocket chargen/discard-like test
 */
class TestCmdCreateChannel :
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
    explicit TestCmdCreateChannel(const MyCmdShell::ArgsType &args)
    :   args_(args),
        cmdMgr_(&args.PeekShell()),
        pChan_(NULL)
    {
    }

    ~TestCmdCreateChannel()
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
        UTIL_PRINT_LINE("%s: Starting...", args_[0]);

        class StartRaii {
        public:
            StartRaii()
            :   pThreadCtx(NULL)
            {
            }

            ~StartRaii()
            {
                if (pThreadCtx) {
                    PmSockThreadCtxUnref(pThreadCtx);
                }

            }
        public:
            PmSockThreadContext*    pThreadCtx;
        };//class StartRaii

        StartRaii raii;

        GMainLoop* const gmainloop =
            (GMainLoop*)wsf::RuntimeDispatcher::GetInternalLoop(*pMgrRd);
        assert(gmainloop);

        GMainContext* const gmainctx = ::g_main_loop_get_context(gmainloop);
        assert(gmainctx);

        /// Create a palmsocket thread context
        PslError pslErr = ::PmSockThreadCtxNewFromGMain(
            gmainctx, args_[0], &raii.pThreadCtx);
        if (pslErr) {
            const std::string errorMsg =
                std::string("PmSockThreadCtxNewFromGMain failed: ") +
                ::PmSockErrStringFromError(pslErr);
            UTIL_THROW_FATAL(args_[0], errorMsg.c_str());
        }

        pslErr = ::PmSockCreateChannel(
            raii.pThreadCtx,
            (PmSockOptionFlags)0/*options*/,
            args_[0],
            &pChan_);
        if (!pslErr) {
            assert(pChan_);
        }
        else {
            const std::string errorMsg(
                std::string("PmSockCreateChannel failed: ") +
                ::PmSockErrStringFromError(pslErr));
            UTIL_THROW_FATAL(args_[0], errorMsg.c_str());
        }

        GSource* pTimeout = g_timeout_source_new(0/*interval*/);
        g_source_set_priority(pTimeout, G_PRIORITY_LOW);
        g_source_set_callback(pTimeout, &TimeoutGSourceFunc, this,
                              NULL/*GDestroyNotify*/);
        g_source_attach(pTimeout, gmainctx);
        g_source_unref(pTimeout);
    }//CommandIfaceStartNB

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
        UTIL_PRINT_LINE("%s: Stopping...", args_[0]);


        if (pChan_) {
            ::g_io_channel_unref((GIOChannel*)pChan_);
            pChan_ = NULL;
        }

    }
    /**@}*/ //wtu::TestCmdMgr::CommandIface virtual member function overrides


private:
    /**
     * GSourceFunc for our timer source
     */
    static gboolean TimeoutGSourceFunc(gpointer const data)
    {
        TestCmdCreateChannel* const me = (TestCmdCreateChannel*)data;

        UTIL_PRINT_LINE("%s: Timer expired, ending test...", me->args_[0]);

        me->cmdMgr_.CommandIsDone();

        return false; // Destroy the source upon return to gmain
    }


    static bool Register()
    {
        MyCmdShellHost::CmdRegInfo info;
        info.pName = kTestCmdName;
        info.pHelp =
            "Simply creates a channel and runs mainloop (no connection is " \
            "attempted) to make sure this case does do anything unexpected.\n"
            "no args." \
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
        TestCmdCreateChannel   handler(args);
        return handler.Execute();
    }

private:
    const MyCmdShell::ArgsType& args_;

    TestCmdMgr                  cmdMgr_;

    PmSockIOChannel*            pChan_;

    static const bool           registered_;
}; // class TestCmdCreateChannel

const bool TestCmdCreateChannel::registered_ = Register();

} /// End of namespace
