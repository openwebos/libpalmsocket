/** 
 * *****************************************************************************
 * @file TestCmdLogLevel.cpp
 * @ingroup psl_test
 * 
 * @brief  Test Command Handler for setting libpalmsocket's log
 *         level.
 * 
 * *****************************************************************************
 */

#include <palmsocklog.h>

#include <PmWsfTestUtils/CommandShell.h>


#include "PslTestCmdShell.h"
#include "CommonUtils.h"


namespace psl_test_blade {
static const char kCmdTestLogLevel[] = "logopt.set";



/**
 * libpalmsocket log options test
 */
class SetPmSockLogLevelTestCmd {
private:


private:
    explicit SetPmSockLogLevelTestCmd(const MyCmdShell::ArgsType &args)
    :   args_(args)
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

        if (args_.Count() != 2) {
            printf("%s: ERROR: Expected exactly one arg (log-level), " \
                   "but got %d\n", args_[0], args_.Count() - 1);
            return false;
        }

        PmSockLogOptions  logOpt = 0;
        if (!UtilPslLogOptionFromStr(args_[1], &logOpt)) {
            printf("%s: ERROR: Unknown log option: %s\n",
                   args_[0], args_[1]);
            return false;
        }

        PslError const pslerr = PmSockLogSetOptions(logOpt);
        if (pslerr) {
            printf("%s: ERROR: PmSockLogSetOptions(0x%X) failed; PslError=%d(%s)\n",
                   args_[0], logOpt, pslerr, PmSockErrStringFromError(pslerr));
            return false;
        }


        printf("%s: libpalmsocket log options successfully set to: 0x%X (%s)\n",
               args_[0], logOpt, args_[1]);

        return true;
    } // Execute()

private:
    static bool Register()
    {
        MyCmdShellHost::CmdRegInfo info;
        info.pName = kCmdTestLogLevel;
        info.pHelp =
            "Sets libpalmsocket logging options; " \
            "args: " \
            "<log-option> " \
            "\n\n" \
            "      <log-option> values: " \
            "      {debuglow|none}\n" \
            "\n";

        info.handlerCb = &Handler;

        RegisterCmdHandler(info);
        return true;
    }

    static bool Handler(const MyCmdShell::ArgsType &args)
    {
        SetPmSockLogLevelTestCmd   handler(args);
        return handler.Execute();
    }

private:
    const MyCmdShell::ArgsType& args_;

    static const bool           registered_;
}; // class SetPmSockLogLevelTestCmd

const bool SetPmSockLogLevelTestCmd::registered_ = Register();

} /// End of namespace
