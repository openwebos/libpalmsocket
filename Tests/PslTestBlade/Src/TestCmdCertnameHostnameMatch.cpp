/** 
 * *****************************************************************************
 * @file TestCmdCertnameHostnameMatch.cpp
 * @ingroup psl_test
 * 
 * @brief  Test Command Handler for testing 
 *         PmSockX509CheckCertHostNameMatch().
 *  
 * @{ 
 * *****************************************************************************
 */

#include <palmsockerror.h>
#include <palmsockx509utils.h>

#include <PmWsfTestUtils/CommandShell.h>


#include "PslTestCmdShell.h"
#include "CommonUtils.h"


namespace psl_test_blade {
static const char kTestCmdName[] = "match.cnhn";



/**
 * libpalmsocket log options test
 */
class TestCmdCertnameHostnameMatch {
private:


private:
    explicit TestCmdCertnameHostnameMatch(const MyCmdShell::ArgsType &args)
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

        if (args_.Count() == 1) {
            return AutoTest();
        }

        if (args_.Count() != 3) {
            printf("%s: ERROR: Expected exactly 2 args, " \
                   "but got %d\n", args_[0], args_.Count() - 1);
            return false;
        }


        const char* const cnStr = args_[1];
        const char* const hnStr = args_[2];
        bool matched = false;

        return CnHnEq(cnStr, strlen(cnStr), hnStr, strlen(hnStr), true, &matched);
    } // Execute()

private:
    /** 
     * AutoTest(): 
     *  
     * @verbatim
     *  
     *      CERT-NAME               HOSTNAME                MATCH?
     *      ======================================================
     *      ""                  vs. <any>                   no
     *      <any>               vs. ""                      no
     *      "*"                 vs. com                     no  
     *      "co*"               vs. com                     no  
     *      "*om"               vs. com                     no  
     *      "*alm.com"          vs. palm.com                no  
     *      "p*lm.com"          vs. palm.com                no
     *      "www.*.com"         vs. www.palm.com            no
     *      "www.pa*.com"       vs. www.palm.com            no
     *      "*.*.com"           vs. www.palm.com            no  
     *      "w*.p*.com"         vs. www.palm.com            no  
     *      "*.palm.com"        vs. "palm.com"              no  
     *      "*.palm.com         vs. "www.eas.palm.com"      no  
     *      "palm*.com"         vs. "palm.com"              no  
     *      "*.tv"              vs. "flinstones.tv"         no
     *      "f*.tv"             vs. "flinstones.tv"         no
     *      "www*.palm.com"     vs. "www.palm.com"          no
     *      "www**.palm.com"    vs. "www12.palm.com"        no
     *      "www.palm.com\0badguy.com" vs. "www.palm.com"   no  
     *      "www*.palm.com"     vs. "www12.palm.com"        yes
     *      "*.palm.com"        vs. "www.palm.com"          yes
     *      "www.palm.com"      vs. "WWW.Palm.Com"          yes
     *      "WWW.Palm.Com"      vs. "www.palm.com"          yes
     *  
     * @endverbatim
     * 
     * @return bool TRUE on success (all tests passed and no API 
     *         error encountered), FALSE on failure (either some
     *         tests didn't pass and/or API error encountered)
     */
    bool AutoTest()
    {
        int     failCount = 0;
        bool    apiSuccess;
        bool    matched;
        const char* cn;
        const char* hn;

        // Expect API failure
        apiSuccess = CnHnEq(
            NULL/*cnStr*/, 1/*cnStrLen*/,
            "palm.com"/*hnStr*/, 8/*hnStrLen*/,
            true/*verbose*/, &matched);
        if (!apiSuccess) {
            printf("%s: PASS: expected API failure; got API failure\n", args_[0]);
        }
        else {
            failCount++;
            printf("%s: FAIL: expected API failure; got API success\n", args_[0]);
        }

        // Expect API failure
        apiSuccess = CnHnEq(
            "*.palm.com"/*cnStr*/, 0/*cnStrLen*/,
            "www.palm.com"/*hnStr*/, 12/*hnStrLen*/,
            true/*verbose*/, &matched);
        if (!apiSuccess) {
            printf("%s: PASS: expected API failure; got API failure\n", args_[0]);
        }
        else {
            failCount++;
            printf("%s: FAIL: expected API failure; got API success\n", args_[0]);
        }

        // Expect API failure
        apiSuccess = CnHnEq(
            "palm.com"/*cnStr*/, 8/*cnStrLen*/,
            NULL/*hnStr*/, 1/*hnStrLen*/,
            true/*verbose*/, &matched);
        if (!apiSuccess) {
            printf("%s: PASS: expected API failure; got API failure\n", args_[0]);
        }
        else {
            failCount++;
            printf("%s: FAIL: expected API failure; got API success\n", args_[0]);
        }

        // Expect API failure
        apiSuccess = CnHnEq(
            "www.palm.com"/*cnStr*/, 12/*cnStrLen*/,
            "www.palm.com"/*hnStr*/, 0/*hnStrLen*/,
            true/*verbose*/, &matched);
        if (!apiSuccess) {
            printf("%s: PASS: expected API failure; got API failure\n", args_[0]);
        }
        else {
            failCount++;
            printf("%s: FAIL: expected API failure; got API success\n", args_[0]);
        }

        /*
         *      cn="*"                 hn=<any>                   no  
         */
        cn = "*"; hn = "com";
        if (!CnHnExpectNoMatch(cn, strlen(cn), hn, strlen(hn))) {
            failCount++;
        }

        /*
         *      cn="co*"               hn=<any>                   no  
         */
        cn = "co*"; hn = "com";
        if (!CnHnExpectNoMatch(cn, strlen(cn), hn, strlen(hn))) {
            failCount++;
        }

        /*
         *      cn="*om"               hn=<any>                   no  
         */
        cn = "*om"; hn = "com";
        if (!CnHnExpectNoMatch(cn, strlen(cn), hn, strlen(hn))) {
            failCount++;
        }

        /*
         *      cn="*alm.com"          hn=<any>                   no  
         */
        cn = "*om"; hn = "www.palm.com";
        if (!CnHnExpectNoMatch(cn, strlen(cn), hn, strlen(hn))) {
            failCount++;
        }

        /*
         *      cn="p*lm.com"          hn=<any>                   no
         */
        cn = "p*lm.com"; hn = "palm.com";
        if (!CnHnExpectNoMatch(cn, strlen(cn), hn, strlen(hn))) {
            failCount++;
        }

        /*
         *      cn="www.*.com"         hn=www.palm.com            no
         */
        cn = "www.*.com"; hn = "www.palm.com";
        if (!CnHnExpectNoMatch(cn, strlen(cn), hn, strlen(hn))) {
            failCount++;
        }

        /*
         *      cn="www.pa*.com"       hn=www.palm.com            no
         */
        cn = "www.pa*.com"; hn = "www.palm.com";
        if (!CnHnExpectNoMatch(cn, strlen(cn), hn, strlen(hn))) {
            failCount++;
        }

        /*
         *      cn="*.*.com"           hn=www.palm.com            no  
         */
        cn = "*.*.com"; hn = "www.palm.com";
        if (!CnHnExpectNoMatch(cn, strlen(cn), hn, strlen(hn))) {
            failCount++;
        }

        /*
         *      cn="w*.p*.com"         hn=www.palm.com            no  
         */
        cn = "w*.p*.com"; hn = "www.palm.com";
        if (!CnHnExpectNoMatch(cn, strlen(cn), hn, strlen(hn))) {
            failCount++;
        }

        /*
         *      cn="*.palm.com"        hn="palm.com"              no  
         */
        cn = "*.palm.com"; hn = "palm.com";
        if (!CnHnExpectNoMatch(cn, strlen(cn), hn, strlen(hn))) {
            failCount++;
        }

        /*
         *      cn="*.palm.com         hn="www.eas.palm.com"      no  
         */
        cn = "*.palm.com"; hn = "www.eas.palm.com";
        if (!CnHnExpectNoMatch(cn, strlen(cn), hn, strlen(hn))) {
            failCount++;
        }

        /*
         *      cn="palm*.com"         hn="palm.com"              no  
         */
        cn = "palm*.com"; hn = "palm.com";
        if (!CnHnExpectNoMatch(cn, strlen(cn), hn, strlen(hn))) {
            failCount++;
        }

        /*
         *      cn="*.tv"              hn="flinstones.tv"         no
         */
        cn = "*.tv"; hn = "flinstones.tv";
        if (!CnHnExpectNoMatch(cn, strlen(cn), hn, strlen(hn))) {
            failCount++;
        }

        /*
         *      cn="f*.com"            hn="flinstones.tv"         no
         */
        cn = "f*.tv"; hn = "flinstones.tv";
        if (!CnHnExpectNoMatch(cn, strlen(cn), hn, strlen(hn))) {
            failCount++;
        }

        /*
         *      cn="www*.palm.com"     hn="www.palm.com"          no
         */
        cn = "www*.palm.com"; hn = "www.palm.com";
        if (!CnHnExpectNoMatch(cn, strlen(cn), hn, strlen(hn))) {
            failCount++;
        }

        /*
         *      cn="www**.palm.com"    hn="www12.palm.com"        no
         */
        cn = "www**.palm.com"; hn = "www12.palm.com";
        if (!CnHnExpectNoMatch(cn, strlen(cn), hn, strlen(hn))) {
            failCount++;
        }

        /*
         *      cn="www.palm.com\0badguy.com"  hn="www.palm.com"   no
         */
        char cnarray[] = "www.palm.com\0badguy.com";
        hn = "www.palm.com";
        if (!CnHnExpectNoMatch(cnarray, sizeof(cnarray) - 1, hn, strlen(hn))) {
            failCount++;
        }

        /*
         *      cn="www*.palm.com"     hn"www12.palm.com"        yes
         */
        cn = "www*.palm.com"; hn = "www12.palm.com";
        if (!CnHnExpectMatch(cn, strlen(cn), hn, strlen(hn))) {
            failCount++;
        }

        /*
         *      cn="www*.eas.palm.com"     hn"www12.eas.palm.com" yes
         */
        cn = "www*.eas.palm.com"; hn = "www12.eas.palm.com";
        if (!CnHnExpectMatch(cn, strlen(cn), hn, strlen(hn))) {
            failCount++;
        }

        /*
         *      cn="*.palm.com"        hn="www.palm.com"          yes
         */
        cn = "*.palm.com"; hn = "www.palm.com";
        if (!CnHnExpectMatch(cn, strlen(cn), hn, strlen(hn))) {
            failCount++;
        }

        /*
         *      cn="*.eas.palm.com"    hn="www.eas.palm.com"      yes
         */
        cn = "*.eas.palm.com"; hn = "www.eas.palm.com";
        if (!CnHnExpectMatch(cn, strlen(cn), hn, strlen(hn))) {
            failCount++;
        }

        /*
         *      cn="www.palm.com"      hn="WWW.Palm.Com"          yes
         */
        cn = "www.palm.com"; hn = "WWW.Palm.Com";
        if (!CnHnExpectMatch(cn, strlen(cn), hn, strlen(hn))) {
            failCount++;
        }


        /*
         *      cn="WWW.Palm.Com"      hn="www.palm.com"          yes
         */
        cn = "WWW.Palm.Com"; hn = "www.palm.com";
        if (!CnHnExpectMatch(cn, strlen(cn), hn, strlen(hn))) {
            failCount++;
        }


        printf("\n%s: SUMMARY: %s: %d failures detected.\n",
               args_[0], failCount ? "FAIL" : "PASS", failCount);
        return !failCount;
    }//AutoTest



    bool CnHnExpectMatch(const char* const cn, unsigned const cnLen,
                         const char* const hn, unsigned const hnLen)
    {
        bool matched;
        bool const apiSuccess = CnHnEq(cn, cnLen, hn, hnLen,
                                       true/*verbose*/, &matched);
        if (apiSuccess) {
            if (matched) {
                printf("%s: PASS: expected match; got match\n", args_[0]);
                return true;
            }
            else {
                printf("%s: FAIL: expected match; got no match\n", args_[0]);
            }
        }
        else {
            printf("%s: FAIL: expected API success; got API failure\n", args_[0]);
        }

        return false;
    }//CnHnExpectMatch


    bool CnHnExpectNoMatch(const char* const cn, unsigned const cnLen,
                           const char* const hn, unsigned const hnLen)
    {
        bool matched;
        bool const apiSuccess = CnHnEq(cn, cnLen, hn, hnLen,
                                       true/*verbose*/, &matched);
        if (apiSuccess) {
            if (!matched) {
                printf("%s: PASS: expected no match; got no match\n", args_[0]);
                return true;
            }
            else {
                printf("%s: FAIL: expected no match; got match\n", args_[0]);
            }
        }
        else {
            printf("%s: FAIL: expected API success; got API failure\n", args_[0]);
        }

        return false;
    }//CnHnExpectNoMatch


    /**
     * CnHnEq(): Wrapper around PmSockX509CheckCertHostNameMatch(); 
     * optioinally, outputs parameters and status to stdout (if 
     * verbose arg is TRUE) 
     * 
     * @param cnStr 
     * @param cnStrLen 
     * @param hnStr 
     * @param hnStrLen 
     * @param verbose 
     * @param pMatched Non-NULL pointer to variable for returning 
     *                 status the match; undefined on failure
     * 
     * @return bool TRUE on success (does not reflect match status),
     *         FALSE on failure
     */
    bool CnHnEq(const char* const cnStr, unsigned const cnStrLen,
                const char* const hnStr, unsigned const hnStrLen,
                bool const verbose, bool* const pMatched)
    {
        if (verbose) {
            printf("%s: Comparing: cn=", args_[0]);

            if (cnStr) {
                putchar('"');

                /// @todo need to replace with proper hex-dump common function
                for (unsigned i=0; i < cnStrLen; i++) {
                    if ('\0' == cnStr[i]) {
                        printf("\\0");
                    }
                    else if ('\\' == cnStr[i]) {
                        printf("\\\\");
                    }
                    else {
                        putchar(cnStr[i]);
                    }
                }

                putchar('"');
            }
            else {
                printf("<NULL>");
            }
    
    
            printf(" versus hn=");
            if (hnStr) {
                putchar('"');

                for (unsigned i=0; i < hnStrLen; i++) {
                    if ('\0' == hnStr[i]) {
                        printf("\\0");
                    }
                    else if ('\\' == hnStr[i]) {
                        printf("\\\\");
                    }
                    else {
                        putchar(hnStr[i]);
                    }
                }
                putchar('"');
            }
            else {
                printf("<NULL>");
            }

            printf("\n");
        }


        PslError const pslerr = PmSockX509CheckCertHostNameMatch(
            cnStr, cnStrLen,
            hnStr, hnStrLen,
            (PmSockX509HostnameMatchOpts)0,
            pMatched);

        if (pslerr) {
            UTIL_PRINT_ERROR(
                "%s: ERROR: PmSockX509CheckCertHostNameMatch() failed: PslError=%d (%s)",
                args_[0], pslerr, PmSockErrStringFromError(pslerr));
            return false;
        }

        if (verbose) {
            printf("%s: result=%s\n", args_[0], *pMatched ? "matched" : "not matched");
        }

        return true;
    }//CnHnEq


    static bool Register()
    {
        MyCmdShellHost::CmdRegInfo info;
        info.pName = kTestCmdName;
        info.pHelp =
            "Tests PmSockX509CheckCertHostNameMatch(); " \
            "args: " \
            "[<cert-name> <hostname>] " \
            "\n\n" \
            "      Without any args: performs automatic validation with pre-set\n" \
            "      values.  Otherwise, expects exactly two args: a cert-name\n" \
            "      string (e.g., *.palm.com or www*.palm.com, www.palm.com, etc.),\n" \
            "      followed by a host-name string (e.g., www.palm.com). The test\n" \
            "      is performed per accepted practices as described in\n" \
            "      http://support.microsoft.com/kb/258858.\n" \
            "\n";

        info.handlerCb = &Handler;

        RegisterCmdHandler(info);
        return true;
    }

    static bool Handler(const MyCmdShell::ArgsType &args)
    {
        TestCmdCertnameHostnameMatch   handler(args);
        return handler.Execute();
    }

private:
    const MyCmdShell::ArgsType& args_;

    static const bool           registered_;
}; // class TestCmdCertnameHostnameMatch

const bool TestCmdCertnameHostnameMatch::registered_ = Register();

} /// End of namespace

/**@}*/
