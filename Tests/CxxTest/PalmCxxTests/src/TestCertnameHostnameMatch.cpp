/*
 * TestCertnameHostnameMatch.cpp
 *
 */


#define VERBOSE


#include <stdio.h>
#include <string.h>


#include "TestCertnameHostnameMatch.h"
#include "palmsockopensslutils.h"
#include "CommonUtils.h"
#include "cxxtest/TestSuite.h"


TestCertnameHostnameMatch::TestCertnameHostnameMatch()
:myName_("TestCertnameHostnameMatch")
{
}


TestCertnameHostnameMatch::~TestCertnameHostnameMatch() {
}


struct Str {
	const char * cnStr;
	unsigned cnStrLen;
	const char * hnStr;
	unsigned hnStrLen;
};


static Str stringsExpectingAPIFailure[] = {
	//cnStr							len		hnStr							  len
	 {NULL, 							1, "palm.com", 							8}
	,{"*.palm.com", 					0, "www.palm.com", 						12}
	,{"palm.com",						8,	NULL, 								1}
	,{"www.palm.com",					12, "www.palm.com",						0}
};


//Creates a Str struct from two strings
#define MAKE_Str(cnStr, hnStr) {cnStr, strlen(cnStr), hnStr, strlen(hnStr)}

static Str stringsExpectingNoMatch[] = {
	//cn="*"                 		hn=<any>                   no
	 MAKE_Str("*",					"com")
    //cn="co*"               		hn=<any>                   no
	,MAKE_Str("co*",				"com")
    //cn="*om"              		hn=<any>                   no
	,MAKE_Str("*om",				"com")
    //cn="*alm.com"         		 hn=<any>                  no
	,MAKE_Str("*om",				"www.palm.com")
    //cn="p*lm.com"         		 hn=<any>                  no
    ,MAKE_Str("p*lm.com",			"palm.com")
	 //cn="www.*.com"         		 hn=www.palm.com            no
    ,MAKE_Str("www.*.com",			"www.palm.com")
     //*      cn="www.pa*.com"       hn=www.palm.com            no
    ,MAKE_Str("www.pa*.com",		"www.palm.com")
     //*      cn="*.*.com"           hn=www.palm.com            no
    ,MAKE_Str("*.*.com",			"www.palm.com")
     //*      cn="w*.p*.com"         hn=www.palm.com            no
    ,MAKE_Str("w*.p*.com",			"www.palm.com")
     //*      cn="*.palm.com"        hn="palm.com"              no
    ,MAKE_Str("*.palm.com",			"palm.com")
     //*      cn="*.palm.com         hn="www.eas.palm.com"      no
    ,MAKE_Str("*.palm.com",			"www.eas.palm.com")
     //*      cn="palm*.com"         hn="palm.com"              no
    ,MAKE_Str("palm*.com",			"palm.com")
     //*      cn="*.tv"              hn="flinstones.tv"         no
    ,MAKE_Str("*.tv",				"flinstones.tv")
     //*      cn="f*.com"            hn="flinstones.tv"         no
    ,MAKE_Str("f*.tv",				"flinstones.tv")
     //*      cn="www*.palm.com"     hn="www.palm.com"          no
    ,MAKE_Str("www*.palm.com",		"www.palm.com")
     //*      cn="www**.palm.com"    hn="www12.palm.com"        no
    ,MAKE_Str("www**.palm.com",		"www12.palm.com")
     //*      cn="www.palm.com\0badguy.com"  hn="www.palm.com"  no
	 ,{"www.palm.com\0badguy.com", 23, "www.palm.com", 12}
};


static Str stringsExpectingMatch[] = {
	//*      cn="www*.palm.com"     hn"www12.palm.com"        yes
	 MAKE_Str("www*.palm.com",		"www12.palm.com")
	//*      cn="www*.eas.palm.com"     hn"www12.eas.palm.com" yes
	,MAKE_Str("www*.eas.palm.com",	"www12.eas.palm.com")
	//*      cn="*.palm.com"        hn="www.palm.com"          yes
	,MAKE_Str("*.palm.com", 		"www.palm.com")
	// *      cn="*.eas.palm.com"    hn="www.eas.palm.com"      yes
	,MAKE_Str("*.eas.palm.com",		"www.eas.palm.com")
	//*      cn="www.palm.com"      hn="WWW.Palm.Com"          yes
	,MAKE_Str("www.palm.com",		"WWW.Palm.Com")
	//*      cn="WWW.Palm.Com"      hn="www.palm.com"          yes
	,MAKE_Str("WWW.Palm.Com",		"www.palm.com")
};


void TestCertnameHostnameMatch::Execute() {
    int     failCount = 0;
    bool    matched;

    // Expect API failure
    const unsigned apiFailureNum = sizeof(stringsExpectingAPIFailure)/sizeof(Str);
    for(unsigned i=0; i<apiFailureNum; i++) {
    	Str& str=stringsExpectingAPIFailure[i];

		bool apiSuccess = CnHnEq(
			str.cnStr, str.cnStrLen,
			str.hnStr, str.hnStrLen,
			&matched);

		TS_ASSERT(!apiSuccess);
		if (!apiSuccess) {
			PRINT_LINE("%s: PASS: expected API failure; got API failure\n", myName_);

		} else {
			failCount++;
			PRINT_LINE("%s: FAIL: expected API failure; got API success\n", myName_);
		}
    }

    // Expect no match
    const unsigned noMatchNum = sizeof(stringsExpectingNoMatch)/sizeof(Str);
    for(unsigned int i=0; i<noMatchNum; i++) {
    	Str& str=stringsExpectingNoMatch[i];

        bool matched;
        bool const apiSuccess = CnHnEq(
        		str.cnStr, str.cnStrLen,
        		str.hnStr, str.hnStrLen,
        		&matched);

        TS_ASSERT(apiSuccess && !matched);
        if (apiSuccess) {
            if (!matched) {
            	PRINT_LINE("%s: PASS: expected no match; got no match\n", myName_);
            } else {
            	PRINT_LINE("%s: FAIL: expected no match; got match\n", myName_);
            	failCount++;
            }

        } else {
        	PRINT_LINE("%s: FAIL: expected API success; got API failure\n", myName_);
        	failCount++;
        }
    }

    // Expect match
    const unsigned matchNum = sizeof(stringsExpectingMatch)/sizeof(Str);
    for(unsigned int i=0; i<matchNum; i++) {
    	Str& str=stringsExpectingMatch[i];

        bool matched;
        bool const apiSuccess = CnHnEq(
        		str.cnStr, str.cnStrLen,
        		str.hnStr, str.hnStrLen,
        		&matched);

        TS_ASSERT(apiSuccess && matched);
        if (apiSuccess) {
            if (matched) {
            	PRINT_LINE("%s: PASS: expected match; got match\n", myName_);
            } else {
            	PRINT_LINE("%s: FAIL: expected match; got no match\n", myName_);
            	failCount++;
            }
        } else {
        	PRINT_LINE("%s: FAIL: expected API success; got API failure\n", myName_);
        	failCount++;
        }
    }

    PRINT_LINE("\n%s: SUMMARY: %s: %d failures detected.",
    		myName_, failCount ? "FAIL" : "PASS", failCount);
}


bool TestCertnameHostnameMatch::CnHnEq(const char* const cnStr, unsigned const cnStrLen,
            const char* const hnStr, unsigned const hnStrLen,
            bool* const pMatched)
{
	PRINT("%s: Comparing: cn=", myName_);

	if (cnStr) {
		PRINT("\"");

		//code fragment borrowed from pslTestBlade
		//@todo need to replace with proper hex-dump common function
		for (unsigned i=0; i < cnStrLen; i++) {
			if ('\0' == cnStr[i]) {
				PRINT("\\0");
			}
			else if ('\\' == cnStr[i]) {
				PRINT("\\\\");
			}
			else {
				PRINT("%c", cnStr[i]);
			}
		}
		PRINT("\"");

	} else {
		PRINT("<NULL>");
	}

	PRINT(" versus hn=");
	if (hnStr) {
		PRINT("\"");

		for (unsigned i=0; i < hnStrLen; i++) {
			if ('\0' == hnStr[i]) {
				PRINT("\\0");
			}
			else if ('\\' == hnStr[i]) {
				PRINT("\\\\");
			}
			else {
				PRINT("%c", hnStr[i]);
			}
		}
		PRINT("\"");

	} else {
		PRINT("<NULL>");
	}

	PRINT("\n");


    PslError const pslerr = PmSockX509CheckCertHostNameMatch(
        cnStr, cnStrLen,
        hnStr, hnStrLen,
        (PmSockX509HostnameMatchOpts)0,
        pMatched);

    bool apiSuccess;
    if (pslerr) {
        PRINT_LINE(
            "%s: ERROR: PmSockX509CheckCertHostNameMatch() failed: PslError=%d (%s)",
            myName_, pslerr, PmSockErrStringFromError(pslerr));
        apiSuccess = false;

    } else {
    	PRINT("%s: result=%s\n", myName_, *pMatched ? "matched" : "not matched");
    	apiSuccess=true;
    }

    return apiSuccess;
}














