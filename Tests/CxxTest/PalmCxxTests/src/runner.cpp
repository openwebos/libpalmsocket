/* Generated file, do not edit */

#ifndef CXXTEST_RUNNING
#define CXXTEST_RUNNING
#endif

#define _CXXTEST_HAVE_STD
#include <cxxtest/TestListener.h>
#include <cxxtest/TestTracker.h>
#include <cxxtest/TestRunner.h>
#include <cxxtest/RealDescriptions.h>
#include <cxxtest/ErrorPrinter.h>

int main() {
 return CxxTest::ErrorPrinter().run();
}
#include "PalmTestSuite.h"

static PalmTestSuite suite_PalmTestSuite;

static CxxTest::List Tests_PalmTestSuite = { 0, 0 };
CxxTest::StaticSuiteDescription suiteDescription_PalmTestSuite( "PalmTestSuite.h", 17, "PalmTestSuite", suite_PalmTestSuite, Tests_PalmTestSuite );

static class TestDescription_PalmTestSuite_testBasicHalfDuplexPlainToServer : public CxxTest::RealTestDescription {
public:
 TestDescription_PalmTestSuite_testBasicHalfDuplexPlainToServer() : CxxTest::RealTestDescription( Tests_PalmTestSuite, suiteDescription_PalmTestSuite, 26, "testBasicHalfDuplexPlainToServer" ) {}
 void runTest() { suite_PalmTestSuite.testBasicHalfDuplexPlainToServer(); }
} testDescription_PalmTestSuite_testBasicHalfDuplexPlainToServer;

static class TestDescription_PalmTestSuite_testBasicHalfDuplexPlainToClient : public CxxTest::RealTestDescription {
public:
 TestDescription_PalmTestSuite_testBasicHalfDuplexPlainToClient() : CxxTest::RealTestDescription( Tests_PalmTestSuite, suiteDescription_PalmTestSuite, 33, "testBasicHalfDuplexPlainToClient" ) {}
 void runTest() { suite_PalmTestSuite.testBasicHalfDuplexPlainToClient(); }
} testDescription_PalmTestSuite_testBasicHalfDuplexPlainToClient;

static class TestDescription_PalmTestSuite_testBasicFullDuplexPlainHostnameBased : public CxxTest::RealTestDescription {
public:
 TestDescription_PalmTestSuite_testBasicFullDuplexPlainHostnameBased() : CxxTest::RealTestDescription( Tests_PalmTestSuite, suiteDescription_PalmTestSuite, 41, "testBasicFullDuplexPlainHostnameBased" ) {}
 void runTest() { suite_PalmTestSuite.testBasicFullDuplexPlainHostnameBased(); }
} testDescription_PalmTestSuite_testBasicFullDuplexPlainHostnameBased;

static class TestDescription_PalmTestSuite_testBasicFullDuplexPlainIPAddressBased : public CxxTest::RealTestDescription {
public:
 TestDescription_PalmTestSuite_testBasicFullDuplexPlainIPAddressBased() : CxxTest::RealTestDescription( Tests_PalmTestSuite, suiteDescription_PalmTestSuite, 49, "testBasicFullDuplexPlainIPAddressBased" ) {}
 void runTest() { suite_PalmTestSuite.testBasicFullDuplexPlainIPAddressBased(); }
} testDescription_PalmTestSuite_testBasicFullDuplexPlainIPAddressBased;

static class TestDescription_PalmTestSuite_testBasicFullDuplexPlainSingleWatch : public CxxTest::RealTestDescription {
public:
 TestDescription_PalmTestSuite_testBasicFullDuplexPlainSingleWatch() : CxxTest::RealTestDescription( Tests_PalmTestSuite, suiteDescription_PalmTestSuite, 58, "testBasicFullDuplexPlainSingleWatch" ) {}
 void runTest() { suite_PalmTestSuite.testBasicFullDuplexPlainSingleWatch(); }
} testDescription_PalmTestSuite_testBasicFullDuplexPlainSingleWatch;

static class TestDescription_PalmTestSuite_testBasicFullDuplexSSLv3 : public CxxTest::RealTestDescription {
public:
 TestDescription_PalmTestSuite_testBasicFullDuplexSSLv3() : CxxTest::RealTestDescription( Tests_PalmTestSuite, suiteDescription_PalmTestSuite, 66, "testBasicFullDuplexSSLv3" ) {}
 void runTest() { suite_PalmTestSuite.testBasicFullDuplexSSLv3(); }
} testDescription_PalmTestSuite_testBasicFullDuplexSSLv3;

static class TestDescription_PalmTestSuite_testBasicFullDuplexTLSv1 : public CxxTest::RealTestDescription {
public:
 TestDescription_PalmTestSuite_testBasicFullDuplexTLSv1() : CxxTest::RealTestDescription( Tests_PalmTestSuite, suiteDescription_PalmTestSuite, 74, "testBasicFullDuplexTLSv1" ) {}
 void runTest() { suite_PalmTestSuite.testBasicFullDuplexTLSv1(); }
} testDescription_PalmTestSuite_testBasicFullDuplexTLSv1;

static class TestDescription_PalmTestSuite_testDeferredSSL : public CxxTest::RealTestDescription {
public:
 TestDescription_PalmTestSuite_testDeferredSSL() : CxxTest::RealTestDescription( Tests_PalmTestSuite, suiteDescription_PalmTestSuite, 89, "testDeferredSSL" ) {}
 void runTest() { suite_PalmTestSuite.testDeferredSSL(); }
} testDescription_PalmTestSuite_testDeferredSSL;

static class TestDescription_PalmTestSuite_testBasicHalfDuplexSSLToServer : public CxxTest::RealTestDescription {
public:
 TestDescription_PalmTestSuite_testBasicHalfDuplexSSLToServer() : CxxTest::RealTestDescription( Tests_PalmTestSuite, suiteDescription_PalmTestSuite, 97, "testBasicHalfDuplexSSLToServer" ) {}
 void runTest() { suite_PalmTestSuite.testBasicHalfDuplexSSLToServer(); }
} testDescription_PalmTestSuite_testBasicHalfDuplexSSLToServer;

static class TestDescription_PalmTestSuite_testBasicHalfDuplesSSLToClient : public CxxTest::RealTestDescription {
public:
 TestDescription_PalmTestSuite_testBasicHalfDuplesSSLToClient() : CxxTest::RealTestDescription( Tests_PalmTestSuite, suiteDescription_PalmTestSuite, 105, "testBasicHalfDuplesSSLToClient" ) {}
 void runTest() { suite_PalmTestSuite.testBasicHalfDuplesSSLToClient(); }
} testDescription_PalmTestSuite_testBasicHalfDuplesSSLToClient;

static class TestDescription_PalmTestSuite_testBasicCertnameHostnameMatch : public CxxTest::RealTestDescription {
public:
 TestDescription_PalmTestSuite_testBasicCertnameHostnameMatch() : CxxTest::RealTestDescription( Tests_PalmTestSuite, suiteDescription_PalmTestSuite, 112, "testBasicCertnameHostnameMatch" ) {}
 void runTest() { suite_PalmTestSuite.testBasicCertnameHostnameMatch(); }
} testDescription_PalmTestSuite_testBasicCertnameHostnameMatch;

static class TestDescription_PalmTestSuite_testCertVerifyHostnameByCommonName : public CxxTest::RealTestDescription {
public:
 TestDescription_PalmTestSuite_testCertVerifyHostnameByCommonName() : CxxTest::RealTestDescription( Tests_PalmTestSuite, suiteDescription_PalmTestSuite, 126, "testCertVerifyHostnameByCommonName" ) {}
 void runTest() { suite_PalmTestSuite.testCertVerifyHostnameByCommonName(); }
} testDescription_PalmTestSuite_testCertVerifyHostnameByCommonName;

static class TestDescription_PalmTestSuite_testCertVerifyHostNameByCommonNameNeg : public CxxTest::RealTestDescription {
public:
 TestDescription_PalmTestSuite_testCertVerifyHostNameByCommonNameNeg() : CxxTest::RealTestDescription( Tests_PalmTestSuite, suiteDescription_PalmTestSuite, 137, "testCertVerifyHostNameByCommonNameNeg" ) {}
 void runTest() { suite_PalmTestSuite.testCertVerifyHostNameByCommonNameNeg(); }
} testDescription_PalmTestSuite_testCertVerifyHostNameByCommonNameNeg;

static class TestDescription_PalmTestSuite_testCertVerifyAddressByCommonName : public CxxTest::RealTestDescription {
public:
 TestDescription_PalmTestSuite_testCertVerifyAddressByCommonName() : CxxTest::RealTestDescription( Tests_PalmTestSuite, suiteDescription_PalmTestSuite, 150, "testCertVerifyAddressByCommonName" ) {}
 void runTest() { suite_PalmTestSuite.testCertVerifyAddressByCommonName(); }
} testDescription_PalmTestSuite_testCertVerifyAddressByCommonName;

static class TestDescription_PalmTestSuite_testCertVerifyAddressByCommonNameNeg : public CxxTest::RealTestDescription {
public:
 TestDescription_PalmTestSuite_testCertVerifyAddressByCommonNameNeg() : CxxTest::RealTestDescription( Tests_PalmTestSuite, suiteDescription_PalmTestSuite, 161, "testCertVerifyAddressByCommonNameNeg" ) {}
 void runTest() { suite_PalmTestSuite.testCertVerifyAddressByCommonNameNeg(); }
} testDescription_PalmTestSuite_testCertVerifyAddressByCommonNameNeg;

static class TestDescription_PalmTestSuite_testCertVerifyHostnameBySubjaltName : public CxxTest::RealTestDescription {
public:
 TestDescription_PalmTestSuite_testCertVerifyHostnameBySubjaltName() : CxxTest::RealTestDescription( Tests_PalmTestSuite, suiteDescription_PalmTestSuite, 175, "testCertVerifyHostnameBySubjaltName" ) {}
 void runTest() { suite_PalmTestSuite.testCertVerifyHostnameBySubjaltName(); }
} testDescription_PalmTestSuite_testCertVerifyHostnameBySubjaltName;

static class TestDescription_PalmTestSuite_testCertVerifyHostnameBySubjaltNameNeg : public CxxTest::RealTestDescription {
public:
 TestDescription_PalmTestSuite_testCertVerifyHostnameBySubjaltNameNeg() : CxxTest::RealTestDescription( Tests_PalmTestSuite, suiteDescription_PalmTestSuite, 190, "testCertVerifyHostnameBySubjaltNameNeg" ) {}
 void runTest() { suite_PalmTestSuite.testCertVerifyHostnameBySubjaltNameNeg(); }
} testDescription_PalmTestSuite_testCertVerifyHostnameBySubjaltNameNeg;

static class TestDescription_PalmTestSuite_testCertVerifyAddressBySubjaltName : public CxxTest::RealTestDescription {
public:
 TestDescription_PalmTestSuite_testCertVerifyAddressBySubjaltName() : CxxTest::RealTestDescription( Tests_PalmTestSuite, suiteDescription_PalmTestSuite, 203, "testCertVerifyAddressBySubjaltName" ) {}
 void runTest() { suite_PalmTestSuite.testCertVerifyAddressBySubjaltName(); }
} testDescription_PalmTestSuite_testCertVerifyAddressBySubjaltName;

static class TestDescription_PalmTestSuite_testCertVerifyAddressBySubjaltNameNeg : public CxxTest::RealTestDescription {
public:
 TestDescription_PalmTestSuite_testCertVerifyAddressBySubjaltNameNeg() : CxxTest::RealTestDescription( Tests_PalmTestSuite, suiteDescription_PalmTestSuite, 214, "testCertVerifyAddressBySubjaltNameNeg" ) {}
 void runTest() { suite_PalmTestSuite.testCertVerifyAddressBySubjaltNameNeg(); }
} testDescription_PalmTestSuite_testCertVerifyAddressBySubjaltNameNeg;

static class TestDescription_PalmTestSuite_testCertVerifyInstalledLeafFallback : public CxxTest::RealTestDescription {
public:
 TestDescription_PalmTestSuite_testCertVerifyInstalledLeafFallback() : CxxTest::RealTestDescription( Tests_PalmTestSuite, suiteDescription_PalmTestSuite, 226, "testCertVerifyInstalledLeafFallback" ) {}
 void runTest() { suite_PalmTestSuite.testCertVerifyInstalledLeafFallback(); }
} testDescription_PalmTestSuite_testCertVerifyInstalledLeafFallback;

static class TestDescription_PalmTestSuite_testCertVerifyInstalledLeafFallbackNeg : public CxxTest::RealTestDescription {
public:
 TestDescription_PalmTestSuite_testCertVerifyInstalledLeafFallbackNeg() : CxxTest::RealTestDescription( Tests_PalmTestSuite, suiteDescription_PalmTestSuite, 238, "testCertVerifyInstalledLeafFallbackNeg" ) {}
 void runTest() { suite_PalmTestSuite.testCertVerifyInstalledLeafFallbackNeg(); }
} testDescription_PalmTestSuite_testCertVerifyInstalledLeafFallbackNeg;

#include <cxxtest/Root.cpp>
