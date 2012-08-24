/*
 * PalmTestSuite.cpp
 *
 */


#define VERBOSE


#include <iostream>
#include <glib.h>
#include "palmsockopensslutils.h"
#include "palmsockerror.h"
#include <unistd.h>
#include <assert.h>


#include "CommonUtils.h"
#include "PalmTestSuite.h"
#include <cxxtest/TestSuite.h>
#include "ServerSetUp.h"
#include "ClientSetUp.h"
#include "ClientPeerHalfDuplexPlainOut.h"
#include "ServerPeerHalfDuplexPlainIn.h"
#include "Creator.h"
#include "ServerPeerHalfDuplexPlainOut.h"
#include "ClientPeerHalfDuplexPlainIn.h"
#include "ConfigFile.h"
#include "PeerFullDuplexPlain.h"
#include "PeerFullDuplexPlainSingleWatch.h"
#include "ClientPeerFullDuplexSSL.h"
#include "ServerPeerFullDuplexSSL.h"
#include "ServerPeerDeferredSSL.h"
#include "ClientPeerDeferredSSL.h"
#include "PipeFd.h"
#include "ServerPeerHalfDuplexSSLIn.h"
#include "ClientPeerHalfDuplexSSLOut.h"
#include "ServerPeerHalfDuplexSSLOut.h"
#include "ClientPeerHalfDuplexSSLIn.h"
#include "TestCertnameHostnameMatch.h"
#include "ClientPeerShouldFailSSL.h"
#include "ServerPeerShouldFailSSL.h"
#include "ClientPeerLeafFallbackNeg.h"


using namespace std;


PalmTestSuite::PalmTestSuite() {
	FN_PRINT_LINE("PalmTestSuite: init gthread ");
	g_thread_init(NULL);
}


template<
	PeerBase* CreateServerPeer(PeerBaseParams& params),
	PeerBase* CreateClientPeer(PeerBaseParams& params)
>
void runTest(const char * configGroupName, unsigned int testNr, const char * testName=NULL) {
	Config config = ConfigFile::GetInstance().GetConfigForGroup(configGroupName);

	if (config.enabled_) {
		PipeFd pipeFd;

		PRINT_LINE(" ");
		PRINT_LINE(" ");
		PRINT_LINE(" ");
		PRINT_LINE("------------------------ Starting test No:%d named: %s -------------------", testNr, testName ? testName : configGroupName);


		ServerSetUp server(CreateServerPeer, config, pipeFd);
		GThread *serverThread = server.Start();

		ClientSetUp client(CreateClientPeer, config, pipeFd);
		GThread *clientThread = client.Start();

		g_thread_join(serverThread);
		FN_PRINT_LINE("serverThread joined ----------------------");

		g_thread_join(clientThread);
		FN_PRINT_LINE("clientThread joined ----------------------");
	}
}


//1
void PalmTestSuite::testBasicHalfDuplexPlainToServer() {
	runTest<
		CreatePeer<ServerPeerHalfDuplexPlainIn>,
		CreatePeer<ClientPeerHalfDuplexPlainOut>
	>(ConfigFile::Group_HalfDuplexPlainToServer, 1);
}


//2
void PalmTestSuite::testBasicHalfDuplexPlainToClient() {
	runTest<
		CreatePeer<ServerPeerHalfDuplexPlainOut>,
		CreatePeer<ClientPeerHalfDuplexPlainIn>
	>(ConfigFile::Group_HalfDuplexPlainToClient, 2);
}


//3
void PalmTestSuite::testBasicFullDuplexPlainHostnameBased() {
	runTest<
		CreatePeer<PeerFullDuplexPlain>,
		CreatePeer<PeerFullDuplexPlain>
	>(ConfigFile::Group_FullDuplexPlainHostnameBased, 3);
}


//4
void PalmTestSuite::testBasicFullDuplexPlainIPAddressBased() {
	runTest<
		CreatePeer<PeerFullDuplexPlain>,
		CreatePeer<PeerFullDuplexPlain>
	>(ConfigFile::Group_FullDuplexPlainIPAddressBased, 4);
}


//5
void PalmTestSuite::testBasicFullDuplexPlainSingleWatch() {
	runTest<
		CreatePeer<PeerFullDuplexPlain>,
		CreatePeer<PeerFullDuplexPlainSingleWatch>
	>(ConfigFile::Group_FullDuplexPlainSingleWatch, 5);
}


//6
void PalmTestSuite::testBasicFullDuplexSSLv3() {
	//ssl init
    PslError pslError = PmSockOpensslInit(kPmSockOpensslInitType_DEFAULT);
    TS_ASSERT(!pslError);
    if (pslError) return;

	runTest<
		CreatePeer<ServerPeerFullDuplexSSL>,
		CreatePeer_SSLv3<ClientPeerFullDuplexSSL>
	>(ConfigFile::Group_FullDuplexSSL, 6, "BasicFullDuplexSSLv3");

	//ssl shutdown
	pslError = PmSockOpensslUninit();
	TS_ASSERT(!pslError);
}


//7
void PalmTestSuite::testBasicFullDuplexTLSv1() {
	//ssl init
    PslError pslError = PmSockOpensslInit(kPmSockOpensslInitType_DEFAULT);
    TS_ASSERT(!pslError);
    if (pslError) return;

	runTest<
		CreatePeer<ServerPeerFullDuplexSSL>,
		CreatePeer_TLSv1<ClientPeerFullDuplexSSL>
	>(ConfigFile::Group_FullDuplexSSL, 7, "BasicFullDuplexTLSv1");

	//ssl shutdown
	pslError = PmSockOpensslUninit();
	TS_ASSERT(!pslError);
}


//8
void PalmTestSuite::testDeferredSSL() {
	//ssl init
    PslError pslError = PmSockOpensslInit(kPmSockOpensslInitType_DEFAULT);
    TS_ASSERT(!pslError);
    if (pslError) return;

    runTest<
		&CreatePeer<ServerPeerDeferredSSL>,
		&CreatePeer<ClientPeerDeferredSSL>
    > (ConfigFile::Group_DeferredSSL, 8);

    //ssl shutdown
	pslError = PmSockOpensslUninit();
	TS_ASSERT(!pslError);
}


//9
void PalmTestSuite::testBasicHalfDuplexSSLToServer() {
	//ssl init
    PslError pslError = PmSockOpensslInit(kPmSockOpensslInitType_DEFAULT);
    TS_ASSERT(!pslError);
    if (pslError) return;

    runTest<
		&CreatePeer<ServerPeerHalfDuplexSSLIn>,
		&CreatePeer_SSLv3<ClientPeerHalfDuplexSSLOut>
    >(ConfigFile::Group_HalfDuplexSSL, 9, "BasicHalfDuplexSSLToServer");

    //ssl shutdown
	pslError = PmSockOpensslUninit();
	TS_ASSERT(!pslError);
}


//10
void PalmTestSuite::testBasicHalfDuplesSSLToClient() {
	//ssl init
    PslError pslError = PmSockOpensslInit(kPmSockOpensslInitType_DEFAULT);
    TS_ASSERT(!pslError);
    if (pslError) return;

    runTest<
		&CreatePeer<ServerPeerHalfDuplexSSLOut>,
		&CreatePeer_SSLv3<ClientPeerHalfDuplexSSLIn>
    >(ConfigFile::Group_HalfDuplexSSL, 10, "BasicHalfDuplexSSLToClient");

    //ssl shutdown
	pslError = PmSockOpensslUninit();
	TS_ASSERT(!pslError);
}


//11
void PalmTestSuite::testBasicCertnameHostnameMatch() {
	Config config = ConfigFile::GetInstance().GetConfigForGroup(ConfigFile::Group_BasicCertnameHostnameMatch);

	if (config.enabled_) {
		PRINT_LINE(" ");
		PRINT_LINE(" ");
		PRINT_LINE(" ");
		PRINT_LINE("------------------------ Starting test No:11 named: BasicCertnameHostnameMatch -------------------");

		TestCertnameHostnameMatch testMatch;
		testMatch.Execute();
	}
}


//12
void PalmTestSuite::testCertVerifyHostnameByCommonName() {
	//ssl init
    PslError pslError = PmSockOpensslInit(kPmSockOpensslInitType_DEFAULT);
    TS_ASSERT(!pslError);
    if (pslError) return;

    runTest<
		&CreatePeer<ServerPeerFullDuplexSSL>, //CheckHostname has no effect for serverpeer (PmSockAcceptCrypto)
		&CreatePeer_CheckHostname<ClientPeerFullDuplexSSL>
    > (ConfigFile::Group_CertVerifyHostnameByCommonName, 12);

    //ssl shutdown
	pslError = PmSockOpensslUninit();
	TS_ASSERT(!pslError);
}


//13
void PalmTestSuite::testCertVerifyHostNameByCommonNameNeg() {
	//ssl init
    PslError pslError = PmSockOpensslInit(kPmSockOpensslInitType_DEFAULT);
    TS_ASSERT(!pslError);
    if (pslError) return;

    runTest<
		&CreatePeer<ServerPeerShouldFailSSL>,  //CheckHostname has no effect for serverpeer (PmSockAcceptCrypto)
		&CreatePeer_CheckHostname<ClientPeerShouldFailSSL>
    > (ConfigFile::Group_CertVerifyHostnameByCommonNameNeg, 13);

    //ssl shutdown
	pslError = PmSockOpensslUninit();
	TS_ASSERT(!pslError);
}


//14
void PalmTestSuite::testCertVerifyAddressByCommonName() {
	//ssl init
    PslError pslError = PmSockOpensslInit(kPmSockOpensslInitType_DEFAULT);
    TS_ASSERT(!pslError);
    if (pslError) return;

    runTest<
		&CreatePeer<ServerPeerFullDuplexSSL>,
		&CreatePeer_CheckHostname<ClientPeerFullDuplexSSL>
    >(ConfigFile::Group_CertVerifyAddressByCommonName, 14);

    //ssl shutdown
	pslError = PmSockOpensslUninit();
	TS_ASSERT(!pslError);
}


//15
void PalmTestSuite::testCertVerifyAddressByCommonNameNeg() {
	//ssl init
    PslError pslError = PmSockOpensslInit(kPmSockOpensslInitType_DEFAULT);
    TS_ASSERT(!pslError);
    if (pslError) return;

    runTest<
    	&CreatePeer<ServerPeerShouldFailSSL>,  //CheckHostname has no effect for serverpeer (PmSockAcceptCrypto)
    	&CreatePeer_CheckHostname<ClientPeerShouldFailSSL>
    >(ConfigFile::Group_CertVerifyAddressByCommonNameNeg, 15);

    //ssl shutdown
	pslError = PmSockOpensslUninit();
	TS_ASSERT(!pslError);
}


//16
void PalmTestSuite::testCertVerifyHostnameBySubjaltName() {
	//ssl init
    PslError pslError = PmSockOpensslInit(kPmSockOpensslInitType_DEFAULT);
    TS_ASSERT(!pslError);
    if (pslError) return;

    runTest<
    	&CreatePeer<ServerPeerFullDuplexSSL>,  //CheckHostname has no effect for serverpeer (PmSockAcceptCrypto)
    	&CreatePeer_CheckHostname<ClientPeerFullDuplexSSL>
    >(ConfigFile::Group_CertVerifyHostnameBySubjaltName, 16);

    //ssl shutdown
	pslError = PmSockOpensslUninit();
	TS_ASSERT(!pslError);
}


//17
void PalmTestSuite::testCertVerifyHostnameBySubjaltNameNeg() {
	//ssl init
    PslError pslError = PmSockOpensslInit(kPmSockOpensslInitType_DEFAULT);
    TS_ASSERT(!pslError);
    if (pslError) return;

    runTest<
    	&CreatePeer<ServerPeerShouldFailSSL>,  //CheckHostname has no effect for serverpeer (PmSockAcceptCrypto)
    	&CreatePeer_CheckHostname<ClientPeerShouldFailSSL>
    >(ConfigFile::Group_CertVerifyHostnameBySubjaltNameNeg, 17);

    //ssl shutdown
	pslError = PmSockOpensslUninit();
	TS_ASSERT(!pslError);
}


//18
void PalmTestSuite::testCertVerifyAddressBySubjaltName() {
	//ssl init
    PslError pslError = PmSockOpensslInit(kPmSockOpensslInitType_DEFAULT);
    TS_ASSERT(!pslError);
    if (pslError) return;

    runTest<
    	&CreatePeer<ServerPeerFullDuplexSSL>,  //CheckHostname has no effect for serverpeer (PmSockAcceptCrypto)
    	&CreatePeer_CheckHostname<ClientPeerFullDuplexSSL>
    >(ConfigFile::Group_CertVerifyAddressBySubjaltName, 18);

    //ssl shutdown
	pslError = PmSockOpensslUninit();
	TS_ASSERT(!pslError);
}


//19
void PalmTestSuite::testCertVerifyAddressBySubjaltNameNeg() {
	//ssl init
    PslError pslError = PmSockOpensslInit(kPmSockOpensslInitType_DEFAULT);
    TS_ASSERT(!pslError);
    if (pslError) return;

    runTest<
    	&CreatePeer<ServerPeerShouldFailSSL>,  //CheckHostname has no effect for serverpeer (PmSockAcceptCrypto)
    	&CreatePeer_CheckHostname<ClientPeerShouldFailSSL>
    >(ConfigFile::Group_CertVerifyAddressBySubjaltNameNeg, 19);

    //ssl shutdown
	pslError = PmSockOpensslUninit();
	TS_ASSERT(!pslError);
}


//20
void PalmTestSuite::testCertVerifyInstalledLeafFallback() {
	//ssl init
    PslError pslError = PmSockOpensslInit(kPmSockOpensslInitType_DEFAULT);
    TS_ASSERT(!pslError);
    if (pslError) return;

    runTest<
    	&CreatePeer<ServerPeerFullDuplexSSL>,  //CheckHostname has no effect for serverpeer (PmSockAcceptCrypto)
    	&CreatePeer_FallbackToInstalledLeaf<ClientPeerFullDuplexSSL>
    >(ConfigFile::Group_CertVerifyInstalledLeafFallback, 20);

    //ssl shutdown
	pslError = PmSockOpensslUninit();
	TS_ASSERT(!pslError);
}


//21
void PalmTestSuite::testCertVerifyInstalledLeafFallbackNeg() {
	//ssl init
    PslError pslError = PmSockOpensslInit(kPmSockOpensslInitType_DEFAULT);
    TS_ASSERT(!pslError);
    if (pslError) return;

    runTest<
    	&CreatePeer<ServerPeerShouldFailSSL>,  //CheckHostname has no effect for serverpeer (PmSockAcceptCrypto)
    	&CreatePeer_SSLv3<ClientPeerLeafFallbackNeg>
    >(ConfigFile::Group_CertVerifyInstalledLeafFallbackNeg, 21);

    //ssl shutdown
	pslError = PmSockOpensslUninit();
	TS_ASSERT(!pslError);
}
