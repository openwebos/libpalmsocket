/*
 * PeerBase.cpp
 *
 */


#define VERBOSE


#include <assert.h>
#include <iostream>
#include <string.h>


#include "PeerBase.h"
#include <cxxtest/TestSuite.h>
#include "Data.h"
#include "DataIn.h"
#include "GMain.h"
#include "CommonUtils.h"
#include "ConfigFile.h"
#include "DataReceiver.h"
#include "PipeFd.h"
#include "Callback.h"
#include "PeerBaseParams.h"


using namespace std;


PeerBase::PeerBase(const PeerBaseParams& params, const std::string& myName)
:gMain_(*params.pGMain_)
,pPmSockIOChannel_(params.pChannel_)
,config_(*params.pConfig_)
,myName_(myName)
,pipeFd_(*params.pPipeFd_)
{
	pDataReceiver_ = new DataReceiver(config_, myName_);

	//subscribe to thread shutdown events
		//create GIOChannel
	pThreadShutdownNotifierChannel_ = g_io_channel_unix_new(pipeFd_.GetFdIn());
		//create GSource on GIOChannel
	pThreadShutdownWatch_ = g_io_create_watch(pThreadShutdownNotifierChannel_, G_IO_IN);
	g_source_set_can_recurse(pThreadShutdownWatch_, false);
	g_source_attach(pThreadShutdownWatch_, gMain_.GetContext());
		//attach this IThreadShutdownObserver to GSource
	Attach(this, pThreadShutdownWatch_);
}


PeerBase::~PeerBase() {
	delete pDataReceiver_;
	g_io_channel_unref(pThreadShutdownNotifierChannel_);
	//@todo jck g_source_destroy for pThreadShutdownWatch_
	g_source_unref(pThreadShutdownWatch_);
}


const char * PeerBase::MyName() {
	return myName_.c_str();
}


void PeerBase::SetMyName(const char * pName) {
	myName_ = pName;
}


void PeerBase::AppendToMyName(const char * str) {
	myName_.append(str);
}


/*virtual*/
gboolean PeerBase::ChannelWatchOn_G_IO_IN(GIOChannel *pChannel, GIOCondition condition) {
	pDataReceiver_->Receive(pChannel);

	bool staySubscribed = !pDataReceiver_->IsFinished();
	if (!staySubscribed) {
		g_main_loop_quit(gMain_.GetLoop());
	}

	return staySubscribed;
	//false will detach watch from main loop
}


/*static*/
gboolean PeerBase::StaticChannelWatchOn_G_IO_IN(GIOChannel *pChannel, GIOCondition condition, gpointer data) {
	return ((PeerBase *)data)->ChannelWatchOn_G_IO_IN(pChannel, condition);
}


/*virtual*/
gboolean PeerBase::ChannelWatchOn_G_IO_OUT(GIOChannel *pChannel, GIOCondition condition) {
	//nothing to do here, override this in derived classes
	assert(false);
	return false;
}


/*static*/
gboolean PeerBase::StaticChannelWatchOn_G_IO_OUT(GIOChannel *pChannel, GIOCondition condition, gpointer data) {
	return ((PeerBase *)data)->ChannelWatchOn_G_IO_OUT(pChannel, condition);
}


/*virtual*/
gboolean PeerBase::OnThreadShutdown(GIOChannel *pChannel, GIOCondition condition) {
	PRINT_LINE("%s OnThreadShutdown() triggered ! ---------------------------------------------------", MyName() );

	g_main_loop_quit(gMain_.GetLoop());

	return false;
}


/**
 * non-member functions
 */


const char * IOStatusToString(GIOStatus ioStatus) {
	const char * stringValue=NULL;
	switch(ioStatus) {
		case G_IO_STATUS_ERROR:
			stringValue = "G_IO_STATUS_ERROR";
			break;
		case G_IO_STATUS_NORMAL:
			stringValue = "G_IO_STATUS_NORMAL";
			break;
		case G_IO_STATUS_EOF:
			stringValue = "G_IO_STATUS_EOF";
			break;
		case G_IO_STATUS_AGAIN:
			stringValue = "G_IO_STATUS_AGAIN";
			break;
	}

	return stringValue;
}


