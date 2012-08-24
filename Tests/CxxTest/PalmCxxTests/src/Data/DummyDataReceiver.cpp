/*
 * DummyDataReceiver.cpp
 *
 */


#include "DummyDataReceiver.h"


#include <assert.h>



DummyDataReceiver::DummyDataReceiver(const Config & config, const std::string & myName)
:DataReceiver(config, myName)
{
}



DummyDataReceiver::~DummyDataReceiver() {
}


bool DummyDataReceiver::IsFinished() {
	return true;
}



void DummyDataReceiver::Receive(GIOChannel *pChannel) {
	//do NOT try to receive data with a dummy receiver
	assert(false);
}

