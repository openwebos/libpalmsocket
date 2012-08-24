/*
 * SetupBase.cpp
 *
 */


#include "SetupBase.h"
#include "PipeFd.h"
#include "GMain.h"


SetupBase::SetupBase(CreatePeerFunctionType Create, const Config& config, const PipeFd& pipeFd,
		const std::string& myName)
:CreatePeer_(Create)
,config_(config)
,pipeFd_(pipeFd)
,myName_(myName)
{
	//1. create gmain context, gmainloop
	pGMain_ = new GMain();
}


/*virtual*/
SetupBase::~SetupBase() {
	delete pGMain_;
}


const char * SetupBase::MyName() {
	return myName_.c_str();
}

