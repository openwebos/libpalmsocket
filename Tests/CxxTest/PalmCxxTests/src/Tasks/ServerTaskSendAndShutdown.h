/* @@@LICENSE
*
*      Copyright (c) 2009-2011 Hewlett-Packard Development Company, L.P.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
* LICENSE@@@ */

/*
 * ServerTaskSendAndShutdown.h
 *
 */


#ifndef SERVERTASKSENDANDSHUTDOWN_H_
#define SERVERTASKSENDANDSHUTDOWN_H_


#include <string>
#include <palmsocket.h>


#include "Task.h"
#include "Observer/IObserver.h"


class GMain;


/**
 * Used by deferred SSL test, on server side
 * Sends final 1 byte
 * Initiates bidirectional shutdown
 */
class ServerTaskSendAndShutdown: public Task, public ICryptoObserver {
	const std::string& myName_;
	PmSockIOChannel *pChannel_;
	const GMain& gMain_;

public:
	ServerTaskSendAndShutdown(PmSockIOChannel *pChannel, const GMain& gMain, const std::string& myName);

	virtual void Execute();

	/** ICryptoObserver */
	virtual void OnShutCrypto(PmSockIOChannel *pChannel, PslError errorCode);

private: //forbidden
	ServerTaskSendAndShutdown(const ServerTaskSendAndShutdown& );
	ServerTaskSendAndShutdown& operator=(const ServerTaskSendAndShutdown& );
};


#endif /* SERVERTASKSENDANDSHUTDOWN_H_ */
