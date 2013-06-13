/* @@@LICENSE
*
*      Copyright (c) 2009-2013 LG Electronics, Inc.
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
 * Client2.h
 *
 */

#ifndef CLIENTSETUP_H_
#define CLIENTSETUP_H_


#include "SetupBase.h"


/**
 * Class for setting up resources necessary for a client peer to connect to a server
 */
class ClientSetUp : public SetupBase {
private:
	//owned:
	PmSockIOChannel *pChannel_;  /** palmsock channel connected to server */

public:
	/** @see SetupBase */
	ClientSetUp(CreatePeerFunctionType create, const Config& config, const PipeFd& pipeFd);
	virtual ~ClientSetUp();

	/**
	 * Starts ThreadFunction() in a separate thread
	 * @returns the newly started thread
	 */
	GThread * Start();
	gpointer ThreadFunction();

};


#endif /* CLIENTSETUP_H_ */
