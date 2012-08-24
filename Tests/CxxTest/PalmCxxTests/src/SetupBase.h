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
 * SetupBase.h
 *
 */


#ifndef SETUPBASE_H_
#define SETUPBASE_H_


#include <string>


class PipeFd;
class GMain;
class Config;
class PeerBase;
class PeerBaseParams;


//Factory. Will create PeerBase derived peer
typedef PeerBase* (*CreatePeerFunctionType)(PeerBaseParams& params);


/**
 * Base class for ClientSetup/ServerSetup
 */
class SetupBase {
protected:
	CreatePeerFunctionType CreatePeer_; /** creates the appropriate peer instance */
	const Config& config_;  /** config params for client/server */
	const PipeFd& pipeFd_;
	std::string myName_;

	//owned:
	GMain *pGMain_;		/** gmainLoop, gmain context of client/server thread */

public:
	/**
	 * @param Create function pointer to creator function, will be used to create peer instance when necessary
	 * @param config these configuration options will be used
	 * @param pipeFd will be passed to created peer instance
	 * @param myName will appear in log as signature
	 */
	SetupBase(CreatePeerFunctionType Create, const Config& config, const PipeFd& pipeFd,
			const std::string& myName);
	virtual ~SetupBase();

	const char * MyName();
};


#endif /* SETUPBASE_H_ */
