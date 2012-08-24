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
 * PeerFullDuplexPlainSingleWatch.h
 *
 */

#ifndef PEERFULLDUPLEXPLAIN2_H_
#define PEERFULLDUPLEXPLAIN2_H_


#include "PeerBase.h"


class DataSender;
class DataReceiver;


/**
 * Full duplex, Plaintext connection
 * - can be used to instantiate both serverpeer, clientpeer;
 * - one single watch will monitor both G_IO_IN and G_IO_OUT
 * - will send specified number of bytes to the other peer
 * - will keep to receive bytes until the specified amount is reached
 * - after all the bytes were sent, and all the bytes were received, will quit main loop
 */
class PeerFullDuplexPlainSingleWatch : public PeerBase {
private:
	//owned:
	DataSender *pDataSender_;
	PmSockWatch *pWatch_;  /** watch on pPmSockIOChannel_ */

public:
	PeerFullDuplexPlainSingleWatch(PeerBaseParams& params);
	virtual ~PeerFullDuplexPlainSingleWatch();

	virtual void Run();

	/** IConnectObserver */
	virtual void OnConnect(PmSockIOChannel *pChannel, PslError errorCode);

	gboolean ChannelWatch(GIOChannel *pChannel, GIOCondition condition);
};


#endif /* PEERFULLDUPLEXPLAIN2_H_ */
