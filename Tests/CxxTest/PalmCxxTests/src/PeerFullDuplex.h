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
 * PeerFullDuplex.h
 *
 */


#ifndef PEERFULLDUPLEX_H_
#define PEERFULLDUPLEX_H_


#include "PeerBase.h"


class DataSender;
class DataReceiver;


/**
 * Abstract base for full duplex operations
 * Full duplex, Plaintext connection
 * - two watches one for G_IO_OUT, one for G_IO_IN
 * - will send certain amount (as specified in config file) bytes to the other peer
 * - will keep to receive bytes until the specified amount is reached
 * - after all the bytes were sent, and all the bytes were received, will quit main loop
 */
class PeerFullDuplex : public PeerBase {
protected:
	//owned:
	PmSockWatch *pWatchOut_;  /** watch on pPmSockIOChannel_ for G_IO_OUT */
	PmSockWatch *pWatchIn_;  /** watch on pPmSockIOChannel_ for G_IO_IN */
	DataSender *pDataSender_;

public:
	PeerFullDuplex(const PeerBaseParams& params, const std::string& myName);
	virtual ~PeerFullDuplex();

	virtual gboolean ChannelWatchOn_G_IO_OUT(GIOChannel *channel, GIOCondition condition);
	virtual gboolean ChannelWatchOn_G_IO_IN(GIOChannel *pChannel, GIOCondition condition);

	/** IConnectCallback */
	virtual void OnConnect(PmSockIOChannel *pChannel, PslError errorCode);
};


#endif /* PEERFULLDUPLEX_H_ */
