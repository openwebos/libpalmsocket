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
 * PeerFullDuplexPlain.h
 *
 */

#ifndef PEERFULLDUPLEXPLAIN_H_
#define PEERFULLDUPLEXPLAIN_H_


#include "PeerFullDuplex.h"


class DataSender;
class DataReceiver;


/**
 * Full duplex, Plaintext connection
 * - can be used to instantiate both server peer, client peer;
 * - two watches one for G_IO_OUT, one for G_IO_IN
 * - will send predefined bytes to the other peer
 * - will keep to receive bytes until the predefined certain amount is reached
 * - after all the bytes were sent, and all the bytes were received, will quit main loop
 */
class PeerFullDuplexPlain : public PeerFullDuplex {
public:
	PeerFullDuplexPlain(const PeerBaseParams& params);
	virtual ~PeerFullDuplexPlain();

	virtual void Run();
};


#endif /* PEERFULLDUPLEXPLAIN_H_ */
