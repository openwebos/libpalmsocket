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
 * DummyDataReceiver.h
 *
 */


#ifndef DUMMYDATARECEIVER_H_
#define DUMMYDATARECEIVER_H_


#include "DataReceiver.h"


/**
 * Cannot be used to receive data, do not call Receive() on this class' instance
 * IsFinished() will always return TRUE.
 */
class DummyDataReceiver: public DataReceiver {
public:
	DummyDataReceiver(const Config& config, const std::string &myName);
	virtual ~DummyDataReceiver();

	virtual bool IsFinished();
	virtual void Receive(GIOChannel *pChannel);
};


#endif /* DUMMYDATARECEIVER_H_ */
