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
 * DummyDataSender.h
 *
 */


#ifndef DUMMYDATASENDER_H_
#define DUMMYDATASENDER_H_


#include "DataSender.h"
#include <assert.h>


/**
 * Cannot be used to send data, do not call Send() on this class' instance
 * IsFinished() will always return TRUE.
 */
class DummyDataSender: public DataSender {
public:
	DummyDataSender(const Config& config, const std::string& myName)
	:DataSender(config, myName) {}

	virtual ~DummyDataSender() {}

	virtual bool IsFinished() {
		return true;
	}
	virtual void Send(GIOChannel *pChannel) {
		//do not try to send with dummy sender
		assert(false);
	}
};

#endif /* DUMMYDATASENDER_H_ */
