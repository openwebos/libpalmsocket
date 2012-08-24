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
 * DataSender.h
 *
 */


#ifndef DATASENDER_H_
#define DATASENDER_H_


#include <giochannel.h>
#include <string>


class DataOut;
class Config;
class DataAllocator;


/**
 * Sends data in chunks through a channel
 */
class DataSender {
private:
	const std::string &myName_;

	DataOut *pChunk_;	/** the chunk currently under send status (means part of the chunk may be sent already ) */
	const unsigned int numberOfBytesToSend_;
	const unsigned int chunkSize_;
	unsigned int numBytesSent_;	/** the number of bytes sent, counted from the existence of the instance */

	//owned:
	DataAllocator *pAllocator_;

public:
	/**
	 * @param numBytesToSend desired amount of data to be sent
	 * @param chunkSize size of a chunk which will be tried to be sent in one G_IO_IN event
	 * @param name signature will appear in log
	 */
	DataSender(const Config& config, const std::string& myName);
	DataSender(unsigned int numBytesToSend, unsigned int chunkSize, const std::string& myName);
	virtual ~DataSender();

	/** @returns true when number of sent bytes equals to numBytesToSend */
	virtual bool IsFinished();

	/**
	 * Sends certain amount of data to specified channel
	 * Tries to send an entire chunk at a time, if does not succeed falls back sending a chunk through multiple calls
	 * In case the desired sum amount of data (numBytesToSend) has been sent already, this method does nothing
	 * @param pChannel send data through this channel
	 */
	virtual void Send(GIOChannel *pChannel);

private:
	void Init();
};


#endif /* DATASENDER_H_ */
