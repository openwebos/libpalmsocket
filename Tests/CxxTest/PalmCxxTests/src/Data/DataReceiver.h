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
 * DataReceiver.h
 *
 */

#ifndef DATARECEIVER_H_
#define DATARECEIVER_H_


#include <giochannel.h>
#include <string>


class DataIn;
class Config;
class BandwidthMeter;
class DataAllocator;


/**
 * Receives data in chunks through a channel.
 * Will use class DataIn to receive data
 * Validates received chunks calling CheckCRC() of the chunk.
 */
class DataReceiver {
private:
	const std::string& myName_;
	const unsigned int numBytesToReceive_;
	const unsigned int chunkSize_;

	DataIn *pChunk_;  /** the chunk currently under receive status (means part of the chunk may have been received already) */
	unsigned int totalBytesReceived_;  /** the number of bytes received, counted from the existence of the instance */

	//owned:
	BandwidthMeter *pMeter_;
	DataAllocator *pAllocator_;

public:
	/**
	 * @param config configuration parameters read from config file
	 * @param myName will appear in log
	 */
	DataReceiver(const Config& config, const std::string &myName);
	DataReceiver(const unsigned int numBytesToReceive, const unsigned int chunkSize, const std::string& myName);
	virtual ~DataReceiver();

	/**
	 * @returns true when all the data has been received.
	 * (number of bytes received equals to config_.numBytesToSend)
	 */
	virtual bool IsFinished();

	/**
	 * Receives certain amount of data from specified channel
	 * Tries to receive an entire chunk, if does not succeed falls back receiving a chunk through multiple calls
	 * In case the desired sum amount of data has been received already, this method asserts
	 * @param pChannel receive data through this channel
	 */
	virtual void Receive(GIOChannel *pChannel);
	unsigned int GetTotalBytesReceived();

private:
	void Init();

private: //forbidden
	DataReceiver(const DataReceiver& );
	DataReceiver& operator=(const DataReceiver& );

};


#endif /* DATARECEIVER_H_ */
