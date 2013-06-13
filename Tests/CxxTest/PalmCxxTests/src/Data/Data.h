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
 * Data.h
 *
 */


#ifndef DATA_H_
#define DATA_H_


#include <giochannel.h>
#include <string>


class DataAllocator;


/**
 * Allocates a data chunk. Fills with random numbers
 */
class Data {
private:
	unsigned const int size_; /** size of a data chunk sent in one piece, in bytes (without CRC) */
	const std::string myName_;
	DataAllocator *pAllocator_;

protected:
	unsigned char *buffer_; /** internal buffer holding data */

public:
	static const int CRC_SIZE; //size of CRC signature

public:
	/**
	 * @param size the size of a data chunk, WITHOUT CRC
	 */
	Data(unsigned int size, DataAllocator *pAllocator);
	virtual ~Data();

	/** @returns size (including CRC) */
	unsigned int GetSize();

	/**
	 * Calculates total size of a data chunk given it's useful size
	 * @param size the chunk size
	 */
	static unsigned int CalculateTotalSize(unsigned int size);
};


/*
 * Tries to write certain amount of bytes to a channel.
 * Will stop writing in case channel is blocked
 * @param pChannel write bytes to this channel
 * @param source write bytes beginning from this address
 * @param sourceCount number of bytes to write
 * @param pSentCount will contain number of bytes sent
 */
GIOStatus WriteBytesToChannel(GIOChannel *pChannel, const void* source, gsize sourceCount, gsize* pSentCount);


#endif /* DATA_H_ */
