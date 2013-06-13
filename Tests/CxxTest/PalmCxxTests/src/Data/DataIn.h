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
 * DataIn.h
 *
 */

#ifndef DATAIN_H_
#define DATAIN_H_


#include <giochannel.h>


class DataAllocator;


/**
 * Reads given amount of data from a channel into an internal buffer.
 * Does a CRC validation of the data chunk by cutting terminating 4 bytes and using it as CRC value
 * for the rest of the data
 */
class DataIn {
private:
	unsigned int size_; /** the size of a data chunk (CRC included)*/
	unsigned int numRead_;	/** number of bytes already received */
	unsigned int numIterationsTaken_; /** number of iterations taken to receive entire chunk */
	DataAllocator *pAllocator_;

	//owned:
	unsigned char *buffer_;


public:
	/**
	 * @param size the size of a data chunk (CRC included)
	 * @param pAllocator will be used to allocate data
	 */
	DataIn(unsigned int size, DataAllocator *pAllocator);
	virtual ~DataIn();

	/**
	 * Reads into internal buffer from the specified channel in multiple iterations.
	 * Call this function in separate iterations until @param pIsFinishedReading will contain true on return
	 * @param pChannel the channel to read data from
	 * @param pIsFinishedReading on return true means the whole chunk has been read successfully (numRead_==size_)
	 * @param pNumRead on return will contain the number of bytes read
	 */
	GIOStatus Read(GIOChannel *pChannel, bool *pIsFinishedReading, gsize *pNumRead);

	/**
	 * @returns true if CRC check was successfull. false otherwise
	 */
	bool CheckCRC();

	unsigned int GetNumIterationsTaken();

	unsigned int GetSize() { return size_; }
};


/*
 * Reads destinationCount bytes from channel, or until channel is blocked
 * @param pReadCount will contain number of bytes read
 */
GIOStatus ReadBytesFromChannel(GIOChannel *pChannel, void * const destination, gsize destinationCount,
		gsize *pReadCount);


#endif /* DATAIN_H_ */
