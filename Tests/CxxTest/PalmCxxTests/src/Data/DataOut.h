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
 * DataOut.h
 *
 */


#ifndef DATAOUT_H_
#define DATAOUT_H_


#include "Data.h"


/**
 * Allocates a chunk of data, sends to a channel
 * Send will try to send a chunksize (specified in config file) as one piece
 * If does not succeed, will send a chunk in multiple calls to Send()
 */
class DataOut: public Data {
private:
	gsize bytesWritten_; /** number of bytes already written */
	unsigned int numIterationsTaken_;	/** number of iterations taken to send entire chunk */

public:
	/**
	 * @param size the size of a data chunk, WITHOUT CRC
	 */
	DataOut(unsigned int size, DataAllocator *pAllocator);
	virtual ~DataOut();

	/**
	 * Sends the data onto the specified channel. If does not succeed to send on first call, call this function
	 * until @param pIsAllSent will contain true. (preferably call in separate G_IO_OUT events )
	 * @param pChannel data will be sent to this channel
	 * @param pIsallSent on return if contains true, means all the data was sent successfull (pNumWritten==size)
	 * @param pNumWritten on return will contain number of bytes successfully written to the channel
	 */
	GIOStatus Send(GIOChannel *pChannel, bool *pIsAllSent, gsize *pNumWritten);

	unsigned int GetNumIterationsTaken();
};

#endif /* DATAOUT_H_ */
