/*
 * DataOut.cpp
 *
 */


#include <assert.h>


#include "DataOut.h"
#include <cxxtest/TestSuite.h>


DataOut::DataOut(unsigned int size, DataAllocator *pAllocator)
:Data(size, pAllocator)
{
	bytesWritten_=0;
	numIterationsTaken_=0;
}


DataOut::~DataOut()
{
}


GIOStatus DataOut::Send(GIOChannel *pChannel, bool *pIsAllSent, gsize *pNumWritten) {
	assert(bytesWritten_<GetSize()); //this does not check data amount correctness, rather it's a warning not to call the function by mistake, after data sending was finished

	*pIsAllSent=false;
	gsize currentIterationBytesWritten=0;

	//send data
	const unsigned char *pSendDataFromThisPoint = buffer_ + bytesWritten_;
	gsize sizeRemaining = GetSize() - bytesWritten_;

	GIOStatus ioStatus = WriteBytesToChannel(pChannel, pSendDataFromThisPoint, sizeRemaining, &currentIterationBytesWritten);
	*pNumWritten = currentIterationBytesWritten;
	numIterationsTaken_++;

	bytesWritten_ += currentIterationBytesWritten;
	TS_ASSERT(bytesWritten_<=GetSize());  //check data amount correctness

	if (bytesWritten_>=GetSize()) {
		//all the chunk was sent
		*pIsAllSent=true;

	} else {
		//just part of data was sent
	}

	return ioStatus;
}


unsigned int DataOut::GetNumIterationsTaken() {
	return numIterationsTaken_;
}
