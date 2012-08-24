/*
 * DataIn.cpp
 *
 */


#define VERBOSE


#include <assert.h>
#include <string.h>
#include <stdlib.h>


//local includes
#include "DataIn.h"
#include "crc/crc.h"
#include "PeerBase.h"
#include "CommonUtils.h"
#include <cxxtest/TestSuite.h>
#include "Data.h"
#include "DataAllocator.h"


DataIn::DataIn(unsigned int size, DataAllocator *pAllocator)
:size_(size)
,pAllocator_(pAllocator)
{
	buffer_ = pAllocator_->Allocate(size);
	numRead_=0;
	numIterationsTaken_=0;
}


DataIn::~DataIn() {
	pAllocator_->Free();
	buffer_=NULL;
}


GIOStatus DataIn::Read(GIOChannel *pChannel, bool *pIsFinishedReading, gsize *pNumRead) {
	*pIsFinishedReading=false;
	gsize currentIterationNumberOfBytesRead=0; //the number of bytes read in the current iteration (current function call)

	//read data
	assert(numRead_<size_);
	gsize numRemaining = size_ - numRead_;
	gchar *pReadDataToThisPosition = (gchar *)(buffer_ + numRead_);

	GIOStatus ioStatus =
			ReadBytesFromChannel(pChannel, pReadDataToThisPosition, numRemaining, &currentIterationNumberOfBytesRead);
	*pNumRead = currentIterationNumberOfBytesRead;
	numIterationsTaken_++;

	numRead_ += currentIterationNumberOfBytesRead;
	if (numRead_==size_) {
		//a chunk finished reading
		*pIsFinishedReading = true;

	} else {
		//there is more data to read for this chunk
	}

	return ioStatus;
}


bool DataIn::CheckCRC() {
	assert(numRead_==size_);

	crc crcValue;
	assert(sizeof(crc)==Data::CRC_SIZE);
	memcpy(&crcValue, buffer_ + size_ - Data::CRC_SIZE, Data::CRC_SIZE);

	//calc crc
	crc calculatedCRCValue = crcFast((const unsigned char*)buffer_, size_ - Data::CRC_SIZE);

	return (calculatedCRCValue==crcValue);
}


unsigned int DataIn::GetNumIterationsTaken() {
	return numIterationsTaken_;
}


/**
 * non-member functions
 */


GIOStatus ReadBytesFromChannel(GIOChannel *pChannel, void * const destination, gsize destinationCount, gsize *pReadCount) {
	GIOStatus ioStatus = G_IO_STATUS_NORMAL;

	*pReadCount = 0;

	do {
		gsize const numRemaining = destinationCount - *pReadCount;
		gsize const numToRead = numRemaining; //or max buffer size
		gchar * const p = (gchar *)((char *)destination + *pReadCount);

		GError *pGError = NULL;
		gsize numRead = 0;
		ioStatus = g_io_channel_read_chars(pChannel, p, numToRead, &numRead, &pGError);

		*pReadCount +=numRead;
		TS_ASSERT(*pReadCount<=destinationCount);

		if (G_IO_STATUS_ERROR==ioStatus) {
			//error occured
			assert(pGError);

			PslError const lastError = PmSockGetLastError((PmSockIOChannel *)pChannel);
	        assert(lastError);

	        FN_PRINT_LINE(
	        	"ERROR from g_io_channel_read_chars: " \
	        	"GError.code=%d GError.message=(%s) " \
	        	"PslError=%d %s",
	        	pGError->code, pGError->message,
	        	lastError, PmSockErrStringFromError(lastError) );

	        g_clear_error(&pGError);

		} else {
			//no error
			assert(!pGError);
		}

	} while (*pReadCount<destinationCount && G_IO_STATUS_NORMAL==ioStatus);

	assert(*pReadCount<=destinationCount);
	return ioStatus;
}

