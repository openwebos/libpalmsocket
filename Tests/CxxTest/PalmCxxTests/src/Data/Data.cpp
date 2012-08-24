/*
 * Data.cpp
 *
 */


#define VERBOSE


#include <gmain.h>
#include <grand.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>


#include "Data.h"
#include "crc/crc.h"
#include "CommonUtils.h"
#include <cxxtest/TestSuite.h>
#include "DataAllocator.h"


const int Data::CRC_SIZE=4;


/**
 * Class for creating a statically allocated grand seed
 */
class GRandInstance {
	GRand *grand_;
public:
	GRandInstance() {
		//create seed
		GTimeVal time;
		g_get_current_time(&time);
		guint32 seed=time.tv_sec;

		grand_=g_rand_new_with_seed(seed);
	}

	~GRandInstance() {
		g_rand_free(grand_);
	}

	GRand *Get() {
		return grand_;
	}
};


//create GRand just once
static GRandInstance gRandInstance;


Data::Data(unsigned int size, DataAllocator *pAllocator)
:size_(size)
,pAllocator_(pAllocator)
{
	buffer_ = pAllocator_->Allocate(size_ + CRC_SIZE);

	GRand *grand = gRandInstance.Get();

	//randomize
	for(unsigned int i=0; i<size_; i+=4) {
		guint32 randomInteger = g_rand_int(grand);
		unsigned int sizeToCopy = MIN(sizeof(randomInteger), size_-i);
		memcpy(buffer_+i, &randomInteger, sizeToCopy);
	}

	//add crc
	crc crcValue = crcFast(buffer_, size_);
	assert(sizeof(crcValue)==CRC_SIZE);
	memcpy(buffer_+size_, &crcValue, sizeof(crcValue));
}


Data::~Data() {
	pAllocator_->Free();
	buffer_=NULL;
}


unsigned int Data::GetSize() {
	return size_ + CRC_SIZE;
}


/*static*/
unsigned int Data::CalculateTotalSize(unsigned int size) {
	return size + CRC_SIZE;
}


/*
 * non member functions
 */


GIOStatus WriteBytesToChannel(GIOChannel *pChannel, const void* source, gsize sourceCount, gsize* pSentCount) {
	GIOStatus ioStatus = G_IO_STATUS_NORMAL;

	*pSentCount=0;

	do {
		gsize const numRemaining = sourceCount - *pSentCount;
		gsize numToWrite = numRemaining; //or max buffer size

		const gchar * const p = (gchar *)((char *)source + *pSentCount);

		GError *pGError = NULL;
		gsize numWritten = 0;

		ioStatus = g_io_channel_write_chars(pChannel, p, numToWrite, &numWritten, &pGError);

		*pSentCount += numWritten;
		assert(numWritten<=numToWrite);

		if (G_IO_STATUS_ERROR==ioStatus) {
			//error occured
			assert(pGError);

			PslError const lastErr = ::PmSockGetLastError((PmSockIOChannel *)pChannel);
			assert(lastErr);

	        FN_PRINT_LINE(
	            "ERROR from g_io_channel_write_chars(%d): " \
	            "%d (%s) after writing %u of %u request bytes; " \
	            "PslError=%d (%s)",
	            numToWrite,
	            (int)pGError->code, pGError->message,
	            *pSentCount, sourceCount, lastErr,
	            PmSockErrStringFromError(lastErr) );

			g_clear_error(&pGError);

			if (*pSentCount>0) {
				ioStatus = G_IO_STATUS_AGAIN;
			}

		} else {
			//no error
			assert(!pGError);
            /// @note We shouldn't see G_IO_STATUS_EOF when writing
            assert(G_IO_STATUS_EOF != ioStatus);
            assert(G_IO_STATUS_NORMAL==ioStatus || G_IO_STATUS_AGAIN==ioStatus);
		}

	} while(*pSentCount<sourceCount && G_IO_STATUS_NORMAL==ioStatus);

	TS_ASSERT(*pSentCount<=sourceCount);
	return ioStatus;
}








