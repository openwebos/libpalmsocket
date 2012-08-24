
/*
 * DataAllocator.cpp
 *
 */


#include <assert.h>
#include <stdlib.h>


#include "DataAllocator.h"


DataAllocator::DataAllocator() {
	lastAllocatedSize_=0;
	buffer_=0;
	isUsed_=false;
}


DataAllocator::~DataAllocator() {
	assert(!isUsed_);
	free(buffer_);
}


void DataAllocator::Free() {
	assert(isUsed_);
	isUsed_=false;
}


unsigned char *DataAllocator::Allocate(unsigned numBytes) {
	assert(!isUsed_);
	assert(numBytes!=0);
	isUsed_=true;

	if (numBytes!=lastAllocatedSize_) {
		free(buffer_);
		buffer_ = (unsigned char *)malloc(numBytes);
		lastAllocatedSize_ = numBytes;
	}

	return buffer_;
}




