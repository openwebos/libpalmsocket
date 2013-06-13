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
 * DataAllocator.h
 *
 */


#ifndef DATAALLOCATOR_H_
#define DATAALLOCATOR_H_


/**
 * Fast allocator. Use instead of malloc, where the same amount of data needs to be allocated again and again.
 * Allocates a specified amount of data.
 * The data is allocated only ONCE during the lifetime of an instance, if demanded size does not change
 * Every call to Allocate() will return pointer to same chunk
 */
class DataAllocator {
private:
	unsigned int lastAllocatedSize_;
	bool isUsed_;			/* true means buffer was given out in a call to Allocate() */

	//owned:
	unsigned char *buffer_;  /** allocated data */

public:
	DataAllocator();
	virtual ~DataAllocator();

	/**
	 * Can give out pointer to internal buffer just once, until Free() is called
	 */
	unsigned char * Allocate(unsigned numBytes);

	/** Marks internal buffer as unused (buffer can be given out once again with allocate) */
	void Free();
};



#endif /* DATAALLOCATOR_H_ */
