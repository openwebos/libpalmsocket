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
 * ServerTasks.h
 *
 */

#ifndef SERVERTASKS_H_
#define SERVERTASKS_H_


#include "Task.h"
#include "DataAllocator.h"


/**
 * Used by deferred SSL test, on server side
 * Sends 10000 bytes to client peer
 */
struct TaskSend : public Task {
	PmSockIOChannel *pChannel_;
	unsigned int configChunkSize_;  /** size of chunk read from config file */
	const std::string& myName_;
	DataAllocator allocator_;

	TaskSend(PmSockIOChannel *pChannel, const Config& config, const std::string& myName)
	:myName_(myName) {
		configChunkSize_ = config.chunkSize_;
		pChannel_=pChannel;
	}

	virtual ~TaskSend() {
	}

	virtual void Execute() {
		FN_PRINT_LINE(" ");
		unsigned int numBytesSent = 0;
		while (numBytesSent<ServerPeerDeferredSSL::NUM_BYTES_TO_SEND) {
			gsize numBytesRemaining = ServerPeerDeferredSSL::NUM_BYTES_TO_SEND-numBytesSent;
			gsize chunkSize = MIN(numBytesRemaining, configChunkSize_);
			DataOut chunk(chunkSize, &allocator_);

			bool isAllSent=false;
			while (!isAllSent) {
				gsize numBytesWritten=0;
				GIOStatus ioStatus = chunk.Send((GIOChannel *)pChannel_, &isAllSent, &numBytesWritten);
				if (G_IO_STATUS_ERROR==ioStatus) {
					std::string errorMessage = "gioStatus = ";
					errorMessage.append(PmSockErrStringFromError(PmSockGetLastError((PmSockIOChannel *)pChannel_)) );
					UTIL_THROW_FATAL(myName_.c_str(), errorMessage.c_str());
				}
			}
			numBytesSent += chunkSize;
		}

		PRINT_LINE("%s:  OUT   bytes sent:%d ", myName_.c_str(), numBytesSent);
		isFinished_=true;
	}
};


/**
 * Used by deferred SSL test, on server side
 * Sleeps 5 seconds
 */
struct TaskSleep : public Task {
	virtual void Execute() {
		PRINT("Sleeping for 5 seconds... ");
		GCond *cond = g_cond_new();
		GMutex *mutex = g_mutex_new();
		g_mutex_lock(mutex);

		GTimeVal time;
		g_get_current_time(&time);
		time.tv_sec += 5;

		g_cond_timed_wait(cond, mutex, &time);

		g_mutex_unlock(mutex);
		g_mutex_free(mutex);
		g_cond_free(cond);
		PRINT_LINE("Done.");
		isFinished_=true;
	}
};


#endif /* SERVERTASKS_H_ */
