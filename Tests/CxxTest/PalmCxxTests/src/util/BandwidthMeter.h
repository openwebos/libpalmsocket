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
 * BandwidthMeter.h
 *
 */


#include <glib/gtimer.h>


#ifndef BANDWIDTHMETER_H_
#define BANDWIDTHMETER_H_


/**
 * Measures bandwidth. Uses glib's gtimer
 */
class BandwidthMeter {
private:
	//owned:
	GTimer *pTimer_;

	bool isStarted_;
	bool wasUsed_;  /** true means BanwidthMeter instance was started and stopped at least once */
	double bytesPerSecond_;  /** measured speed in bytes/sec */
	double bitsPerSecond_;   /** measured speed in bits/sec */

public:
	BandwidthMeter();
	virtual ~BandwidthMeter();

	void Start();
	void Stop(unsigned numBytesTransferred);
	bool IsStarted() { return isStarted_; }

	double GetBytesPerSecond();
	double GetBitsPerSecond();
	double GetElapsedSeconds();

	bool WasUsed() { return wasUsed_; }
};


#endif /* BANDWIDTHMETER_H_ */
