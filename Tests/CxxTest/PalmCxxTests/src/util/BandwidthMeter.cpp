/*
 * BandwidthMeter.cpp
 *
 */


#include <assert.h>


#include "BandwidthMeter.h"


BandwidthMeter::BandwidthMeter() {
	pTimer_ = g_timer_new();
	isStarted_=false;
	wasUsed_=false;
}


BandwidthMeter::~BandwidthMeter() {
	g_timer_destroy(pTimer_);
}


void BandwidthMeter::Start() {
	assert(!isStarted_);
	isStarted_=true;
	g_timer_start(pTimer_);
}


void BandwidthMeter::Stop(unsigned numBytesTransferred) {
	assert(isStarted_);
	isStarted_=false;
	wasUsed_=true;
	g_timer_stop(pTimer_);

	gulong microseconds;
	gdouble elapsedSeconds = g_timer_elapsed(pTimer_, &microseconds);

	bytesPerSecond_ = numBytesTransferred/elapsedSeconds;

	static const int numBitsInAByte=8;
	bitsPerSecond_ = numBytesTransferred*numBitsInAByte/elapsedSeconds;
}


double BandwidthMeter::GetBytesPerSecond() {
	return bytesPerSecond_;
}


double BandwidthMeter::GetBitsPerSecond() {
	return bitsPerSecond_;
}


double BandwidthMeter::GetElapsedSeconds() {
	gulong microseconds;
	gdouble elapsedSeconds = g_timer_elapsed(pTimer_, &microseconds);

	return elapsedSeconds;
}


