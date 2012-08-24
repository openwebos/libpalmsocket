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
 * PeerBase.h
 *
 */

#ifndef PEERBASE_H_
#define PEERBASE_H_


#include <palmsocket.h>
#include <string>


#include "IObserver.h"


class GMain;
class Config;
class DataReceiver;
class Channels;
class PipeFd;
class PeerBaseParams;


/*
 * Abstract base class for all peers
 */
class PeerBase : public IConnectObserver, IThreadShutdownObserver {
protected:
	//owned:
	DataReceiver *pDataReceiver_;
	GIOChannel *pThreadShutdownNotifierChannel_; /** thread shutdown event will come on this channel */
	GSource *pThreadShutdownWatch_; /** watches G_IO_IN on pThreadShutdownNotifierChannel_ */

	//not owned:
	const GMain &gMain_;		/** gmaincontext and gmainloop, in which this peerbase will run */

	/**
	 * Peer will send/receive data through this.
	 * For client peers: Channel made with PmSockCreateChannel() on current threadcontext,
	 * parameterized with PmSockSetConnectAddress().
	 */
	PmSockIOChannel *pPmSockIOChannel_;
	const Config& config_; /** configuration options */
	std::string myName_;  /** signature will appear in log */

private:
	const PipeFd& pipeFd_; /** get filedescriptor on which to listen for thread shutdown events, from this */

public:
	/**
	 * @param pGMain gmaincontext,loop in which this peerbase will run
	 * @param pChannel peer will send/receive data through this.
	 */
	PeerBase(const PeerBaseParams& params, const std::string& myName);
	virtual ~PeerBase();

	/** Starts peer operation */
	virtual void Run()=0;

	/** @returns signature of peer */
	const char * MyName();
	void SetMyName(const char * pName);
	void AppendToMyName(const char * str);

	/** Override in derived classes to obtain the desired behaviour */
	virtual gboolean ChannelWatchOn_G_IO_IN(GIOChannel *pChannel, GIOCondition condition);
	static gboolean StaticChannelWatchOn_G_IO_IN(GIOChannel *pChannel, GIOCondition condition, gpointer data);

	/** Override in derived classes to obtain the desired behaviour */
	virtual gboolean ChannelWatchOn_G_IO_OUT(GIOChannel *pChannel, GIOCondition condition);
	static gboolean StaticChannelWatchOn_G_IO_OUT(GIOChannel *pChannel, GIOCondition condition, gpointer data);

	/** IConnectObserver */
	virtual void OnConnect(PmSockIOChannel *pChannel, PslError errorCode)=0;

	/** IThreadShutdownObserver */
	virtual gboolean OnThreadShutdown(GIOChannel *pChannel, GIOCondition condition);
};


const char * IOStatusToString(GIOStatus ioStatus);



#endif /* PEERBASE_H_ */
