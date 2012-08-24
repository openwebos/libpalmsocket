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
 * IObserver.h
 *
 */

#ifndef IOBSERVER_H_
#define IOBSERVER_H_


/**
 * Implement this interface if you want to catch crypto shut events
 */
class ICryptoObserver {
public:
	virtual void OnShutCrypto(PmSockIOChannel *pChannel, PslError errorCode)=0;
};


/**
 * Implement this interface if you want to catch channel connect events
 */
class IConnectObserver {
public:
	virtual void OnConnect(PmSockIOChannel *pChannel, PslError errorCode)=0;
};


/**
 * Implement this interface if you want to catch thread shutdown events.
 */
class IThreadShutdownObserver {
public:
	virtual gboolean OnThreadShutdown(GIOChannel *pChannel, GIOCondition condition)=0;
};


#endif /* IOBSERVER_H_ */
