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
 * Callback.h
 *
 */

#ifndef CALLBACK_H_
#define CALLBACK_H_


#include <palmsocket.h>


/**
 * PmSockCompletionCb type function, can be passed to PmSockConnectCrypto
 * Generalized unimplemented function
 */
template<class T>
static void Callback(PmSockIOChannel *pChannel, void * pUserData, PslError errorCode);


/**
 * PmSockCompletionCb type function
 * ICryptoObserver specialization
 * Triggers ICryptoObserver -> OnShutCrypto() event
 */
template<>
void Callback<ICryptoObserver>(PmSockIOChannel *pChannel, void *pUserData, PslError errorCode) {
	((ICryptoObserver *)pUserData)->OnShutCrypto(pChannel, errorCode);
}


/**
 * PmSockCompletionCb type function
 * IConnectObserver specialization
 * Triggers IConnectObserver -> OnConnect() event
 */
template<>
void Callback<IConnectObserver>(PmSockIOChannel *pChannel, void *pUserData, PslError errorCode) {
	((IConnectObserver *)pUserData)->OnConnect(pChannel, errorCode);
}


////////////////////////////////////////////////////////


/**
 * GIOFunc type function, can be passed to g_source_set_callback
 * Generalized unimplemented function
 */
template<class T>
static gboolean GIOFuncCallback(GIOChannel *pChannel, GIOCondition condition, gpointer data);


/**
 * GIOFunc type function
 * IThreadShtudownObserver specialization
 * Triggers IThreadShutdownObserver -> OnThreadShutdown() event
 */
template<>
gboolean GIOFuncCallback<IThreadShutdownObserver>(GIOChannel *pChannel, GIOCondition condition,
		gpointer data) {
	IThreadShutdownObserver *pObserver = (IThreadShutdownObserver *)data;
	return pObserver->OnThreadShutdown(pChannel, condition);
}


template<class T>
void UtilPmSockConnectPlain(PmSockIOChannel *pChannel, T *pObserver) {
	PmSockSetUserData(pChannel, pObserver);
    PslError pslError = PmSockConnectPlain(pChannel, Callback<T>);
}


/**
 * Attaches IThreadShutdownObserver instance to the given source
 * meaning, triggering of GSource will trigger in turn IThreadShutdownObserver->OnThreadShutdown()
 * @param pObserver will be attached to @param pSource
 * @param pSource
 */
void Attach(IThreadShutdownObserver *pObserver, GSource *pSource);


#endif /* CALLBACK_H_ */
