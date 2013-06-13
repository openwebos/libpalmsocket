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

/**
 * *****************************************************************************
 * @file palmhostlookup.h
 * @ingroup psl_hostlookup
 *  
 * @brief Public API for libpalmsocket's non-blocking IP address 
 *        resolver
 *  
 * @{ 
 * *****************************************************************************
 */
#ifndef PALMHOSTLOOKUP_H__
#define PALMHOSTLOOKUP_H__


#include <glib.h>

#include "palmsockerror.h"



#if defined(__cplusplus)
extern "C" {
#endif



/**
 * Non-blocking address lookup session opaque type
 * 
 * An instance of this type is created by PmSockHostLookupNew,
 * and it represents the state of the given host lookup session.
 */
typedef struct PmSockHostLookupSession_ PmSockHostLookupSession;

/**
 * Callback function for returning results of the lookup
 * operation.  Will be called exactly once after a successful
 * call to PmSockHostLookupStart.
 * 
 * @note This will be called from the scope of the gmainloop
 *       context that is passed to PmSockHostLookupNew when
 *       creating the lookup session instance.
 * 
 * @note The callback function may safely free the lookup
 *       session by calling PmSockHostLookupDestroy().
 * 
 * @param userData The userData value that was passed to
 *                PmSockHostLookupNew().
 * @param session Pointer to the lookup session that emitted
 *               this callback.
 * @param result Result of the lookup or NULL on error (if host
 *              wasn't found or some other error occurred); the
 *              callback function may examine the contents of
 *              this data structure, but MUST NOT modify it in
 *              any way. It will be freed automatically upon
 *              return from the callback function.
 * @param errorCode 0 if the lookup succeeded; non-zero PslError
 *                  code if the lookup failed.
 */
typedef void PmSockHostLookupCb(void*                       userData,
                                PmSockHostLookupSession*    session,
                                const struct hostent*       result,
                                PslError                    errorCode);


/**
 * PmSockHostLookupNew - creates a host lookup session
 * instance.  Once created, call PmSockHostLookupStart to kick
 * off the look-up process.
 * 
 * @note WARNING: The implementation of this API is NOT
 *       thread-safe; therefore, for a given session instance,
 *       the host lookup API MUST be called ONLY from the same
 *       gmainloop context that is passed to
 *       PmSockHostLookupNew when creating that instance.
 * 
 * @note We use a separate function for starting the lookup in
 *       order to facilitate setting additional lookup options
 *       in the future.
 * 
 * @param pSession: non-NULL pointer to location for returning
 *                the lookup session instance on success;
 *                NULL on failure. Caller is responsible for
 *                freeing the (non-NULL) session via
 *                PmSockHostLookupDestroy().
 * @param hostname: non-NULL, zero-terminated hostname whose
 *                address is to be resolved up; this string is
 *                copied.
 * @param family: address family: AF_INET or AF_INET6 (AF_INET6
 *          support is experimental)
 * @param userData: user-specific data pointer that should be
 *                passed to the user-specified completion
 *                callback function.
 * @param cb: non-NULL user-specified callback function that
 *          will be called upon completion of the lookup
 *          operation.
 * @param userLabel: an OPTIONAL (may be NULL) short,
 *                 zero-terminated string that will be displayed
 *                 in logs associated with this lookup session;
 *                 this string is copied;
 * @param gmainContext: gmainloop context that this session
 *                    should use; pass NULL for the default
 *                    gmainloop context.
 * @return PslError 0 on success, non-zero PslError code on
 *         error
 *         
 */
PslError
PmSockHostLookupNew(PmSockHostLookupSession**   pSession,
                    const char*                 hostname,
                    int                         family,
                    void*                       userData,
                    PmSockHostLookupCb*         cb,
                    const char*                 userLabel,
                    GMainContext*               gmainContext);


/**
 * PmSockHostLookupStart - begins the non-blocking lookup
 * session.
 * 
 * If PmSockHostLookupStart() completes successfully, the
 * PmSockHostLookupCb callback function passed to
 * PmSockHostLookupNew() will be called exactly once upon
 * completion of the request at some point after
 * PmSockHostLookupStart() returns (it will be called from the
 * scope of the gmainloop context passed to
 * PmSockHostLookupNew()).
 * 
 * @note WARNING: The implementation of this API is NOT
 *       thread-safe per lookup session instance; therefore, for
 *       a given session instance, the host lookup API MUST be
 *       called ONLY from the same gmainloop context that is
 *       passed to PmSockHostLookupNew when creating that
 *       instance.
 * 
 * @param session: non-NULL, "fresh" PmSockHostLookupSession
 *               instance that hasn't been started before.
 * 
 * @return PslError 0 on success, non-zero PslError code on
 *         error
 */
PslError
PmSockHostLookupStart(PmSockHostLookupSession* session);


/**
 * PmSockHostLookupDestroy - Frees the lookup session.  If the
 * lookup session was active (started and still in progress), it
 * will be stopped before this function returns, guaranteeing
 * that the user callback associated with this session will not
 * be called.
 * 
 * @note WARNING: The implementation of this API is NOT
 *       thread-safe; therefore, for a given session instance,
 *       the host lookup API MUST be called ONLY from the same
 *       gmainloop context that is passed to
 *       PmSockHostLookupNew when creating that instance.
 * 
 * @param session: non-NULL lookup session instance to be freed.
 */
void
PmSockHostLookupDestroy(PmSockHostLookupSession* session);




#if defined(__cplusplus)
}
#endif

#endif // PALMHOSTLOOKUP_H__

/**@}*/
