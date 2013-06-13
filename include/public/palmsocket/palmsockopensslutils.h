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
 * @file palmsockopensslutils.h
 * @ingroup psl_opensslutils
 * 
 * @brief  libpalmsocket Openssl utilities API.
 * 
 * @{ 
 *  
 * See @ref palmsockopensslutils_usage_info 
 * *****************************************************************************
 */
#ifndef PALMSOCK_OPENSSL_UTILS_H__
#define PALMSOCK_OPENSSL_UTILS_H__

#include <stdint.h>

#include "palmsockerror.h"
#include "palmsockx509utils.h"



#if defined(__cplusplus)
extern "C" {
#endif


/**
 * Forward declaration for the equivalent of PmSockIOChannel
 */
struct PmSockIOChannel_;

/**
 * Forward declarations for structs that represent openssl's
 * X509_STORE_CTX and X509 aliases
 */
struct x509_st;
struct x509_store_ctx_st;

/**
 * Forward declaration for structs that represent openssl's SSL 
 * and SSL_CTX aliases 
 */
struct ssl_st;
struct ssl_ctx_st;


/**
 * kPmSockOpensslInitType_DEFAULT: most apps SHOULD pass
 * this value to PmSockOpensslInit(), unless they have a
 * special-case scenario to address 
 *  
 * @see PmSockOpensslInit
 * @see PmSockOpensslInitType 
 */
#define kPmSockOpensslInitType_DEFAULT  (kPmSockOpensslInitType_multiThreaded)

/** 
 * OPENSSL initialization types for PmSockOpensslInit(). 
 *  
 * @note most apps should pass 
 *       kPmSockOpensslInitType_DEFAULT to
 *       PmSockOpensslInit(), unless they have a special-case
 *       scenario to address.
 *  
 * @see PmSockOpensslInit
 * @see kPmSockOpensslInitType_DEFAULT 
 */
typedef enum PmSockOpensslInitType_ {
    /**
     * kPmSockOpensslInitType_singleThreaded: basic openssl 
     * initialization suitable only for a single-threaded process; 
     * loads error strings. 
     *  
     * @note kPmSockOpensslInitType_singleThreaded and 
     *       kPmSockOpensslInitType_singleThreaded are
     *       mutually-exclusive
     *  
     * @note libpalmsocket may automatically upgrade the 
     *       request to a higher level (e.g.,
     *       kPmSockOpensslInitType_multiThreaded) at its
     *       discretion.
     */
    kPmSockOpensslInitType_singleThreaded   = 0x01,

    /**
     * kPmSockOpensslInitType_multiThreaded: openssl initialization 
     * for multi-threaded use.  Also loads error strings.
     *  
     * @note kPmSockOpensslInitType_singleThreaded and 
     *       kPmSockOpensslInitType_singleThreaded are
     *       mutually-exclusive
     */
    kPmSockOpensslInitType_multiThreaded    = 0x02
} PmSockOpensslInitType;


/**
 * PmSockOpensslInit(): Initializes the openssl library. The use
 * of kPmSockOpensslInitType_DEFAULT is VERY HIGHLY recommended!
 *  
 * If the openssl library is already initialized by 
 * PmSockOpensslInit() and a compatible initType is requested, 
 * this function will simply increment libpalmsocket's openssl 
 * initialization reference count. 
 *  
 * The number of _SUCCESSFUL_ calls to PmSockOpensslInit() MUST 
 * be balanced with an equal number of calls to 
 * PmSockOpensslUninit() (libpalmsocket maintains a 
 * mutex-protected openssl initialization reference count; when 
 * the reference count reaches zero, libpalmsocket will 
 * uninitialize openssl) 
 *  
 * @note PmSockOpensslInit and PmSockOpensslUninit may also be 
 *       used by other applications that only wish to initialize
 *       and uninitialize openssl, and not use libpalmsocket's
 *       other APIs.
 *  
 * @note See the USAGE INFO section in palmsocket.h for more 
 *       information about opensssl initialization.
 *  
 * @note Although PmSockOpensslInit() is thread-safe and 
 *       reentrant, openssl's own initialization and
 *       uninitialization API is NOT thread-safe and NOT
 *       re-entrant.  This means that: processes that may
 *       include other users of openssl (e.g., directly,
 *       libcurl, or another shared object or static library)
 *       MUST provide their own mechanism for arbitrating
 *       between the openssl initialization and uninitialization
 *       provided by those entities and libpalmsocket and doing
 *       so in a thread-safe and reentrant way so they don't
 *       step on each other (e.g., libcurl allows the user to
 *       pass flags indicating how much, if any, openssl
 *       initialization libcurl should perform); these
 *       limitations are imposed by the openssl library.
 *  
 * @note All calls to PmSockOpensslInit() within a given process 
 *       MUST use the same PmSockOpensslInitType value. The
 *       result of using different PmSockOpensslInitType values
 *       is undefined.  In particular, upgrading from
 *       single-threaded to multi-threaded initialization is not
 *       allowed because it cannot be accomplished in a
 *       thread-safe way (an openssl limitation).
 *  
 * @param initType Openssl initialization type: 
 *                 kPmSockOpensslInitType_DEFAULT is VERY HIGHLY
 *                 recommended!  See note above regarding use of
 *                 different PmSockOpensslInitType within the
 *                 same process. The outcome of using an
 *                 inappropriate PmSockOpensslInitType value for
 *                 your application is undefined (i.e., bad
 *                 things will happen).
 *  
 * 
 * @return PslError 0 on success; non-zero PslError code if an 
 *         incompatible initType is requested or if openssl
 *         initialization error is detected.
 *  
 * @see kPmSockOpensslInitType_DEFAULT 
 * @see PmSockOpensslInitType 
 */
PslError
PmSockOpensslInit(PmSockOpensslInitType initType);


/**
 * PmSockOpensslUninit(): unreferences libpalmsocket's openssl
 * initialization reference count.  If the reference count drops
 * to zero, libpalmsocket will uninitialize its openssl
 * initialization.
 * 
 * @note The number of calls to PmSockOpensslInit() and
 *       PmSockOpensslUninit() MUST be balanced within a given
 *       process
 * 
 * @note See PmSockOpensslInit() notes regarding thread-safety
 *       and interoperability with other users of openssl within
 *       the same process (e.g., libcurl)
 * 
 * @see PmSockOpensslInit 
 *  
 * @return PslError 0 on success; non-zero PslError code on 
 *         failure.
 */
PslError
PmSockOpensslUninit(void);


/**
 * PmSockOpensslThreadCleanup(): Cleans-up/frees openssl's
 * thread-specific data.
 * 
 * PmSockOpensslThreadCleanup() SHOULD be called before the exit
 * of any thread from which openssl API's were executed
 * (directly, via libpalmsocket or libcurl, etc.) 
 *  
 * @note libpalmsocket's openssl initialization must have been 
 *       continuously initialized from the time of your use of
 *       openssl (directly or indirectly) through the completion
 *       of your PmSockOpensslThreadCleanup call (i.e.,
 *       initialized via PmSockOpensslInit() and not
 *       uninitialized until after your call to
 *       PmSockOpensslThreadCleanup)
 * 
 * @note Not calling this function before a thread that used
 *       openssl exits may result in memory leaks of openssl
 *       data structures associated with that thread (openssl
 *       implements its own thread-local store mechanism
 *       _without_ automatic clean-up capability).
 *  
 * @return PslError 0 on success; non-zero PslError code on 
 *         failure.
 */
PslError
PmSockOpensslThreadCleanup(void);



/**
 * Options to pass to PmSockOpensslVerifyHostname. 
 *  
 * No options have been defined at this point, so callers MUST 
 * pass 0 for the value of this field. 
 */
typedef long PmSockOpensslHostnameVerifyOpts;


/**
 * PmSockOpensslVerifyHostname(): Perform a match of the 
 * hostname against the given certificate per RFC-2595, 
 * RFC-2818, and accepted practices. 
 *  
 * @note This function assumes that openssl is already 
 *       appropriately initialized.
 * 
 * @param hostname Non-NULL, non-empty ASCII (IA5), 
 *                 zero-terminated hostname or address string;
 *                 may be any case (uppper/lower/mixed)
 *                 
 * @param pCert Non-NULL, valid openssl X509 instance 
 *  
 * @param verifyOpts 1 or more PmSockOpensslHostnameVerifyOpts 
 *                   flags bitwise-or'ed together or 0 (zero) if
 *                   none.
 *  
 * @param nameMatchOpts 1 or more PmSockX509HostnameMatchOpts 
 *                      flags bitwise-or-ed together or 0 (zero)
 *                      if none.
 *  
 * @param pMatchRes Non-NULL pointer to variable for returning 
 *                  the status of the verification:
 *                  true=matched; false="no match"; undefined on
 *                  failure
 * 
 * @return PslError 0 on success (match status is indicated by 
 *         *pMatchRes); non-zero PslError code on failure (match
 *          status is undefined).
 *  
 * @see PmSockX509CheckCertHostNameMatch
 *  
 * @todo For IDNA support, may need to accept cert name and 
 *       hostname args in UTF8 format. (UTF8 is backward
 *       compatible with IA5)
 */
PslError
PmSockOpensslVerifyHostname(const char*                     hostname,
                            struct x509_st*                 pCert,
                            PmSockOpensslHostnameVerifyOpts verifyOpts,
                            PmSockX509HostnameMatchOpts     nameMatchOpts,
                            bool*                           pMatchRes);



/**
 * Options to pass to PmSockOpensslMatchCertInStore. 
 *  
 * No options have been defined at this point, so callers MUST 
 * pass 0 for the value of this field. 
 */
typedef long PmSockOpensslMatchCertOpts;


/**
 * PmSockOpensslMatchCertInStore(): checks for presence of the 
 * given cert in the device's certificate store referenced by 
 * the given x509StoreCtx. Subject Name is used as the key for 
 * matching, followed by exact comparison. 
 * 
 * @param x509StoreCtx Non-NULL, valid openssl X509_STORE_CTX 
 *                     instance
 *  
 * @param pCert Non-NULL, valid openssl X509 instance 
 *  
 * @param matchOpts 1 or more PmSockOpensslMatchCertOpts flags 
 *                  bitwise-or-ed together or 0 (zero) for
 *                  default behavior.  An _exact_ match is
 *                  sought by default.
 *  
 * @param pMatchRes Non-NULL pointer to variable for returning 
 *                  the status of the verification:
 *                  true=matched; false="no match"; undefined on
 *                  failure
 * 
 * @return PslError 0 on success (match status is indicated by 
 *         *pMatchRes); non-zero PslError code on failure (match
 *          status is undefined).
 */
PslError
PmSockOpensslMatchCertInStore(struct x509_store_ctx_st*  x509StoreCtx,
                              struct x509_st*            pCert,
                              PmSockOpensslMatchCertOpts matchOpts,
                              bool*                      pMatchRes);



#if defined(__cplusplus)
}
#endif


#endif //PALMSOCK_OPENSSL_UTILS_H__

/**@}*/
