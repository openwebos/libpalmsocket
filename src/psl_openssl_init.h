/* @@@LICENSE
*
*      Copyright (c) 2009-2012 Hewlett-Packard Development Company, L.P.
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

/** ****************************************************************************
 * @file psl_openssl_init.h
 * @ingroup psl_internal 
 * 
 * @brief  Internal Openssl library initialization definitions.
 * 
 * *****************************************************************************
 */
#ifndef PSL_OPENSSL_INIT_H__
#define PSL_OPENSSL_INIT_H__

#include "psl_build_config.h"



#if defined(__cplusplus)
extern "C" {
#endif

/**
 * psl_openssl_init_conditional(): this function is used 
 * internally by the SSL-related libpalmsocket implementation 
 * modules to make sure that openssl library is initialized 
 * before we use it. 
 *  
 * This functions differs from PmSockOpensslInit() as follows: 
 * if libpalmsocket's openssl initialization is already 
 * activated, psl_openssl_init_conditional() ignores the 
 * initType interoperability check and simply increments the 
 * reference count.  The rationalle is that this allows a 
 * single-threaded application to force initialization of 
 * openssl to single-threaded support by explicitly calling 
 * PmSockOpensslInit(kPmSockOpensslInitType_singleThreaded).
 *  
 * @note psl_openssl_init_conditional() calls MUST be balanced 
 *       by an equal number of PmSockOpensslUninit() calls.
 * 
 * @param initType SHOULD be kPmSockOpensslInitType_DEFAULT
 */
void psl_openssl_init_conditional(PmSockOpensslInitType initType);


#if defined(__cplusplus)
}
#endif

#endif // PSL_OPENSSL_INIT_H__

