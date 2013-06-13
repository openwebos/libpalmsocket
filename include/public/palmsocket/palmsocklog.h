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
 * @file palmsocklog.h
 *  
 * @ingroup psl_log psl_diag_runtime
 *  
 * @brief  Logging control API for libpalmsocket.
 * @{
 * *****************************************************************************
 */
#ifndef PALMSOCK_LOG_H__
#define PALMSOCK_LOG_H__

#include <stdint.h>
#include <stdbool.h>

#include "palmsockerror.h"


#if defined(__cplusplus)
extern "C" {
#endif


/**
 * PmSockLogOptions: libpalmsocket logging options that may be 
 * bitwise-or'ed together 
 */
typedef uint32_t    PmSockLogOptions;
enum {
    /**
     * kPmSockLogOption_debuglow: enables emission of low-level 
     * debug logging. This logging will be rendered in the log if 
     * libpalmsocket's PmLogLib context's log level is set to DEBUG 
     * (via PmLogCtl utility or PmLogLib's .conf file) 
     */
    kPmSockLogOption_debuglow   = 0x01,   ///< enables low-level debug logging


    /// All valid logging options
    kPmSockLogOption_ALL_OPTS   = (kPmSockLogOption_debuglow)
};

/**
 * PmSockLogSetOptions(): sets libpalmsocket's logging options, 
 * replacing previous logging options 
 * 
 * @param opts Valid PmSockLogOptions values 
 *             (kPmSockLogOption_*); multiple values MUST be
 *             bitwise-or'ed together. 0 = none
 * 
 * @return PslError 
 */
PslError
PmSockLogSetOptions(PmSockLogOptions opts);





#if defined(__cplusplus)
}
#endif

#endif //PALMSOCK_LOG_H__

/**@}*/
