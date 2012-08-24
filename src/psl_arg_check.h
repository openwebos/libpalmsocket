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

/**
 * *****************************************************************************
 * @file psl_arg_check.h
 * @ingroup psl_internal 
 *  
 * @brief  arg-checking utilites for the libpalmsocket
 *         implementation.
 * 
 * *****************************************************************************
 */
#ifndef PSL_ARG_CHECK_H__
#define PSL_ARG_CHECK_H__


#include "psl_build_config.h"

#include <stdbool.h>

#include "psl_log.h"


#if defined(__cplusplus)
extern "C" {
#endif

#define PSL_ARG_CHECK_IS_ZERO(arg__)                                            \
        ((0 == (arg__))                                                         \
         ? (true)                                                               \
         : ((PSL_LOG_ERROR(                                                     \
            "%s: ERROR: expected zero value for arg %s, but got 0x%lX; "        \
            "file=%s, line=%d",                                                 \
            __func__, #arg__, (unsigned long)(arg__), __FILE__, __LINE__)), false))


#define PSL_ARG_CHECK_NOT_ZERO(arg__)                                           \
        ((arg__)                                                                \
         ? (true)                                                               \
         : ((PSL_LOG_ERROR(                                                     \
            "%s: ERROR: expected non-zero value for arg %s, but got zero; "     \
            "file=%s, line=%d",                                                 \
            __func__, #arg__, __FILE__, __LINE__)), false))


#define PSL_ARG_CHECK_NOT_NULL(arg__)                                           \
        ((arg__)                                                                \
         ? (true)                                                               \
         : ((PSL_LOG_ERROR(                                                     \
            "%s: ERROR: expected non-NULL value for arg %s, but got NULL; "     \
            "file=%s, line=%d",                                                 \
            __func__, #arg__, __FILE__, __LINE__)), false))


#if defined(__cplusplus)
}
#endif

#endif // PSL_ARG_CHECK_H__
