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
 * @file psl_assert.h
 * @ingroup psl_internal 
 *  
 * @brief  assert-related utilites for the libpalmsocket
 *         implementation.
 * 
 * *****************************************************************************
 */
#ifndef PSL_ASSERT_H__
#define PSL_ASSERT_H__


#include "psl_build_config.h"

#include <stdbool.h>
#include <assert.h>

#include "psl_log.h"


#if defined(__cplusplus)
extern "C" {
#endif

/**
 * Test the given predicate and log if it evaluates to FALSE,
 * passing the failure to the standard assert() macro.
 */
#define PSL_ASSERT(pred__) \
    do { \
        const int fail__ = !(pred__); \
        if (fail__) { \
            PSL_LOG_FATAL("ERROR: FAILED ASSERTION: <%s>, func=%s, line=%d", \
                #pred__, __func__, (int)__LINE__); \
            /* FORCE a failed assert() statement */ \
            assert(!("failed expression: " #pred__)); \
        } \
    } while ( 0 )



/**
 * Compile-time, static assertion: If expression evaluates to
 * false, compilation should faile with a divide-by-zero error.
 * assertionName__ is used to form the name of the typedef that
 * is used to perform the compile-time assertion.
 */
#define PSL_ASSERT_STATIC(assertionName__, expr__) \
    typedef struct { int foo : expr__; } assertionName__ 


#if defined(__cplusplus)
}
#endif

#endif // PSL_ASSERT_H__
