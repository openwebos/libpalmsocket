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
 * @file psl_string_utils.h
 * @ingroup psl_internal 
 * 
 * @brief  Libpalmsocket's private string utilities
 * 
 * *****************************************************************************
 */
#ifndef PSL_STRING_UTILS_H__
#define PSL_STRING_UTILS_H__

#include "psl_build_config.h"


#include <string.h>


#if defined(__cplusplus)
extern "C" {
#endif





/** ========================================================================
 * Like strncpy, but guarantees that destination will be 
 * zero-terminated within the available destination buffer 
 * memory; 
 *  
 * @note If bufSize bytes are copied without reaching 
 *       zero-terminator, then the string in the destination
 *       buffer will be truncated
 * 
 * @param dest 
 * @param src 
 * @param n max number of bytes to copy
 * @param bufSize size of destination buffer: MUST be greater 
 *                than 0
 * 
 * @return char* 
 * =========================================================================
 */
PSL_CONFIG_INLINE_FUNC char*
psl_str_zero_strncpy(char* const dest, const char* const src, size_t n,
                     size_t const bufSize)
{
    PSL_ASSERT(bufSize > 0);

    if (n > bufSize) {
        n = bufSize;
    }

    PSL_ASSERT(0 == n || (dest && src));

    size_t i;
    for (i=0; i < n; i++) {
        char const octet = src[i];
        if ('\0' == octet) {
            break;
        }
        dest[i] = octet;
    }

    /// i is now equal to the number of copied octets _before_ zero-termination

    if (i < bufSize) {
        dest[i] = '\0';
    }
    else {
        dest[bufSize-1] = '\0'; ///< truncation
    }

    return dest;
}



#if defined(__cplusplus)
}
#endif

#endif // PSL_STRING_UTILS_H__
