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
 * @file psl_build_config.h
 * @ingroup psl_internal 
 * 
 * @brief  libpalmsocket Build Configuration settings
 * 
 * ****************************************************************************
 */

#ifndef PSL_BUILD_CONFIG_H__
#define PSL_BUILD_CONFIG_H__


#if defined(__cplusplus)
extern "C" {
#endif


/**
 * Define the appropriate inline attribute for inline functions
 */
#ifndef PSL_CONFIG_INLINE_FUNC
    #ifdef __GNUC__
        #define PSL_CONFIG_INLINE_FUNC  extern __inline
    #else
        #error "I don't know how to declare inline funcs in this build environment"
    #endif
#endif


/**
 * Define the default logging options for libpalmsocket. The 
 * values are from the PmSockLogOptions defined in 
 * palmsocklog.h. 
 *  
 * This may be controlled at runtime via PmSockLogSetOptions(). 
 *  
 * @see PmSockLogSetOptions 
 *  
 * @ingroup psl_diag_compiletime 
 * @{ 
 */
#ifndef PSL_CONFIG_LOG_OPTIONS_DEFAULT
    #define PSL_CONFIG_LOG_OPTIONS_DEFAULT  (0)
#endif
/**@}*/


/**
 * This macro controls logging of information that should be
 * obfuscated in official builds for various security and
 * personal reasons (e.g., security, embarrassing personal info,
 * etc.), but would be very helpful to have for debugging with a
 * local builds.
 * 
 * @see PSL_LOG_OBFUSCATE_STR
 *  
 * @ingroup psl_diag_compiletime 
 * @{ 
 */
#ifndef PSL_CONFIG_ALLOW_OBFUSCATED_LOGGING
    #define PSL_CONFIG_ALLOW_OBFUSCATED_LOGGING 0
#endif
/**@}*/


/**
 * This macro control logging of input and output of palmsocket
 * data stream.
 * 
 * @note This is definitely something we DON'T want turned on in
 *       official builds.
 *  
 * @ingroup psl_diag_compiletime 
 * @{ 
 */
#ifndef PSL_CONFIG_ALLOW_SOCK_DATASTREAM_LOGGING
    #define PSL_CONFIG_ALLOW_SOCK_DATASTREAM_LOGGING 0
#endif
/**@}*/


/**
 * This macro controls additional error checks that may be
 * enabled in a local build for including extra error-checks
 * taht would be too costly for production builds. 
 *  
 * @ingroup psl_diag_compiletime 
 * @{ 
 */
#ifndef PSL_CONFIG_DEEP_ERROR_CHECKS
    #define PSL_CONFIG_DEEP_ERROR_CHECKS 0
#endif
/**@}*/


#if defined(__cplusplus)
}
#endif

#endif // PSL_BUILD_CONFIG_H__
