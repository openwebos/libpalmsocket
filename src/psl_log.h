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
 * @file psl_log.h
 * @ingroup psl_internal 
 * 
 * @brief  Logging module for libpalmsocket implementation.
 * 
 * *****************************************************************************
 */

#ifndef PSL_LOG_H__
#define PSL_LOG_H__

#include "psl_build_config.h"

#include <stdbool.h>

#include <glib.h>

#include <PmLogLib.h>

#include "palmsocklog.h"


#if defined(__cplusplus)
extern "C" {
#endif


/**
 * PSL_LOG_MAKE_SAFE_STR(str) - Wrap string args that might be
 * NULL using this macro when passing such args to logging
 * functions/macros
 * 
 * @param str string that may be NULL
 * 
 * @return const char* A non-NULL string; a NULL string will be
 *         replaced by a string constant
 */
#define PSL_LOG_MAKE_SAFE_STR(str__) psl_log_make_safe_str(str__)

/**
 * PSL_LOG_OBFUSCATE_STR(str) - When passing strings to logging
 * macros and functions that are needed for debugging with local
 * builds, bug should be obfuscated from official builds (e.g.,
 * for security/personal info reasons), wrap them in this macro.
 * 
 * @param str string a (possibly NULL) string that should be
 *            obfuscated
 * 
 * @return const char* A non-NULL string; if obfuscation is
 *         turned on or a NULL string was passed, it will be
 *         replaced by a string constant
 * 
 * @see PSL_CONFIG_ALLOW_OBFUSCATED_LOGGING
 */
#define PSL_LOG_OBFUSCATE_STR(str__) \
    ((!PSL_CONFIG_ALLOW_OBFUSCATED_LOGGING) \
     ? "[OBFUSCATED]" \
     : psl_log_process_obfuscated_str((str__), __func__))

/**
 * PSL_LOG_XXXX Usage Guidelines
 * 
 * The following comments are a set of guidelines for deciding
 * which log level to use for a particular event of interest. To
 * enable a predictable experience when debugging, it's
 * important to use the logging levels consistently.
 * 
 * If you're new to libpalmsocket code, it's a good idea to
 * search the code for particular logging calls, to get a feel
 * for how the various logging levels are used.
 * 
 * PSL_LOG_DEBUGLOW: (Linux mapping: debug) For logging debug
 * info that's too low-level to be included in production code,
 * but useful for low-level debugging on local builds.
 * 
 * PSL_LOG_DEBUG: (Linux mapping: debug) Almost everything that
 * is of interest to log should be logged at the DEBUG level;
 * NOTE: this level will normally be disabled in production at
 * PmLogLib level, but will still incur a fair amount of
 * overhead in PmLogLib's atomic check of the logging context.
 * 
 * PSL_LOG_INFO: (Linux mapping: info) Informational;
 * 
 * PSL_LOG_NOTICE: (Linux mapping: notice) Noramal, but
 * significant condition
 * 
 * PSL_LOG_WARNING: (Linux mapping: warning) Warning conditions;
 * 
 * PSL_LOG_ERROR: (Linux mapping: err); Error condition
 * 
 * PSL_LOG_FATAL: (Linux mapping: crit); Critical condition.
 */

#define PSL_LOG_HELPER(palmLevel__, ...) \
     PmLogPrint(gPslLogContext, (palmLevel__), __VA_ARGS__)


/**
 * PSL_LOG_DEBUGLOW(const char* fmt, ...)
 * 
 * For extra-granular logging details that you would very rarely
 * want to see during typical debugging.
 */
#define PSL_LOG_DEBUGLOW(...)                                                   \
    (psl_log_is_psl_log_option_set(kPmSockLogOption_debuglow)                   \
     ? PSL_LOG_HELPER(kPmLogLevel_Debug, __VA_ARGS__)                           \
     : ((void)0))                                                               \

/**
 * PSL_LOG_DEBUG(const char* fmt, ...)
 */
#define PSL_LOG_DEBUG(...) \
    PSL_LOG_HELPER(kPmLogLevel_Debug, __VA_ARGS__)

/**
 * PSL_LOG_INFO(const char* fmt, ...)
 */
#define PSL_LOG_INFO(...) \
    PSL_LOG_HELPER(kPmLogLevel_Info, __VA_ARGS__)

/**
 * PSL_LOG_NOTICE(const char* fmt, ...)
 */
#define PSL_LOG_NOTICE(...) \
    PSL_LOG_HELPER(kPmLogLevel_Notice, __VA_ARGS__)

/**
 * PSL_LOG_WARNING(const char* fmt, ...)
 */
#define PSL_LOG_WARNING(...) \
    PSL_LOG_HELPER(kPmLogLevel_Warning, __VA_ARGS__)

/**
 * PSL_LOG_ERROR(const char* fmt, ...)
 */
#define PSL_LOG_ERROR(...) \
    PSL_LOG_HELPER(kPmLogLevel_Error, __VA_ARGS__)

/**
 * PSL_LOG_CRITICAL(const char* fmt, ...)
 */
#define PSL_LOG_CRITICAL(...) \
    PSL_LOG_HELPER(kPmLogLevel_Critical, __VA_ARGS__)

/**
 * PSL_LOG_FATAL(const char* fmt, ...)
 */
#define PSL_LOG_FATAL(...)      PSL_LOG_CRITICAL(__VA_ARGS__)


#define PSL_LOG_DATASTREAM_HELPER(palmLevel__, pData__, byteCnt__)              \
    (PSL_CONFIG_ALLOW_SOCK_DATASTREAM_LOGGING                                   \
     ? (void)PmLogDumpData(gPslLogContext, (palmLevel__), (pData__),            \
         (byteCnt__), kPmLogDumpFormatDefault)                                  \
     : ((void)0))

#define PSL_LOG_DATASTREAM_DEBUGLOW(pData__, byteCnt__)                         \
    (psl_log_is_psl_log_option_set(kPmSockLogOption_debuglow)                   \
     ? PSL_LOG_DATASTREAM_HELPER(kPmLogLevel_Debug, (pData__), (byteCnt__))     \
     : ((void)0))
    



/**
 * The following set of macros determine efficiently whether a
 * given log output level is enabled
 */
#define PSL_LOG_IS_DEBUGLOW_ENABLED()                                           \
    (psl_log_is_psl_log_option_set(kPmSockLogOption_debuglow) &&                \
     psl_log_level_is_fully_enabled(kPmLogLevel_Debug))


#define PSL_LOG_IS_DEBUG_ENABLED() \
    psl_log_level_is_fully_enabled(kPmLogLevel_Debug)


#define PSL_LOG_IS_INFO_ENABLED() \
    psl_log_level_is_fully_enabled(kPmLogLevel_Info)


#define PSL_LOG_IS_NOTICE_ENABLED() \
    psl_log_level_is_fully_enabled(kPmLogLevel_Notice)


#define PSL_LOG_IS_WARNING_ENABLED() \
    psl_log_level_is_fully_enabled(kPmLogLevel_Warning)




/**
 * Logging options for use by psl_log module implementation. See
 * psl_log.c for description. 
 * 
 * @note We use gint in order to take advantage of glib's atomic
 *       access functions.  The values are actually from
 *       PmSockLogOptions, defined in palmsocklog.h.
 */
extern gint         gPslLogOptions;

/**
 * Our logging context; initialized during library construction 
 * in psl_log.c. 
 */
extern PmLogContext gPslLogContext;


/**
 * psl_log_init - To be called by the library's per-process
 * constructor.  Initializes libpalmsocket's logging module.
 * psl_log_init MUST be called before any other calls
 * into the logging module!
 */
void
psl_log_init(void);

/**
 * psl_log_uninit - to be called by the library's per-process
 * destructor.  Uninitializes libpalmsocket's logging module.
 * No other psl_log_* functions may be called after calling
 * psl_log_uninit().
 */
void
psl_log_uninit(void);


/**
 * psl_log_is_psl_log_option_set(): 
 *  
 * @param opt 
 * 
 * @return bool True if any of the requested options is/are 
 *         enabled.
 */
PSL_CONFIG_INLINE_FUNC bool
psl_log_is_psl_log_option_set(PmSockLogOptions const opt)
{
    return (0 != (g_atomic_int_get(&gPslLogOptions) & opt));
}


/**
 * @return True, if the given log level is enabled at PmLogLib; 
 *         false if not.
 */
PSL_CONFIG_INLINE_FUNC bool
psl_log_level_is_fully_enabled(PmLogLevel pmLogLevel)
{
    return (PmLogIsEnabled(gPslLogContext, pmLogLevel));
}

/**
 * For use by PSL_LOG_MAKE_SAFE_STR macro only.  Don't call this
 * function directly!  See PSL_LOG_MAKE_SAFE_STR for more info.
 * 
 * @param unsafestr
 * 
 * @return const char*
 */
PSL_CONFIG_INLINE_FUNC const char*
psl_log_make_safe_str(const char* unsafestr)
{
    /**
     * @note using an inline function helps with type-checking
     */
    return (unsafestr) ? (unsafestr) : "(NULL)";
}


/**
 * For use by PSL_LOG_OBFUSCATE_STR macro only.  Don't call
 * this function directly!  See PSL_LOG_OBFUSCATE_STR for more
 * info.
 * 
 * @param str
 * @param funcName
 * 
 * @return const char*
 */
const char*
psl_log_process_obfuscated_str(const char* str, const char* funcName);


#if defined(__cplusplus)
}
#endif

#endif // PSL_LOG_H__
