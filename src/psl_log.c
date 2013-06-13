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
 * @file psl_log.c
 * @ingroup psl_internal 
 * 
 * @brief  Logging module for libpalmsocket implementation.
 * 
 * *****************************************************************************
 */
#include "psl_build_config.h"

#include <stdbool.h>

#include <glib.h>

#include <PmLogLib.h>

#include "psl_log.h"


/**
 * This flag tracks whether the logging module is initialized or
 * not. Set by psl_log_init() during library construction and
 * cleared by psl_log_uninit() during library destruction.
 */
static bool gIsPslLogInit = false;


/**
 * This variable tracks logging options for libpalmsocket. 
 * 
 * Checking this variable in PSL_LOG_* macros before calling
 * into PmLogLib saves considerable overhead (evaluation of 
 * arguments) even when the corresponding log level is disabled 
 * for our logging context. 
 * 
 * @note We use gint in order to take advantage of glib's atomic
 *       access functions.  The values are actually from
 *       PmSockLogOptions, defined in palmsocklog.h.
 */
gint gPslLogOptions = PSL_CONFIG_LOG_OPTIONS_DEFAULT;


/**
 * Our PmLogLib logging context.  Initialized by psl_log_init()
 * during per-process library construction
 */
PmLogContext gPslLogContext;

static const char* const kPslLogContextName = "libpalmsocket";


/* ============================================================================
 *                            FUNCTIONS
 * ============================================================================
 */


/* =========================================================================
 * =========================================================================
 */
PslError
PmSockLogSetOptions(PmSockLogOptions const opts)
{
    if ((opts & ~kPmSockLogOption_ALL_OPTS) != 0) {
        PSL_LOG_ERROR("%s: invalid log options=0x%X",
                      __func__, (opts & ~kPmSockLogOption_ALL_OPTS));
        return PSL_ERR_INVAL;
    }

    PSL_LOG_INFO("%s: setting log options to 0x%X; old options were 0x%X",
                 __func__, (unsigned)opts,
                 (unsigned)g_atomic_int_get(&gPslLogOptions));

    /**
     * @note There is a race condition between the get (in logging) 
     *       and the following set (in case this function is called
     *       from multiple threads at the same time), but it's not
     *       important for the usage model of what we're trying to
     *       accomplish in this function.
     */

    g_atomic_int_set(&gPslLogOptions, (gint)opts);

    return PSL_ERR_NONE;
}


/* =========================================================================
 * =========================================================================
 */
void
psl_log_init(void)
{
    (void)PmLogGetContext(kPslLogContextName, &gPslLogContext);

    gIsPslLogInit = true;

    if (psl_log_is_psl_log_option_set(kPmSockLogOption_debuglow)) {
        PmLogPrint(gPslLogContext, kPmLogLevel_Critical,
                   "%s: WARNING: "
                   "kPmSockLogOption_debuglow IS NOW TURNED ON, "
                   "BUT IT MUST BE TURNED OFF IN OFFICIAL BUILDS!!!",
                   __func__);
    }

    if (PSL_CONFIG_ALLOW_OBFUSCATED_LOGGING) {
        PmLogPrint(gPslLogContext, kPmLogLevel_Critical,
                   "%s: WARNING: DANGER, DANGER... "
                   "PSL_CONFIG_ALLOW_OBFUSCATED_LOGGING IS NOW TURNED ON, "
                   "BUT IT MUST BE TURNED OFF IN OFFICIAL BUILDS!!!",
                   __func__);
    }

    if (PSL_CONFIG_ALLOW_SOCK_DATASTREAM_LOGGING) {
        PmLogPrint(gPslLogContext, kPmLogLevel_Critical,
                   "%s: WARNING: DANGER, DANGER... "
                   "PSL_CONFIG_ALLOW_SOCK_DATASTREAM_LOGGING IS NOW TURNED ON, "
                   "BUT IT MUST BE TURNED OFF IN OFFICIAL BUILDS!!!",
                   __func__);
    }
}


/* =========================================================================
 * =========================================================================
 */
void
psl_log_uninit(void)
{
    gIsPslLogInit = false;
}


/* =========================================================================
 * psl_log_process_obfuscated_str - refer to
 * PSL_LOG_OBFUSCATE_STR() for more details
 * @param str
 * @param funcName
 * 
 * @return const char*
 * =========================================================================
 */
const char*
psl_log_process_obfuscated_str(const char* str, const char* funcName)
{
    if (!PSL_CONFIG_ALLOW_OBFUSCATED_LOGGING) {
        return "[OBFUSCATED]";
    }

    else {
        PSL_LOG_CRITICAL("%s: WARNING: PSL_CONFIG_ALLOW_OBFUSCATED_LOGGING "
                         "IS NOW TURNED ON, BUT IT MUST BE TURNED OFF "
                         "IN OFFICIAL BUILDS!!!", funcName);
        return PSL_LOG_MAKE_SAFE_STR(str);
    }
}
