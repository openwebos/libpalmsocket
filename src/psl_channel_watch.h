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
 * @file psl_channel_watch.h
 * @ingroup psl_internal 
 * 
 * @brief  palmsocket watch GSource definitions.
 * 
 * *****************************************************************************
 */
#ifndef PSL_CHANNEL_WATCH_H__
#define PSL_CHANNEL_WATCH_H__

#include "psl_build_config.h"

#include <glib.h>

#include "palmsocket.h"

//#include "psl_channel_fwd.h"
#include "psl_channel.h"


#if defined(__cplusplus)
extern "C" {
#endif


/**
 * Create a watch source for the given PmSockIOChannel
 * instance.  The resulting source instance MUST be used on the
 * same thread as the corresponding palmsocket channel instance.
 * 
 * The source is created with an initial reference count of 1,
 * which is owned by the user.
 * 
 * A valid PmSockWatch instance pointer may be
 * type-cast to a GSource pointer for operations requiring a
 * GSource.
 * 
 * @param pWatch Non-NULL pointer to location for returning the
 *               newly-created PmSockWatch instance
 *               on success; undefined on failure
 * @param channel The PmSockIOChannel instance for which the
 *                watch is being created.
 * @param conditions Conditions to monitor
 * 
 * @return PslError 0 on success; PslError error code on
 *         failure.
 */
PslError
psl_chan_watch_new(PmSockWatch** pWatch,
                   PmSockIOChannel* channel,
                   GIOCondition conditions);


#if defined(__cplusplus)
}
#endif

#endif // PSL_CHANNEL_WATCH_H__
