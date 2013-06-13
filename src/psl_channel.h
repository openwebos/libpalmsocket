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
 * @file psl_channel.h
 * @ingroup psl_internal 
 * 
 * @brief  Common definitions for the PmSockIOChannel
 *         implementation.  It wraps our openssl integration as
 *         a GIOChannel abstraction
 * 
 * *****************************************************************************
 */
#ifndef PSL_CHANNEL_H__
#define PSL_CHANNEL_H__

#include "psl_build_config.h"

#include <stdbool.h>
#include <glib.h>

#include "psl_channel_fwd.h"


#if defined(__cplusplus)
extern "C" {
#endif


/**
 * PslChanIOReadiness: result arg type for
 * psl_chan_io_readiness_preflight;
 */
typedef struct {
    int             fd;         ///< comms file descriptor; -1 if none

    bool            isClosed;   ///< TRUE if channel is closed

    GIOCondition    pollCond;   ///< conditions that should be polled; 0=none

    GIOCondition    readyCond;  ///< conditions that are ready now
} PslChanIOReadiness;


/**
 * Performs an I/O readiness preflight check; used by
 * psl_channel_watch implementation to determine which I/O
 * conditions are ready now and which should be polled.
 * 
 * @param channel Non-NULL libpalmsocket channel instance to
 *                which you hold a reference.
 * 
 * @param pRes Non-NULL pointer to PslChanIOReadiness structure
 *             for returning results of the operation.
 */
void
psl_chan_do_io_readiness_preflight(struct PmSockIOChannel_*     channel,
                                   GIOCondition                 monCond,
                                   PslChanIOReadiness*          pRes);


/**
 * psl_chan_header_ref(): acquires a reference to the palmsocket 
 * channel's header memory. 
 *  
 * @note palmsock watch (GSource) instances _MUST_ use 
 *       psl_chan_header_ref and psl_chan_header_unref instead
 *       of g_io_channel_ref/g_io_channel_unref in order to
 *       avoid a deadlock in glib's gmain implementation (@see
 *       struct PmSockIOChannel_)
 * 
 * @param channel 
 *  
 * @return The value of the channel arg 
 *  
 * @see PmSockIOChannel_::headerRef
 */
struct PmSockIOChannel_*
psl_chan_header_ref(struct PmSockIOChannel_* channel);

/**
 * psl_chan_header_unref(): Decrements the palmscoket channel's 
 * header memory reference count.  When this reference count 
 * reaches 0 (zero), the struct PmSockIOChannel_ memory is 
 * destroyed. 
 *  
 * @note palmsock watch (GSource) instances _MUST_ use 
 *       psl_chan_header_ref and psl_chan_header_unref instead
 *       of g_io_channel_ref/g_io_channel_unref in order to
 *       avoid a deadlock in glib's gmain implementation
 * 
 * @param channel 
 *  
 * @see PmSockIOChannel_::headerRef
 */
void
psl_chan_header_unref(struct PmSockIOChannel_* channel);


#if defined(__cplusplus)
}
#endif

#endif // PSL_CHANNEL_H__
