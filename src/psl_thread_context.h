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
 * @file psl_thread_context.h
 * @ingroup psl_internal 
 * 
 * @brief  Internal declarations for libpalmsocket's management
 *         of PmSockThreadContext instances.
 * 
 * *****************************************************************************
 */
#ifndef PSL_THREAD_CONTEXT_H__
#define PSL_THREAD_CONTEXT_H__

#include "psl_build_config.h"

#include <glib.h>

#include "psl_refcount.h"


#if defined(__cplusplus)
extern "C" {
#endif


/**
 * Other libpalmsocket modules may access the non-private
 * member variables as long as those modules hold a reference to
 * the context instance.
 *
 * @see PmSockThreadCtxRef, PmSockThreadCtxUnref
 */
struct PmSockThreadContext_ {
    char*           userLabel;  ///< duplicated string for logging

    GMainContext*   gmainCtx;   ///< referenced gmain context instance

    PslRefcount     refCount_;  ///< reference count (private)
};



#if defined(__cplusplus)
}
#endif

#endif // PSL_THREAD_CONTEXT_H__
