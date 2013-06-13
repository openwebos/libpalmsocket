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
 * @file psl_refcount.h
 * @ingroup psl_internal 
 * 
 * @brief  libpalmsocket's reference-counting abstraction
 * 
 * *****************************************************************************
 */
#ifndef PSL_REFCOUNT_H__
#define PSL_REFCOUNT_H__

#include "psl_build_config.h"

#include <stdbool.h>
#include <glib.h>

#include "psl_assert.h"


#if defined(__cplusplus)
extern "C" {
#endif

typedef struct PslRefcount_ {
    gint            refCount_;
    const char*     staticLabel_;   ///< for logging
    const void*     cookie_;        ///< for logging
} PslRefcount;


/**
 * PSL_REFCOUNT_STATIC_INITIALIZER: this macro may be used to 
 * initialize a static PslRefcount variable instead of calling 
 * psl_refcount_init().  @see psl_refcount_init() for 
 * description of staticLabel and cookie 
 */
#define PSL_REFCOUNT_STATIC_INITIALIZER(staticLabel__, cookie__) {      \
    .refCount_          = 1,                                            \
    .staticLabel_       = (staticLabel__),                              \
    .cookie_            = (cookie__)                                    \
}


/**
 * Initializes the given refcount instance and sets the initial
 * refcount value at 1.
 * 
 * @param counter Non-NULL refcount instance to be initialized
 * @param staticLabel Static string label to be output to log:
 *                    MUST outlive the use of the refcount
 *                    instance (e.g., "fsm"); may be NULL;
 * @param cookie A user-specific 'cookie' value to be output to
 *               log; may be NULL.
 */
PSL_CONFIG_INLINE_FUNC void
psl_refcount_init(PslRefcount*  const counter,
                  const char*   const staticLabel,
                  const void*   const cookie)
{
    PSL_ASSERT(counter);
    counter->refCount_      = 1;
    counter->staticLabel_   = staticLabel;
    counter->cookie_        = cookie;
}


/**
 * Atomically increments reference count by one
 * 
 * @param counter Non-NULL, previously initialized refcount
 *                instance
 */
PSL_CONFIG_INLINE_FUNC void
psl_refcount_atomic_ref(PslRefcount* const counter)
{
    PSL_LOG_DEBUGLOW("%s (label='%s', cookie=%p): refcnt before inc: %d",
                     __func__,
                     PSL_LOG_MAKE_SAFE_STR(counter->staticLabel_),
                     counter->cookie_,
                     (int)g_atomic_int_get(&counter->refCount_));

    g_atomic_int_inc(&counter->refCount_);
}


/**
 * Atomically decrements reference count by one
 * 
 * @param counter Non-NULL, previously initialized refcount
 *                instance
 * 
 * @return bool TRUE if reference count has reached zero as the
 *         result of this unref call; FALSE if not.
 */
PSL_CONFIG_INLINE_FUNC bool
psl_refcount_atomic_unref(PslRefcount* const counter)
{
    PSL_LOG_DEBUGLOW("%s (label=%s, cookie=%p): refcnt before dec: %d",
                     __func__,
                     PSL_LOG_MAKE_SAFE_STR(counter->staticLabel_),
                     counter->cookie_,
                     (int)g_atomic_int_get(&counter->refCount_));

    /**
     * @note g_atomic_int_exchange_and_add() atomically returns the
     *       counter's value just BEFORE the operation.
     */
    return 1 == g_atomic_int_exchange_and_add(&counter->refCount_, -1);
}


#if defined(__cplusplus)
}
#endif

#endif // PSL_REFCOUNT_H__
