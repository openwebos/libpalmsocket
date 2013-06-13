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
 * @file psl_thread_context.c
 * @ingroup psl_internal 
 * 
 * @brief  libpalmsocket's management of PmSockThreadContext
 *         instances.
 * 
 * *****************************************************************************
 */
#include "psl_build_config.h"

#include <stdbool.h>
#include <string.h>
#include <glib.h>

#include "palmsocket.h"
#include "psl_log.h"
#include "psl_assert.h"
#include "psl_error_utils.h"
#include "psl_refcount.h"

#include "psl_thread_context.h"



static void
thread_context_destroy_internal(PmSockThreadContext* ctx);


/* ============================================================================
 *                            FUNCTIONS
 * ============================================================================
 */


/* =========================================================================
 * =========================================================================
 */
PslError
PmSockThreadCtxNewFromGMain(GMainContext*                 gmainCtx,
                            const char*             const userLabel,
                            PmSockThreadContext**   const pThreadCtx)
{
    PSL_LOG_DEBUG("%s: pThreadCtx=%p, userLabel=\"%s\", gmaincxt=%p", 
                  __func__, pThreadCtx, PSL_LOG_MAKE_SAFE_STR(userLabel),
                  gmainCtx);

    PSL_ASSERT(pThreadCtx); *pThreadCtx = NULL;

    struct PmSockThreadContext_* const ctx =
        g_new0(struct PmSockThreadContext_, 1);

    PslError    pslerr = 0;

    if (!ctx) {
        pslerr = PSL_ERR_MEM;
        goto error_cleanup;
    }

    psl_refcount_init(&ctx->refCount_, "PSL_THREAD_CTX", ctx);

    ctx->userLabel = g_strdup(userLabel ? userLabel : "PSL_user");
    if (!ctx->userLabel) {
        pslerr = PSL_ERR_MEM;
        goto error_cleanup;
    }

    gmainCtx = gmainCtx ? gmainCtx : g_main_context_default();
    ctx->gmainCtx = g_main_context_ref(gmainCtx);


    PSL_LOG_DEBUG("%s (%s): PSL Thread Context created: ctx=%p",
                  __func__, ctx->userLabel, ctx);
    *pThreadCtx = ctx;
    return 0;

error_cleanup:
    PSL_ASSERT(pslerr);
    PSL_LOG_FATAL("%s (%s): ERROR: PslError=%d (%s)", __func__,
                  PSL_LOG_MAKE_SAFE_STR(userLabel),
                  (int)pslerr, PmSockErrStringFromError(pslerr));
    if (ctx) {
        thread_context_destroy_internal(ctx);
    }
    return pslerr;
}//PmSockThreadCtxNewFromGMain



/* =========================================================================
 * =========================================================================
 */
GMainContext*
PmSockThreadCtxPeekGMainContext(PmSockThreadContext* const ctx)
{
    PSL_ASSERT(ctx);

    PSL_LOG_DEBUGLOW("%s (ctx=%p/%s): gmainCtx=%p",
                     __func__, ctx, ctx->userLabel, ctx->gmainCtx);

    return ctx->gmainCtx;
}



/* =========================================================================
 * =========================================================================
 */
PmSockThreadContext*
PmSockThreadCtxRef(PmSockThreadContext* const ctx)
{
    PSL_ASSERT(ctx);

    PSL_LOG_DEBUGLOW("%s (ctx=%p/%s)", __func__, ctx, ctx->userLabel);

    psl_refcount_atomic_ref(&ctx->refCount_);

    return ctx;
}



/* =========================================================================
 * =========================================================================
 */
void
PmSockThreadCtxUnref(PmSockThreadContext* const ctx)
{
    PSL_ASSERT(ctx);

    PSL_LOG_DEBUGLOW("%s (ctx=%p/%s)", __func__, ctx, ctx->userLabel);


    if (!psl_refcount_atomic_unref (&ctx->refCount_)) {
        return;
    }

    thread_context_destroy_internal(ctx);
}


/* =========================================================================
 * =========================================================================
 */
static void
thread_context_destroy_internal(PmSockThreadContext* const ctx)
{
    PSL_LOG_DEBUG("%s (ctx=%p/%s)", __func__, ctx,
                  PSL_LOG_MAKE_SAFE_STR(ctx->userLabel));

    PSL_ASSERT(ctx);

    g_free(ctx->userLabel);

    if (ctx->gmainCtx) {
        g_main_context_unref(ctx->gmainCtx);
    }

    g_free(ctx);


    PSL_LOG_DEBUGLOW("%s (ctx=%p): LEAVING", __func__, ctx);
}

