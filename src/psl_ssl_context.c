/* @@@LICENSE
*
*      Copyright (c) 2009-2012 Hewlett-Packard Development Company, L.P.
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
 * @file psl_ssl_context.c
 * @ingroup psl_internal 
 * 
 * @brief  libpalmsocket's management of PmSockSSLContext
 *         instances.
 * 
 * *****************************************************************************
 */
#include "psl_build_config.h"

#include <stdbool.h>
#include <string.h>
#include <glib.h>

#include <openssl/ssl.h>

#include "palmsocket.h"
#include "psl_log.h"
#include "psl_assert.h"
#include "psl_error_utils.h"
#include "psl_refcount.h"
#include "psl_openssl_init.h"
#include "psl_ssl_context.h"


//#define DEFAULT_CAFILE_PATH "/etc/ssl/certs/ca-certificates.crt"
#define DEFAULT_CAFILE_PATH (NULL)
#define DEFAULT_CADIR       "/var/ssl/certs"


static void
ssl_context_destroy_internal(PmSockSSLContext* ctx);


/* ============================================================================
 *                            FUNCTIONS
 * ============================================================================
 */


/* =========================================================================
 * =========================================================================
 */
PslError
PmSockSSLCtxNew(const char* const userLabel, PmSockSSLContext** const pSSLCtx)
{
    PSL_LOG_DEBUG("%s: pSSLCtx=%p, userLabel=\"%s\"", 
                  __func__, pSSLCtx, PSL_LOG_MAKE_SAFE_STR(userLabel));

    PSL_ASSERT(pSSLCtx); *pSSLCtx = NULL;

    struct PmSockSSLContext_* const ctx =
        g_new0(struct PmSockSSLContext_, 1);

    PslError    pslerr = 0;

    if (!ctx) {
        pslerr = PSL_ERR_MEM;
        goto error_cleanup;
    }

    psl_refcount_init(&ctx->refCount_, "PSL_SSL_CTX", ctx);

    psl_openssl_init_conditional(kPmSockOpensslInitType_DEFAULT);

    ctx->userLabel = g_strdup(userLabel ? userLabel : "PSL_user");
    if (!ctx->userLabel) {
        pslerr = PSL_ERR_MEM;
        goto error_cleanup;
    }


    PSL_LOG_DEBUG("%s (ctx=%p/%s): New SSL Context memory allocated",
                  __func__, ctx, ctx->userLabel);

    /// Allocate an openssl SSL Context instance and initialize it
    char errTextBuf[PSL_ERR_OPENSSL_ERROR_BUF_SIZE] = "";

    ctx->opensslCtx = SSL_CTX_new(SSLv23_method());
    if (!ctx->opensslCtx) {
        pslerr = psl_err_process_and_purge_openssl_err_stack(ctx, errTextBuf,
                                                             sizeof(errTextBuf),
                                                             PSL_ERR_SSL_CTX,
                                                             NULL);
        pslerr = pslerr ? pslerr : PSL_ERR_SSL_CTX;
        PSL_LOG_ERROR("%s (ctx=%p/%s): ERROR: SSL_CTX_new() failed: '%s'",
                      __func__, ctx, ctx->userLabel, errTextBuf);
        goto error_cleanup;
    }
    if (!SSL_CTX_load_verify_locations(ctx->opensslCtx,
                                       DEFAULT_CAFILE_PATH,
                                       DEFAULT_CADIR)) {

        pslerr = psl_err_process_and_purge_openssl_err_stack(ctx, errTextBuf,
                                                             sizeof(errTextBuf),
                                                             PSL_ERR_SSL_CTX,
                                                             NULL);
        pslerr = pslerr ? pslerr : PSL_ERR_SSL_CTX;
        PSL_LOG_ERROR(
            "%s (ctx=%p/%s): ERROR: SSL_CTX_load_verify_locations " \
            "failed: cafile=%s, cadir=%s ('%s')", __func__, ctx, ctx->userLabel,
            PSL_LOG_MAKE_SAFE_STR(DEFAULT_CAFILE_PATH),
            PSL_LOG_MAKE_SAFE_STR(DEFAULT_CADIR), errTextBuf);
        goto error_cleanup;
    }

    if (!SSL_CTX_set_default_verify_paths(ctx->opensslCtx)) {

        pslerr = psl_err_process_and_purge_openssl_err_stack(ctx, errTextBuf,
                                                             sizeof(errTextBuf),
                                                             PSL_ERR_SSL_CTX,
                                                             NULL);
        pslerr = pslerr ? pslerr : PSL_ERR_SSL_CTX;
        PSL_LOG_ERROR(
            "%s (ctx=%p/%s): ERROR: SSL_CTX_set_default_verify_paths " \
            "failed: '%s'", __func__, ctx, ctx->userLabel, errTextBuf);
        goto error_cleanup;
    }


    PSL_LOG_DEBUG("%s (ctx=%p/%s): SUCCESS: PSL SSL Context created",
                  __func__, ctx, ctx->userLabel);
    *pSSLCtx = ctx;
    return 0;

error_cleanup:
    PSL_ASSERT(pslerr);
    PSL_LOG_FATAL("%s (ctx=%p/%s): ERROR: PslError=%d (%s)", __func__, ctx,
                  PSL_LOG_MAKE_SAFE_STR(userLabel),
                  (int)pslerr, PmSockErrStringFromError(pslerr));
    if (ctx) {
        ssl_context_destroy_internal(ctx);
    }
    return pslerr;
}//PmSockSSLCtxNew



/** ========================================================================
 * =========================================================================
 */
struct ssl_ctx_st*
PmSockSSLCtxPeekOpensslContext(PmSockSSLContext* const ctx)
{
    PSL_ASSERT(ctx);

    PSL_LOG_DEBUGLOW("%s (ctx=%p/%s): opensslCtx=%p",
                     __func__, ctx, ctx->userLabel, ctx->opensslCtx);

    return ctx->opensslCtx;
}//PmSockSSLCtxPeekOpensslContext



/* =========================================================================
 * =========================================================================
 */
PmSockSSLContext*
PmSockSSLCtxRef(PmSockSSLContext* const ctx)
{
    PSL_ASSERT(ctx);

    PSL_LOG_DEBUGLOW("%s (ctx=%p/%s)", __func__, ctx, ctx->userLabel);

    psl_refcount_atomic_ref(&ctx->refCount_);

    return ctx;
}



/** ========================================================================
 * =========================================================================
 */
void
PmSockSSLCtxUnref(PmSockSSLContext* const ctx)
{
    PSL_ASSERT(ctx);

    PSL_LOG_DEBUGLOW("%s (ctx=%p/%s)", __func__, ctx, ctx->userLabel);


    if (!psl_refcount_atomic_unref (&ctx->refCount_)) {
        return;
    }

    ssl_context_destroy_internal(ctx);
}


/* =========================================================================
 * =========================================================================
 */
static void
ssl_context_destroy_internal(PmSockSSLContext* const ctx)
{
    PSL_LOG_DEBUG("%s: PSL ctx=%p", __func__, ctx);

    PSL_ASSERT(ctx);

    g_free(ctx->userLabel);

    if (ctx->opensslCtx) {
        SSL_CTX_free(ctx->opensslCtx);
    }

    PmSockOpensslUninit();

    g_free(ctx);
}

