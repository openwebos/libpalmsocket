/** 
 * *****************************************************************************
 * @file CommonUtils.cpp
 * @ingroup psl_test 
 *  
 * @brief  Common utilities for libpalmsocket Debug/test blade.
 * 
 * *****************************************************************************
 */


#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h> /// For clock_gettime()
#include <errno.h>
#include <assert.h>
#include <string.h>

#include <stdexcept>
#include <algorithm>
#include <string>
#include <sstream>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <glib.h>

#include <palmsocket.h>
#include <palmsocklog.h>

#include "CommonUtils.h"


namespace psl_test_blade {


::GIOStatus
UtilRxPmSockBytes(::PmSockIOChannel*    const pChan,
              void*                 const dst,
              uint32_t              const dstCnt,
              uint32_t*             const pRxCnt,
              bool                  const isVerbose,
              const char*           const userLabel)
{
    *pRxCnt = 0;
    GIOStatus giostatus = G_IO_STATUS_NORMAL;

    do {
        uint32_t    const numRem = dstCnt - *pRxCnt;
        gsize numToRead = std::min(G_MAXSIZE, numRem);

        gchar* const p = (gchar*)((uint8_t*)dst + *pRxCnt);

        GError* pGerror = NULL;
        gsize   numRead = 0;
        giostatus = ::g_io_channel_read_chars(
            (::GIOChannel*)pChan,
            p, numToRead, &numRead,
            &pGerror
            );

        *pRxCnt += numRead;
        assert(*pRxCnt <= dstCnt);

        if (isVerbose) {
            UTIL_PRINT_LINE(
                "%s/%s: g_io_channel_read_chars(%u) completed with: " \
                "GIOStatus=%s, bytesRead=%u, totalReadSoFar=%u",
                userLabel, __func__, numToRead,
                UtilStringFromGIOStatus(giostatus, userLabel),
                numRead, *pRxCnt);
        }

        if (G_IO_STATUS_ERROR != giostatus) {
            assert(!pGerror);
        }

        switch (giostatus) {
        case G_IO_STATUS_ERROR:
            {
                assert(pGerror);

                /// Test PmSockGetLastError
                PslError const lastErr = ::PmSockGetLastError(pChan);
                assert(lastErr);

                if (isVerbose) {
                    UTIL_PRINT_ERROR(
                        "%s/%s: ERROR from g_io_channel_read_chars: " \
                        "%d (%s); PslError=%d (%s)", userLabel, __func__,
                        (int)pGerror->code, pGerror->message,
                        lastErr, PmSockErrStringFromError(lastErr));
                }
                ::g_clear_error(&pGerror);
            }
            break;

        case G_IO_STATUS_NORMAL:
            break;
        case G_IO_STATUS_EOF:
            break;
        case G_IO_STATUS_AGAIN:
            break;
        }
    } while (0 /* *pRxCnt < dstCnt && G_IO_STATUS_NORMAL == giostatus*/);


    assert(*pRxCnt <= dstCnt);

    return giostatus;
}//UtilRxPmSockBytes


::GIOStatus
UtilTxPmSockBytes(::PmSockIOChannel*    const pChan,
              const void*           const src,
              uint32_t              const srcCnt,
              uint32_t*             const pSentCnt,
              bool                  const isVerbose,
              const char*           const userLabel)
{
    *pSentCnt = 0;
    GIOStatus giostatus = G_IO_STATUS_NORMAL;

    do {
        uint32_t    const numRem = srcCnt - *pSentCnt;
        gssize numToWrite = std::min((gsize)G_MAXSSIZE, numRem);

        const gchar* const p = (gchar*)((uint8_t*)src + *pSentCnt);

        GError* pGerror = NULL;
        gsize   numWritten = 0;
        giostatus = g_io_channel_write_chars(
            (::GIOChannel*)pChan, p, numToWrite, &numWritten, &pGerror);

        /**
         * @note According to g_io_channel_write_chars API doc,
         *       numWritten may be non-zero even if return value is not
         *       G_IO_STATUS_NORMAL
         */
        *pSentCnt += numWritten;

        if (isVerbose) {
            UTIL_PRINT_LINE(
                "%s: g_io_channel_write_chars(%d) completed with: " \
                "GIOStatus=%s, numWritten=%u, so far: %u/%u",
                userLabel, numToWrite,
                UtilStringFromGIOStatus(giostatus, userLabel),
                numWritten, *pSentCnt, srcCnt);
        }

        assert(numWritten >= 0);
        assert(numWritten <= (gsize)numToWrite);

        if (::G_IO_STATUS_ERROR == giostatus) {
            assert(pGerror);

            /// Test PmSockGetLastError
            ::PslError const lastErr = ::PmSockGetLastError(pChan);
            assert(lastErr);

            if (isVerbose) {
                UTIL_PRINT_ERROR(
                    "%s: ERROR from g_io_channel_write_chars(%d): " \
                    "%d (%s) after writing %u of %u request bytes; " \
                    "PslError=%d (%s)",
                    userLabel, numToWrite,
                    (int)pGerror->code, pGerror->message,
                    *pSentCnt, srcCnt, lastErr,
                    ::PmSockErrStringFromError(lastErr));
            }
            g_clear_error(&pGerror);


            if (*pSentCnt) {
                giostatus = G_IO_STATUS_AGAIN;
            }

        }

        else {
            assert(!pGerror);
            /// @note We shouldn't see G_IO_STATUS_EOF when writing
            assert(G_IO_STATUS_EOF != giostatus);
            assert(G_IO_STATUS_NORMAL == giostatus ||
                   G_IO_STATUS_AGAIN == giostatus);
        }
    } while (*pSentCnt < srcCnt && G_IO_STATUS_NORMAL == giostatus);


    assert(*pSentCnt <= srcCnt);

    return giostatus;
}//UtilTxPmSockBytes


::PmSockWatch*
UtilCreatePmSockWatch(::PmSockIOChannel*   const pChan,
                  ::GIOCondition       const cond,
                  ::GIOFunc            const cbFunc,
                  void*                const cbArg,
                  const char*          const userLabel)
{
    PmSockWatch* pWatch = NULL;
    PslError const pslerr = ::PmSockCreateWatch(pChan, cond, &pWatch);
    if (pslerr) {
        const std::string errorMsg =
            std::string("PmSockCreateWatch failed: ") +
            ::PmSockErrStringFromError(pslerr);
        UTIL_THROW_FATAL(userLabel, errorMsg.c_str());
    }

    ::GMainContext* const pGMainCtx = ::PmSockThreadCtxPeekGMainContext(
        ::PmSockPeekThreadContext(pChan));
    assert(pGMainCtx);


    ::g_source_set_can_recurse((::GSource*)pWatch, false);
    ::g_source_set_callback((::GSource*)pWatch,
                          (::GSourceFunc)cbFunc,
                          cbArg, NULL);
    ::g_source_attach((::GSource*)pWatch, pGMainCtx);

    return pWatch;
}//UtilCreatePmSockWatch


void
UtilDestroyPmSockWatch(::PmSockWatch* const pWatch)
{
    //UTIL_PRINT_LINE("%s: Detaching PmSockWatch=%p from main loop...", __func__, pWatch);

    ::g_source_destroy((::GSource*)pWatch); ///< detach from main loop

    //UTIL_PRINT_LINE("%s: Finished detaching PmSockWatch=%p from main loop", __func__, pWatch);

    //UTIL_PRINT_LINE("%s: Unref'ing PmSockWatch=%p ...", __func__, pWatch);

    ::g_source_unref((::GSource*)pWatch);   ///< release our reference count

    //UTIL_PRINT_LINE("%s: Finished unref'ing PmSockWatch=%p ...", __func__, pWatch);
}//UtilDestroyPmSockWatch


void
UtilUpdatePmSockWatch(::PmSockWatch* const pWatch,
                  ::GIOCondition const cond,
                  const char*    const userLabel)
{
    PslError const pslerr = ::PmSockWatchUpdate(pWatch, cond);
    if (pslerr) {
        const std::string errorMsg =
            std::string("::PmSockWatchUpdate(pWatch, cond) failed: ") +
            ::PmSockErrStringFromError(pslerr);
        UTIL_THROW_FATAL(userLabel, errorMsg.c_str());
    }
}//UtilUpdatePmSockWatch


void
UtilInitOpenssl(const char* const userLabel)
{
    ::PslError const pslerr = ::PmSockOpensslInit(
        kPmSockOpensslInitType_DEFAULT
        );
    if (pslerr) {
        const std::string errorMsg =
            std::string("PmSockOpensslInit failed: ") +
            ::PmSockErrStringFromError(pslerr);
        UTIL_THROW_FATAL(userLabel, errorMsg.c_str());
    }
}//UtilInitOpenssl



::PmSockSSLContext*
UtilMakeSSLCtx(const char* const userLabel)
{
    /// Create a palmsocket SSL context
    ::PmSockSSLContext* pSSLCtx = NULL;
    ::PslError const pslerr = ::PmSockSSLCtxNew(userLabel, &pSSLCtx);
    if (pslerr) {
        const std::string errorMsg =
            std::string("PmSockSSLCtxNew failed: ") +
            ::PmSockErrStringFromError(pslerr);
        UTIL_THROW_FATAL(userLabel, errorMsg.c_str());
    }

    assert(pSSLCtx);

    return pSSLCtx;
}//UtilMakeSSLCtx


class UtilPmSockSSLCtxRAII {
public:

    UtilPmSockSSLCtxRAII()
    :   pCtx(NULL)
    {
    }

    ~UtilPmSockSSLCtxRAII()
    {
        if (pCtx) {
            ::PmSockSSLCtxUnref(pCtx);
        }
    }

    ::PmSockSSLContext* Release()
    {
        ::PmSockSSLContext*  const c = pCtx;
        pCtx = NULL;
        return c;
    }

    ::PmSockSSLContext*   pCtx;
};



::PmSockSSLContext*
UtilMakeServerSSLCtx(const std::string& rPrivkeyPath, const char* const userLabel)
{
    if (rPrivkeyPath.empty()) {
        const std::string errorMsg =
            std::string(__func__) +  "ERROR: private key path string is empty";
        UTIL_THROW_FATAL(userLabel, errorMsg.c_str());
    }

    UtilPmSockSSLCtxRAII    pmctx;

    pmctx.pCtx = UtilMakeSSLCtx(userLabel);

    struct ssl_ctx_st* opensslctx = PmSockSSLCtxPeekOpensslContext(pmctx.pCtx);
    assert(opensslctx);

    const char* ssl_func_name;

    ssl_func_name = "SSL_CTX_use_RSAPrivateKey_file()";
    int sslres = SSL_CTX_use_RSAPrivateKey_file(opensslctx,
                                                rPrivkeyPath.c_str(),
                                                SSL_FILETYPE_PEM);
    if (1 == sslres) {
        ssl_func_name = "SSL_CTX_use_certificate_file()";
        sslres = SSL_CTX_use_certificate_file(opensslctx,
                                              rPrivkeyPath.c_str(),
                                              SSL_FILETYPE_PEM);
    }
    if (1 == sslres) {
        ssl_func_name = "SSL_CTX_check_private_key()";
        sslres = SSL_CTX_check_private_key(opensslctx);
    }
    if (sslres != 1) {
        unsigned long opensslErr = 0;

        std::ostringstream oss;


        oss << __func__ << ": ERROR: " << ssl_func_name;
        oss << "failed (privkeyPath=" << rPrivkeyPath << "): ";

        while ((opensslErr = ::ERR_get_error()) != 0) {
            char errText[120]; ///< openssl doc recommends 120 bytes
            ERR_error_string_n(opensslErr, errText, sizeof(errText));

            oss << errText << "; ";
        }

        UTIL_THROW_FATAL(userLabel, oss.str().c_str());
    }

    

    return pmctx.Release();
}//UtilMakeServerSSLCtx



void
UtilTriggerSSLRenegotiation(::PmSockIOChannel*  const pChan,
                            ::PmSockRenegOpts   const opts,
                            const char*         const userLabel)
{
    PmSockRenegotiateConf const conf = {
        enabledFlds : kPmSockRenegConfEnabledField_opts,
        opts        : opts
    };

    const PmSockRenegotiateConf* const pConf = opts ? &conf : NULL;

    ::PslError const pslerr = ::PmSockRenegotiateCrypto(pChan, pConf,
                                                        NULL/*cb*/);
    if (pslerr) {
        const std::string errorMsg =
            std::string("PmSockRenegotiateCrypto failed: ") +
            ::PmSockErrStringFromError(pslerr);
        UTIL_THROW_FATAL(userLabel, errorMsg.c_str());
    }
}//UtilTriggerSSLRenegotiation


/**
 * 
 * @note May be called _only_ after SSL/TLS connection 
 *       completion callback (also from that callback) and while
 *       still in SSL mode.
 */
void
UtilDumpPeerVerifyErrorInfo(::PmSockIOChannel* pChan,
                            const char*        userLabel)
{
    ::PmSockPeerCertVerifyErrorInfo verifyErrorInfo;
    ::PslError pslErr = ::PmSockGetPeerCertVerifyError(
        pChan, &verifyErrorInfo);
    if (pslErr) {
        UTIL_PRINT_ERROR("%s/%s: PmSockGetPeerCertVerifyError() FAILED: " \
                         "PslError=%d (%s)",
                         userLabel, __func__, pslErr,
                         ::PmSockErrStringFromError(pslErr));
    }
    else {    
        UTIL_PRINT_LINE("%s/%s: PmSockGetPeerCertVerifyError() reports: " \
                        "X509_V_ERR_=%ld (%s); psl_v_err=%d (%s)",
                        userLabel, __func__,
                        verifyErrorInfo.opensslx509_v_err,
                        ::X509_verify_cert_error_string(
                            verifyErrorInfo.opensslx509_v_err
                            ),
                        verifyErrorInfo.psl_v_err,
                        ::PmSockErrStringFromError(verifyErrorInfo.psl_v_err));
    }
}//UtilDumpPeerVerifyErrorInfo



bool
UtilPslLogOptionFromStr(const char*       const pLogOptStr,
                        PmSockLogOptions* const pLogOpt)
{
    if (0 == strcmp("debuglow", pLogOptStr)) {
        *pLogOpt = kPmSockLogOption_debuglow;
    }
    else
    if (0 == strcmp("none", pLogOptStr)) {
        *pLogOpt = 0;
    }
    else {
        return false;
    }

    return true;
}



const char*
UtilStringFromGIOStatus(GIOStatus const giostatus, const char* const userLabel)
{
    switch (giostatus) {
    case G_IO_STATUS_ERROR:     return "G_IO_STATUS_ERROR";
        break;
    case G_IO_STATUS_NORMAL:    return "G_IO_STATUS_NORMAL";
        break;
    case G_IO_STATUS_EOF:       return "G_IO_STATUS_EOF";
        break;
    case G_IO_STATUS_AGAIN:     return "G_IO_STATUS_AGAIN";
        break;
    }

    UTIL_PRINT_ERROR("%s: ERROR: unexpected GIOStatus value: %d",
                     userLabel, (int)giostatus);
    assert(false && "unexpected GIOStatus value");
}






} // end of namespace psl_test_blade
