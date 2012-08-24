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
 * @file psl_error_utils.c
 * @ingroup psl_internal 
 * 
 * @brief  Error utilities for libpalmsocket.
 * *****************************************************************************
 */
#include "psl_build_config.h"

#include <stdio.h>

#include <glib.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <glib-object.h>

#include "psl_log.h"
#include "psl_assert.h"
#include "psl_channel_fsm_main.h"
#include "psl_error_utils.h"

static PslError
pslerror_from_openssl_lib_ssl_reason_code(int reasonCode, PslError defaultResult);



/* =========================================================================
 * =========================================================================
 */
GQuark PmSockErrGErrorDomain (void)
{
    static GQuark error_quark = 0;
    
    if (error_quark == 0) {
        error_quark = g_quark_from_static_string ("libpalmsocket-error-quark");
    }
    
    return error_quark;
}



/* =========================================================================
 * =========================================================================
 */
PslError
psl_err_pslerror_from_errno(int errnoCode, PslError defaultResult)
{
    switch (errnoCode) {
    case 0:             return PSL_ERR_NONE;
        break;
    case EACCES:        return PSL_ERR_ACCESS;
        break;
    case EADDRINUSE:    return PSL_ERR_ADDRINUSE;
        break;
    case EADDRNOTAVAIL: return PSL_ERR_ADDRNOTAVAIL;
        break;
    case EALREADY:      return PSL_ERR_ALREADY;
        break;
    case ECONNREFUSED:  return PSL_ERR_TCP_CONNREFUSED;
        break;
    case ECONNRESET:    return PSL_ERR_TCP_CONNRESET;
        break;
    case EINTR:         return PSL_ERR_INTR;
        break;
    case EINVAL:        return PSL_ERR_INVAL;
        break;
    case EIO:           return PSL_ERR_IO;
        break;
    case EISCONN:       return PSL_ERR_ISCONN;
        break;
    case ENETUNREACH:   return PSL_ERR_TCP_NETUNREACH;
        break;
    case ENOMEM:        return PSL_ERR_MEM;
        break;
    case ENOTCONN:      return PSL_ERR_NOTCONN;
        break;
    case EOVERFLOW:     return PSL_ERR_OVERFLOW;
        break;
    case EPIPE:         return PSL_ERR_PIPE;
        break;
    case ETIMEDOUT:     return PSL_ERR_TIMEDOUT;
        break;
    case EWOULDBLOCK:   return PSL_ERR_WOULDBLOCK;
        break;
    default:            return defaultResult;
        break;

    }
}//psl_err_pslerror_from_errno



/* =========================================================================
 * =========================================================================
 */
PslError
psl_err_pslerror_from_connect_errno(int const connErrno)
{
    /**
     * @note EAGAIN (which has the same value as EWOULDBLOCK) is a
     *       special case for connect() since it indicates that
     *       insufficient resources weren available to start the
     *       connection, so the connection wasn't even started, and
     *       waiting on the socket won't help.
     */
    switch (connErrno) {
    case 0:             return 0;
        break;
    case EAGAIN:        return PSL_ERR_TCP_CONN_AGAIN;
        break;
    default:            return psl_err_pslerror_from_errno(connErrno,
                                                           PSL_ERR_TCP_CONNECT);
        break;

    }
}



/* =========================================================================
 * =========================================================================
 */
PslError
psl_err_pslerror_from_gerror(const GError* const gerr)
{
    PSL_ASSERT(gerr);

    if (gerr->domain == PmSockErrGErrorDomain()) {
        return gerr->code;
    }

    else if (gerr->domain == g_io_channel_error_quark()) {
        return psl_err_pslerror_from_giochanerror(gerr->code);
    }

    else {
        PSL_LOG_ERROR("%s: ERROR: unexpected GError: domain='%s', " \
                      "code=%d (%s)",
                      __func__, g_quark_to_string (gerr->domain),
                      gerr->code, PSL_LOG_MAKE_SAFE_STR(gerr->message));
        return PSL_ERR_FAILED;
    }
}



/* =========================================================================
 * =========================================================================
 */
GIOChannelError
psl_err_giochanerror_from_pslerror(PslError const pslErrorCode)
{
    /// @note There is no 'success' equivalent in GIOChannelError enum.
    PSL_ASSERT(pslErrorCode);

    switch (pslErrorCode) {
    case PSL_ERR_INVAL:       return G_IO_CHANNEL_ERROR_INVAL;
        break;
    case PSL_ERR_IO:          return G_IO_CHANNEL_ERROR_IO;
        break;
    case PSL_ERR_OVERFLOW:    return G_IO_CHANNEL_ERROR_OVERFLOW;
        break;
    case PSL_ERR_PIPE:        return G_IO_CHANNEL_ERROR_PIPE;
        break;
    default:                return G_IO_CHANNEL_ERROR_FAILED;
        break;
    }

}



/* =========================================================================
 * =========================================================================
 */
PslError
psl_err_pslerror_from_giochanerror(GIOChannelError gioErrorCode)
{
    switch (gioErrorCode) {
    case G_IO_CHANNEL_ERROR_INVAL:      return PSL_ERR_INVAL;
        break;
    case G_IO_CHANNEL_ERROR_IO:         return PSL_ERR_IO;
        break;
    case G_IO_CHANNEL_ERROR_OVERFLOW:   return PSL_ERR_OVERFLOW;
        break;
    case G_IO_CHANNEL_ERROR_PIPE:       return PSL_ERR_PIPE;
        break;
    case G_IO_CHANNEL_ERROR_FAILED: /// FALLTHROUGH
    case G_IO_CHANNEL_ERROR_FBIG:   /// FALLTHROUGH
    case G_IO_CHANNEL_ERROR_ISDIR:  /// FALLTHROUGH
    case G_IO_CHANNEL_ERROR_NOSPC:  /// FALLTHROUGH
    case G_IO_CHANNEL_ERROR_NXIO:       return PSL_ERR_FAILED;
        break;
    }

    return PSL_ERR_FAILED;
}



/* =========================================================================
 * =========================================================================
 */
GError*
psl_err_pslgerror_from_pslerror(PslError const pslerr)
{
    if (!pslerr) {
        return NULL;
    }

    return g_error_new(PmSockErrGErrorDomain(), pslerr,
                       "ERROR: PslError code=%d (%s)",
                       (int)pslerr,
                       PmSockErrStringFromError(pslerr));
}



/* =========================================================================
 * =========================================================================
 */
GError*
psl_err_giochangerror_from_pslerror(PslError const pslerr)
{
    if (!pslerr) {
        return NULL;
    }

    GIOChannelError const gioerr = psl_err_giochanerror_from_pslerror(pslerr);

    return g_error_new(
        g_io_channel_error_quark(),
        gioerr,
        "ERROR: GIOChannelError=%d, libpalmsocket PslError=%d (%s)",
        (int)gioerr, (int)pslerr,
        PmSockErrStringFromError(pslerr));
}



/* =========================================================================
 * =========================================================================
 */
const char* 
PmSockErrStringFromError(PslError code)
{
    switch (code) {
    case PSL_ERR_ACCESS:          return "Permission denied (EACCES)";
        break;
    case PSL_ERR_ALREADY:         return "Operation already in progress";
        break;
    case PSL_ERR_ADDRINUSE:       return "Address already in use (EADDRINUSE)";
        break;
    case PSL_ERR_ADDRNOTAVAIL:    return "Can't assign address (EADDRNOTAVAIL)";
        break;
    case PSL_ERR_BAD_BIND_ADDR:   return "Invalid local bind address";
        break;
    case PSL_ERR_BAD_SERV_ADDR:   return "Invalid server address";
        break;
    case PSL_ERR_FAILED:          return "Non-specific error";
        break;
    case PSL_ERR_GETADDRINFO:     return "Address resolution failed";
        break;
    case PSL_ERR_INTR:            return "Interrupted system call (EINTR)";
        break;
    case PSL_ERR_INVAL:           return "Invalid argument (EINVAL)";
        break;
    case PSL_ERR_IO:              return "I/O error (EIO)";
        break;
    case PSL_ERR_ISCONN:          return "Already connected (EISCONN)";
        break;
    case PSL_ERR_MEM:             return "Out of memory";
        break;
    case PSL_ERR_NONE:            return "ok";
        break;
    case PSL_ERR_NOT_ALLOWED:     return "Operation not allowed";
        break;
    case PSL_ERR_NOTCONN:         return "Not connected";
        break;
    case PSL_ERR_OPENSSL:         return "openssl error";
        break;
    case PSL_ERR_OVERFLOW:        return "Value too large for type (EOVERFLOW)";
        break;
    case PSL_ERR_PIPE:            return "Broken pipe (EPIPE)";
        break;
    case PSL_ERR_SOCKET:          return "socket() failed";
        break;
    case PSL_ERR_SOCKET_CONFIG:   return "Socket configuration failed";
        break;
    case PSL_ERR_SSL_ALERT_UNKNOWN_CA:
                                  return "TLS alert received: unknown CA";
        break;
    case PSL_ERR_SSL_CERT_VERIFY: return "Certificate verification failed";
        break;
    case PSL_ERR_SSL_CONFIG:      return "openssl SSL_new or config failed";
        break;
    case PSL_ERR_SSL_CONNECT:     return "SSL connect failed";
        break;
    case PSL_ERR_SSL_CTX:         return "openssl context error";
        break;
    case PSL_ERR_SSL_BAD_EOF:     return "Unexpected, unclean SSL EOF";
        break;
    case PSL_ERR_SSL_CLEAN_EOF:   return "SSL 'Close notify' alert rx from peer";
        break;
    case PSL_ERR_SSL_HOSTNAME_MISMATCH:
                                  return "Certificate does not match hostname";
        break;
    case PSL_ERR_SSL_PROTOCOL:    return "Non-specific SSL protcol error";
        break;
    case PSL_ERR_SSL_SHUT_FAIL:   return "SSL shutdown failed";
        break;
    case PSL_ERR_SSL_WANT_READ:   return "Internal: waiting for readable sock";
        break;
    case PSL_ERR_SSL_WANT_WRITE:  return "Internal: waiting for writeable sock";
        break;
    case PSL_ERR_SYSCALL:         return "Non-specific system call failed";
        break;
    case PSL_ERR_TCP_CONNECT:     return "TCP/IP connect attempt failed";
        break;
    case PSL_ERR_TCP_CONN_AGAIN:  return "Connect failed (EAGAIN)";
        break;
    case PSL_ERR_TCP_CONNREFUSED: return "Connect failed (ECONNREFUSED)";
        break;
    case PSL_ERR_TCP_CONNRESET:   return "Connection reset by peer (ECONNRESET)";
        break;
    case PSL_ERR_TCP_NETUNREACH:  return "Connect failed (ENETUNREACH)";
        break;
    case PSL_ERR_TIMEDOUT:        return "Connect failed (ETIMEDOUT)";
        break;
    case PSL_ERR_WOULDBLOCK:      return "Would block (EWOULDBLOCK)";
        break;
    case PSL_ERR_reserved:        return "PSL_ERR_reserved";
        break;
    }

    PSL_LOG_WARNING("%s: Unmapped libpalmsocket error code (%d)",
                    __func__, (int)code);
    return "Unexpected libpalmsocket error code";
}



/* =========================================================================
 * =========================================================================
 */
PslError
psl_err_get_and_process_SSL_channel_error(
    struct PslChanFsm_*   const pFsm,
    SSL*                  const ssl,
    int                   const sslFuncRet,
    PslError              const defaultPslErr)
{
    PSL_ASSERT(defaultPslErr != 0);

    int const savederrno = errno;

    int const sslErr = SSL_get_error(ssl, sslFuncRet);

    if (SSL_ERROR_NONE == sslErr) {
        return PSL_ERR_NONE;
    }

    switch (sslErr) {
    PslError    pslErr;

    case SSL_ERROR_NONE:
        return PSL_ERR_NONE;
        break;

    case SSL_ERROR_SSL:
        pslErr = psl_err_process_and_purge_openssl_err_stack(
            pFsm, NULL, 0, defaultPslErr, NULL);
        return (pslErr ? pslErr : defaultPslErr);
        break;

    case SSL_ERROR_ZERO_RETURN:
        PSL_LOG_INFO("%s (fsm=%p): TLS/SSL Clean EOF " \
                     "(SSL_ERROR_ZERO_RETURN)", __func__, pFsm);
        return PSL_ERR_SSL_CLEAN_EOF;
        break;

    case SSL_ERROR_SYSCALL:
        /// @see 'man SSL_get_error'

        /// First, check the openssl error stack
        pslErr = psl_err_process_and_purge_openssl_err_stack(
            pFsm, NULL, 0, PSL_ERR_SYSCALL, NULL);
        if (pslErr) {
            return pslErr; ///< openssl error stack was _not_ empty
        }

        /// Now, check the code returned by the failed openssl function
        if (0 == sslFuncRet) {
            pslErr = PSL_ERR_SSL_BAD_EOF;
            PSL_LOG_ERROR("%s (fsm=%p): ERROR: pslerr=%d (%s)",
                          __func__, pFsm, pslErr, PmSockErrStringFromError(pslErr));
        }
        else if (-1 == sslFuncRet) { /// consult errno
            pslErr = psl_err_pslerror_from_errno(savederrno, PSL_ERR_SYSCALL);
            pslErr = (pslErr ? pslErr : PSL_ERR_SYSCALL);
            PSL_LOG_ERROR("%s (fsm=%p): ERROR: errno=%d (%s), pslerr=%d (%s)",
                          __func__, pFsm, savederrno, strerror(savederrno),
                          pslErr, PmSockErrStringFromError(pslErr));
        }
        return pslErr;
        break;

    case SSL_ERROR_WANT_CONNECT:
        PSL_LOG_ERROR("%s (fsm=%p): ERROR: unexpected SSL_ERROR_WANT_CONNECT",
                      __func__, pFsm);
        return PSL_ERR_OPENSSL;
        break;
    case SSL_ERROR_WANT_ACCEPT:
        PSL_LOG_ERROR("%s (fsm=%p): ERROR: unexpected SSL_ERROR_WANT_ACCEPT",
                      __func__, pFsm);
        return PSL_ERR_OPENSSL;
        break;

    case SSL_ERROR_WANT_X509_LOOKUP:
        PSL_LOG_ERROR(
            "%s (fsm=%p): ERROR: unexpected SSL_ERROR_WANT_X509_LOOKUP",
            __func__, pFsm);
        return PSL_ERR_OPENSSL;
        break;

    case SSL_ERROR_WANT_READ:
        PSL_LOG_DEBUG("%s (fsm=%p): SSL is waiting for readable sock",
                      __func__, pFsm);
        return PSL_ERR_SSL_WANT_READ;
        break;

    case SSL_ERROR_WANT_WRITE:
        PSL_LOG_DEBUG("%s (fsm=%p): SSL is waiting for writeable sock",
                      __func__, pFsm);
        return PSL_ERR_SSL_WANT_WRITE;
        break;
    }

    return defaultPslErr;
}



/* =========================================================================
 * =========================================================================
 */
PslError
psl_err_process_and_purge_openssl_err_stack(
    const void*         const client,
    char*               const errStringBuf,
    int                 const bufSize,
    PslError            const defaultPslErr,
    const char*         const defaultErrString)
{
    PslOpensslErr_t opensslErr = 0;
    PslError        pslErr = 0;

    PSL_ASSERT(defaultPslErr != 0);

    if (bufSize) {
        PSL_ASSERT(errStringBuf);
        errStringBuf[0] = '\0';
    }

    bool gotErrors = false;

    while ((opensslErr = ERR_get_error()) != 0) {
        gotErrors = true;

        char errText[PSL_ERR_OPENSSL_ERROR_BUF_SIZE] = "";
        ERR_error_string_n(opensslErr, errText, sizeof(errText));

        if (!pslErr) {
            pslErr = psl_err_pslerror_from_openssl_err_stack_code(opensslErr,
                                                                  defaultPslErr);
            if (bufSize) {
                snprintf(errStringBuf, bufSize, "%s", errText);
            }
        }

        const int libNum = ERR_GET_LIB(opensslErr);
        const int funcCode = ERR_GET_FUNC(opensslErr);
        const int reasonCode = ERR_GET_REASON(opensslErr);

        PSL_LOG_ERROR("%s (client=%p): ERROR from openssl error-stack (raw) "
                      "%lu (0x%lx); lib=%d, func=%d, reason=%d (%s)",
                      __func__, client,
                      (unsigned long)opensslErr,
                      (unsigned long)opensslErr,
                      libNum, funcCode, reasonCode, errText);
    }

    if (!gotErrors) {
        return PSL_ERR_NONE;
    }

    PSL_ASSERT(pslErr);

    if (bufSize && '\0' == errStringBuf[0]) {
        snprintf(errStringBuf, bufSize, "%s",
                 (defaultErrString
                  ? defaultErrString
                  : PmSockErrStringFromError(pslErr)));
    }

    return pslErr;
}



/* =========================================================================
 * =========================================================================
 */
PslError
psl_err_pslerror_from_openssl_err_stack_code(PslOpensslErr_t opensslErr,
                                             PslError defaultPslErr)
{
    /**
     * @todo The default case
     *       needs to be fleshed out further
     * 
     * see ERR_LIB_X509, ERR_LIB_X509V3, ERR_LIB_PKCS12, etc.
     * 
     * see ERR_load_BIO_strings
     * 
     * see SYS_F_SOCKET, etc.
     * 
     * Also, see ERR_FATAL_ERROR()
     */

    PSL_ASSERT(defaultPslErr);

    if (!opensslErr) {
        return PSL_ERR_NONE;
    }

    int const libNum = ERR_GET_LIB(opensslErr);
    int const reasonCode = ERR_GET_REASON(opensslErr);

    switch (libNum) {
    case ERR_LIB_SYS:
        return psl_err_pslerror_from_errno(reasonCode, defaultPslErr);
        break;

    case ERR_LIB_SSL:
        return pslerror_from_openssl_lib_ssl_reason_code(reasonCode, defaultPslErr);
        break;

    default:
        return (defaultPslErr ? defaultPslErr : PSL_ERR_OPENSSL);
        break;
    }

}



/** ========================================================================
 *  
 * pslerror_from_openssl_lib_ssl_reason_code(): Maps a reason 
 * code from ERR_LIB_SSL to the corresponding PslError code
 * 
 * @param reasonCode Reason code from ERR_LIB_SSL
 * @param defaultResult An PslError value to return if an exact
 *                      mapping isn't found.
 * 
 * @return PslError PslError code matching the given errnoCode.
 *         If no exact match is found, the value from the
 *         defaultResult arg is returned.
 *  
 * =========================================================================
 */
static PslError
pslerror_from_openssl_lib_ssl_reason_code(int reasonCode, PslError defaultResult)
{
    /**
     * @todo The default case 
     *       should be fleshed out further
     */
    switch (reasonCode) {
    case 0:                                 return PSL_ERR_NONE;
        break;
    case SSL_R_CERTIFICATE_VERIFY_FAILED:   return PSL_ERR_SSL_CERT_VERIFY;
        break;
    case SSL_R_TLSV1_ALERT_UNKNOWN_CA:      return PSL_ERR_SSL_ALERT_UNKNOWN_CA;
        break;
    default:                                return defaultResult;
        break;

    }
}//psl_err_pslerror_from_errno


