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
 * @file psl_error_utils.h
 * @ingroup psl_internal 
 * 
 * @brief  Error utilities for libpalmsocket.
 * 
 * *****************************************************************************
 */
#ifndef PSL_ERROR_UTILS_H__
#define PSL_ERROR_UTILS_H__

#include "psl_build_config.h"

#include <glib.h>
#include <glib-object.h>

#include <openssl/ssl.h>

#include "palmsockerror.h"

#include "psl_log.h"
#include "psl_channel_fsm_fwd.h"


#if defined(__cplusplus)
extern "C" {
#endif


/**
 * Maps an errno value to the corresponding PslError code.
 * 
 * @note WARNING: for conversion of error codes from a call to
 *       connect(), use psl_err_pslerror_from_connect_errno()
 *       instead!
 * 
 * @param errnoCode An errno value (EAGAIN, EACCESS, etc.)
 * @param defaultResult An PslError value to return if an exact
 *                      mapping isn't found.
 * 
 * @return PslError PslError code matching the given errnoCode.
 *         If no exact match is found, the value from the
 *         defaultResult arg is returned.
 * 
 * @see psl_err_pslerror_from_connect_errno()
 */
PslError
psl_err_pslerror_from_errno(int errnoCode, PslError defaultResult);



/**
 * Converts a connect()-related errno value to PslError
 * 
 * @note Some errno values are context-sensitive and result in
 *       unexpected interpretations.  Error code mappings in
 *       such cases should be resolved at a higher level in
 *       order to preserve semantics.  For example, EWOULDBLOCK
 *       is defined to have the same value as EAGAIN. Typically,
 *       EWOULDBLOCK after read/write on a non-blocking
 *       fd/socket means that you have to wait for the socket to
 *       be readable/writeable and then try again. However,
 *       EAGAIN (same value as EWOULDBLOCK) returned from
 *       connect() means out-of-local-ports or
 *       insufficient-entries-in-routing-cache, and waiting on
 *       the socket will not help.  Instead, connect() returns
 *       EINPROGRESS to indicate that we should wait on the
 *       non-blocking socket to become writeable (and then check
 *       SO_ERROR states).
 * 
 * @param connErrno errno value that resulted from a failed
 *                  connect() call.
 * 
 * @return PslError
 * 
 * @see psl_err_pslerror_from_errno
 */
PslError
psl_err_pslerror_from_connect_errno(int connErrno);



/**
 * Maps the given GError value to a PslError code
 * 
 * @param fsm
 * @param gerr
 * 
 * @return PslError
 */
PslError
psl_err_pslerror_from_gerror(const GError* gerr);


/**
 * Maps from a PslError code to a GIOChannelError code.
 * 
 * @param pslErrorCode Non-zero PSLError code (GIOChannelError
 *                     enum doesn't have a "success" equivalent)
 * 
 * @return GIOChannelError
 */
GIOChannelError
psl_err_giochanerror_from_pslerror(PslError pslErrorCode);


/**
 * Maps from GIOChannelError code to PslError code
 * 
 * @param gioErrorCode
 * 
 * @return PslError
 */
PslError
psl_err_pslerror_from_giochanerror(GIOChannelError gioErrorCode);



/**
 * Returns a newly-instantiated GError instance in the
 * libpalmsocket error domain corresponding to the given error
 * code.
 * 
 * @param pslerr PslError code
 * 
 * @return GError* A newly-instantiated GError instance
 *         corresponding to the given PslError code, or NULL if
 *         the PslError code is 0.  The GError instance
 *         will be of the PmSockErrGErrorDomain() domain with a
 *         PslError code. The caller is responsible for
 *         destroying the non-NULL GError instance via
 *         g_error_free or equivalent.
 */
GError*
psl_err_pslgerror_from_pslerror(PslError pslerr);



/**
 * Generates a GIOChannel GError instance from the given
 * PslError code
 * 
 * @param err Non-zero PslError code
 * 
 * @return GError* GError instance with GIOChannelError code in
 *         the g_io_channel_error_quark domain corresponding to
 *         the given PslError code or NULL if the PslError code
 *         is PSL_ERR_NONE (GIOChannelError does not have a
 *         "success" equivalent). The caller is responsible for
 *         destroying the non-NULL GError instance via
 *         g_error_free or equivalent.
 */
GError*
psl_err_giochangerror_from_pslerror(PslError const pslerr);



/// Numeric error type used by openssl
typedef unsigned long PslOpensslErr_t;

/// size of text buffer (in bytes) to pass to ERR_error_string_n() and friends
#define PSL_ERR_OPENSSL_ERROR_BUF_SIZE  (120 + 50/*fudge, just in case*/)


/**
 * Calls SSL_get_error(pFsm->sslInfo.ssl, sslFuncRet) and
 * deduces the corresponding PslError code
 * 
 * @param pFsm
 * @param sslFuncRet Error value returned directly by the
 *                   openssl SSL channel function (e.g.,
 *                   SSL_connect())
 * @param defaultPslErr Non-zero, default PslError value to be
 *                      returned if an exact mapping cannot be
 *                      made
 * 
 * @return PslError 0 (zero) if SSL_get_error() returns
 *         SSL_ERROR_NONE; otherwise a non-zero PslError code
 *         corresponding to the SSL channel error.
 */
PslError
psl_err_get_and_process_SSL_channel_error(struct PslChanFsm_*   pFsm,
                                          SSL*                  ssl,
                                          int                   sslFuncRet,
                                          PslError              defaultPslErr);

/**
 * Get the earliest SSL error from openssl's thread-specific
 * error stack and map it to PslError value, then clear all
 * openssl errors stacked for the calling thread.
 * 
 * @param client A 'client' pointer value to output when logging
 * @param errStringBuf If bufSize is positive, this
 *                   location will be used to return the error
 *                   text (an empty string is guaranteed at the
 *                   minimum).
 * @param bufSize Size of buffer errStringBuf or 0 to suppress
 *                error string output.
 * @param defaultPslErr Non-zero, default PslError error value
 *                   to return if there is a value one on
 *                   openssl's thread-specific error stack, but
 *                   we don't have an exact mapping.
 * @param defaultErrString If not NULL, specifies an error
 *                         string that should be returned (via
 *                         pErrString) if couldn't obtain an
 *                         error string from openssl. If NULL, a
 *                         string will be obtained via
 *                         PmSockErrStringFromError if
 *                         needed.
 * @return PSL_ERR_NONE is returned if the openssl error stack is
 *         empty; otherwise, the PslError PSL error code
 *         corresponding to the top-most error on the OPENSSL
 *         thread-specific error stack or defaultPslErr if there
 *         was no exact mapping.
 */
PslError
psl_err_process_and_purge_openssl_err_stack(const void* client,
                                            char        errStringBuf[],
                                            int         bufSize,
                                            PslError    defaultPslErr,
                                            const char* defaultErrString);

/**
 * Takes an openssl error code and maps it to the PslError value
 * 
 * @param opensslErr openssl error code from ERR_get_error() (a
 *                   hash of libNum, funcCode, and reasonCode)
 * 
 * @param defaultPslErr PSL error code to substitute if a
 *                      mapping was not found
 * 
 * @return PslError PSL error code that maps to the given
 *         opensslErr error value, or the value of defaultPslErr
 *         if no mappig was found.
 */
PslError
psl_err_pslerror_from_openssl_err_stack_code(PslOpensslErr_t    opensslErr,
                                             PslError           defaultPslErr);


/**
 * PSL_ERR_LOG_AND_SET_GERROR - takes the same args as g_set_error,
 * logs the error, and returns a GError instance in ppError if
 * ppError is not NULL.
 * 
 * void PSL_ERR_LOG_AND_SET_GERROR(GError** ppError,
 *                             GQuark errQuark,
 *                             gint errCode,
 *                             const gchar *fmt, ...);
 */
#define PSL_ERR_LOG_AND_SET_GERROR(ppError__, errQuark__, errCode__, ...) \
do { \
    GError* gerr__ = g_error_new((errQuark__), (errCode__), \
                                 __VA_ARGS__); \
    const char* domainStr__ = g_quark_to_string(gerr__->domain); \
    PSL_LOG_ERROR("ERROR: domain=%s, code=%d (%s); func=%s, lineNo=%d", \
                  PSL_LOG_MAKE_SAFE_STR(domainStr__), \
                  (int)gerr__->code, \
                  PSL_LOG_MAKE_SAFE_STR(gerr__->message), \
                  __func__, (int)__LINE__); \
    g_propagate_error ((ppError__), gerr__); \
} while ( 0 )




#if defined(__cplusplus)
}
#endif

#endif //PSL_ERROR_UTILS_H__
