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
 * @file palmsockerror.h
 * @ingroup psl_error
 * 
 * @brief  Error numbers and functions for libpalmsocket.
 * @{
 * *****************************************************************************
 */
#ifndef PALMSOCK_ERROR_H__
#define PALMSOCK_ERROR_H__

#include <glib.h>


#if defined(__cplusplus)
extern "C" {
#endif




/**
 * libpalmsocket error codes
 * 
 * @brief These are returned libpalmsocket v2.0 API and used
 *        with the PmSockErrGErrorDomain() GError domain errors
 *        returned by libpalmsocket v1.0 API
 */
typedef enum PslError_
{
    PSL_ERR_NONE                  = 0,
    PSL_ERR_ACCESS                , /* Permission denied:e.g.,EACCES from bind()*/
    PSL_ERR_ADDRINUSE             , /* Address already in use (EADDRINUSE) */
    PSL_ERR_ADDRNOTAVAIL          , /* Can't bind to address (EADDRNOTAVAIL)*/
    PSL_ERR_ALREADY               , /* Operation already in progress (EALREADY) */
    PSL_ERR_BAD_SERV_ADDR         , /* Invalid server address */
    PSL_ERR_BAD_BIND_ADDR         , /* Invalid local bind address */
    PSL_ERR_FAILED                , /* Non-specific libpalmsocket error */
    PSL_ERR_GETADDRINFO           , /* Can't resolve address */
    PSL_ERR_INTR                  , /* Interrupted system call (EINTR) */
    PSL_ERR_INVAL                 , /* Invalid argument (EINVAL) */
    PSL_ERR_IO                    , /* EIO */
    PSL_ERR_ISCONN                , /* Already connected (EISCONN) */
    PSL_ERR_MEM                   , /* Out of memory (ENOMEM)*/
    PSL_ERR_NOT_ALLOWED           , /* Operation not allowed in current state */
    PSL_ERR_NOTCONN               , /* Not connected (ENOTCONN) */
    PSL_ERR_OPENSSL               , /* Non-specific OPENSSL error value */
    PSL_ERR_OVERFLOW              , /* EOVERFLOW */
    PSL_ERR_PIPE                  , /* EPIPE */
    PSL_ERR_SOCKET                , /* Error opening socket */
    PSL_ERR_SOCKET_CONFIG         , /* Error configuring socket */
    PSL_ERR_SSL_ALERT_UNKNOWN_CA  , /* TLS alert received: unknown CA */
    PSL_ERR_SSL_BAD_EOF           , /* Unexpected, unclean SSL EOF */
    PSL_ERR_SSL_CERT_VERIFY       , /* SSL cert verification failed */
    PSL_ERR_SSL_CONFIG            , /* SSL instance SSL_new or config failed */
    PSL_ERR_SSL_CONNECT           , /* SSL connection attempt failed */
    PSL_ERR_SSL_CTX               , /* Non-specific SSL CTX error value */
    PSL_ERR_SSL_CLEAN_EOF         , /* 'Close notify' alert received from peer */
    PSL_ERR_SSL_HOSTNAME_MISMATCH , /* Certificate does not match hostname */
    PSL_ERR_SSL_PROTOCOL          , /* Non-specific SSL protocol error */
    PSL_ERR_SSL_SHUT_FAIL         , /* SSL shutdown failed */
    PSL_ERR_SSL_WANT_READ         , /* Internal: waiting for readable sock */
    PSL_ERR_SSL_WANT_WRITE        , /* Internal: waiting for writeable sock */
    PSL_ERR_SYSCALL               , /* Non-specific system call failed */
    PSL_ERR_TCP_CONNECT           , /* TCP/IP connection attempt failed */
    PSL_ERR_TCP_CONNREFUSED       , /* ECONNREFUSED from connect() */
    PSL_ERR_TCP_CONNRESET         , /* Connection reset by peer (ECONNRESET) */
    PSL_ERR_TCP_CONN_AGAIN        , /* EAGAIN from connect(); see 'man connect' */
    PSL_ERR_TCP_NETUNREACH        , /* ENETUNREACH */
    PSL_ERR_TIMEDOUT              , /* ETIMEDOUT */
    PSL_ERR_WOULDBLOCK            , /* Operation would block (EWOULDBLOCK) */


    /// Not an actual error code: makes sure our Enum type is 'wide' enough for
    /// future changes
    PSL_ERR_reserved              = 0xFFFFFFFFUL
} PslError;


/**
 * Returns libpalmsocket's error quark value.
 * 
 * Useful for comparing to the GError::domain member to
 * determine whether the error code is a PslError value.
 * 
 * @note The returned value is generated at runtime by glib and
 *       may differ between process instances.
 * 
 * @return GQuark
 * 
 * @see g_quark_from_static_string
 */
GQuark
PmSockErrGErrorDomain();


/**
 * Given a PslError error code, return the corresponding static
 * error string
 * 
 * @param code PslError error code
 * 
 * @return const char* Thread-local error string corresponding
 *         to the given PslError error code.  libpalmsocket owns
 *         the string, and user MUST NOT delete or alter it in
 *         any way.  The string must be consumed before the next
 *         libpalmsocket call from the same thread.
 */
const char* 
PmSockErrStringFromError(PslError code);





#if defined(__cplusplus)
}
#endif

#endif //PALMSOCK_ERROR_H__

/**@}*/
