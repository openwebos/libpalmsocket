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
 * @file psl_inet_utils.h
 * @ingroup psl_internal 
 * 
 * @brief  Libpalmsocket's private internet utilities
 * 
 * *****************************************************************************
 */
#include "psl_build_config.h"

#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>


#include "palmsockerror.h"

#include "psl_log.h"
#include "psl_assert.h"
#include "psl_error_utils.h"
#include "psl_inet_utils.h"




/** ========================================================================
 * =========================================================================
 */
bool
psl_inet_ipaddr_from_string(const char*         const hn,
                            PslInetIPAddress*   const pBuf,
                            const char*         const userLabel,
                            const void*         const cookie)
{
    PSL_ASSERT(pBuf);

    pBuf->family = AF_UNSPEC;

    if (!hn || !*hn) {
        PSL_LOG_ERROR("%s (%s=%p): ERROR: NULL or empty hostname string",
                      __func__, userLabel, cookie);
        return false;
    }

    int             rc;

    rc = inet_pton(AF_INET, hn, &pBuf->addr);
    if (rc > 0) {
        PSL_LOG_DEBUGLOW("%s (%s=%p): hostname looks like IPv4 address",
                         __func__, userLabel, cookie);
        pBuf->family = AF_INET;
        pBuf->len = sizeof(struct in_addr);
        return true;
    }
    else {
        rc = inet_pton(AF_INET6, hn, &pBuf->addr);
        if (rc > 0) {
            PSL_LOG_DEBUGLOW("%s (%s=%p): hostname looks like IPv6 address",
                             __func__, userLabel, cookie);
            pBuf->family = AF_INET6;
            pBuf->len = sizeof(struct in6_addr);
            return true;
        }
        else {
            PSL_LOG_DEBUGLOW("%s (%s=%p): hostname string '%s' doesn't look " \
                             "like an IP address'.",
                             __func__, userLabel, cookie, PSL_LOG_OBFUSCATE_STR(hn));
        }
    }

    return false;
}//psl_inet_ipaddr_from_string



/** ========================================================================
 * =========================================================================
 */
bool
psl_inet_is_hostname_ip_address(const char* const hn,
                                const char* const userLabel,
                                const void* const cookie)
{
    PslInetIPAddress    pslinaddr;
    return psl_inet_ipaddr_from_string(hn, &pslinaddr, userLabel, cookie);
}//psl_inet_is_hostname_ip_address



/** ========================================================================
 * =========================================================================
 */
int
psl_inet_make_sock_addr(int                       const reqFamily,
                        const char*               const addrStr,
                        int                       const port,
                        PslInetGenericSockAddr*   const res,
                        const char*               const userLabel,
                        const void*               const cookie)
{
    PSL_ASSERT(AF_INET == reqFamily || AF_INET6 == reqFamily ||
           AF_UNSPEC == reqFamily);
    PSL_ASSERT(AF_UNSPEC != reqFamily || (addrStr && addrStr[0]));
    PSL_ASSERT(res);

    memset(res, 0, sizeof(*res));

    res->family = AF_UNSPEC;


    PslInetIPAddress    pslinaddr;
    int                 inaddrlen = 0;

    int actualFamily = reqFamily;

    if (AF_UNSPEC == reqFamily) {
        PSL_LOG_DEBUGLOW("%s (%s=%p): resoloving addrfamily (was AF_UNSPEC)",
                         __func__, userLabel, cookie);
        PSL_ASSERT(addrStr);

        bool const gotAddr = psl_inet_ipaddr_from_string(addrStr, &pslinaddr,
                                                         userLabel, cookie);
        if (gotAddr) {
            actualFamily = pslinaddr.family;
            inaddrlen = pslinaddr.len;
        }
        else {
            PSL_LOG_ERROR("%s (%s=%p): ERROR: could not determine " \
                          "address family from address string '%s'.",
                          __func__, userLabel, cookie,
                          PSL_LOG_OBFUSCATE_STR(addrStr));
            return EINVAL;
        }
    }


    void*   addrDst = NULL;
    if (AF_INET == actualFamily) {
        res->addrLength = sizeof(res->sa);
        res->sa.sin_family = actualFamily;
        res->sa.sin_port = htons(port);
        res->sa.sin_addr.s_addr = INADDR_ANY;
        addrDst = &res->sa.sin_addr;
    }
    else {
        PSL_ASSERT(AF_INET6 == actualFamily);
        res->addrLength = sizeof(res->sa6);
        res->sa6.sin6_family = actualFamily;
        //res->sa6.sin6_flowinfo = 0; ///< what should we do with these?
        //res->sa6.sin6_scope_id = 0;
        res->sa6.sin6_port = htons(port);
        res->sa6.sin6_addr = in6addr_any;
        addrDst = &res->sa6.sin6_addr;
    }

    if (addrStr && inaddrlen) {
        memcpy(addrDst, &pslinaddr.addr, inaddrlen);
    }
    else if (addrStr) {
        PSL_ASSERT(addrDst);
        int const ptonRes = inet_pton(actualFamily, addrStr, addrDst);

        if (ptonRes < 0) {  /// unexpected address family - check errno
            int const saverrno = errno;
            PSL_LOG_ERROR("%s (%s=%p): ERROR: inet_pton() failed; " \
                          "family=%d, addrStr=%s, errno=%d (%s).",
                          __func__, userLabel, cookie, actualFamily,
                          PSL_LOG_OBFUSCATE_STR(addrStr), saverrno,
                          strerror(saverrno));
            PSL_ASSERT(saverrno);
            return saverrno;
        }
        else if (ptonRes == 0) {    /// addr does not match family
            /// @note This case does not set errno
            PSL_LOG_ERROR("%s (%s=%p): ERROR: inet_pton() failed; Address " \
                          "does not match family; family=%d, addrStr=%s.",
                          __func__, userLabel, cookie, actualFamily,
                          PSL_LOG_OBFUSCATE_STR(addrStr));
            return EINVAL;
        }
    }

    res->family = actualFamily;
    return 0;
}// psl_inet_make_sock_addr



/** ========================================================================
 * =========================================================================
 */
PslError
psl_inet_make_fd_non_blocking(int const fd, const char* const userLabel,
                              const void* const cookie)
{
    /// Make it non-blocking
    int const flags = fcntl(fd, F_GETFL, 0);
    if (-1 == flags) {
        int const savederrno = errno;
        PSL_LOG_ERROR("%s (%s=%p): ERROR: fcntl(%d, F_GETFL, 0) failed; " \
                      "errno=%d (%s)", __func__, userLabel, cookie, fd,
                      savederrno, strerror(savederrno));
        return psl_err_pslerror_from_errno(savederrno, PSL_ERR_SOCKET_CONFIG);
    }

    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        int const savederrno = errno;
        PSL_LOG_ERROR("%s (%s=%p): ERROR: fcntl(%d, F_SETFL, " \
                      "flags | O_NONBLOCK) failed; errno=%d (%s)",
                      __func__, userLabel, cookie, fd, savederrno,
                      strerror(savederrno));
        return psl_err_pslerror_from_errno(savederrno, PSL_ERR_SOCKET_CONFIG);
    }

    return 0;
}//psl_inet_make_fd_non_blocking



/** ========================================================================
 * =========================================================================
 */
PslError
psl_inet_connect_sock(int         const s,
                      int         const addrFamily,
                      const char* const addrStr,
                      int         const port,
                      const char* const userLabel,
                      const void* const cookie)
{
    PslInetGenericSockAddr  server;

    PSL_LOG_DEBUG("%s (%s=%p): fd=%d, addrfamily=%d, addrStr=%s, port=%d",
                  __func__, userLabel, cookie, s, addrFamily,
                  PSL_LOG_OBFUSCATE_STR(addrStr), port);

    bool success = !psl_inet_make_sock_addr(addrFamily, addrStr,
                                            port, &server, userLabel, cookie);
    if (!success) {
        return PSL_ERR_BAD_SERV_ADDR;
    }

    int rc = connect(s, (struct sockaddr*)&server.sa, server.addrLength);
    PSL_ASSERT(rc <= 0);
    if (0 == rc) {
        PSL_LOG_DEBUG("%s (%s=%p): connect() succeeded immediately",
                      __func__, userLabel, cookie);
        return 0;
    }
    else if (rc < 0 && EINPROGRESS == errno) {
        PSL_LOG_DEBUG("%s (%s=%p): connect() returned EINPROGRESS",
                      __func__, userLabel, cookie);
        return 0;
    }
    /* @todo The implication of EINTR
             when connecting on a non-blocking socket is vague, at best.
             Should we retry connect(), assume that all is well, or give up
             on this connection?
    else if (rc < 0 && EINTR == errno) {
        PSL_LOG_DEBUG("%s (fsm=%p): connect() returned EINTR",
                      __func__, pFsm);
        return 0;
    }
    */
    else { /// (rc < 0)
        int const saverrno = errno;
        PSL_LOG_ERROR("%s (%s=%p): ERROR: connect() failed; errno=%d (%s)",
                      __func__, userLabel, cookie, saverrno, strerror(saverrno));

        return psl_err_pslerror_from_connect_errno(saverrno);
    }
}//psl_inet_connect_sock
