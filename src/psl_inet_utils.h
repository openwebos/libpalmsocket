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
 * @file psl_inet_utils.h
 * @ingroup psl_internal 
 * 
 * @brief  Libpalmsocket's private internet utilities
 * 
 * *****************************************************************************
 */
#ifndef PSL_INET_UTILS_H__
#define PSL_INET_UTILS_H__

#include "psl_build_config.h"

#include <stdbool.h>

#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>


#if defined(__cplusplus)
extern "C" {
#endif



/**
 * Generic socket address for ipv4 and ipv6
 */
typedef struct PslInetGenericSockAddr_ {
    int                     family;     ///< AF_INET or AF_INET6
    int                     addrLength; ///< length of the socket address
    union {
        struct sockaddr_in  sa;
        struct sockaddr_in6 sa6;
    };
} PslInetGenericSockAddr;


/// Representation of a binary IPv4 or IPv6 address
typedef struct PslInetIPAddress_ {
    /// family: AF_INET, AF_INET6, or AF_UNSPEC if unknown
    int                     family;

    /// length of the address data field in # of bytes; undefined
    /// when family is AF_UNSPEC
    int                     len;

    /// address data with with len significant bytes; undefined
    /// when family is AF_UNSPEC
    union {
        struct in_addr  ipv4;
        struct in6_addr ipv6;
    } addr;
} PslInetIPAddress;



/**
 * psl_inet_ipaddr_from_string(): Attempts to construct a binary 
 * IP address from the given hostname string 
 * 
 * @param hn Non-NULL, non-empty ASCII string that may represent 
 *           an IP address (IPv4 or IPv6)
 * @param pBuf Pointer to variable for returning result of the 
 *             operation
 * @param userLabel For logging
 * @param cookie For logging
 * 
 * @return bool TRUE if conversion was successful; FALSE if the 
 *         string does not represent a valid IPv4 or IPv6
 *         address.
 */
bool
psl_inet_ipaddr_from_string(const char*         hn,
                            PslInetIPAddress*   pBuf,
                            const char*         userLabel,
                            const void*         cookie);


/**
 * psl_inet_is_hostname_ip_address(): Tests whether the given 
 * hostname string is actually an IP address 
 * 
 * @param hostname Non-NULL, non-empty zero-terminated address
 *                string (ASCII/IA5 encoding)
 * @param userLabel for logging
 * @param cookie for logging
 * 
 * @return bool true if it looks like an IP address; false if 
 *         not
 */
bool
psl_inet_is_hostname_ip_address(const char* hostname,
                                const char* userLabel,
                                const void* cookie);


/**
 * psl_inet_make_sock_addr(): Makes a generic socket address 
 * from the given args 
 * 
 * @param reqFamily Requested address family: AF_INET, AF_INET6,
 *                  or AF_UNSPEC; if AF_UNSPEC, then addrStr
 *                  MUST contain a valid AF_INET or AF_INET6
 *                  address, and AF will be determined from
 *                  addrStr.
 * @param addrStr Non-NULL, non-empty zero-terminated address
 *                string (ASCII/IA5 encoding), or NULL for
 *                INADDR_ANY/in6addr_any
 * @param port Port number or 0 for "any port"
 * @param res Non-NULL location for the result; contents
 *           undefined on error.
 * @param userLabel for logging
 * @param cookie for logging
 * 
 * @return 0 on success, errno on failure
 * 
 * @note getaddrinfo() could do some of the work for us
 */
int
psl_inet_make_sock_addr(int                       reqFamily,
                        const char*               addrStr,
                        int                       port,
                        PslInetGenericSockAddr*   res,
                        const char*               userLabel,
                        const void*               cookie);


/**
 * Configures the given file descriptor to non-blocking mode
 * 
 * @param fd File descriptor 
 * @param userLabel for logging
 * @param cookie for logging
 * 
 * @return PslError
 */
PslError
psl_inet_make_fd_non_blocking(int fd, const char* userLabel, const void* cookie);


/**
 * Initiate a socket connection
 * 
 * @param addrFamily AF_INET or AF_INET6
 * @param addrStr
 * @param port
 * @param userLabel for logging
 * @param cookie for logging
 * 
 * @return PslError
 */
PslError
psl_inet_connect_sock(int         sock,
                      int         addrFamily,
                      const char* addrStr,
                      int         port,
                      const char* userLabel,
                      const void* cookie);





#if defined(__cplusplus)
}
#endif

#endif // PSL_INET_UTILS_H__
