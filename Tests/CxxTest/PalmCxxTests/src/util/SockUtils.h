/* @@@LICENSE
*
*      Copyright (c) 2009-2011 Hewlett-Packard Development Company, L.P.
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
 * @file SockUtils.h
 * @ingroup psl_test
 * 
 * @brief  Socket utilities for libpalmsocket Debug/test blade.
 * 
 * *****************************************************************************
 */

#ifndef PSL_TEST_BLADE_SOCK_UTILS_H
#define PSL_TEST_BLADE_SOCK_UTILS_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <assert.h>
#include <netdb.h>
#include <error.h>
#include <errno.h>
#include <string.h>


const int kSockUtilInvalidFD  = -1;

/**
 * Generic socket address for ipv4 and ipv6
 */
typedef struct SockUtilGenSA_ {
    int                     family;     ///< AF_INET or AF_INET6
    int                     addrLength; ///< length of the socket address
    union {
        ///< generic address access; len=SockUtilGenSA::addrLength
        uint8_t             sa[1]; 

        struct sockaddr_in  sa4;
        struct sockaddr_in6 sa6;
    };
} SockUtilGenSA;



/**
 * Get and clear the SOL_SOCKET/SO_ERROR option on the given
 * socket
 * 
 * @param s
 * 
 * @return int value of the SO_ERROR option (0 if no error is
 *         set; non-zero errno-compatible value if error is set)
 */
inline int
sock_util_get_and_clear_so_error(int s)
{
    /// @note getsockopt(..., SO_ERROR, ...)  should also clear SO_ERROR
    int soerror = 0;
    socklen_t solen = sizeof(soerror);
    int rc = ::getsockopt(s, SOL_SOCKET, SO_ERROR, &soerror, &solen);
    assert(0 == rc);

    return soerror;
}



/**
 * Makes the given FD non-blocking
 * 
 * @param fd Any file descriptor, including a socket
 * 
 * @return int 0 on success; non-zero errno-compatible error
 *         code on error.
 */
inline int
sock_util_make_fd_non_blocking(int fd)
{
    //::printf("Making FD %d non-blocking\n", fd);
    int x;
    x = ::fcntl(fd, F_GETFL, 0);
    if (-1 == x) {
        int const saverrno = errno;
        ::error(0, saverrno, "ERROR in fcntl(s, F_GETFL, 0), errno=%d", saverrno);
        return saverrno;
    }
    x = ::fcntl(fd, F_SETFL, x | O_NONBLOCK);
    if (-1 == x) {
        int const saverrno = errno;
        ::error(0, saverrno, "ERROR in fcntl(s, F_SETFL, x | O_NONBLOCK), errno=%d",
                saverrno);
        return saverrno;
    }

    return 0;
}


/**
 * Makes a generic socket address from the given args
 * 
 * @param reqFamily Requested address family: AF_INET, AF_INET6,
 *                  or AF_UNSPEC; if AF_UNSPEC, then addrStr
 *                  MUST contain a valid AF_INET or AF_INET6
 *                  address, and AF will be determined from
 *                  addrStr.
 * @param addrStr Non-NULL, non-empty zero-terminated address
 *                string, or NULL for INADDR_ANY/in6addr_any
 * @param port Port number or 0 for "any port"
 * @param res Non-NULL location for the result; contents
 *            undefined on error.
 * 
 * @return 0 on success, non-zero errno value on failure
 * 
 * @note getaddrinfo() could do some of the work for us
 */
inline int
sock_util_make_sock_addr(int                const reqFamily,
                         const char*        const addrStr,
                         int                const port,
                         SockUtilGenSA*     const res)
{
    assert(AF_INET == reqFamily || AF_INET6 == reqFamily ||
           AF_UNSPEC == reqFamily);
    assert(AF_UNSPEC != reqFamily || (addrStr && addrStr[0]));
    assert(res);

    ::memset(res, 0, sizeof(*res));

    res->family = AF_UNSPEC;


    struct in6_addr inaddr;
    int             inaddrlen = 0;

    int actualFamily = reqFamily;

    if (AF_UNSPEC == actualFamily) {
        int             rc;

        rc = ::inet_pton(AF_INET, addrStr, &inaddr);
        if (rc > 0) {
            actualFamily = AF_INET;
            inaddrlen = sizeof(struct in_addr);
        }
        else {
            rc = ::inet_pton(AF_INET6, addrStr, &inaddr);
            if (rc > 0) {
                actualFamily = AF_INET6;
                inaddrlen = sizeof(struct in6_addr);
            }
            else {
                ::fprintf(stderr, "%s: ERROR: could not determine address " \
                          "family from address string.\n", __func__);
                return EINVAL;
            }
        }
    }

    void*   addrDst = NULL;
    if (AF_INET == actualFamily) {
        res->sa4.sin_family = actualFamily;
        res->sa4.sin_port = htons(port);
        res->sa4.sin_addr.s_addr = INADDR_ANY;
        addrDst = &res->sa4.sin_addr;
        res->addrLength = sizeof(res->sa4);
    }
    else {
        res->sa6.sin6_family = actualFamily;
        //res->sa6.sin6_flowinfo = 0; ///< what should we do with these?
        //res->sa6.sin6_scope_id = 0;
        res->sa6.sin6_port = htons(port);
        res->sa6.sin6_addr = ::in6addr_any;
        addrDst = &res->sa6.sin6_addr;
        res->addrLength = sizeof(res->sa6);
    }

    if (addrStr && inaddrlen) {
        ::memcpy(addrDst, &inaddr, inaddrlen);
    }
    else if (addrStr) {
        int const ptonRes = ::inet_pton(actualFamily, addrStr, addrDst);

        if (ptonRes < 0) {  /// unexpected address family - check errno
            int const savederrno = errno;
            ::fprintf(stderr, "%s: ERROR: inet_pton() failed; " \
                      "family=%d, errno=%d (%s)\n", __func__,
                      actualFamily, savederrno, ::strerror(savederrno));
            assert(savederrno);
            return savederrno;
        }
        else if (ptonRes == 0) {    /// addr does not match family
            /// @note This case does not set errno
            ::fprintf(stderr, "%s: ERROR: inet_pton() failed; " \
                      "Address does not match family; family=%d.\n",
                      __func__, actualFamily);
            return EINVAL;
        }
    }

    res->family = actualFamily;
    return 0;
}//sock_util_make_sock_addr



/**
 * Bind a socket to the given address
 * 
 * @param s
 * @param addr
 * 
 * @return 0 on success, non-zero errno value on failure
 */
inline int
sock_util_bind_sock(int const s, const SockUtilGenSA* const addr)
{
	//::printf("Binding socket %d\n", s);
	int const bindRes = ::bind(s, (struct sockaddr*)&addr->sa, addr->addrLength);
	if (bindRes < 0) {
		int const savederrno = errno;
		::fprintf(stderr, "%s: ERROR: bind() failed; errno=%d (%s)\n",
                  __func__, savederrno, ::strerror(savederrno));
		return savederrno;
	}

	return 0;
}



/**
 * Creates and configures a non-blocking TCP/IP socket
 * appropriate for accepting incoming connections.
 * 
 * The successfully-created socket should be waited upon the
 * readable-ready indication and accepted when so.
 * 
 * @param reqFamily Requested address family: AF_INET, AF_INET6,
 *                  or AF_UNSPEC; if AF_UNSPEC, then addrStr
 *                  MUST contain a valid AF_INET or AF_INET6
 *                  address, and AF will be determined from
 *                  addrStr.
 * @param addrStr Non-NULL, non-empty zero-terminated address
 *                string, or NULL for INADDR_ANY/in6addr_any
 * @param port Port number or 0 for "any port"
 * @param listenQueueSize socket listen queue size (passed
 *                        directly to the listen() function)
 * @param pSock Non-NULL location for the resulting socket file
 *              descriptor; contents undefined on error.
 * 
 * @return 0 on success, non-zero errno value on failure
 */
inline int
sock_util_make_nb_listening_sock(int                const reqFamily,
                                 const char*        const addrStr,
                                 int                const port,
                                 int                const listenQueueSize,
                                 int*               const pSock)
{
    int res = 0;
    int rc = 0;


    assert(pSock);

    int s = *pSock = kSockUtilInvalidFD;

    /**
     * Process the given address/port info
     */
    SockUtilGenSA   bindAddr;
    res = sock_util_make_sock_addr(reqFamily, addrStr, port, &bindAddr);
    if (res) {
        goto error_exit;
    }

    /**
     * Create the socket
     */
    s = ::socket(bindAddr.family, SOCK_STREAM, 0);
    if (s < 0) {
		res = errno;
        ::perror("socket(bindAddr.family, SOCK_STREAM, 0) failed");
        goto error_exit;
    }

    /**
     * Allow socket address reuse in case the server is restarted
     * before the required wait time expires
     */
    {
        int const on = 1;
        rc = ::setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
        if (rc < 0) {
            res = errno;
            ::perror("setsockopt(s, SOL_SOCKET, SO_REUSEADDR,...) failed");
            goto error_exit;
        }
    }


    /**
     * Bind the socket to the requested address/port
     */
    res = sock_util_bind_sock(s, &bindAddr);
    if (res) {
        goto error_exit;
    }

    /**
     * Allow the server to accept incoming connections
     */
    if (::listen(s, listenQueueSize) < 0) {
		res = errno;
        ::perror("listen(sd, listenQueueSize) failed");
        goto error_exit;
    }

    /**
     * Exiting with success!
     */
    *pSock = s;
    return 0;

error_exit:
    assert(res);
    if (s >= 0) {
        ::close(s);
    }

    return res;
}


#endif //PSL_TEST_BLADE_SOCK_UTILS_H
