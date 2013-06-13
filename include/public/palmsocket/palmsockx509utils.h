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
 * @file palmsockx509utils.h
 * @ingroup psl_x509utils
 * 
 * @brief  libpalmsocket's X509-related utilities API.
 * 
 * @{ 
 * *****************************************************************************
 */
#ifndef PALMSOCK_X509_UTILS_H__
#define PALMSOCK_X509_UTILS_H__

#include <stdint.h>
#include <stdbool.h>

#include "palmsockerror.h"

#if defined(__cplusplus)
extern "C" {
#endif

/**
 * Options to pass to PmSockX509CheckCertHostNameMatch. 
 *  
 * No options have been defined at this point, so callers MUST 
 * pass 0 for the value of this field. 
 */
typedef long PmSockX509HostnameMatchOpts;

/**
 * PmSockX509CheckCertHostNameMatch(): Attempts to match a name 
 * obtained from a certificate (subjAltName/dNSName or most 
 * specific common name) against the given hostname. 
 *  
 * @note We use the combination of rules per RFC-2595, RFC-2818,
 *       and accepted practices documented in
 *       http://support.microsoft.com/kb/258858
 *  
 * @note The name extracted from the certificate may contain 
 *       wildcard(s), we only support one wildcard, and it may
 *       only be in the left-most label of the domain name, and
 *       it must be immediately followed by the label-separator
 *       character ('.')
 *  
 * Examples: In the following table of match/mismatch examples, 
 *          the tag "<any>" in the HOSTNAME column means "any
 *          _valid_ hostname"
 *  
 * @verbatim
 *  
 *      CERT-NAME               HOSTNAME                MATCH?
 *      ======================================================
 *      ""                  vs. <any>                   error
 *      <any>               vs. ""                      error
 *      "*"                 vs. com, palm.com           no
 *      "co*"               vs. com                     no  
 *      "*om"               vs. com, palm.com           no  
 *      "*alm.com"          vs. palm.com                no  
 *      "p*lm.com"          vs. palm.com                no
 *      "www.*.com"         vs. www.palm.com            no
 *      "www.pa*.com"       vs. www.palm.com            no
 *      "*.*.com"           vs. www.palm.com            no  
 *      "w*.p*.com"         vs. www.palm.com            no  
 *      "*.palm.com"        vs. "palm.com"              no  
 *      "*.palm.com         vs. "www.eas.palm.com"      no  
 *      "palm*.com"         vs. "palm.com"              no  
 *      "*.tv"              vs. "flinstones.tv"         no
 *      "f*.tv"             vs. "flinstones.tv"         no
 *      "www*.palm.com"     vs. "www.palm.com"          no
 *      "www**.palm.com"    vs. "www12.palm.com"        no
 *      "www.palm.com\0badguy.com" vs. "www.palm.com"   no  
 *      "www*.palm.com"     vs. "www12.palm.com"        yes
 *      "*.palm.com"        vs. "www.palm.com"          yes
 *      "www.palm.com"      vs. "WWW.Palm.Com"          yes
 *      "WWW.Palm.Com"      vs. "www.palm.com"          yes
 *  
 * @endverbatim 
 *  
 * @note Earlier builds (e.g., submission 21 for Blowfish)
 *       allowed matches with a wildcard in the left-most label
 *       of a two-label dNSName or Common Name (e.g., palm.com
 *       versus *.com or pa*.com), but that has been disallowed
 *       on submission 22 and later targeting "Barley Wine"
 * 
 * @param cn Non-NULL valid certificate name IA5-encoded (subset
 *           of ASCII); MAY contain NUL byte(s); NOT expected to
 *           be zero-terminated; may be any case
 *           (uppper/lower/mixed)
 *  
 * @param cnLen Non-zero number of octets in the certificate 
 *              name string, NOT including zero-termination
 *  
 * @param hn Non-NULL, valid hostname (domain name) IA5-encoded 
 *           (subset of ASCII); NOT expected to be
 *           zero-terminated; may be any case
 *           (uppper/lower/mixed); (not validated by this
 *           function)
 *  
 * @param hnLen Non-zero number of octets in the hostname 
 *              string, NOT including zero-termination
 * 
 * @param opts 1 or more PmSockX509HostnameMatchOpts flags 
 *             bitwise-or'ed together or 0 (zero) if none.
 *  
 * @param pMatchRes Non-NULL pointer to variable for returning 
 *                  the status of the match: true=matched;
 *                  false="no match"; undefined on failure
 * 
 * @return PslError 0 on success (match status is indicated by 
 *         *pMatchRes); non-zero PslError code on failure (match
 *          status is undefined).
 *  
 * @todo For IDNA support, may need to accept cert name and 
 *       hostname args in UTF8 format. (UTF8 is backward
 *       compatible with IA5)
 */
PslError
PmSockX509CheckCertHostNameMatch(const char* cn,         unsigned cnLen,
                                 const char* hn,         unsigned hnLen,
                                 PmSockX509HostnameMatchOpts opts,
                                 bool*                   pMatchRes);




#if defined(__cplusplus)
}
#endif


#endif //PALMSOCK_X509_UTILS_H__

/**@}*/
