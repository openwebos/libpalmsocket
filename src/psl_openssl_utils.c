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

/** ****************************************************************************
 * @file psl_openssl_utils.c
 * @ingroup psl_internal 
 * 
 * @brief  implementation of libpalmsocket's Openssl utilities. 
 * 
 * *****************************************************************************
 */
#include "psl_build_config.h"

#include <stdbool.h>
#include <string.h>

#include <sys/socket.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>


#include "palmsockerror.h"
#include "palmsockopensslutils.h"
#include "palmsockx509utils.h"

#include "psl_log.h"
#include "psl_assert.h"
#include "psl_common.h"
#include "psl_string_utils.h"
#include "psl_inet_utils.h"

static bool
verify_hostname_in_subj_alt_name(const char*                     hn,
                                 bool                            isIPAddr,
                                 const PslInetIPAddress*         pslinaddr,
                                 struct x509_st*                 pCert,
                                 PmSockOpensslHostnameVerifyOpts verifyOpts,
                                 PmSockX509HostnameMatchOpts     nameMatchOpts);

static bool
verify_hostname_in_common_name(const char*                     hn,
                               bool                            isIPAddr,
                               const PslInetIPAddress*         pslinaddr,
                               struct x509_st*                 pCert,
                               PmSockOpensslHostnameVerifyOpts verifyOpts,
                               PmSockX509HostnameMatchOpts     nameMatchOpts);


/* =========================================================================
 * =========================================================================
 */
PslError
PmSockOpensslVerifyHostname(const char*                     const hn,
                            struct x509_st*                 const pCert,
                            PmSockOpensslHostnameVerifyOpts const verifyOpts,
                            PmSockX509HostnameMatchOpts     const nameMatchOpts,
                            bool*                           const pMatchRes)
{
    PSL_LOG_DEBUGLOW(
        "%s: hn=%p (%s), hnLen=%zd, pCert=%p verifyOpts=0x%lX, " \
        "nameMatchOpts=0x%lX, pMatchRes=%p",
        __func__, hn, PSL_LOG_OBFUSCATE_STR(hn), strlen(hn), pCert, verifyOpts,
        nameMatchOpts, pMatchRes);


    PSL_ASSERT(pMatchRes);

    *pMatchRes = false;

    /// No options defined yet, so callers MUST pass 0  
    if (verifyOpts) {
        PSL_LOG_ERROR(
            "%s (hn=%p): ERROR: Unexpected PmSockOpensslHostnameVerifyOpts: " \
            "expected 0, but got 0x%lX", __func__, hn, verifyOpts);
        return PSL_ERR_INVAL;
    }

    if (!hn || !*hn) {
        PSL_LOG_ERROR("%s (hn=%p): ERROR: NULL or empty hostname string",
                      __func__, hn);
        return PSL_ERR_INVAL;
    }

    if (!pCert) {
        PSL_LOG_ERROR("%s (hn=%p): ERROR: NULL cert", __func__, hn);
        return PSL_ERR_INVAL;
    }


    /// Determine whether hostname is a domain name or an IP address
    PslInetIPAddress pslinaddr;
    bool const isIPAddr = psl_inet_ipaddr_from_string(hn, &pslinaddr, "hn", hn);

    /// Look through subjectAltName fields first
    *pMatchRes = verify_hostname_in_subj_alt_name(hn, isIPAddr, &pslinaddr,
                                                  pCert, verifyOpts, nameMatchOpts);
    if (*pMatchRes) {
        return PSL_ERR_NONE;
    }

    *pMatchRes = verify_hostname_in_common_name(hn, isIPAddr, &pslinaddr,
                                                pCert, verifyOpts, nameMatchOpts);
    return PSL_ERR_NONE;
}



/* =========================================================================
 * =========================================================================
 */
PslError
PmSockOpensslMatchCertInStore(struct x509_store_ctx_st*  const x509StoreCtx,
                              struct x509_st*            const cert,
                              PmSockOpensslMatchCertOpts const opts,
                              bool*                      const pMatchRes)
{
    PSL_LOG_DEBUG("%s: x509StoreCtx=%p, cert=%p, matchOpts=0x%lX",
                  __func__, x509StoreCtx, cert, (unsigned long)opts);

    PSL_ASSERT(x509StoreCtx);
    PSL_ASSERT(cert);
    PSL_ASSERT(pMatchRes);

    *pMatchRes = false;

    if (opts) {
        PSL_LOG_ERROR(
            "%s (cert=%p): ERROR: Unexpected PmSockOpensslMatchCertOpts: " \
            "expected 0, but got 0x%lX", __func__, cert, (unsigned long)opts);
        return PSL_ERR_INVAL;
    }

    /// @see X509_STORE_CTX_get1_issuer + X509_check_issued + X509_cmp

    X509_NAME* const subjName = X509_get_subject_name(cert);
    X509_OBJECT installedObj;
    int const rc = X509_STORE_get_by_subject(x509StoreCtx, X509_LU_X509, subjName,
                                             &installedObj); 
    
    bool matched = false;

    if (X509_LU_X509 == rc && installedObj.data.x509) {
        matched = (0 == X509_cmp(cert, installedObj.data.x509));
    }

    if (X509_LU_FAIL != rc) {
        X509_OBJECT_free_contents(&installedObj);
    }

    if (X509_LU_X509 != rc) {
        PSL_LOG_DEBUG("%s (cert=%p): cert not found: X509_LU_=%d",
                      __func__, cert, rc);
        return PSL_ERR_NONE;
    }

    if (matched) {
        PSL_LOG_DEBUG("%s (cert=%p): cert found", __func__, cert);
        *pMatchRes = true;
        return PSL_ERR_NONE;
    }

    /**
     * Look through all certs with matching subject names
     */
    int i = X509_OBJECT_idx_by_subject(x509StoreCtx->ctx->objs, X509_LU_X509, subjName);
    if (-1 == i) {
        PSL_LOG_WARNING("%s (cert=%p): ERROR: X509_OBJECT_idx_by_subject() " \
                        "found no certs with matching subject" \
                        "after X509_STORE_get_by_subject() found one",
                        __func__, cert);
        return PSL_ERR_NONE;
    }

    for (; i < sk_X509_OBJECT_num(x509StoreCtx->ctx->objs); i++) {
        X509_OBJECT* const pObj = sk_X509_OBJECT_value(x509StoreCtx->ctx->objs, i);

        if (0 != X509_NAME_cmp(subjName, X509_get_subject_name(pObj->data.x509))) {
            continue;
        }

        if (0 == X509_cmp(cert, pObj->data.x509)) {
            PSL_LOG_DEBUG("%s (cert=%p): cert found", __func__, cert);
            *pMatchRes = true;
            return PSL_ERR_NONE;
        }
    }

    PSL_LOG_DEBUG("%s (cert=%p): cert not found", __func__, cert);
    return PSL_ERR_NONE;
}//PmSockOpensslMatchCertInStore



/* =========================================================================
 * =========================================================================
 */
static bool
verify_hostname_in_subj_alt_name(const char*                     const hn,
                                 bool                            const isIPAddr,
                                 const PslInetIPAddress*         const pslinaddr,
                                 struct x509_st*                 const pCert,
                                 PmSockOpensslHostnameVerifyOpts const verifyOpts,
                                 PmSockX509HostnameMatchOpts     const nameMatchOpts)
{
    PSL_ASSERT(!verifyOpts); ///< none are defined yet

    if (X509_get_ext_count(pCert) <= 0) {
        PSL_LOG_DEBUGLOW("%s: hn=%p, pCert=%p: no extensions in cert",
                         __func__, hn, pCert);
        return false;
    }

    STACK_OF(GENERAL_NAME)* altNames;
    altNames = (STACK_OF(GENERAL_NAME)*) X509_get_ext_d2i( ///< _ALLOCATION_
        pCert, NID_subject_alt_name, NULL, NULL);
    if (!altNames) {
        PSL_LOG_DEBUGLOW("%s: hn=%p, pCert=%p: no subject_alt_name fields in cert",
                         __func__, hn, pCert);
        return false;
    }
    
    bool gotMatch = false;
    int hnLen = strlen(hn);
    int const cnt = sk_GENERAL_NAME_num(altNames);
    int i;
    for (i=0; i < cnt; i++) {
        GENERAL_NAME* const name = sk_GENERAL_NAME_value(altNames, i);
        if(!name) {
            continue;
        }

        if (GEN_DNS == name->type && !isIPAddr) {
            /// Per RFC-528: dNSName in subjAltName field MUST be IA5String
            if(ASN1_STRING_type(name->d.dNSName) != V_ASN1_IA5STRING) {
                continue;
            }

            const char* const rawDnsName = (const char*)ASN1_STRING_data(name->d.dNSName);
            int const dnsNameLength = ASN1_STRING_length(name->d.dNSName);
            
            PslError const pslerr = PmSockX509CheckCertHostNameMatch(
                rawDnsName, dnsNameLength, hn, hnLen, nameMatchOpts, &gotMatch);
            if (pslerr || !gotMatch) {
                gotMatch = false;
                continue;
            }

            /// We got a dNSName match!
            PSL_LOG_DEBUGLOW("%s: hn=%p, pCert=%p: GOT A dNSName MATCH",
                             __func__, hn, pCert);
            break;
        }//dNSName

        else if (GEN_IPADD == name->type && isIPAddr) {
            /// Per RFC-5280: ipAddress in subjAltName field is OCTET STRING in
            /// network byte order; exactly 4 octets for IPv4 and
            /// exactly 16 octets for IPv6
            const unsigned char* const pRawIPAddr = ASN1_STRING_data(
                name->d.iPAddress);
            int const rawIPAddrLen = ASN1_STRING_length(name->d.iPAddress);

            PSL_ASSERT(pslinaddr->family != AF_UNSPEC);

            if (pslinaddr->len != rawIPAddrLen ||
                0 != memcmp(&pslinaddr->addr, pRawIPAddr, rawIPAddrLen)) {
                continue;
            }

            /// We got an address match!
            PSL_LOG_DEBUGLOW("%s: hn=%p, pCert=%p: GOT AN ipAddress MATCH",
                             __func__, hn, pCert);
            gotMatch = true;
            break;
        }

    }//search for dNSName or ipAddress match

    GENERAL_NAMES_free(altNames);

    if (!gotMatch) {
        PSL_LOG_DEBUGLOW("%s: hn=%p, pCert=%p: NO MATCH", __func__, hn, pCert);
    }

    return gotMatch;
}//verify_hostname_in_subj_alt_name


/* =========================================================================
 * =========================================================================
 */
static bool
verify_hostname_in_common_name(const char*                     const hn,
                               bool                            const isIPAddr,
                               const PslInetIPAddress*         const pslinaddr,
                               struct x509_st*                 const pCert,
                               PmSockOpensslHostnameVerifyOpts const verifyOpts,
                               PmSockX509HostnameMatchOpts     const nameMatchOpts)
{
    PSL_ASSERT(!verifyOpts); ///< none are defined yet


    X509_NAME *subj = X509_get_subject_name(pCert);
    if (!subj) {
        PSL_LOG_DEBUGLOW("%s: hn=%p, pCert=%p: NO MATCH: no subject_name in cert",
                         __func__, hn, pCert);
        return false;
    }

    /**
     * @todo RFC-2818 states that the "most specific" Common Name 
     *       field should be used, but there is no explanation of
     *       how to reliably determine which of the fields is the
     *       "most specific".
     */
    bool gotMatch = false;
    int hnLen = strlen(hn);
    int index = -1;
    while( (index = X509_NAME_get_index_by_NID(subj, NID_commonName, index)) >= 0 ) {
        X509_NAME_ENTRY* const cnEntry = X509_NAME_get_entry(subj, index);
        if (!cnEntry) {
            continue;
        }

        ASN1_STRING* const cn = X509_NAME_ENTRY_get_data(cnEntry);
        if (!cn) {
            continue;
        }

        /**
         * @note Common name fields may have different encodings, 
         *       uncluding Unicode
         */
        unsigned char* fld = NULL;
        int const fldLen = ASN1_STRING_to_UTF8(&fld, cn); ///< _ALLOCATION_
        if (fldLen < 0 || !fld) {
            continue;
        }

        if (PSL_LOG_IS_DEBUGLOW_ENABLED()) {
            /// Buffers for logging
            char cnzt[PSL_DOMAIN_NAME_ASCII_LOG_BUF_SIZE];
            PSL_LOG_DEBUGLOW(
                "%s: attempting to match cn='%s' (cnLen=%d) against hn='%s' " \
                "(hnLen=%u, isIPAddr=%d)",
                __func__,
                PSL_LOG_OBFUSCATE_STR(
                    psl_str_zero_strncpy(cnzt, (char*)fld, fldLen, sizeof(cnzt))
                    ),
                fldLen,
                PSL_LOG_OBFUSCATE_STR(hn),
                hnLen,
                isIPAddr);
        }

        if (isIPAddr) {
            PSL_ASSERT(pslinaddr->family != AF_UNSPEC);

            /// Convert string to binary form for comparison
            PslInetIPAddress certaddr;
            bool const maybeAddr = psl_inet_ipaddr_from_string(
                (char*)fld, &certaddr, "hn", hn);

            if (maybeAddr) {
                if (pslinaddr->len == certaddr.len &&
                    0 == memcmp(&pslinaddr->addr, &certaddr.addr, certaddr.len)) {
                    /// We got a match!
                    PSL_LOG_DEBUGLOW("%s: hn=%p, pCert=%p: GOT AN ipAddress MATCH",
                                     __func__, hn, pCert);
                    gotMatch = true;
                }
            }
        }//isIPAddr

        else {
            PslError const pslerr = PmSockX509CheckCertHostNameMatch(
                (char*)fld, fldLen, hn, hnLen, nameMatchOpts, &gotMatch);
            if (!pslerr && gotMatch) {
                /// We got a match!
                PSL_LOG_DEBUGLOW("%s: hn=%p, pCert=%p: GOT A hostname MATCH",
                                 __func__, hn, pCert);
            }
            else {
                gotMatch = false;
            }
        }

        OPENSSL_free(fld);

        if (gotMatch) {
            break;
        }
    }/// check all Common Name fields

    if (!gotMatch) {
        PSL_LOG_DEBUGLOW("%s: hn=%p, pCert=%p: NO MATCH", __func__, hn, pCert);
    }

    return gotMatch;
}//verify_hostname_in_common_name
