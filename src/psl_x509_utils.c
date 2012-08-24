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
 * @file psl_x509_utils.h
 * @ingroup psl_internal 
 * 
 * @brief  Libpalmsocket's X509-related utilities
 * 
 * *****************************************************************************
 */
#include "psl_build_config.h"

#include <ctype.h>

#include "palmsockerror.h"
#include "palmsockx509utils.h"

#include "psl_log.h"
#include "psl_arg_check.h"
#include "psl_assert.h"
#include "psl_common.h"
#include "psl_string_utils.h"



/* =========================================================================
 * =========================================================================
 */
PslError
PmSockX509CheckCertHostNameMatch(const char* cn, unsigned const cnLen,
                                 const char* hn, unsigned const hnLen,
                                 PmSockX509HostnameMatchOpts  const opts,
                                 bool*                    const pMatchRes)
{
    if (PSL_LOG_IS_DEBUGLOW_ENABLED()) {
        // Buffers for logging
        char cnzt[PSL_DOMAIN_NAME_ASCII_LOG_BUF_SIZE];
        char hnzt[PSL_DOMAIN_NAME_ASCII_LOG_BUF_SIZE];
        PSL_LOG_DEBUGLOW(
            "%s: cn=%p (%s), cnLen=%u, hn=%p (%s), hnLen=%u, opts=0x%lX, pMatchRes=%p",
            __func__,
            cn,
            PSL_LOG_OBFUSCATE_STR(psl_str_zero_strncpy(cnzt, cn, cnLen, sizeof(cnzt))),
            cnLen,
            hn,
            PSL_LOG_OBFUSCATE_STR(psl_str_zero_strncpy(hnzt, hn, hnLen, sizeof(hnzt))),
            hnLen,
            opts,
            pMatchRes);
    }

    // No options defined yet, so callers MUST pass 0
    if (!PSL_ARG_CHECK_IS_ZERO(opts)) {
        return PSL_ERR_INVAL;
    }

    if (!PSL_ARG_CHECK_NOT_NULL(pMatchRes)) {
        return PSL_ERR_INVAL;
    }

    if (!PSL_ARG_CHECK_NOT_NULL(cn)) {
        return PSL_ERR_INVAL;
    }

    if (!PSL_ARG_CHECK_NOT_ZERO(cnLen)) {
        return PSL_ERR_INVAL;
    }

    if (!PSL_ARG_CHECK_NOT_NULL(hn)) {
        return PSL_ERR_INVAL;
    }

    if (!PSL_ARG_CHECK_NOT_ZERO(hnLen)) {
        return PSL_ERR_INVAL;
    }

    bool const GOT_A_MATCH  = true;
    bool const NO_MATCH     = false;

    *pMatchRes = NO_MATCH;

    /**
     * @todo If hnLen < cnLen, may we conclude NO_MATCH for all cn 
     *       and hn??? (potential optimization)
     */

    unsigned const cnLastOctetIdx = cnLen - 1;
    //unsigned const hnLastOctetIdx = hnLen - 1;
    int curLabelIdx  =  0;  // index of current label being parsed (0-based)
    int wildLabelIdx = -1;  // index of label w/ wildcard (0-based; -1=none)
    unsigned cnIdx = 0, hnIdx = 0;
    while (1) {
        PSL_ASSERT(cnIdx <= cnLen);
        PSL_ASSERT(hnIdx <= hnLen);

        if (cnIdx == cnLen && hnIdx == hnLen) {         // Both EOF
            /*
             * fail the match for cn = "*.com" or "p*.com" scenario 
             */
            if (wildLabelIdx >= 0) {
                if ((curLabelIdx - wildLabelIdx) < 2) {
                    goto no_match;
                }
            }
            goto got_a_match;
        }
        else if (cnIdx == cnLen || hnIdx == hnLen) {    // Only one EOF
            // Label count mismatch: "www.foo.com" vs. "foo.com" scenario
            goto no_match;
        }

        // Neither is EOF

        char const cnOctet = toupper(cn[cnIdx]);
        char const hnOctet = toupper(hn[hnIdx]);

        if (cnOctet == hnOctet) {
            if (cnOctet == '.') {
                curLabelIdx++;
            }
            cnIdx++;
            hnIdx++;
            continue;
        }

        // Octets differ

        if (cnOctet != '*') {
            goto no_match;
        }

        // Current cn octet is wildcard

        if (0 != curLabelIdx) {
            // @note wildcard only allowed in leftmost label
            goto no_match;
        }

        // Wildcard is in the leftmost label

        if (cnIdx == cnLastOctetIdx) {
            // cn = "*" or "c*" scenario
            goto no_match;
        }

        if (cn[cnIdx+1] != '.') {
            // cn = "*om" or "*ww.bar.com" scenario
            goto no_match;
        }

        if (hnOctet == '.') {
            // "www*.palm.com" vs. "www.palm.com" scenario
            goto no_match;
        }

        // Wildcard looks alright

        wildLabelIdx = curLabelIdx;

        // Advance cn and hn to the next label separator, if any
        cnIdx++;
        do {
            hnIdx++;
        } while (hnIdx < hnLen && hn[hnIdx] != '.');
    }//while (1)


got_a_match:
    PSL_LOG_DEBUGLOW("%s: GOT A MATCH BETWEEN cn=%p and hn=%p", __func__, cn, hn);
    *pMatchRes = GOT_A_MATCH;
    return PSL_ERR_NONE;

no_match:
    PSL_LOG_DEBUGLOW("%s: NO MATCH BETWEEN cn=%p and hn=%p", __func__, cn, hn);
    *pMatchRes = NO_MATCH;
    return PSL_ERR_NONE;
}

