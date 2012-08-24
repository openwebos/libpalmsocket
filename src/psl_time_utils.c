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
 * @file psl_time_utils.c
 * @ingroup psl_internal 
 * 
 * @brief  Time related utilites for the libpalmsocket
 *         implementation.
 * 
 * *****************************************************************************
 */

#include "psl_build_config.h"

#include <stdbool.h>
#include <time.h>
#include <errno.h>

#include "psl_log.h"
#include "psl_assert.h"
#include "psl_time_utils.h"


#define PSL_TIME_NANOSEC_PER_SEC        (1000 * 1000 * 1000)

#define PSL_TIME_MILLISEC_PER_SEC       (1000)

#define PSL_TIME_NANOSEC_PER_MILLISEC   (1000 * 1000)




/**
 * Validates that the timespec is non-negative and normalized
 * 
 * @note Fails an assertion, if negative or not normalized
 * 
 * @param ts__ Non-NULL pointer to struct timespec to validate
 */
#define PSL_TIME_EC_VALIDATE_TIMESPEC_NORMALIZED_NON_NEGATIVE(ts__) \
    do { \
        const struct timespec* const time__ = (ts__); \
        PSL_ASSERT((time__)->tv_sec >= 0 && (time__)->tv_nsec >= 0 \
                   && (time__)->tv_nsec < PSL_TIME_NANOSEC_PER_SEC); \
    } while ( 0 )


/** ========================================================================
 * 
 * =========================================================================
 */
void
psl_time_normalize_timespec(struct timespec* const ts)
{
    const long addSec = ts->tv_nsec / PSL_TIME_NANOSEC_PER_SEC;
    if (addSec) {
        ts->tv_sec += addSec;
        ts->tv_nsec -= (addSec * PSL_TIME_NANOSEC_PER_SEC);
    }
}



/** ========================================================================
 * 
 * =========================================================================
 */
bool
psl_time_get_current_mono_time(struct timespec* const now)
{
    if (clock_gettime(CLOCK_MONOTONIC, now) != 0) {
        PSL_LOG_FATAL("%s: ERROR: clock_gettime(CLOCK_MONOTONIC,) " \
                      "failed; errno=%d", __func__, (int)errno);
        return false;
    }

    psl_time_normalize_timespec(now);

    return true;
}



/** ========================================================================
 * 
 * =========================================================================
 */
void
psl_time_add_timespec(struct timespec* const x, const struct timespec* const y)
{
    PSL_TIME_EC_VALIDATE_TIMESPEC_NORMALIZED_NON_NEGATIVE(x);
    PSL_TIME_EC_VALIDATE_TIMESPEC_NORMALIZED_NON_NEGATIVE(y);

    /// @note Does not detect overflow

    x->tv_sec += y->tv_sec;
    x->tv_nsec += y->tv_nsec;

    psl_time_normalize_timespec(x);
}



/** ========================================================================
 * 
 * =========================================================================
 */
void
psl_time_subtract_timespec_abs(struct timespec* const x,
                               const struct timespec* const y,
                               bool* const wouldUnderflow)
{
    PSL_TIME_EC_VALIDATE_TIMESPEC_NORMALIZED_NON_NEGATIVE(x);
    PSL_TIME_EC_VALIDATE_TIMESPEC_NORMALIZED_NON_NEGATIVE(y);

    if (x->tv_sec < y->tv_sec ||
        (x->tv_sec == y->tv_sec && x->tv_nsec < y->tv_nsec)) {

        /// Handle the underflow case
        *wouldUnderflow = true;

        struct timespec temp;

        temp.tv_sec = y->tv_sec - x->tv_sec;
        temp.tv_nsec = y->tv_nsec - x->tv_nsec;
        if (y->tv_nsec < x->tv_nsec) {
            temp.tv_sec--;
            temp.tv_nsec += PSL_TIME_NANOSEC_PER_SEC;
        }

        *x = temp;
    }
    else {
        *wouldUnderflow = false;

        x->tv_sec -= y->tv_sec;
        if (x->tv_nsec < y->tv_nsec) {
            x->tv_sec--;
            x->tv_nsec += PSL_TIME_NANOSEC_PER_SEC;
        }
        x->tv_nsec -= y->tv_nsec;
    }
}



/** ========================================================================
 * 
 * =========================================================================
 */
int
psl_time_compare_timespecs(const struct timespec* const x,
                           const struct timespec* const y)
{
    PSL_TIME_EC_VALIDATE_TIMESPEC_NORMALIZED_NON_NEGATIVE(x);
    PSL_TIME_EC_VALIDATE_TIMESPEC_NORMALIZED_NON_NEGATIVE(y);

    if (x->tv_sec < y->tv_sec ||
        (x->tv_sec == y->tv_sec && x->tv_nsec < y->tv_nsec)) {
        return -1; ///< x < y
    }

    /// so, x >= y
    if (x->tv_sec == y->tv_sec && x->tv_nsec == y->tv_nsec) {
        return 0; ///< x == y
    }
    else {
        return 1; ///< x > y
    }
}



/** ========================================================================
 * 
 * =========================================================================
 */
int
psl_time_convert_timespec_to_millisec(const struct timespec* const x)
{
    PSL_TIME_EC_VALIDATE_TIMESPEC_NORMALIZED_NON_NEGATIVE(x);

    /// @note Does not detect overflow
    int res;

    res = x->tv_sec * PSL_TIME_MILLISEC_PER_SEC;

    int temp = x->tv_nsec + PSL_TIME_NANOSEC_PER_MILLISEC - 1;
    temp /= PSL_TIME_NANOSEC_PER_MILLISEC;

    res += temp;

    return res;
}



/** ========================================================================
 * 
 * =========================================================================
 */
void
psl_time_add_millisec_to_timespec(struct timespec* const x,
                                  int const numMillisec)
{
    PSL_TIME_EC_VALIDATE_TIMESPEC_NORMALIZED_NON_NEGATIVE(x);
    PSL_ASSERT(numMillisec >= 0);

    /// @note Does not detect overflow

    const int addSec = numMillisec / PSL_TIME_MILLISEC_PER_SEC;
    const int remMillisec = numMillisec - (addSec * PSL_TIME_MILLISEC_PER_SEC);

    x->tv_sec += addSec;
    x->tv_nsec += (remMillisec * PSL_TIME_NANOSEC_PER_MILLISEC);

    psl_time_normalize_timespec(x);
}
