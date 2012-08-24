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
 * @file psl_time_utils.h
 * @ingroup psl_internal 
 * 
 * @brief  Time related utilites for the libpalmsocket
 *         implementation.
 * 
 * *****************************************************************************
 */
#ifndef PSL_TIME_UTILS_H__
#define PSL_TIME_UTILS_H__

#include "psl_build_config.h"

#include <stdbool.h>
#include <time.h>

#if defined(__cplusplus)
extern "C" {
#endif


/**
 * @todo consider switching
 *       implementation to use timeval and the C
 *       library-provided macros timercmp(), etc. instead of
 *       rolling/debugging our own primitives.
 */



/** ========================================================================
 * Normalize a timespec
 * 
 * @param ts
 * 
 * =========================================================================
 */
void
psl_time_normalize_timespec(struct timespec* const ts);



/** ========================================================================
 * 
 * Gets normalized current monotonic time
 * 
 * @param ts
 * 
 * @return gboolean TRUE on success, FALSE on failure
 * 
 * =========================================================================
 */
bool
psl_time_get_current_mono_time(struct timespec* now);


/** ========================================================================
 * Adds two timespecs: X += Y; the result (X) is normalized
 * 
 * @note Does not detect overflow
 * 
 * @param x timespec X (assumed to be normalized)
 * @param y timespec Y (assumed to be normalized)
 * 
 * =========================================================================
 */
void
psl_time_add_timespec(struct timespec* x, const struct timespec* y);


/** ========================================================================
 * Subtracts timespecs: X = ABS(X - Y); the result (X) is
 * normalized
 * 
 * @param x timespec X (assumed to be normalized and
 *          non-negative)
 * @param y timespec Y (assumed to be normalized and
 *          non-negative)
 * @param wouldUnderflow Non-NULL pointer to location for
 *                       returning a boolean value indicating
 *                       whether the subtraction would underflow
 *                       (i.e., input X was less than input Y)
 * 
 * =========================================================================
 */
void
psl_time_subtract_timespec_abs(struct timespec* x,
                               const struct timespec* y,
                               bool* wouldUnderflow);

/**
 * Compares x with y
 * 
 * @param x timespec X (assumed to be normalized and
 *          non-negative)
 * @param y timespec Y (assumed to be normalized and
 *          non-negative)
 * 
 * @return int: Negative value if x < y; zero if x == y;
 *         positive value if x > y
 */
int
psl_time_compare_timespecs(const struct timespec* x, const struct timespec* y);


/**
 * Converts a timespec (typically result of timespec
 * subtraction) into milliseconds, rounded up to the nearest
 * millisecond
 * 
 * @note Does not detect overflow
 * 
 * @param x timespec X (assumed to be normalized and
 *          non-negative)
 * 
 * @return int
 */
int
psl_time_convert_timespec_to_millisec(const struct timespec* x);


/**
 * Adds milliseconds to a timespec: X += numMillisec; the result
 * is normalized
 * 
 * @note Does not detect overflow
 * 
 * @param x timespec X (assumed to be normalized and
 *          non-negative)
 * @param millisec Non-negative number of milliseconds to add
 */
void
psl_time_add_millisec_to_timespec(struct timespec* x, int numMillisec);




#if defined(__cplusplus)
}
#endif

#endif // PSL_TIME_UTILS_H__
