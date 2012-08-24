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
 * @file psl_io_buf.h
 * @ingroup psl_internal 
 * 
 * @brief  I/O buffer utilities for PmSockIOChannel
 *         implementation.
 * 
 * @note This is a specialized implementation of a contiguous
 *       buffer scheme that is intended for for the following
 *       simple data management cycles:
 * 
 *          1. Place a quantity of data in an empty buffer;
 * 
 *          2. Consume the data over one or more iterations
 *             until completely consumed, and the buffer returns
 *             to empty state;
 * 
 *          3. Go to step 1.
 * 
 * *****************************************************************************
 */
#ifndef PSL_IO_BUF_H__
#define PSL_IO_BUF_H__

#include "psl_build_config.h"

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include <string.h>
#include <glib.h>

#include "psl_log.h"
#include "psl_assert.h"

#include "psl_error_utils.h"


#if defined(__cplusplus)
extern "C" {
#endif


typedef struct PslIOBuf_ {
    ssize_t     maxSize_;

    /**
     * @note garray_->len is the size of the buffer.
     */
    GArray*     garray_;

    /**
     * 0-based index of the next byte to be consumed out of the
     * buffer. (garray_->len - nextConsumeIndex_) is the size of the
     * remaining data in the buffer
     */
    ssize_t     nextConsumeIndex_;
} PslIOBuf;


/**
 * Initializes the I/O buffer structure.  psl_io_buf_uninit()
 * will need to be called when the buffer is no longer needed in
 * order to free up its memory.
 * 
 * @param pIOBuf Non-NULL pointer to the PslIOBuf data structure
 *               to initialize.
 * @param maxSize Non-zero maximum allowed data size for this
 *                buffer instance.
 * 
 * @return PslError
 */
PSL_CONFIG_INLINE_FUNC PslError
psl_io_buf_init(PslIOBuf* const pIOBuf, ssize_t const maxSize)
{
    PSL_ASSERT(pIOBuf);
    PSL_ASSERT(maxSize > 0);

    memset(pIOBuf, 0, sizeof(*pIOBuf));

    pIOBuf->maxSize_            = maxSize;
    pIOBuf->nextConsumeIndex_   = 0;

    pIOBuf->garray_ = g_array_new(false/*zero_terminated*/, false/*clear_*/,
                                  1/*element_size*/);
    return pIOBuf->garray_ ? PSL_ERR_NONE : PSL_ERR_MEM;
}


/**
 * Uninitializes an I/O buffer that was previously successfully
 * initialized via psl_io_buf_init().
 * @param pIOBuf Non-NULL, valid (successfully initialized) I/O
 *               buffer instance.
 */
PSL_CONFIG_INLINE_FUNC void
psl_io_buf_uninit(PslIOBuf* const pIOBuf)
{
    PSL_ASSERT(pIOBuf);
    (void)g_array_free(pIOBuf->garray_, true/*free_segment*/);
    pIOBuf->garray_ = NULL;
}


/**
 * Returns the maxSize value that was previously passed to
 * psl_io_buf_init() for this I/O buffer instance.
 * @param pIOBuf Non-NULL, valid I/O buffer instance
 * 
 * @return ssize_t
 */
PSL_CONFIG_INLINE_FUNC ssize_t
psl_io_buf_get_max_capacity(const PslIOBuf* const pIOBuf)
{
    return (pIOBuf->maxSize_);
}


/**
 * Returns the size of available (unconsumed) data in the given
 * I/O buffer instance.
 * @param pIOBuf Non-NULL, valid I/O buffer instance
 * 
 * @return ssize_t  Number of available data bytes or zero if
 *         none.
 */
PSL_CONFIG_INLINE_FUNC ssize_t
psl_io_buf_get_data_size(const PslIOBuf* const pIOBuf)
{
    return (pIOBuf->garray_->len - pIOBuf->nextConsumeIndex_);
}


/**
 * Tests the I/O buffer instance for emptiness.
 * @param pIOBuf Non-NULL, valid I/O buffer instance
 * 
 * @return bool TRUE if empty; FALSE if not empty.
 */
PSL_CONFIG_INLINE_FUNC bool
psl_io_buf_is_empty(const PslIOBuf* const pIOBuf)
{
    return (0 == psl_io_buf_get_data_size(pIOBuf));
}



PSL_CONFIG_INLINE_FUNC void*
psl_io_buf_get_data_ptr_impl_(PslIOBuf* const pIOBuf, ssize_t* pByteCnt)
{
    ssize_t     cnt;
    if (!pByteCnt) {
        pByteCnt = &cnt;
    }

    if ((*pByteCnt = psl_io_buf_get_data_size(pIOBuf)) != 0) {
        return (uint8_t*)pIOBuf->garray_->data + pIOBuf->nextConsumeIndex_;
    }
    else {
        return NULL;
    }
}


/**
 * Returns a pointer to and size of the available (unconsumed)
 * data in the given I/O buffer instance.  NULL is returned if
 * the buffer is empty.
 * 
 * @param pIOBuf Non-NULL, valid I/O buffer instance
 * @param pByteCnt Non-NULL pointer to location for returning
 *                 the size of the available data.
 * 
 * @return void* NULL if the buffer is empty; otherwise, a
 *         pointer to the first available (unsconsumed) byte of
 *         data.  IMPORTANT: the pointer and data size are
 *         invalidated by other I/O buffer API's, such as
 *         psl_io_buf_reset_data, psl_io_buf_extend,
 *         psl_io_buf_truncate_data, and psl_io_buf_consume.
 * 
 */
PSL_CONFIG_INLINE_FUNC void*
psl_io_buf_get_data_ptr(PslIOBuf* const pIOBuf, ssize_t* const pByteCnt)
{
    PSL_ASSERT(pByteCnt);

    return psl_io_buf_get_data_ptr_impl_(pIOBuf, pByteCnt);
}


/**
 * Discards the previous data contents of the given I/O buffer
 * instance, and sets it to empty state.
 * 
 * @note Invalidates pointers into this buffer.
 * 
 * @param pIOBuf Non-NULL, valid I/O buffer instance
 */
PSL_CONFIG_INLINE_FUNC void
psl_io_buf_reset_data(PslIOBuf* const pIOBuf)
{
    if (pIOBuf->garray_->len > 0) {
        g_array_set_size(pIOBuf->garray_, 0);
    }
    pIOBuf->nextConsumeIndex_ = 0;
}


/**
 * Discards the previous contents of the I/O buffer instance and
 * sizes the data buffer up to the amount specified in the
 * reqCnt arg, such that the maximum buffer size that was passed
 * to psl_io_buf_init() is not exceeded.
 * 
 * @note Invalidates pointers into this buffer.
 * 
 * @note May not grant the entire requested amount, subject to
 *       maximum buffer size limit that was passed to
 *       psl_io_buf_init() for this instance.
 * 
 * @param pIOBuf Non-NULL, valid I/O buffer instance
 * @param reqCnt Non-negative byte count that should be the new
 *               data size, subject to the maximum buffer size
 *               limits.
 * @param pNewDataSize Non-NULL pointer to location for
 *                     returning the total size of available
 *                     data: (new_size = min(reqCnt, max_size)).
 * 
 * @return void* NULL if the buffer is empty; otherwise, a
 *         pointer to the first available (unsconsumed) byte of
 *         data.  IMPORTANT: the pointer and data size are
 *         invalidated by other I/O buffer API's, such as
 *         psl_io_buf_reset_data, psl_io_buf_extend,
 *         psl_io_buf_truncate_data, and psl_io_buf_consume.
 * 
 * @see psl_io_buf_truncate_data()
 */
PSL_CONFIG_INLINE_FUNC void*
psl_io_buf_reset_set_size(PslIOBuf* const pIOBuf,
                          ssize_t   const reqCnt,
                          ssize_t*  const pNewDataSize)
{
    PSL_ASSERT(reqCnt >= 0);
    PSL_ASSERT(pNewDataSize);

    ssize_t const allowedSize = ((reqCnt <= pIOBuf->maxSize_)
                                 ? reqCnt
                                 : pIOBuf->maxSize_);

    (void)g_array_set_size(pIOBuf->garray_, allowedSize);

    pIOBuf->nextConsumeIndex_ = 0;

    return psl_io_buf_get_data_ptr_impl_(pIOBuf, pNewDataSize);
}


/**
 * Extends the data space at the end of the given I/O buffer up
 * to the amount specified in the reqCnt arg, such that the
 * maximum buffer size that was passed to psl_io_buf_init() is
 * not exceeded.
 * 
 * @note NOT TESTED YET
 * 
 * @note Invalidates pointers into this buffer.
 * 
 * @note May not grant the entire requested amount, subject to
 *       maximum buffer size limit that was passed to
 *       psl_io_buf_init() for this instance.  You may calculate
 *       the actual extension size by getting the old size
 *       before calling psl_io_buf_extend, and then subracting
 *       the old size from the new size.
 * 
 * @param pIOBuf Non-NULL, valid I/O buffer instance
 * @param reqCnt Non-negative byte count by which to attempt to
 *               extend the buffer's available data
 * @param pNewDataSize Non-NULL pointer to location for
 *                     returning the total size of available
 *                     data following this operation: new_size =
 *                     (min((old_size + reqCnt), max_size)).
 * 
 * @return void* NULL if the buffer is empty (i.e., caller tried
 *         to extend an empty buffer by zero bytes); otherwise,
 *         a pointer to the first available (unsconsumed) byte
 *         of data. IMPORTANT: the pointer and data size are
 *         invalidated by other I/O buffer API's, such as
 *         psl_io_buf_reset_data, psl_io_buf_extend,
 *         psl_io_buf_truncate_data, and psl_io_buf_consume.
 * 
 * @see psl_io_buf_truncate_data()
 */
PSL_CONFIG_INLINE_FUNC void*
psl_io_buf_extend_if_possible(PslIOBuf* const pIOBuf,
                              ssize_t   const reqCnt,
                              ssize_t*  const pNewDataSize)
{
    PSL_ASSERT(reqCnt >= 0);
    PSL_ASSERT(pNewDataSize);

    ssize_t const maxRes = pIOBuf->maxSize_ - psl_io_buf_get_data_size(pIOBuf);
    ssize_t const actualRes = (reqCnt <= maxRes) ? reqCnt : maxRes;

    if ((pIOBuf->garray_->len + actualRes) <= pIOBuf->maxSize_) {
        (void)g_array_set_size(pIOBuf->garray_, pIOBuf->garray_->len + actualRes);
    }
    else {
        ssize_t oldDataSize;
        const void* const src = psl_io_buf_get_data_ptr(pIOBuf, &oldDataSize);
        if (src) { /// Might be zero data bytes offset from beginning of buff
            memmove(pIOBuf->garray_->data, src, oldDataSize);
        }
        (void)g_array_set_size(pIOBuf->garray_, oldDataSize + actualRes);
        pIOBuf->nextConsumeIndex_ = 0;
    }

    return psl_io_buf_get_data_ptr_impl_(pIOBuf, pNewDataSize);
}


/**
 * Truncates the available data at the size given by
 * keepCnt.
 * 
 * @note Invalidates pointers into this buffer.
 * 
 * @param pIOBuf Non-NULL, valid I/O buffer instance
 * @param keepCnt Non-negative new size of available data; MUST
 *                NOT exceed the size of available data.
 * 
 * @return void* NULL if the buffer is empty following this
 *         operation; otherwise, pointer to the beginning of
 *         available data.  The new data size will be equal to
 *         the value of the passed-in keepCnt parameter.
 */
PSL_CONFIG_INLINE_FUNC void*
psl_io_buf_truncate_data(PslIOBuf*      const pIOBuf,
                         ssize_t        const keepCnt)
{
    PSL_ASSERT(keepCnt >= 0);
    PSL_ASSERT(keepCnt <= psl_io_buf_get_data_size(pIOBuf));

    (void)g_array_set_size(pIOBuf->garray_,
                           pIOBuf->nextConsumeIndex_ + keepCnt);

    return psl_io_buf_get_data_ptr_impl_(pIOBuf, NULL);
}


/**
 * Consumes the number of bytes of available data at the
 * beginning by the amount specified in consumeCnt.
 * 
 * @note Invalidates pointers into this buffer.
 * 
 * @param pIOBuf Non-NULL, valid I/O buffer instance
 * @param consumeCnt Non-negative number of bytes to consume;
 *                   MUST NOT exceed the size of available data.
 * @param pNewDataSize Optional (may be NULL) pointer to
 *                     location for returning the total size of
 *                     available data following this operation:
 *                     new_size = (old_size - consumeCnt).
 * 
 * @return void* NULL if the buffer is empty following this
 *         operation; otherwise, pointer to the beginning of
 *         available data.
 */
PSL_CONFIG_INLINE_FUNC void*
psl_io_buf_consume(PslIOBuf*    const pIOBuf,
                   ssize_t      const consumeCnt,
                   ssize_t*     const pNewDataSize)
{
    PSL_ASSERT(consumeCnt >= 0);
    PSL_ASSERT(consumeCnt <= psl_io_buf_get_data_size(pIOBuf));

    pIOBuf->nextConsumeIndex_ += consumeCnt;

    return psl_io_buf_get_data_ptr_impl_(pIOBuf, pNewDataSize);
}





#if defined(__cplusplus)
}
#endif

#endif // PSL_IO_BUF_H__
