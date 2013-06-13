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
 * @file psl_channel_fsm.h
 * @ingroup psl_internal 
 * 
 * @brief  Finite State Machine definitions for the
 *         PmSockIOChannel implementation.
 * 
 * *****************************************************************************
 */
#ifndef PSL_CHANNEL_FSM_H__
#define PSL_CHANNEL_FSM_H__

#include "psl_build_config.h"

#include <stdbool.h>
#include <glib.h>
#include <openssl/ssl.h>
#include <PmStateMachineEngine/PalmFsm.h>

#include "palmsocket.h"
//#include "psl_channel_fsm_events.h"
#include "psl_channel_fsm_fwd.h"


#if defined(__cplusplus)
extern "C" {
#endif



/**
 * PSL IO Channel's finite state machine opaque definition
 */
typedef struct PslChanFsm_ PslChanFsm;


/**
 * Error value sources
 */
typedef enum PslChanFsmErrorSource_ {
    kPslChanFsmErrorSource_errno    = 1,    ///< errno or compatible
    kPslChanFsmErrorSource_psl      = 2     ///< PslError
} PslChanFsmErrorSource;


/**
 * GError targets
 * 
 * @see psl_chan_fsm_set_gerror_from_last_error
 */
typedef enum PslChanFsmGErrorTarget_ {

    /// Use libpalmsocket error domain
    kPslChanFsmGErrorTarget_psl         = 1,

    /// Use GIOChannel error domain
    kPslChanFsmGErrorTarget_giochannel  = 2,
} PslChanFsmGErrorTarget;


/**
 * Constructs the palmsocket channel's state machine and sets
 * its feference count to 1 (this reference count belongs to the
 * caller);
 * 
 * See PmSockCreateChannel() definition for a complete
 * description of the args
 * 
 * @param fsmResult Non-NULL pointer to the location for
 *                  returning a pointer to the newly-constructed
 *                  FSM instance; undefined on error.  Use
 *                  psl_chan_fsm_finalize() to close and advance
 *                  the FSM to the final zombie-like state;
 *                  then, use psl_chan_fsm_unref() to release
 *                  the channel's reference to the FSM instance.
 * @param threadCtx
 * 
 * @param channel The GIOChannel instance that will contain the
 *                newly-created FSM instance on success;
 *                undefined on failure.  The channel pointer is
 *                needed as an argument for callbacks into user
 *                code.
 * 
 * @param userLabel
 * 
 * @return PslError 0 on success, non-zero PslError code on
 *         failure
 */
PslError
psl_chan_fsm_new(PslChanFsm**           fsmResult,
                 PmSockThreadContext*   threadCtx,
                 PmSockOptionFlags      options,
                 GIOChannel*            channel,
                 const char*            userLabel);


/**
 * psl_chan_fsm_finalize(): Closes and tranitions the FSM 
 * instance to the PslChanFsmFinalState state, but does _not_ 
 * decrement its reference count. 
 *  
 * Called by palmsock_io_free() when the corresponding 
 * palmsocket channel's g_io_channel refcount drops to zero, 
 * indicating that users should no longer call any 
 * GIOChannel and PmSockIOChannel functions on the channel 
 * instance. 
 *  
 * @note For use exclusively by palmsock_io_free().
 *  
 * @note At this point, channel header references from 
 *       PmSockWatch instance(s) to the corresponding channel
 *       instance may still exist in case the user is
 *       destroying the channel before the watch(es).  In this
 *       case, any _active_ PmSockWatch instances associated
 *       with this channel should report the G_IO_NVAL
 *       GIOCondition.
 *  
 * @note Deadlock work-around: This function results in the 
 *       destruction of the FSM's multi-fd-watch (GSource)
 *       instance and other utility widgets used by the FSM.
 *       This is part of the mechanism for working around a
 *       deadlock that would otherwise occur in glib's gmain
 *       implementation if the user destroys the PmSockWatch
 *       instance _after_ releases all of the user's references
 *       to the corresponding channel instance: in such a case,
 *       if the FSM's multi-fd-watch was still around during the
 *       destruction of the PmSockWatch instance, then the
 *       watch's "finalize" callback, which is called by gmain
 *       with the gmain-context's non-recursive mutex locked,
 *       would unref its channel reference, leading to the
 *       destruction of the channel, FSM, and the FSM's
 *       multi-fd-watch GSource instance, causing the deadlock
 *       when gmain attempts to lock the same non-recursive
 *       mutex while destroying the multi-fd-watch GSource.
 * 
 * @param fsm Non-NULL pointer to the FSM instance to be
 *            finalized.
 * 
 * @see psl_chan_fsm_unref
 */
void
psl_chan_fsm_finalize(PslChanFsm* fsm);


/**
 * Increments the reference count of the FSM instance by one.
 * 
 * @note The number of calls to psl_chan_fsm_ref and
 *       psl_chan_fsm_unref MUST balance
 * 
 * @param pFsm Non-NULL, valid FSM instance
 * 
 * @return PslChanFsm* Pointer to the passed FSM instance 
 *  
 * @see psl_chan_fsm_unref 
 */
PslChanFsm*
psl_chan_fsm_ref(PslChanFsm* pFsm);


/**
 * Decrements the reference count of the FSM by one.  If the
 * reference count reaches zero as the result of this operation,
 * the FSM insance will be closed and freed.
 *
 * The intended use of psl_chan_fsm_ref() and
 * psl_chan_fsm_unref() is to protect a set of related
 * activities while making an external callback call (or calling
 * something that might make an external call), and the
 * callback could possibly destroy the channel and this FSM
 * instance
 * 
 * @note WARNING: DO NOT CALL THIS FUNCTION FROM THE SCOPE OF
 *       ANY STATE EVENT HANDLER WITHIN THIS FSM.  If the count
 *       reaches zero, psl_chan_fsm_unref() may dispatch events
 *       to the FSM prior to freeing the instance.  If called
 *       from the scope of a state event handler, this will
 *       result in an FSM run-to-completion violation, resulting
 *       in a crash.
 * 
 * @note The number of calls to psl_chan_fsm_ref and
 *       psl_chan_fsm_unref MUST balance
 * 
 * @param pFsm
 * 
 * @see psl_chan_fsm_ref
 */
void
psl_chan_fsm_unref(PslChanFsm* pFsm);


/**
 * Returns TRUE if the channel's FSM is now closed (e.g., via
 * g_io_channel_close() or equivalent)
 * 
 * @param pFsm
 * 
 * @return bool
 */
bool
psl_chan_fsm_is_closed(const PslChanFsm* pFsm);


/**
 * Returns a pointer to the FSM's PmSockThreadContext instance
 * without incrementing its reference count.
 * 
 * @param fsm
 * 
 * @return PmSockThreadContext*
 */
PmSockThreadContext*
psl_chan_fsm_peek_thread_ctx(PslChanFsm* fsm);


/**
 * Associates a 'userData' value with the FSM instance
 * @param fsm
 * @param userData
 */
void
psl_chan_fsm_set_userdata(PslChanFsm* fsm, void* userData);


/**
 * Returns the 'userData' value associated with the FSM instance
 * 
 * @param fsm
 * 
 * @return void* 'userData' value
 */
void*
psl_chan_fsm_get_userdata(const PslChanFsm* fsm);


/**
 * Sets the FSM's 'last error' record
 * 
 * @param fsm Non-NULL FSM instance
 * 
 * @param errSrc Error source PslChanFsmErrorSource enum value
 * 
 * @param code Error code; MUST be non-zero (use
 *             psl_chan_fsm_reset_last_error to reset the FSM's
 *             'last error record')
 * 
 * @see psl_chan_fsm_set_gerror_from_last_error()
 * @see psl_chan_fsm_clear_last_error()
 */
void
psl_chan_fsm_set_last_error(PslChanFsm* fsm, PslChanFsmErrorSource errSrc,
                            int code);


/**
 * Returns the FSM's 'last error' code
 * 
 * @param fsm
 * 
 * @return PslError
 */
PslError
psl_chan_fsm_get_last_error(const PslChanFsm* fsm);


/**
 * Resets the the FSM's 'last error' record.
 * 
 * @note Resetting of last error is typically not needed since
 *       the API allows for intermediate values to be stored in
 *       'last error' and specifies that 'last error' value is
 *       meaningful only when retrieved immediately following a
 *       PmSockIOChannel or g_io_channel API call that indicates
 *       the call failed.
 * 
 * @param fsm Non-NULL FSM instance
 * 
 * @see psl_chan_fsm_set_last_error()
 */
void
psl_chan_fsm_reset_last_error(PslChanFsm* fsm);


/**
 * If pError is not NULL, sets the location pointed to by pError
 * to a new GError instance based on last error cache and the
 * value of targetErrDomain.
 * 
 * @note WARNING: the caller must be sure that an error is
 *       currently set in the FSM before calling this function:
 *       an assertion will fail if it isn't set.
 * 
 * @param fsm Non-NULL FSM instance
 * @param pError Optional (may be NULL) location for returning
 *               the GError instance.
 * @param targetErrDomain Target GError domain for GError
 *                        instantiation.
 * 
 * @see psl_chan_fsm_set_last_error()
 * @see psl_chan_fsm_clear_last_error()
 */
void
psl_chan_fsm_set_gerror_from_last_error(const PslChanFsm* fsm,
                                        GError** pError,
                                        PslChanFsmGErrorTarget targetDomain);


/**
 * Return a string rerpresntation of the given GIOStatus value.
 * @param giostatus
 * 
 * @return const char*
 */
const char*
psl_chan_fsm_str_from_giostatus(GIOStatus giostatus);




#if defined(__cplusplus)
}
#endif

#endif // PSL_CHANNEL_FSM_H__
