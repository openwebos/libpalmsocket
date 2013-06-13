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
 * @file psl_channel_fsm_events.c
 * @ingroup psl_internal 
 * 
 * @brief  Event definitions and primitives for the the
 *         PmSockIOChannel Finite State Machine
 *         implementation.
 * 
 * *****************************************************************************
 */
#include "psl_build_config.h"

#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>

#include <glib.h>

#include "palmsocket.h"

#include "psl_log.h"
#include "psl_assert.h"
#include "psl_error_utils.h"

#include "psl_channel_fsm.h"
#include "psl_channel_fsm_main.h"
#include "psl_channel_fsm_events.h"



/** ========================================================================
 * =========================================================================
 */
PslSmeEventStatus
psl_chan_fsm_evt_dispatch_full_(PslChanFsm*             const fsm,
                                PslChanFsmEvtId         const evtId,
                                const PslChanFsmEvtArg* const arg)
{
    PSL_ASSERT(fsm);
    PSL_ASSERT(!fsm->heartbeatPending);

    /// Dispatch the event
    PslSmeEventStatus const status = psl_sme_dispatch_event(&fsm->base,
                                                            evtId,
                                                            arg);
    if (kPslSmeEventStatus_notHandled == status) {
        PSL_LOG_FATAL("%s (fsm=%p/%s): ERROR: event %d not handled", __func__,
                      fsm, FsmDbgPeekMachineName(&fsm->base.base), evtId);
        PSL_ASSERT(!(kPslSmeEventStatus_notHandled == status));
    }

    /// Take care of PSL_CHAN_FSM_EVT_HEARTBEAT event request
    while (fsm->heartbeatPending) {
        fsm->heartbeatPending = false;

        PslSmeEventStatus const hbStatus = psl_sme_dispatch_event(
            &fsm->base,
            PSL_CHAN_FSM_EVT_HEARTBEAT,
            NULL);

        if (kPslSmeEventStatus_notHandled == hbStatus) {
            PSL_LOG_FATAL("%s (fsm=%p/%s): ERROR: HEARTBEAT event not handled",
                          __func__, fsm,
                          FsmDbgPeekMachineName(&fsm->base.base));
            PSL_ASSERT(!(kPslSmeEventStatus_notHandled == hbStatus));
        }
    }

    return status;
}



/** ========================================================================
 * =========================================================================
 */
void
psl_chan_fsm_evt_req_heartbeat(PslChanFsm*      const fsm,
                               const FsmState*  const requester)
{
    PSL_ASSERT(fsm->base.inEvtDispatch &&
               "MUST be called from a state event handler");

    PSL_LOG_DEBUG("%s (fsm=%p/%s): state %s is requesting a heartbeat",
                  __func__, fsm, FsmDbgPeekMachineName(&fsm->base.base),
                  FsmDbgPeekStateName(requester));

    fsm->heartbeatPending = true;
}
