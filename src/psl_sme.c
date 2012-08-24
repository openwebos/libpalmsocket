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
 * @file psl_sme.c
 * @ingroup psl_internal 
 * 
 * @brief  Extensions to the Palm State Machine Engine for
 *         libpalmsocket.
 * 
 * @note IMPORTANT: for the details of the state machine
 *       behavior (e.g., hierarchical state machine event
 *       processing, kFsmEventEnterScope, kFsmEventExitScope,
 *       kFsmEventBegin, etc.) consult
 *       <PmStateMachineEngine/PalmFsm.h> and
 *       <PmStateMachineEngine/PalmFsmDbg.h>
 * 
 * *****************************************************************************
 */
#include "psl_build_config.h"

#include <stdbool.h>
#include <sys/types.h>
#include <string.h>

#include "psl_log.h"
#include "psl_assert.h"
#include "psl_sme.h"


/** ========================================================================
 * =========================================================================
 */
void
psl_sme_begin_transition(PslSmeMachineBase* const pFsm,
                         PslSmeStateBase*   const pTargetState,
                         const void*        const beginEvtArg,
                         size_t             const beginEvtArgSize,
                         const char*        const requesterFuncName)
{
    PSL_ASSERT(pFsm);
    PSL_ASSERT(pTargetState);

    if (!pFsm->inEvtDispatch) {
        PSL_LOG_FATAL("%s (fsm=%p/%s): FATAL ERROR: %s() requested transition " \
                      "to state=%s from non-event-handler scope",
                      __func__, pFsm, FsmDbgPeekMachineName(&pFsm->base),
                      requesterFuncName,
                      FsmDbgPeekStateName(&pTargetState->base));
        PSL_ASSERT(pFsm->inEvtDispatch);
    }

    if (pFsm->beginEvtData_.reqArgSize) {
        PSL_LOG_FATAL(
            "%s (fsm=%p/%s): ERROR: Prior kFsmEventBegin arg not " \
            "reaped: prior targetState=%s, arg size=%zd, " \
            "requester=%s",
            __func__, pFsm, FsmDbgPeekMachineName(&pFsm->base),
            (pFsm->beginEvtData_.reqTargetState
             ? FsmDbgPeekStateName(&pFsm->beginEvtData_.reqTargetState->base)
             : "(NULL)"),
            pFsm->beginEvtData_.reqArgSize,
            pFsm->beginEvtData_.requesterFuncName);
        PSL_ASSERT(!pFsm->beginEvtData_.reqArgSize);
    }

    if (beginEvtArg) {
        PSL_ASSERT(beginEvtArgSize > 0 &&
                   beginEvtArgSize <= pFsm->beginEvtData_.beginArgBufSize);
        pFsm->beginEvtData_.reqTargetState = pTargetState;
        pFsm->beginEvtData_.reqArgSize = beginEvtArgSize;
        pFsm->beginEvtData_.requesterFuncName = requesterFuncName;
        memcpy(pFsm->beginEvtData_.beginRequestArgBuf, beginEvtArg,
               beginEvtArgSize);
    }

    FsmBeginTransition(&pFsm->base, &pTargetState->base);
}

/**
 * Our FsmStateHandlerFnType hook for psl_sme-based state
 * machines.
 * 
 * We use this to perform a bit of magic: Enable state handlers
 * to return PslSmeEventStatus values reliably and pass event
 * args to kFsmEventBegin handlers in a standard way.
 * 
 * This is also a good place for other FSM-wide event
 * necessities, such as diagnostics.
 * 
 * @param pStateBase
 * @param pFsmBase
 * @param pEvtBase
 * 
 * @return int TRUE (non-zero) if the event was handled; FALSE
 *         (zero) if not handled.  For user-defined events, if
 *         the event isn't handled, it is passed to the
 *         user-defined parent state (if any) of the given
 *         state.
 */
FsmStateHandlerFnType psl_sme_default_state_evt_handler;
int
psl_sme_default_state_evt_handler(FsmState*         const pStateBase,
                                  FsmMachine*       const pFsmBase,
                                  const FsmEvent*   const pEvtBase)
{
    PslSmeMachineBase*  const pFsm = (PslSmeMachineBase*)pFsmBase;
    PslSmeStateBase*    const pState = (PslSmeStateBase*)pStateBase;

    if (pEvtBase->evtId < kFsmEventFirstUserEvent) {

        void*               pArg = NULL;

        /// Set up the arg (if any) for kFsmEventBegin
        if (pEvtBase->evtId == kFsmEventBegin &&
            pFsm->beginEvtData_.reqArgSize > 0) {

            PSL_ASSERT(pState == pFsm->beginEvtData_.reqTargetState);

            memcpy(pFsm->beginEvtData_.beginDispatchArgBuf,
                   pFsm->beginEvtData_.beginRequestArgBuf,
                   pFsm->beginEvtData_.reqArgSize);

            pArg = pFsm->beginEvtData_.beginDispatchArgBuf;

            /// Reset the request arg after reaping it, so that a new one
            /// may be set if the kFsmEventBegin requests an initial transition
            pFsm->beginEvtData_.reqArgSize = 0;
            pFsm->beginEvtData_.reqTargetState = NULL;
        }

        PslSmeEventStatus const status = pState->handler_(pState,
                                                          pFsm,
                                                          pEvtBase->evtId,
                                                          pArg);

        if (status != kPslSmeEventStatus_success &&
            status != kPslSmeEventStatus_notHandled) {
            PSL_LOG_WARNING("%s (fsm=%p/%s): WARNING: handler for " \
                            "system evt=%d returned unexpected status=%d",
                            __func__, pFsm, FsmDbgPeekMachineName(&pFsm->base),
                            pEvtBase->evtId, (int)status);
        }

        return (status != kPslSmeEventStatus_notHandled);
    }

    else {
        const PslSmeEvent_* const pEvt = (const PslSmeEvent_*) pEvtBase;

        PslSmeEventStatus const status = pState->handler_(pState,
                                                          pFsm,
                                                          pEvtBase->evtId,
                                                          pEvt->arg);

        pEvt->res->status = status; ///< for psl_sme_dispatch_event()

        return (status != kPslSmeEventStatus_notHandled);
    }
}
