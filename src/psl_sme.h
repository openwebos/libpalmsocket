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
 * @file psl_sme.h
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
#ifndef PSL_SME_H__
#define PSL_SME_H__

#include "psl_build_config.h"

#include <stdbool.h>
#include <sys/types.h>
#include <string.h>

#include <PmStateMachineEngine/PalmFsm.h>
#include <PmStateMachineEngine/PalmFsmDbg.h>

#include "psl_assert.h"


#if defined(__cplusplus)
extern "C" {
#endif

/// Our event identifier type
typedef FsmEventIdType PslSmeEventId;


/**
 * Status codes for state event handlers
 */
typedef enum PslSmeEventStatus_e {
    /// This status indicates success; returned fields are pre event/result
    /// spec.  Client code may use a comparison against zero when wishing
    /// only to discern success from the rest of the status codes. 
    kPslSmeEventStatus_success          = 0,

    /// Error reported by the intended handler; returned fields are
    /// per event/result spec.
    /// 
    /// Handlers for system events (kFsmEventEnterScope, kFsmEventExitScope,
    /// and kFsmEventBegin) should NOT return this status code.
    kPslSmeEventStatus_error            = 1,

    /// Error reported by a catch-all handler; only this status
    /// field (enum PslChanFsmEventStatus) is valid; the rest of the
    /// returned info is undefined.
    /// 
    /// Handlers for system events (kFsmEventEnterScope, kFsmEventExitScope,
    /// and kFsmEventBegin) should NOT return this status code.
    kPslSmeEventStatus_errorCatchAll    = 2,

    /// This handler status causes the state machine engine to pass the
    /// USER-DEFINED event to the parent state, if any.  System-defined
    /// events (kFsmEventEnterScope, kFsmEventExitScope, and kFsmEventBegin)
    /// are NEVER passed to the parent, so don't use this value as it will
    /// be ignored by the engine and a warning message will be printed to
    /// the log.  This value is interpreted as "event not handled".
    kPslSmeEventStatus_notHandled       = 3

} PslSmeEventStatus;


/// For semantic convenience
#define kPslSmeEventStatus_passToParent (kPslSmeEventStatus_notHandled)


/**
 * Event result base 'class' structure; this data structure is
 * private.
 */
typedef struct PslSmeEventResBase__ {
    PslSmeEventStatus       status; ///< private; don't access
} PslSmeEventResBase_;


/**
 * PSL FSM Event structure: This data structure is private!
 */
typedef struct PslSmeEvent__ {
    FsmEvent                base;   ///< MUST BE FIRST MEMBER

    /**
     * Event-specific argument or NULL if the event takes no arg.
     * Event handler will access only the even-specific sub-member.
     * 
     * This field is set automatically by the psl_sme API functions.
     * 
     * User-defined events and kFsmEventBegin event may have an arg.
     * However, other system-defined events (kFsmEventEnterScope and
     * kFsmEventExitScope) do not have an arg; kFsmEventBegin is
     * targeted to a specific state that is the target of a state
     * transition request, while enter-scope/exit-scope events are
     * dispatched to entire state chains in a hierarchical state
     * machine)
     * 
     * @note While a specific user-defined event always takes the
     *       same arg, no matter which state will end up handling
     *       it, the kFsmEventBegin event is state-specific, by
     *       necessity.  Unlike user-defined events, kFsmEventBegin
     *       (and other system-defined events) are NEVER passed to
     *       the parent state if unhandled by the target state.
     */
    const void*                 arg;

    /**
     * Event result: mandatory (MUST be non-NULL) for user-defined
     * events; NULL for system-defined events (kFsmEventEnterScope,
     * kFsmEventExitScope, and kFsmEventBegin); Event handler will
     * access only the even-specific sub-member.
     * 
     * This field is set automatically by the psl_sme API functions.
     */
    PslSmeEventResBase_*        res; 
} PslSmeEvent_;


struct PslSmeMachineBase_s ;
struct PslSmeStateBase_s;


/**
 * Typedef of the state handler function for psl_sme-based FSMs.
 * 
 * @param pState Non-NULL pointer to the state that should
 *               handle the event.
 * @param pFsm Non-NULL pointer to the state's state machine.
 * @param evtId event ID: a system-defined eventID
 *     (kFsmEventEnterScope, kFsmEventExitScope, kFsmEventBegin)
 *     or a user-defined event
 * @param evtArg Event argument or NULL if none.
 * 
 * @return PslSmeEventStatus The overall status of the event
 *         dispatch.
 * 
 * @note A state handler MUST NEVER return
 *       kPslSmeEventStatus_passToParent after calling
 *       FsmBeginTransition(), because FsmBeginTransition() may
 *       cause parent state(s) to be exited.
 */
typedef PslSmeEventStatus PslSmeStateHandlerFnType(
    struct PslSmeStateBase_s*   pState,
    struct PslSmeMachineBase_s* pFsm,
    PslSmeEventId               evtId,
    const void*                 evtArg);


/**
 * State base 'class' structure: this MUST be included as the
 * FIRST MEMBER of ALL libpalmsocket FSMs.
 */
typedef struct PslSmeStateBase_s {
    FsmState                    base;   ///< MUST BE FIRST MEMBER

    /// State event handler function.  This member is private.
    PslSmeStateHandlerFnType*   handler_;
} PslSmeStateBase;


/**
 * FSM base 'class' structure: this MUST be included as the
 * FIRST MEMBER of ALL libpalmsocket FSMs.
 */
typedef struct PslSmeMachineBase_s {
    FsmMachine                  base;   ///< MUST BE FIRST MEMBER

    /// Management data for kFsmEventBegin support.
    /// @note Private to the psl_sme module.
    struct PslSmeBeginEvtData_ {
        /// Size of the request and sispatch arg buffers provided by the user.
        /// Both buffers must be of the same size
        size_t                  beginArgBufSize;

        /// kFsmEventBegin request argument buffer; Upon state transition
        /// request with a non-NULL kFsmEventBegin arg, the arg is saved in
        /// this buffer.  It is then copied to beginDispatchArgBuf prior to
        /// kFsmEventBegin dispatch to free up beginRequestArgBuf in case
        /// the target state makes an initial transition. beginRequestArgBuf
        /// and beginDispatchArgBuf MUST be two distinct buffers.
        void*                   beginRequestArgBuf;

        /// kFsmEventBegin dispatch argument buffer; see beginRequestArgBuf
        /// comments for the description of how these buffers are used.
        void*                   beginDispatchArgBuf;

        /// Identifies the state for which the begin arg is provided in
        /// beginRequestArgBuf; NULL when beginRequestArgBuf is empty.
        PslSmeStateBase*        reqTargetState;

        /// Size of the arg in beginRequestArgBuf; 0 when beginRequestArgBuf
        /// is empty.
        size_t                  reqArgSize;
        const char*             requesterFuncName;  ///< const, static string
    } beginEvtData_;

    /// Set/cleared by psl_sme_dispatch_event() around event dispatch
    /// logic; used for error-checking; FSM event dispatch is non-recursive,
    /// so a bool will suffice (versus counter)
    bool                        inEvtDispatch;

} PslSmeMachineBase;


/**
 * Initializes an FSM instance
 * 
 * @param pFsm Non-NULL pointer to an instance of
 *             PslSmeMachineBase-derived structure to be
 *             initialized.  PslSmeMachineBase MUST be the FIRST
 *             MEMBER of that structure.
 * @param pName A static FSM name string to use for logging and
 *              debugging. State Machine Engine saves the given
 *              pointer (i.e., doesn't copy the string).
 * @param beginArgBufSize IF not zero, then beginRequestArgBuf
 *                        and beginDispatchArgBuf MUST be both
 *                        non-NULL pointers to distinct
 *                        user-provided kFsmEventBegin arg
 *                        buffers, each of at least this size.
 *                        @see beginArgBufSize field in
 *                        PslSmeMachineBase::beginEvtData_.
 * @param beginRequestArgBuf @see beginRequestArgBuf field in
 *                           PslSmeMachineBase::beginEvtData_.
 * @param beginDispatchArgBuf @see beginDispatchArgBuf field in
 *                            PslSmeMachineBase::beginEvtData_.
 * 
 * @see FsmInitMachine() in <PmStateMachineEngine/PalmFsm.h> for
 *      more details about FSM initialization and restrictions
 *      on FSM names.
 */
PSL_CONFIG_INLINE_FUNC void
psl_sme_init_machine(PslSmeMachineBase* const pFsm,
                     const char*        const pName,
                     size_t             const beginArgBufSize,
                     void*              const beginRequestArgBuf,
                     void*              const beginDispatchArgBuf)
{
    PSL_ASSERT(pFsm);
    PSL_ASSERT(!beginArgBufSize ||
               (beginRequestArgBuf && beginDispatchArgBuf &&
                beginRequestArgBuf != beginDispatchArgBuf));

    memset(pFsm, 0, sizeof(*pFsm));
    pFsm->beginEvtData_.beginArgBufSize     = beginArgBufSize;
    pFsm->beginEvtData_.beginRequestArgBuf      = beginRequestArgBuf;
    pFsm->beginEvtData_.beginDispatchArgBuf = beginDispatchArgBuf;

    FsmInitMachine(&pFsm->base, pName);
}


/**
 * Initializes an FSM state instance.
 * 
 * @param pState Non-NULL pointer to an instance of
 *               PslSmeStateBase-derived structure to be
 *               initialized.
 * @param pStateEvtHandler Non-NULL state event handler function
 * @param pName State name to use for logging and debugging.
 *              FSM saves the given pointer (i.e., doesn't copy
 *              the string).
 * 
 * @see FsmInitState() in <PmStateMachineEngine/PalmFsm.h> for
 *      more details about state initialization and restrictions
 *      on state names.
 */
PSL_CONFIG_INLINE_FUNC void
psl_sme_init_state(PslSmeStateBase*             const pState,
                   PslSmeStateHandlerFnType*    const pStateEvtHandler,
                   const char*                  const pName)
{
    PSL_ASSERT(pState && pStateEvtHandler);

    pState->handler_ = pStateEvtHandler;

    extern FsmStateHandlerFnType    psl_sme_default_state_evt_handler;

    FsmInitState(&pState->base, &psl_sme_default_state_evt_handler, pName);
}


/**
 * Inserts a state instance into an initialized state machine
 * 
 * @note WARNING: Do NOT insert states after calling
 *       psl_sme_fsm_start()!
 * 
 * @note Do NOT insert a given state instance more than once
 *       within a given state machine instance's lifetime.
 * 
 * @param pFsm Non-NULL pointer to an initialized state machine.
 * @param pState Non-NULL pointer to an initialize state
 *               instance to insert into the FSM. Note: It's the
 *               caller's responsibility to avoid cycles.
 * @param pParentState NULL for a top super-state; or non-NULL
 *                     pointer to parent state that was already
 *                     inserted into this state machine.  Note:
 *                     It's the caller's responsibility to avoid
 *                     cycles.
 * 
 * @see FsmInsertState()
 */
PSL_CONFIG_INLINE_FUNC void
psl_sme_insert_state(PslSmeMachineBase* const pFsm,
                     PslSmeStateBase*   const pState,
                     PslSmeStateBase*   const pParentState)
{
    PSL_ASSERT(pFsm && pState);
    FsmInsertState(&pFsm->base, &pState->base, &pParentState->base);
}


/**
 * Starts FSM at the given initial state.
 * 
 * @note WARNING: DO NOT call this from a state event handler or
 *       any other callback of the given state machine.
 * 
 * @param pFsm Properly initialized state machine instance
 * 
 * @param pInitialState Non-NULL pointer to the initial state in
 *                      the state machine.  This state MUST be
 *                      already inserted into the FSM.
 */
PSL_CONFIG_INLINE_FUNC void
psl_sme_fsm_start(PslSmeMachineBase*    const pFsm,
                  PslSmeStateBase*      const pInitialState)
{
    PSL_ASSERT(pFsm && pInitialState);
    FsmStart(&pFsm->base, &pInitialState->base);
}


/**
 * Dispatches a USER-DEFINED event to the given state machine.
 * 
 * @note User code MUST NOT attempt to dispatch system-defined
 *       events (e.g., kFsmEventEnterScope. kFsmEventExitScope,
 *       kFsmEventBegin).  System-defined events are dispatched
 *       automatically when needed by the state machine engine.
 * 
 * @param pFsm Non-NULL FSM instance
 * @param evtId User defined event identifier greater than or
 *              equal to kFsmEventFirstUserEvent.
 * @param arg Event-specific argument, or NULL if the given
 *            event does not take an argument.
 * 
 * @return PslSmeEventStatus
 */
PSL_CONFIG_INLINE_FUNC PslSmeEventStatus
psl_sme_dispatch_event(PslSmeMachineBase*   const pFsm,
                       PslSmeEventId        const evtId,
                       const void*          const arg)
{
    PSL_ASSERT(pFsm);
    PSL_ASSERT(!pFsm->inEvtDispatch &&
               "MUST avoid FSM Run-to-completion violation");

    pFsm->inEvtDispatch = true;

    PslSmeEventResBase_ res = {
        .status     = kPslSmeEventStatus_notHandled
    };

    PslSmeEvent_ const evt = {
        .base       = {
            .evtId      = evtId
        },
        .arg        = arg,
        .res        = &res
    };

    bool handled = FsmDispatchEvent(&pFsm->base, &evt.base);

    PSL_ASSERT(handled == (kPslSmeEventStatus_notHandled != res.status));

    pFsm->inEvtDispatch = false;
    return res.status;
}


/**
 * Helper function for starting a state transition
 * 
 * @note WARNING: psl_sme_begin_transition() may be called ONLY
 *       from the scope of a state event handler.
 * 
 * @param pFsm Non-NULL FSM instance
 * @param pTargetState Non-NULL target state.  If called from
 *                     kFsmEventBegin handler, the target state
 *                     MUST be a descendant of the calling event
 *                     handler's state.
 * @param beginEvtArg Pointer to argument for the target state's
 *                    kFsmEventBegin handler, or NULL if none
 * @param beginEvtArgSize Size of the passed kFsmEventBegin
 *                        argument (# of bytes), or 0 if none.
 *                        MUST NOT exceed the size of begin arg
 *                        buffers that was passed to
 *                        psl_sme_init_machine() for this FSM
 *                        instance.
 * @param requesterFuncName A const, static function name string
 *                       (__func__) from the caller for
 *                       debugging (the pointer will be saved,
 *                       but the string is not copied)
 * 
 * @see FsmBeginTransition()
 */
void
psl_sme_begin_transition(PslSmeMachineBase* pFsm,
                         PslSmeStateBase*   pTargetState,
                         const void*        beginEvtArg,
                         size_t             beginEvtArgSize,
                         const char*        requesterFuncName);



#if defined(__cplusplus)
}
#endif

#endif // PSL_SME_H__
