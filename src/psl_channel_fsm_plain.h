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
 * @file psl_channel_fsm_plain.h
 * @ingroup psl_internal 
 * 
 * @brief  Plaintext state difinitions for the PmSockIOChannel
 *         Finite State Machine.
 * 
 * *****************************************************************************
 */
#ifndef PSL_CHANNEL_FSM_PLAIN_H__
#define PSL_CHANNEL_FSM_PLAIN_H__

#include "psl_build_config.h"

#include <stdbool.h>

#include <PmStateMachineEngine/PalmFsm.h>

#include "palmsocket.h"
#include "palmhostlookup.h"

#include "psl_sme.h"
#include "psl_channel_fsm_events.h"


#if defined(__cplusplus)
extern "C" {
#endif


/**
 * Plaintext connection establishment failure state
 */
typedef struct {
    PslSmeStateBase         base; ///< MUST BE FIRST MEMBER

    struct PslChanFsmEvtBeginArgPlainFail   arg;

} PslChanFsmPlainFailState;


/**
 * Host lookup state
 */
typedef struct {
    PslSmeStateBase         base; ///< MUST BE FIRST MEMBER

    struct PslChanFsmEvtBeginArgPlainLookup arg;

    PmSockHostLookupSession*    lookupSes;
} PslChanFsmPlainLookupState;


/**
 * Plaintext connection establishment state
 */
typedef struct {
    PslSmeStateBase         base; ///< MUST BE FIRST MEMBER

    struct PslChanFsmEvtBeginArgPlainConn   arg;

    /// Non-zero PslError error code if hard failure
    PslError                                failPslErr;
} PslChanFsmPlainConnState;


/**
 * Plaintext TCP session state: socket has been connected and
 * staying in plaintext mode until further notice
 */
typedef struct {
    PslSmeStateBase         base; ///< MUST BE FIRST MEMBER
} PslChanFsmPlainTCPState;


/**
 * Plaintext socket shutdown state
 */
typedef struct {
    PslSmeStateBase         base; ///< MUST BE FIRST MEMBER
} PslChanFsmPlainShutState;


/**
 * Plaintext mode parent state
 */
typedef struct {
    PslSmeStateBase         base; ///< MUST BE FIRST MEMBER

    /**
     * Child states
     */
    PslChanFsmPlainConnState    connState;
    PslChanFsmPlainFailState    failState;
    PslChanFsmPlainLookupState  lookupState;
    PslChanFsmPlainShutState    shutState;
    PslChanFsmPlainTCPState     tcpState;
} PslChanFsmPlainModeState;



/**
 * Initialize plaintext mode states and and insert them into the FSM
 * 
 * @param fsm
 * @param parent The state that should be the parent state for
 *               our states (NULL if root)
 */
void
psl_chan_fsm_plain_init(struct PslChanFsm_* fsm, PslSmeStateBase* parentState);


/**
 * Peform the socket shutdown operation indicated by the 'how'
 * argument; if successful, initiates transition to the
 * Plain-Shut state.  On failure, sets last channel error.
 * 
 * @param fsm
 * @param how SHUT_RD, SHUT_WR, or SHUT_RDWR from sys/socket.h
 * 
 * @return enum PslChanFsmEventStatus
 *         kPslChanFsmEventStatus_success on success,
 *         kPslChanFsmEventStatus_error on failure.
 */
PslSmeEventStatus
psl_chan_fsm_plain_shut_sock_and_goto_shut_on_success(
    struct PslChanFsm_* fsm,
    int                 how);



#if defined(__cplusplus)
}
#endif

#endif // PSL_CHANNEL_FSM_PLAIN_H__
