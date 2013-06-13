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
 * @file psl_channel_fsm_fwd.h
 * @ingroup psl_internal 
 * 
 * @brief Forward declarations for the PmSockIOChannel's FSM.
 *        Include this file in modules that only use
 *        pointers to the various FSM structures.  This helps
 *        eliminate circular header inclusion and reduces
 *        compile load.
 * 
 * *****************************************************************************
 */
#ifndef PSL_CHANNEL_FSM_FWD_H__
#define PSL_CHANNEL_FSM_FWD_H__

#include "psl_build_config.h"


#if defined(__cplusplus)
extern "C" {
#endif



/**
 * PSL IO Channel's finite state machine opaque definition
 */
struct PslChanFsm_;




#if defined(__cplusplus)
}
#endif

#endif // PSL_CHANNEL_FSM_FWD_H__
