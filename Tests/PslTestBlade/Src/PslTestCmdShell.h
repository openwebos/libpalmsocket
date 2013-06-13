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
 * @file PslTestCmdShell.h
 * @ingroup psl_test
 * 
 * @brief  Defines the command-shell for our test blade.
 * 
 * *****************************************************************************
 */

#ifndef PSL_TEST_CMD_SHELL_H
#define PSL_TEST_CMD_SHELL_H

#include <PmWsfTestUtils/CommandShellHost.h>


namespace psl_test_blade {


typedef wtu::CommandShellHostT                      MyCmdShellHost;
typedef MyCmdShellHost::CmdShell                    MyCmdShell;

typedef std::vector<MyCmdShellHost::CmdRegInfo>     HandlerTableType;


/** Register a command handler
 * @note All registered command handlers MUST be unique per
 *       case-insentive string comparison
 * @param rInfo
 */
void RegisterCmdHandler(const MyCmdShellHost::CmdRegInfo& rInfo);

/// Returns a reference to our static table of command handlers
HandlerTableType& PeekHandlerTable();

void SaveBladeName(const char name[]);

const char* PeekBladeName();



} // end of namespace


#endif // PSL_TEST_CMD_SHELL_H
