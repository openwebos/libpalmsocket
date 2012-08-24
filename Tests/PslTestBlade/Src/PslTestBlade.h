/* @@@LICENSE
*
*      Copyright (c) 2009-2011 Hewlett-Packard Development Company, L.P.
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
 * @file PslTestBlade.h
 * @ingroup psl_test
 * 
 * @brief  Header file for libpalmsocket ("PSL") Debug/test
 *         blade.
 * 
 * *****************************************************************************
 */

#ifndef PSL_TEST_BLADE_H
#define PSL_TEST_BLADE_H

#include <stddef.h>

#include <PmWirelessSystemFramework/Core/ServiceBlade.h>
#include <PmWirelessSystemFramework/Utils/RuntimeDispatcher/RuntimeDispatcher.h>
#include <PmWirelessSystemFramework/Utils/RuntimeDispatcher/RdPortMonitor.h>

#include "PslTestCmdShell.h"


namespace psl_test_blade {



/**
 * This is our specific Blade class, subclassed from
 * wsf::ServiceBlade.  After construction, WSF Shell will call
 * our Run() method.
 */
class PslTestBlade : public wsf::ServiceBlade {
public:
    /**
     * Default constructor
     */
    PslTestBlade();

    /**
     * This is our implementation of the Run virtual function
     * defined by wsf::ServiceBlade class.
     * 
     * @param rBladeEnvironment
     */
    void Run(const wsf::ServiceBladeEnvironment& rBladeEnvironment);

private:
    /**
     * @brief Port Monitor callback function for our Blade Control
     *        port
     */
    void BladeControlPortMonCb(wsf::RdPortMonitor* pMon,
                               const wsf::PortEventInterface* pPort,
                               bool isReadable, bool isWritable,
                               bool isException,
                               const wsf::ServiceBladeEnvironment* pBladeEnv);

private:

    /// The Runtime Dispatcher.  It implements our main loop.
    wsf::RuntimeDispatcher  rd_;

    MyCmdShellHost        shellHost_;

}; // class TestBlade



} // end of namespace psl_test_blade

#endif // PSL_TEST_BLADE_H
