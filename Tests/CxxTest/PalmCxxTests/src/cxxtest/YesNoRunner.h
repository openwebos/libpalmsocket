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

#ifndef __cxxtest__YesNoRunner_h__
#define __cxxtest__YesNoRunner_h__

//
// The YesNoRunner is a simple TestListener that
// just returns true iff all tests passed.
//

#include <cxxtest/TestRunner.h>
#include <cxxtest/TestListener.h>

namespace CxxTest 
{
    class YesNoRunner : public TestListener
    {
    public:
        YesNoRunner()
        {
        }
        
        int run()
        {
            TestRunner::runAllTests( *this );
            return tracker().failedTests();
        }
    };
}

#endif // __cxxtest__YesNoRunner_h__
