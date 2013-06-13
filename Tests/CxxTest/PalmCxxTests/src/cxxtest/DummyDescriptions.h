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

#ifndef __cxxtest__DummyDescriptions_h__
#define __cxxtest__DummyDescriptions_h__

//
// DummyTestDescription, DummySuiteDescription and DummyWorldDescription
//

#include <cxxtest/Descriptions.h>

namespace CxxTest 
{
    class DummyTestDescription : public TestDescription
    {
    public:
        DummyTestDescription();
        
        const char *file() const;
        unsigned line() const;
        const char *testName() const;
        const char *suiteName() const;
        bool setUp();
        void run();
        bool tearDown();

        TestDescription *next();
        const TestDescription *next() const;
    };

    class DummySuiteDescription : public SuiteDescription
    {      
    public:
        DummySuiteDescription();
        
        const char *file() const;
        unsigned line() const;
        const char *suiteName() const;
        TestSuite *suite() const;
        unsigned numTests() const;
        const TestDescription &testDescription( unsigned ) const;
        SuiteDescription *next();
        TestDescription *firstTest();
        const SuiteDescription *next() const;
        const TestDescription *firstTest() const;
        void activateAllTests();
        bool leaveOnly( const char * /*testName*/ );
        
        bool setUp();
        bool tearDown();

    private:
        DummyTestDescription _test;
    };

    class DummyWorldDescription : public WorldDescription
    {
    public:
        DummyWorldDescription();
        
        unsigned numSuites( void ) const;
        unsigned numTotalTests( void ) const;
        const SuiteDescription &suiteDescription( unsigned ) const;
        SuiteDescription *firstSuite();
        const SuiteDescription *firstSuite() const;
        void activateAllTests();
        bool leaveOnly( const char * /*suiteName*/, const char * /*testName*/ = 0 );
            
        bool setUp();
        bool tearDown();

    private:
        DummySuiteDescription _suite;
    };
}

#endif // __cxxtest__DummyDescriptions_h__

