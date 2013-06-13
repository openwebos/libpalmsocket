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

#ifndef __cxxtest__Descriptions_h__
#define __cxxtest__Descriptions_h__

//
// TestDescription, SuiteDescription and WorldDescription
// hold information about tests so they can be run and reported.
//

#include <cxxtest/LinkedList.h>

namespace CxxTest 
{
    class TestSuite;

    class TestDescription : public Link
    {
    public:
        virtual ~TestDescription();
        
        virtual const char *file() const = 0;
        virtual unsigned line() const = 0;
        virtual const char *testName() const = 0;
        virtual const char *suiteName() const = 0;
        
        virtual void run() = 0;

        virtual const TestDescription *next() const = 0;
        virtual TestDescription *next() = 0;        
    };

    class SuiteDescription : public Link
    {
    public:
        virtual ~SuiteDescription();
        
        virtual const char *file() const = 0;
        virtual unsigned line() const = 0;
        virtual const char *suiteName() const = 0;
        virtual TestSuite *suite() const = 0;
        
        virtual unsigned numTests() const = 0;
        virtual const TestDescription &testDescription( unsigned /*i*/ ) const = 0;

        virtual TestDescription *firstTest() = 0;
        virtual const TestDescription *firstTest() const = 0;
        virtual SuiteDescription *next() = 0;
        virtual const SuiteDescription *next() const = 0;

        virtual void activateAllTests() = 0;
        virtual bool leaveOnly( const char * /*testName*/ ) = 0;
    };

    class WorldDescription : public Link
    {
    public:
        virtual ~WorldDescription();
        
        virtual unsigned numSuites( void ) const = 0;
        virtual unsigned numTotalTests( void ) const = 0;
        virtual const SuiteDescription &suiteDescription( unsigned /*i*/ ) const = 0;

        enum { MAX_STRLEN_TOTAL_TESTS = 32 };
        char *strTotalTests( char * /*buffer*/ ) const;

        virtual SuiteDescription *firstSuite() = 0;
        virtual const SuiteDescription *firstSuite() const = 0;

        virtual void activateAllTests() = 0;
        virtual bool leaveOnly( const char * /*suiteName*/, const char * /*testName*/ = 0 ) = 0;
    };
}

#endif // __cxxtest__Descriptions_h__

