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

#ifndef __cxxtest_TestRunner_h__
#define __cxxtest_TestRunner_h__

//
// TestRunner is the class that runs all the tests.
// To use it, create an object that implements the TestListener
// interface and call TestRunner::runAllTests( myListener );
// 

#include <cxxtest/TestListener.h>
#include <cxxtest/RealDescriptions.h>
#include <cxxtest/TestSuite.h>
#include <cxxtest/TestTracker.h>

namespace CxxTest 
{
    class TestRunner
    {
    public:
        static void runAllTests( TestListener &listener )
        {
            tracker().setListener( &listener );
            _TS_TRY { TestRunner().runWorld(); }
            _TS_LAST_CATCH( { tracker().failedTest( __FILE__, __LINE__, "Exception thrown from world" ); } );
            tracker().setListener( 0 );
        }

        static void runAllTests( TestListener *listener )
        {
            if ( listener ) {
                listener->warning( __FILE__, __LINE__, "Deprecated; Use runAllTests( TestListener & )" );
                runAllTests( *listener );
            }
        }        
    
    private:
        void runWorld()
        {
            RealWorldDescription wd;
            WorldGuard sg;
            
            tracker().enterWorld( wd );
            if ( wd.setUp() ) {
                for ( SuiteDescription *sd = wd.firstSuite(); sd; sd = sd->next() )
                    if ( sd->active() )
                        runSuite( *sd );
            
                wd.tearDown();
            }
            tracker().leaveWorld( wd );
        }
    
        void runSuite( SuiteDescription &sd )
        {
            StateGuard sg;
            
            tracker().enterSuite( sd );
            if ( sd.setUp() ) {
                for ( TestDescription *td = sd.firstTest(); td; td = td->next() )
                    if ( td->active() )
                        runTest( *td );

                sd.tearDown();
            }
            tracker().leaveSuite( sd );
        }

        void runTest( TestDescription &td )
        {
            StateGuard sg;
            
            tracker().enterTest( td );
            if ( td.setUp() ) {
                td.run();
                td.tearDown();
            }
            tracker().leaveTest( td );
        }
        
        class StateGuard
        {
#ifdef _CXXTEST_HAVE_EH
            bool _abortTestOnFail;
#endif // _CXXTEST_HAVE_EH
            unsigned _maxDumpSize;
            
        public:
            StateGuard()
            {
#ifdef _CXXTEST_HAVE_EH
                _abortTestOnFail = abortTestOnFail();
#endif // _CXXTEST_HAVE_EH
                _maxDumpSize = maxDumpSize();
            }
            
            ~StateGuard()
            {
#ifdef _CXXTEST_HAVE_EH
                setAbortTestOnFail( _abortTestOnFail );
#endif // _CXXTEST_HAVE_EH
                setMaxDumpSize( _maxDumpSize );
            }
        };

        class WorldGuard : public StateGuard
        {
        public:
            WorldGuard() : StateGuard()
            {
#ifdef _CXXTEST_HAVE_EH
                setAbortTestOnFail( CXXTEST_DEFAULT_ABORT );
#endif // _CXXTEST_HAVE_EH
                setMaxDumpSize( CXXTEST_MAX_DUMP_SIZE );
            }
        };
    };

    //
    // For --no-static-init
    //
    void initialize();
};


#endif // __cxxtest_TestRunner_h__
