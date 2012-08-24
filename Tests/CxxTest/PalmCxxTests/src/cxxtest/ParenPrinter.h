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

#ifndef __cxxtest__ParenPrinter_h__
#define __cxxtest__ParenPrinter_h__

//
// The ParenPrinter is identical to the ErrorPrinter, except it
// prints the line number in a format expected by some compilers
// (notably, MSVC).
//

#include <cxxtest/ErrorPrinter.h>

namespace CxxTest 
{
    class ParenPrinter : public ErrorPrinter
    {
    public:
        ParenPrinter( CXXTEST_STD(ostream) &o = CXXTEST_STD(cout) ) : ErrorPrinter( o, "(", ")" ) {}
    };
}

#endif // __cxxtest__ParenPrinter_h__
