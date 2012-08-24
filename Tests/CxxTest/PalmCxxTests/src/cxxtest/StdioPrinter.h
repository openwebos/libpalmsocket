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

#ifndef __cxxtest__StdioPrinter_h__
#define __cxxtest__StdioPrinter_h__

//
// The StdioPrinter is an StdioFilePrinter which defaults to stdout.
// This should have been called StdOutPrinter or something, but the name
// has been historically used.
//

#include <cxxtest/StdioFilePrinter.h>

namespace CxxTest 
{
    class StdioPrinter : public StdioFilePrinter
    {
    public:
        StdioPrinter( FILE *o = stdout, const char *preLine = ":", const char *postLine = "" ) :
            StdioFilePrinter( o, preLine, postLine ) {}
    };
}

#endif // __cxxtest__StdioPrinter_h__
