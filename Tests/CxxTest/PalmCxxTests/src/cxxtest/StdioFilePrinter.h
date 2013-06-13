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

#ifndef __cxxtest__StdioFilePrinter_h__
#define __cxxtest__StdioFilePrinter_h__

//
// The StdioFilePrinter is a simple TestListener that
// just prints "OK" if everything goes well, otherwise
// reports the error in the format of compiler messages.
// This class uses <stdio.h>, i.e. FILE * and fprintf().
//

#include <cxxtest/ErrorFormatter.h>
#include <stdio.h>

namespace CxxTest 
{
    class StdioFilePrinter : public ErrorFormatter
    {
    public:
        StdioFilePrinter( FILE *o, const char *preLine = ":", const char *postLine = "" ) :
            ErrorFormatter( new Adapter(o), preLine, postLine ) {}
        virtual ~StdioFilePrinter() { delete outputStream(); }

    private:
        class Adapter : public OutputStream
        {
            Adapter( const Adapter & );
            Adapter &operator=( const Adapter & );
            
            FILE *_o;
            
        public:
            Adapter( FILE *o ) : _o(o) {}
            void flush() { fflush( _o ); }
            OutputStream &operator<<( unsigned i ) { fprintf( _o, "%u", i ); return *this; }
            OutputStream &operator<<( const char *s ) { fputs( s, _o ); return *this; }
            OutputStream &operator<<( Manipulator m ) { return OutputStream::operator<<( m ); }
        };
    };
}

#endif // __cxxtest__StdioFilePrinter_h__
