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

#ifndef __cxxtest_StdHeaders_h__
#define __cxxtest_StdHeaders_h__

//
// This file basically #includes the STL headers.
// It exists to support warning level 4 in Visual C++
//

#ifdef _MSC_VER
#   pragma warning( push, 1 )
#endif // _MSC_VER

#include <complex>
#include <deque>
#include <list>
#include <map>
#include <set>
#include <string>
#include <vector>

#ifdef _MSC_VER
#   pragma warning( pop )
#endif // _MSC_VER

#endif // __cxxtest_StdHeaders_h__
