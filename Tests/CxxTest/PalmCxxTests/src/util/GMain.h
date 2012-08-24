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

/*
 * GMain.h
 *
 */

#ifndef GMAIN_H_
#define GMAIN_H_


#include <glib/gmain.h>


/*
 * Creates a GMainContext and the corresponding GMainLoop
 */
class GMain {
private: //owned
	GMainContext *gMainContext_;
	GMainLoop *gMainLoop_;

public:
	GMain() {
		gMainContext_ = g_main_context_new();
		gMainLoop_ = g_main_loop_new(gMainContext_, false);
	}

	~GMain() {
		g_main_loop_unref(gMainLoop_);
		g_main_context_unref(gMainContext_);
	}

	GMainContext *GetContext() const {
		return gMainContext_;
	}

	GMainLoop * GetLoop() const {
		return gMainLoop_;
	}

};


#endif /* GMAIN_H_ */
