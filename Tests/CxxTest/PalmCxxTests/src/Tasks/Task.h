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
 * Task.h
 *
 */

#ifndef TASK_H_
#define TASK_H_


#define DEFERRED_SSL_SINGLE_BYTE_VALUE 255


/**
 * Abstract base class for a task
 */
class Task {
protected:
	/**
	 * true means current task finished operation. Use it when a task has to be executed in multiple
	 * iterations. On every iteration Execute() should be called, until task is finished.
	 */
	bool isFinished_;

public:
	Task() { isFinished_=false; }
	virtual ~Task() {}

	/** Executes the task */
	virtual void Execute()=0;
	virtual bool IsFinished() { return isFinished_; }
};


#endif /* TASK_H_ */
