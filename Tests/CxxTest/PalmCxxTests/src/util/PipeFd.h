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
 * PipeFd.h
 *
 */

#ifndef PIPEFD_H_
#define PIPEFD_H_


/**
 * Class creates a pipe, stores the 2 file descriptors returned by the pipe in member variables.
 * Ability to send the thread shutdown signal.
 * @see IThreadShutdownObserver
 * @see GIOFuncCallback<IThreadShutdownObserver>
 * @see PeerBase constructor
 */
class PipeFd {
	int fdIn_;  /** file descriptor in, read from this one */
	int fdOut_; /** file descriptor out, write onto this one */
public:
	PipeFd();

	/** @returns file descriptor of pipe to read from */
	int GetFdIn() const { return fdIn_; }

	/**
	 * Will send a stop signal by writing one single byte into the fdOut_ filedescriptor
	 * Everyone who's listening for read events on fdOut_ (@see IThreadShutdownObserver) will get notified
	 */
	void SendShutdownSignal() const;

private:
	/** @returns file descriptor of pipe to write onto */
	int GetFdOut() const { return fdOut_; }
};


#endif /* PIPEFD_H_ */
