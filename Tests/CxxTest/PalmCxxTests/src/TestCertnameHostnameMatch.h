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
 * TestCertnameHostnameMatch.h
 *
 */


#ifndef TESTCERTNAMEHOSTNAMEMATCH_H_
#define TESTCERTNAMEHOSTNAMEMATCH_H_


/**
 * Validates PmSockX509CheckCertHostNameMatch(); this function is exported from libpalmsocket via
 * palmsockx509utils.h.  The comment block for this function in palmsockx509utils.h lists a set of cases
 * that are not supposed to pass and another set that are supposed to pass.
 *
 * Exceptions: NOTE2 PmSockX509CheckCertHostNameMatch should incorrectly report the following as
 * matching on Nova-Blowfish and Nova-Barleywine builds, but should correctly report them as not
 * matching on Nova-Main and future builds.
 * "*.tv"              vs. "flinstones.tv"         no
 * "f*.tv"             vs. "flinstones.tv"         no
 */
class TestCertnameHostnameMatch {
private:
	const char * const myName_;

public:
	TestCertnameHostnameMatch();
	virtual ~TestCertnameHostnameMatch();

	void Execute();

	/**
	 * CnHnEq(): Wrapper around PmSockX509CheckCertHostNameMatch();
	 * optioinally, outputs parameters and status to stdout (if
	 * verbose arg is TRUE)
	 *
	 * @param cnStr
	 * @param cnStrLen
	 * @param hnStr
	 * @param hnStrLen
	 * @param verbose
	 * @param pMatched Non-NULL pointer to variable for returning
	 *                 status the match; undefined on failure
	 *
	 * @return bool TRUE on success (does not reflect match status),
	 *         FALSE on failure
	 */
	bool CnHnEq(const char* const cnStr, unsigned const cnStrLen,
	            const char* const hnStr, unsigned const hnStrLen,
	            bool* const pMatched);
};


#endif /* TESTCERTNAMEHOSTNAMEMATCH_H_ */
