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

/*
 * ConfigFile.h
 *
 */

#ifndef CONFIGFILE_H_
#define CONFIGFILE_H_


#include <memory>


#include <gkeyfile.h>
#include <string>


/**
 * Contains all the configuration options necessary for a test
 */
class Config {
private:
	friend class ConfigFile;
	Config(unsigned int numBytes, int serverPort, unsigned int chunkSize, bool enabled,
			const char * address, const std::string& path, bool logToFile, const std::string& logFilePath);

public:
	const unsigned int numberOfBytesToSend_;
	const int serverListenPort_;
	const unsigned int chunkSize_;
	const bool enabled_;
	const std::string address_;  		/** addres to which client peer will try to connect (IP or dns name) */
	const std::string privateKeyPath_;	/** the full path to they .pem file which contains the private key */

	//log file related configuration option (not applicable for individual tests)
	const bool logToFile_; //true means log to a file on disk
	const std::string logFilePath_;
};


/**
 * Executes configuration file related operations:
 */
class ConfigFile {
private:
	static std::auto_ptr<ConfigFile> instance_;

	//owned
	GKeyFile *pGKeyFile_;	/** the GKeyFile to give to g_key .... () glib functions */
	Config *pHardCodedDefault_;		/** contains hard coded default values */
	Config *pConfigFileDefault_;	/** contains values from Default group from the config file */

public:
	//group names
	static const char * Group_Default;

	//half duplex plain, client sends, server receives
	static const char * Group_HalfDuplexPlainToServer;
	//half duplex plain, client receives, server sends
	static const char * Group_HalfDuplexPlainToClient;
	//full duplex plain hostname based, client receives, server sends
	static const char * Group_FullDuplexPlainHostnameBased;
	//full duplex plain IP address based
	static const char * Group_FullDuplexPlainIPAddressBased;
	//full duplex plain single watch
	static const char * Group_FullDuplexPlainSingleWatch;
	//full duplex SSL
	static const char * Group_FullDuplexSSL;
	//deferred SSL
	static const char * Group_DeferredSSL;
	//half duplex SSL
	static const char * Group_HalfDuplexSSL;
	//cert verify host name by common name
	static const char * Group_CertVerifyHostnameByCommonName;
	//cert verify host name by common name neg
	static const char * Group_CertVerifyHostnameByCommonNameNeg;
	//cert verify address by common name
	static const char * Group_CertVerifyAddressByCommonName;
	//cert verify address by common name neg
	static const char * Group_CertVerifyAddressByCommonNameNeg;
	//cert verify hostname by subjalt_name
	static const char * Group_CertVerifyHostnameBySubjaltName;
	//cert verify hostname by subjalt_name neg
	static const char * Group_CertVerifyHostnameBySubjaltNameNeg;
	//cert verify address by subjalt_name
	static const char * Group_CertVerifyAddressBySubjaltName;
	//cert verify address by subjalt_name neg
	static const char * Group_CertVerifyAddressBySubjaltNameNeg;
	//cert verify installed leaf fallback
	static const char * Group_CertVerifyInstalledLeafFallback;
	//cert verify installed leaf fallback neg
	static const char * Group_CertVerifyInstalledLeafFallbackNeg;
	//basic certname hostname match
	static const char * Group_BasicCertnameHostnameMatch;

private:
	ConfigFile();

public:
	virtual ~ConfigFile();

	/** @returns configuration options of test named @param groupname */
	Config GetConfigForGroup(const char * groupName);

	static ConfigFile& GetInstance();

private:
	/** Loads keyfile, or creates a new one based on default settings */
	void LoadKeyFile();

	/**
	 * @param defaultConfig fall back to these values in case group @param groupName is missing some values
	 */
	Config GetConfigForGroup(const char* groupName, const Config& defaultConfig);

};


#endif /* CONFIGFILE_H_ */
