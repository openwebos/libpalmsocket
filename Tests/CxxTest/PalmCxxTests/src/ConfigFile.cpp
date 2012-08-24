/*
 * Options.cpp
 *
 */


//#define VERBOSE


#include <assert.h>


#include "ConfigFile.h"
#include "CommonUtils.h"


using namespace std;


std::auto_ptr<ConfigFile> ConfigFile::instance_;


//group names
const char * ConfigFile::Group_Default="Default";
const char * ConfigFile::Group_HalfDuplexPlainToServer="HalfDuplexPlainToServer";
const char * ConfigFile::Group_HalfDuplexPlainToClient="HalfDuplexPlainToClient";
const char * ConfigFile::Group_FullDuplexPlainHostnameBased="FullDuplexPlainHostnameBased";
const char * ConfigFile::Group_FullDuplexPlainIPAddressBased="FullDuplexPlainIPAddressBased";
const char * ConfigFile::Group_FullDuplexPlainSingleWatch="FullDuplexPlainSingleWatch";
const char * ConfigFile::Group_FullDuplexSSL="FullDuplexSSL";
const char * ConfigFile::Group_DeferredSSL="DeferredSSL";
const char * ConfigFile::Group_HalfDuplexSSL="HalfDuplexSSL";
const char * ConfigFile::Group_CertVerifyHostnameByCommonName="CertVerifyHostnameByCommonName";
const char * ConfigFile::Group_CertVerifyHostnameByCommonNameNeg="CertVerifyHostnameByCommonNameNeg";
const char * ConfigFile::Group_CertVerifyAddressByCommonName="CertVerifyAddressByCommonName";
const char * ConfigFile::Group_CertVerifyAddressByCommonNameNeg="CertVerifyAddressByCommonNameNeg";
const char * ConfigFile::Group_CertVerifyHostnameBySubjaltName="CertVerifyHostnameBySubjaltName";
const char * ConfigFile::Group_CertVerifyHostnameBySubjaltNameNeg="CertVerifyHostnameBySubjaltNameNeg";
const char * ConfigFile::Group_CertVerifyAddressBySubjaltName="CertVerifyAddressBySubjaltName";
const char * ConfigFile::Group_CertVerifyAddressBySubjaltNameNeg="CertVerifyAddressBySubjaltNameNeg";
const char * ConfigFile::Group_CertVerifyInstalledLeafFallback="CertVerifyInstalledLeafFallback";
const char * ConfigFile::Group_CertVerifyInstalledLeafFallbackNeg="CertVerifyInstalledLeafFallbackNeg";
const char * ConfigFile::Group_BasicCertnameHostnameMatch="BasicCertnameHostnameMatch";


//key names
static const char * Key_NumberOfBytesToSend = "NumberOfBytesToSend";
static const char * Key_ServerListenPort = "ServerListenPort";
static const char * Key_ChunkSize = "ChunkSize";
static const char * Key_Enabled = "Enabled";
static const char * Key_Address = "Address";
static const char * Key_PrivateKeyPath = "PrivateKeyPath";
static const char * Key_LogToFile = "LogToFile";
static const char * Key_LogFilePath = "LogFilePath";


//keyfile name
static const char * ConfigFileName="palmTestsConfig";


ConfigFile::ConfigFile()
:pHardCodedDefault_(new Config(
		/*numBytes*/10240,
		/*serverPort*/30999,
		/*chunkSize*/1024,
		/*enabled*/true,
		/*address*/"localhost",
		/*privateKeyPath*/"/tmp/cxx/privatekey.pem",
		/*logToFile*/true,
		/*logFilePath*/"logfile.txt")
)
,pConfigFileDefault_(NULL)
{
	pGKeyFile_ = g_key_file_new();
	LoadKeyFile();
}


ConfigFile::~ConfigFile() {
	FN_PRINT_LINE("...");
	g_key_file_free(pGKeyFile_);
	delete pHardCodedDefault_;
	delete pConfigFileDefault_;
}


/*static*/
ConfigFile& ConfigFile::GetInstance() {
	if (instance_.get()==NULL) {
		instance_.reset(new ConfigFile() );
	}

	return *instance_.get();
}


void ConfigFile::LoadKeyFile() {
	GError *pError=NULL;
	gboolean loaded= g_key_file_load_from_file(pGKeyFile_, ConfigFileName, G_KEY_FILE_NONE, &pError);

	assert(pConfigFileDefault_==NULL);
	pConfigFileDefault_ = new Config( GetConfigForGroup(Group_Default, *pHardCodedDefault_) );
}


Config ConfigFile::GetConfigForGroup(const char * groupName) {
	return GetConfigForGroup(groupName, *pConfigFileDefault_);
}


Config ConfigFile::GetConfigForGroup(const char* groupName, const Config& defaultConfig) {
	GError *pGError = NULL;

	//numberOfBytesToSend
	int numberOfBytesToSend = g_key_file_get_integer(pGKeyFile_, groupName, Key_NumberOfBytesToSend, &pGError);
	if (pGError) {
		FN_PRINT_LINE("%s has no key named %s. Falling back to Default", groupName, Key_NumberOfBytesToSend);
		numberOfBytesToSend=defaultConfig.numberOfBytesToSend_;
		g_error_free(pGError);
		pGError=NULL;
	}

	//serverListenPort
	int serverListenPort = g_key_file_get_integer(pGKeyFile_, groupName, Key_ServerListenPort, &pGError);
	if (pGError) {
		FN_PRINT_LINE("%s has no key named %s. Falling back to Default", groupName, Key_ServerListenPort);
		serverListenPort=defaultConfig.serverListenPort_;
		g_error_free(pGError);
		pGError=NULL;
	}

	//chunkSize
	int chunkSize = g_key_file_get_integer(pGKeyFile_, groupName, Key_ChunkSize, &pGError);
	if (pGError) {
		FN_PRINT_LINE("%s has no key named %s. Falling back to Default", groupName, Key_ChunkSize);
		chunkSize=defaultConfig.chunkSize_;
		g_error_free(pGError);
		pGError=NULL;
	}

	//enabled
	int enabled = g_key_file_get_integer(pGKeyFile_, groupName, Key_Enabled, &pGError);
	if (pGError) {
		FN_PRINT_LINE("%s has no key named %s.Falling back to Default", groupName, Key_Enabled);
		enabled=defaultConfig.enabled_;
		g_error_free(pGError);
		pGError=NULL;
	}

	//address
	string address;
	gchar *pAddress = g_key_file_get_value(pGKeyFile_, groupName, Key_Address, &pGError);
	if (pGError) {
		FN_PRINT_LINE("%s has no key named %s. Falling back to Default", groupName, Key_Enabled);
		address=defaultConfig.address_;
		g_error_free(pGError);
		pGError=NULL;
	} else {
		//success
		address = pAddress;
		g_free(pAddress);
	}

	//private key path
	string privateKeyPath;
	gchar *pPrivateKeyPath = g_key_file_get_value(pGKeyFile_, groupName, Key_PrivateKeyPath, &pGError);
	if (pGError) {
		FN_PRINT_LINE("%s has no key named %s. Falling back to Default", groupName, Key_PrivateKeyPath);
		privateKeyPath=defaultConfig.privateKeyPath_;
		g_error_free(pGError);
		pGError=NULL;
	} else {
		//success
		privateKeyPath = pPrivateKeyPath;
		g_free(pPrivateKeyPath);
	}

	//logToFile
	int logToFile = g_key_file_get_integer(pGKeyFile_, groupName, Key_LogToFile, &pGError);
	if (pGError) {
		FN_PRINT_LINE("%s has no key named %s. Falling back to Default", groupName, Key_LogToFile);
		logToFile=defaultConfig.logToFile_;
		g_error_free(pGError);
		pGError=NULL;
	}

	//logFilePath
	string logFilePath;
	gchar *pLogFilePath = g_key_file_get_value(pGKeyFile_, groupName, Key_LogFilePath, &pGError);
	if (pGError) {
		FN_PRINT_LINE("%s has no key named %s. Falling back to Default", groupName, Key_LogFilePath);
		logFilePath=defaultConfig.logFilePath_;
		g_error_free(pGError);
		pGError=NULL;
	} else {
		//success
		logFilePath = pLogFilePath;
		g_free(pLogFilePath);
	}


	return Config(
			numberOfBytesToSend,
			serverListenPort,
			chunkSize,
			enabled,
			address.c_str(),
			privateKeyPath,
			logToFile,
			logFilePath
	);
}


//Config


Config::Config(unsigned int numberOfBytesToSend, int serverListenPort, unsigned int chunkSize, bool enabled,
		const char * address, const std::string& path, bool logToFile, const std::string& logFilePath)
:numberOfBytesToSend_(numberOfBytesToSend)
,serverListenPort_(serverListenPort)
,chunkSize_(chunkSize)
,enabled_(enabled)
,address_(address)
,privateKeyPath_(path)
,logToFile_(logToFile)
,logFilePath_(logFilePath)
{
}



