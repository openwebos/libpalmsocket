/*
 * CommonUtils.cpp
 *
 */


#define VERBOSE


#include <string>
#include <assert.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sstream>
#include <glib.h>
#include <glib/gtypes.h>


#include "CommonUtils.h"
#include "cxxtest/TestSuite.h"
#include "ConfigFile.h"


FILE *pOutputTarget=stdout;


class LogFileCreator {
private:
	bool isLogToFileEnabled_;
public:
	LogFileCreator() {
		UTIL_PRINT_NEWLINE(stdout, "LogFileCreator");

		Config config = ConfigFile::GetInstance().GetConfigForGroup(ConfigFile::Group_Default);
		isLogToFileEnabled_ = config.logToFile_;
		if (isLogToFileEnabled_) {
			pOutputTarget=fopen(config.logFilePath_.c_str(), "w");
			fprintf(pOutputTarget, "logfile opened by LogFileCreator() ... \n");
		}
	}

	~LogFileCreator() {
		UTIL_PRINT_NEWLINE(stdout, "~LogFileCreator");

		//do not try to get ConfigFile instance in here =>segmentation fault
		if (isLogToFileEnabled_) {
			fprintf(pOutputTarget, "..... logfile successfully closed by ~LogFileCreator().");
			fclose(pOutputTarget);
		}
	}
};


LogFileCreator logFileCreator;


PmSockCryptoConfArgs * UtilCreateEmptyPmSockCryptoConfArgs() {
	PmSockCryptoConfArgs *pCryptoConfArgs = new PmSockCryptoConfArgs();
	pCryptoConfArgs->enabledOpts=0;
	pCryptoConfArgs->lifecycleCb=0;
	pCryptoConfArgs->verifyCb=0;
	pCryptoConfArgs->verifyOpts=0;
	return pCryptoConfArgs;
}


class PmSockSSLCtxRAII {
public:
    PmSockSSLContext*   pCtx_;

    PmSockSSLCtxRAII()
    :pCtx_(NULL)
    {
    }

    ~PmSockSSLCtxRAII() {
        if (pCtx_) {
            PmSockSSLCtxUnref(pCtx_);
        }
    }

    PmSockSSLContext* Release() {
        PmSockSSLContext* const c = pCtx_;
        pCtx_ = NULL;
        return c;
    }
};


PmSockSSLContext* UtilMakeSSLContext(const char *userLabel, const std::string *pTrustedCertPath/*=NULL*/,
		SSL_METHOD *pSSLMethod/*=NULL*/)
{
    //Create a palmsocket SSL context
	PmSockSSLCtxRAII sslContext;
    PslError const pslerr = PmSockSSLCtxNew(userLabel, &sslContext.pCtx_);
    UTIL_ASSERT_THROW_FATAL(pslerr==0, userLabel, Err("PmSockSSLCtxNew failed: ", pslerr).c_str())

	SSL_CTX *pOpensslContext = PmSockSSLCtxPeekOpensslContext(sslContext.pCtx_);

	//add a CA certificate as trusted
	if (pTrustedCertPath){
		int result = SSL_CTX_load_verify_locations(pOpensslContext, /*CAfile*/pTrustedCertPath->c_str(), /*CApath*/NULL);
		UTIL_ASSERT_THROW_FATAL(result, userLabel, "SSL_CTX_load_verify_locations failed");
	}

    //set connection method
    if (pSSLMethod) {
    	int result = SSL_CTX_set_ssl_version(pOpensslContext, pSSLMethod/* e.g: TLSv1_method()*/ );
    	UTIL_ASSERT_THROW_FATAL(result, userLabel, "SSL_CTX_set_ssl_version failed");
    }
    //set connection method

    assert(sslContext.pCtx_);
    return sslContext.Release();
}


PmSockSSLContext* UtilMakeServerSSLContext(const char * userLabel, const std::string& privateKeyPath) {
	//checks if private key is empty, we don't need this
	if (privateKeyPath.empty()) {
        UTIL_THROW_FATAL(userLabel, "ERROR: private key path string is empty");
    }
    PmSockSSLCtxRAII pmContext;

    pmContext.pCtx_ = UtilMakeSSLContext(userLabel);

    //get the SSL_CTX out of palmsocket ssl context
    SSL_CTX* pOpenSSLContext = PmSockSSLCtxPeekOpensslContext(pmContext.pCtx_);
    assert(pOpenSSLContext);

    const char* ssl_func_name;

    ssl_func_name = "SSL_CTX_use_RSAPrivateKey_file()";
    int sslres = SSL_CTX_use_RSAPrivateKey_file(pOpenSSLContext, privateKeyPath.c_str(), SSL_FILETYPE_PEM);

    if (1==sslres) {
        ssl_func_name = "SSL_CTX_use_certificate_file()";
        sslres = SSL_CTX_use_certificate_file(pOpenSSLContext, privateKeyPath.c_str(), SSL_FILETYPE_PEM);
    }

    if (1==sslres) {
        ssl_func_name = "SSL_CTX_check_private_key()";
        sslres = SSL_CTX_check_private_key(pOpenSSLContext);
    }

    if (sslres != 1) {
        unsigned long opensslErr = 0;

        std::ostringstream oss;


        oss << __func__ << ": ERROR: " << ssl_func_name;
        oss << " failed (privateKeyPath=" << privateKeyPath << "): ";

        while ((opensslErr = ::ERR_get_error()) != 0) {
            char errText[120]; ///< openssl doc recommends 120 bytes
            ERR_error_string_n(opensslErr, errText, sizeof(errText));

            oss << errText << "; ";
        }

        UTIL_THROW_FATAL(userLabel, oss.str().c_str());
    }

    return pmContext.Release();
}


void CreateWatchWithCallback(PmSockIOChannel * const pOnChannel, GIOCondition ioCondition,
		PmSockWatch **pWatchToCreate, GSourceFunc CallbackForWatch,
		gpointer dataPassedToCallback, const char * myName)
{
	GMainContext *pGMainContext = PmSockThreadCtxPeekGMainContext(PmSockPeekThreadContext(pOnChannel)); //this should be the same as gMainContext_
    assert(pGMainContext);

	assert(*pWatchToCreate==NULL);
	PslError pslError = PmSockCreateWatch(pOnChannel, ioCondition, pWatchToCreate);
	UTIL_ASSERT_THROW_FATAL(!pslError, myName, Err("PmSockCreateWatch failed:", pslError).c_str() );

    g_source_set_can_recurse((GSource *)*pWatchToCreate, false);
    g_source_set_callback((GSource *)*pWatchToCreate, CallbackForWatch, dataPassedToCallback, /*notify*/NULL);
    g_source_attach((GSource *)*pWatchToCreate, pGMainContext);

    PRINT_LINE("%s watch for ioCondition==%s created", myName, IOConditionToString(ioCondition));
}


std::string ioConditionString;
const char * IOConditionToString(GIOCondition ioCondition) {
	ioConditionString.clear();

	if (ioCondition & G_IO_IN) {
		ioConditionString.append("G_IO_IN");
	}
	if (ioCondition & G_IO_OUT) {
		ioConditionString.append(" G_IO_OUT");
	}

	return ioConditionString.c_str();
}


std::string Err(const std::string& message, PslError errorCode)
{
	return message + PmSockErrStringFromError(errorCode);
}


void PrintVar(FILE *pFile, int var) {
	gchar * const msgBuf__ = g_strdup_printf("%d", var);
	UTIL_PRINT_NEWLINE(pFile, msgBuf__);
	g_free(msgBuf__);
}


void PrintVar(FILE *pFile, long var) {
	gchar * const msgBuf__ = g_strdup_printf("%d", var);
	UTIL_PRINT_NEWLINE(pFile, msgBuf__);
	g_free(msgBuf__);
}


void PrintVar(FILE *pFile, unsigned int var) {
	gchar * const msgBuf__ = g_strdup_printf("%u", var);
	UTIL_PRINT_NEWLINE(pFile, msgBuf__);
	g_free(msgBuf__);
}


void PrintVar(FILE *pFile, const std::string& var) {
	gchar *msgBuf__ = g_strdup_printf("%s", var.c_str() );
	UTIL_PRINT_NEWLINE(pFile, msgBuf__);
	g_free(msgBuf__);
}


void PrintVar(FILE *pFile, bool var) {
	gchar *msgBuf__ = g_strdup_printf("%s", (var ? "true" : "false") );
	UTIL_PRINT_NEWLINE(pFile, msgBuf__);
	g_free(msgBuf__);
}


