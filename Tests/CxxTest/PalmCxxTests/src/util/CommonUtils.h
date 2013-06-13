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
 * CommonUtils.h
 *
 */

#ifndef COMMONUTILS_H_
#define COMMONUTILS_H_


#include <openssl/ssl.h>
#include <palmsocket.h>
#include <stdio.h>
#include <stdexcept>


extern FILE *pOutputTarget;


//#define OutputTarget stdout
//#define OutputTarget pLogFile;


/** Creates a PmSockCryptoConfArgs, every member initialized with 0 */
PmSockCryptoConfArgs * UtilCreateEmptyPmSockCryptoConfArgs();


/**
 * Creates a PmSockSSLContext instance wich will be used with accept crypto function
 */
PmSockSSLContext* UtilMakeServerSSLContext(const char * userLabel, const std::string& privateKeyPath);


/**
 * Creates a PmSockSSLContext instance wich will be used with connect crypto and accept crypto functions
 * @param pSSLMethod the connection method to use (or NULL for default)
 * @param pTrustedCertPath indicates a file, that should contain a certificate which will be added as
 * trusted on client side
 */
PmSockSSLContext* UtilMakeSSLContext(const char * userLabel, const std::string *pTrustedCertPath=NULL,
		SSL_METHOD *pSSLMethod=NULL);


/**
 * Creates a watch on specified channel and attaches a callback function to it.
 * @param pOnChannel on this channel will be the watch created
 * @param ioCondition fire watch on this condition
 * @param pWatchToCreate returns the created watch
 * @param CallbackForWatch will be called upon firing the watch
 * @param dataPassedToCallback data will be passed to callback function each time watch is fired
 * @param myName signature to appear in log
 */
void CreateWatchWithCallback(PmSockIOChannel * const pOnChannel, GIOCondition ioCondition,
		PmSockWatch **pWatchToCreate, GSourceFunc CallbackForWatch, gpointer dataPassedToCallback,
		const char * myName);

const char * IOConditionToString(GIOCondition ioCondition);


//prints given args, prints filename, functionname, appends newline
#define UTIL_PRINT_NEWLINE_WITH_FILENAME_AND_FUNCTIONNAME(pFile__, ...) \
    do {                                                                \
            FILE* const f__ = pFile__;                                  \
            gchar* const msg__ = g_strdup_printf(__VA_ARGS__);          \
            fprintf(f__, "%s::%s %s \n", __FILE__, __func__, msg__);	\
            fflush(f__);                                                \
            g_free(msg__);                                              \
    } while (0)


//prints given args, appends newline
#define UTIL_PRINT_NEWLINE(pFile__, ...)                            		\
    do {                                                                \
            FILE* const f__ = pFile__;                                  \
            gchar* const msg__ = g_strdup_printf(__VA_ARGS__);          \
            fprintf(f__, "%s \n", msg__);								\
            fflush(f__);                                                \
            g_free(msg__);                                              \
    } while (0)


//prints given args, without newline
#define UTIL_PRINT(pFile__, ...)									\
	do {                                                                \
			FILE* const f__ = pFile__;                                  \
			gchar* const msg__ = g_strdup_printf(__VA_ARGS__);          \
			fprintf(f__, "%s", msg__);									\
			fflush(f__);                                                \
			g_free(msg__);                                              \
	} while (0)


//public macros


//Use when an error occurs which prevents further execution of test
//exception should be catched on deepest level in stack, of the current thread
#define UTIL_THROW_FATAL(label__, msg__)                                \
    do {                                                                \
        gchar* const msgBuf__ = g_strdup_printf(                        \
            "%s: FATAL ERROR: '%s', func='%s', file='%s', line=%d",     \
            (label__), (msg__),                                         \
            __func__, __FILE__, __LINE__                                \
            );                                                          \
        fflush(stdout);                                                 \
        UTIL_PRINT_NEWLINE_WITH_FILENAME_AND_FUNCTIONNAME(stderr, msgBuf__);                \
        std::runtime_error runtimeError(msgBuf__);						\
        g_free(msgBuf__);                                               \
																		\
		throw runtimeError;												\
    } while ( 0 )


//Asserts condition with TS_ASSERT, throws runtime_error if condition is false
//Use when an error occurs which prevents further execution of test
//exception should be catched on lowest level in stack, of the current thread
#define UTIL_ASSERT_THROW_FATAL(condition, label__, msg__)						\
	TS_ASSERT(condition);														\
	if (!(condition) ) {														\
		gchar * const msgBuf__ = g_strdup_printf(								\
			"%s: FATAL ERROR: '%s', func='%s', file='%s', line=%d",				\
			(label__), (msg__),													\
			__func__, __FILE__, __LINE__										\
			);																	\
		fflush(stdout);															\
        UTIL_PRINT_NEWLINE_WITH_FILENAME_AND_FUNCTIONNAME(stderr, msgBuf__);    \
        std::runtime_error runtimeError(msgBuf__);								\
		g_free(msgBuf__);														\
																				\
		throw runtimeError;                        								\
	}


//!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
// 											W A R N I N G
//define VERBOSE in .cpp if you want these logging functions to actually log something !!!!!!!!!!!!!!!!
//!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
#ifdef VERBOSE
#define FN_PRINT_LINE(...)  \
    UTIL_PRINT_NEWLINE_WITH_FILENAME_AND_FUNCTIONNAME(pOutputTarget, __VA_ARGS__)

#define PRINT_LINE(...) \
	UTIL_PRINT_NEWLINE(pOutputTarget, __VA_ARGS__)

#define PRINT(...) \
	UTIL_PRINT(pOutputTarget, __VA_ARGS__)

#else
#define FN_PRINT_LINE(...)
#define PRINT_LINE(...)
#define PRINT(...)

#endif


/*
 * Creates an error message concatenating @param message and error message corresponding to @param errorCode
 */
std::string Err(const std::string& message, PslError errorCode);


void PrintVar(FILE *pFile, int var);
void PrintVar(FILE *pFile, long var);
void PrintVar(FILE *pFile, unsigned int var);
void PrintVar(FILE *pFile, const std::string& var);
void PrintVar(FILE *pFile, bool var);


#define LOGVAR(var)																			\
	do {																					\
		gchar * const msgBuf__ = g_strdup_printf("%s::%s: %s=", __FILE__, __func__, #var);	\
		UTIL_PRINT(stdout, msgBuf__);														\
		g_free(msgBuf__);																	\
		PrintVar(stdout, var);																\
	} while ( 0 )


#endif /* COMMONUTILS_H_ */
