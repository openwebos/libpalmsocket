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

/** ****************************************************************************
 * @file psl_openssl_init.c
 * @ingroup psl_internal 
 * 
 * @brief  Openssl library initialization and uninitialization
 *         implementation.
 * 
 * *****************************************************************************
 */
#include "psl_build_config.h"

#include <stdbool.h>
#include <stdlib.h>

#include <pthread.h>

#include <openssl/conf.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>


/**
 * openssl thread support test per 'man
 * CRYPTO_set_locking_callback'
 */
#define OPENSSL_THREAD_DEFINES
#include <openssl/opensslconf.h>
#if defined(OPENSSL_THREADS)
    // thread support enabled
#else
    // no thread support
    #error "ERROR: openssl thread support is disabled"
#endif

#include "palmsocket.h"

#include "psl_log.h"
#include "psl_assert.h"

#include "psl_refcount.h"


/**
 * Structures for our openssl thread-safety hook info
 */

typedef struct ThreadLock_ {
    pthread_mutex_t     mutex;
} ThreadLock;


typedef struct ThreadSafetyInfo_ {

    bool                isInitialized;
    ThreadLock*         pLocks;
    int                 numLocks;

} ThreadSafetyInfo;

typedef struct PslOpensslInitData_ {
    ThreadSafetyInfo    threadSafety;
} PslOpensslInitData;



typedef struct PslOpensslInitState_ {
    /// This mutex protects our openssl initialization and uninitialization logic
    pthread_mutex_t         mutex;


    bool                    isInitialized;  ///< TRUE, if openssl is initialized
    PmSockOpensslInitType   initType;

    PslRefcount             refCount;       ///< initializer refcount

    PslOpensslInitData      opensslData;
} PslOpensslInitState;


static PslOpensslInitState gInitState = {
    /// "fast", non-recursive mutex
    .mutex                  = PTHREAD_MUTEX_INITIALIZER,
    .isInitialized          = false,
    .initType               = 0,
    .refCount               = {0},

    .opensslData    = {
        .threadSafety = {
            .isInitialized  = false,
            .pLocks         = NULL,
            .numLocks       = 0
        }
    }
};

static PslError
init_openssl_already_locked(PmSockOpensslInitType initType);

static PslError
init_openssl_low(PslOpensslInitData*    pData,
                 PmSockOpensslInitType  initType);

static void uninit_openssl_low(PslOpensslInitData* pData);


static void thread_safety_init(ThreadSafetyInfo* pData);

static void thread_safety_cleanup(ThreadSafetyInfo* pData);

static unsigned long get_thread_id_cb();

static void lock_or_unlock_cb(int mode, int type, const char *file, int line);



/* =========================================================================
 * =========================================================================
 */
PslError
PmSockOpensslInit(PmSockOpensslInitType const initType)
{
    PslError        rc = PSL_ERR_NONE;

    pthread_mutex_lock(&gInitState.mutex);

    rc = init_openssl_already_locked(initType);

    pthread_mutex_unlock(&gInitState.mutex);

    return rc;
}//PmSockOpensslInit



/* =========================================================================
 * =========================================================================
 */
PslError
PmSockOpensslUninit(void)
{
    pthread_mutex_lock(&gInitState.mutex);

    PSL_LOG_DEBUG("%s: isInitialized=%d, current initType=%d", __func__,
                  (int)gInitState.isInitialized, (int)gInitState.initType);

    /// @note if triggered, this assertion indicates excess of Uninit calls
    ///       (or _unlikely_ overflow of unbalanced Init calls: over 4 Billion)
    PSL_ASSERT(gInitState.isInitialized);

    if (psl_refcount_atomic_unref(&gInitState.refCount)) {
        uninit_openssl_low(&gInitState.opensslData);

        gInitState.isInitialized = false;
    }

    pthread_mutex_unlock(&gInitState.mutex);

    return PSL_ERR_NONE;
}//PmSockOpensslUninit



/* =========================================================================
 * =========================================================================
 */
PslError
PmSockOpensslThreadCleanup(void)
{
    PslError pslerr = PSL_ERR_NONE;

    pthread_mutex_lock(&gInitState.mutex);

    PSL_LOG_DEBUG("%s: isInitialized=%d, current initType=%d", __func__,
                  (int)gInitState.isInitialized, (int)gInitState.initType);

    //PSL_ASSERT(gInitState.isInitialized);

    if (gInitState.isInitialized) {
        ERR_remove_state(0);
    }
    else {
        pslerr = PSL_ERR_NOT_ALLOWED;
        PSL_LOG_CRITICAL(
            "%s: USAGE ERROR: %s called outside the scope of libpalmsocket's " \
            "initialization of OpenSSL", __func__, __func__);
    }

    pthread_mutex_unlock(&gInitState.mutex);

    return pslerr;
}//PmSockOpensslThreadCleanup


/* =========================================================================
 * =========================================================================
 */
void psl_openssl_init_conditional(PmSockOpensslInitType const initType)
{
    pthread_mutex_lock(&gInitState.mutex);

    PSL_LOG_DEBUG("%s: initType=%d", __func__, (int)initType);

    if (gInitState.isInitialized) {
        psl_refcount_atomic_ref(&gInitState.refCount);
    }

    else {
        (void)init_openssl_already_locked(initType);
    }

    pthread_mutex_unlock(&gInitState.mutex);
}



/** ========================================================================
 * init_openssl_already_locked(): the worker function that 
 * implements PmSockOpensslInit() and is also used by 
 * psl_openssl_init_conditional(). Assumes that this module's 
 * mutex is already locked. 
 *  
 * =========================================================================
 */
static PslError
init_openssl_already_locked(PmSockOpensslInitType const initType)
{
    PslError        rc = PSL_ERR_NONE;

    PSL_LOG_DEBUG("%s: initType=%d", __func__, (int)initType);

    if (gInitState.isInitialized) {
        if (kPmSockOpensslInitType_singleThreaded == gInitState.initType &&
            kPmSockOpensslInitType_multiThreaded == initType) {
            PSL_LOG_CRITICAL("%s: ERROR: multi-threaded openssl initialization " \
                             "is NOT allowed after single-threaded initialization",
                             __func__);
            rc = PSL_ERR_NOT_ALLOWED;
        }
        else {
            psl_refcount_atomic_ref(&gInitState.refCount);
        }
    }
    else {
        rc = init_openssl_low(&gInitState.opensslData, initType);
        if (PSL_ERR_NONE == rc) {
            gInitState.isInitialized = true;
            gInitState.initType = initType;
            psl_refcount_init(&gInitState.refCount, "PSL_OPENSSL_INIT",
                              &gInitState);

        }
    }

    return rc;
}//init_openssl_already_locked


/** ========================================================================
 * init_openssl_low(): performs the requested openssl 
 * initialization. Assumes our module's mutex is locked.
 *  
 * @todo Consider relocating this initialization logic to Palm's
 *       patch of the openssl library, along with patching the
 *       related initialiation/cleanup functions to do the right
 *       thing when called directly by various users (probably
 *       replace with no-ops or use re-entrant and thread-safe
 *       reference-count-based mechanisms)
 * 
 * @param pData 
 * @param initType 
 *  
 * @return PslError 0 on success; non-zero PslError code on 
 *         failure
 *  
 * =========================================================================
 */
static PslError
init_openssl_low(PslOpensslInitData*    const pData,
                 PmSockOpensslInitType  const initType)
{
    PSL_LOG_INFO("%s: ENTERING", __func__);

    PSL_ASSERT(pData);

    PSL_ASSERT(kPmSockOpensslInitType_singleThreaded == initType ||
               kPmSockOpensslInitType_multiThreaded  == initType);

    /**
     * @note SSL_library_init() is neither reentrant nor
     *       thread-safe.  This probably applies to
     *       SSL_load_error_strings(), etc.
     */
    PSL_LOG_DEBUG("%s: Calling SSL_library_init()", __func__);
    if (!SSL_library_init()) {
        PSL_LOG_FATAL("%s: ERROR: OpenSSL SSL_library_init() failed.",
                      __func__);
        return PSL_ERR_OPENSSL;
    }

    PSL_LOG_DEBUG("%s: Calling SSL_load_error_strings()", __func__);
    SSL_load_error_strings();

    if (kPmSockOpensslInitType_multiThreaded  == initType) {
        PSL_LOG_DEBUG("%s: Calling thread_safety_init", __func__);
        thread_safety_init(&pData->threadSafety);
    }

    /**
     * @note /dev/urandom emits bytes from a PRNG and will produce 
     *       bytes forever. Seeding with 1k byes is appropriate.
     *       /dev/random produces better quality randomness but can
     *       block, so urandom is better here.
     */
    PSL_LOG_DEBUG("%s: Calling RAND_load_file()", __func__);
    const char* const urandomPath = "/dev/urandom";
    int const numRandBytesRead = RAND_load_file(urandomPath, 1024);
    PSL_LOG_DEBUG("%s: RAND_load_file() read %d bytes from %s",
                  __func__, numRandBytesRead, urandomPath);

    PSL_LOG_INFO("%s: LEAVING WITH SUCCESS", __func__);

    return PSL_ERR_NONE;
}


/** ========================================================================
 * uninit_openssl_low(): Uninitializes openssl.  Assumes our 
 * module's mutex is locked. 
 * 
 * @param pData 
 *  
 * =========================================================================
 */
static void
uninit_openssl_low(PslOpensslInitData* const pData)
{
    PSL_LOG_INFO("%s: ENTERING", __func__);

    /**
     * @note Properly cleaning up openssl's memory allocations is
     *       very important for the purpose of analyzing an
     *       application's memory leaks.  If we don't have a
     *       reliable mechanism for cleaning up the library's memory
     *       allocations, it makes it more difficult to perform
     *       memory leak analysis (discerning openssl leaks from
     *       other leaks in the process).  Unforturnately, there is
     *       no SSL_library_cleanup(), so openssl cleanup is pure
     *       voodoo.  Search the WEB for "Leaks in
     *       SSL_Library_init()" to see other threads on this topic.
     * 
     * @note Thread-local cleanup: ERR_remove_state(0) MUST be
     *       called from the thread that called any openssl
     *       functions to avoid a thread-specific memory leak.
     */

    /**
     * Thread-safe cleanup, apparently
     */
    ENGINE_cleanup();
    CONF_modules_free();


    /**
     * global non-thread-safe cleanup after all SSL activity is
     * terminated
     */
    ERR_free_strings();
    EVP_cleanup();

    /// DO THIS LAST:
    thread_safety_cleanup(&pData->threadSafety);

    PSL_LOG_INFO("%s: LEAVING", __func__);
}



/** ========================================================================
 * thread_safety_init(): Initializes openssl thread-safety 
 * hooks. Assumes our module's mutex is locked. 
 * 
 * @todo openssl 1.0 switches to a dynamic thread-safety lock
 *       API.  We'll need to update thread_safety_init and
 *       thread_safety_cleanup once WebOS switches to openssl
 *       v1.0.  Need to file a JIRA for this task that is
 *       blocked by the openssl v1.0 upgrade task.
 * 
 * @todo 'man CRYPTO_set_id_callback' claims that dynamic locks
 *       are sometimes used by openssl for better performance.
 *       Do both 'dynamic' and 'static' locks need to be
 *       supported or just one of them?
 * 
 * @see CRYPTO_THREADID_set_callback,
 *      CRYPTO_set_dynlock_create_callback,
 *      CRYPTO_set_dynlock_lock_callback,
 *      CRYPTO_set_dynlock_destroy_callback
 * 
 * =========================================================================
 */
static void
thread_safety_init(ThreadSafetyInfo* const pData)
{
    PSL_LOG_DEBUG("%s: ENTERING", __func__);

    PSL_ASSERT(pData);
    PSL_ASSERT(!pData->isInitialized);
    PSL_ASSERT(!pData->numLocks);
    PSL_ASSERT(!pData->pLocks);

    pData->numLocks = CRYPTO_num_locks();

    PSL_LOG_DEBUG("%s: Initializing %d thread locks", __func__, pData->numLocks);

    pData->pLocks = malloc(pData->numLocks * sizeof(pData->pLocks[0]));
    PSL_ASSERT(!pData->numLocks || pData->pLocks);

    int i;
    for (i=0; i < pData->numLocks; i++) {
        PSL_LOG_DEBUGLOW("%s: Creating thread lock type=%d (%s)",
                         __func__, i, CRYPTO_get_lock_name(i));

        /// @note The locks are of the non-recursive kind by default
        int const mutexInitRes = pthread_mutex_init(&(pData->pLocks[i].mutex),
                                                    NULL);
        if (0 != mutexInitRes) {
            PSL_LOG_CRITICAL("%s: ERROR: pthread_mutex_init returned unexpected " \
                             "non-zero value: %d", __func__, mutexInitRes);
        }
    }

    PSL_LOG_DEBUG("%s: Calling CRYPTO_set_id_callback", __func__);
    CRYPTO_set_id_callback(get_thread_id_cb);

    PSL_LOG_DEBUG("%s: Calling CRYPTO_set_locking_callback", __func__);
    CRYPTO_set_locking_callback(lock_or_unlock_cb);

    pData->isInitialized = true;

    PSL_LOG_DEBUG("%s: LEAVING", __func__);
}


/** ========================================================================
 * thread_safety_cleanup(): Uninitializes openssl thread-safety
 * hooks
 * 
 * =========================================================================
 */
static void
thread_safety_cleanup(ThreadSafetyInfo* const pData)
{
    PSL_LOG_DEBUG("%s", __func__);

    if (!pData->isInitialized) {
        PSL_LOG_DEBUG("%s: thread-safety was not initialized, so nothing to do",
                      __func__);
        return;
    }

    CRYPTO_set_locking_callback(NULL);
    CRYPTO_set_id_callback(NULL);

    PSL_LOG_DEBUG("%s: Destroying %d thread locks",
                  __func__, pData->numLocks);

    int i;
    for (i=0; i < pData->numLocks; i++) {
        PSL_LOG_DEBUGLOW("%s: Destroying thread lock type=%d (%s)",
                         __func__, i, CRYPTO_get_lock_name(i));

        pthread_mutex_destroy(&(pData->pLocks[i].mutex));
    }

    free(pData->pLocks);

    pData->numLocks = 0;
    pData->pLocks = NULL;
    pData->isInitialized = false;
}


/** ========================================================================
 * get_thread_id_cb(): callback function registered via
 * CRYPTO_set_id_callback()
 * 
 * @return unsigned long
 * 
 * =========================================================================
 */
static unsigned long
get_thread_id_cb()
{
    unsigned long const threadId = (unsigned long)pthread_self();

    PSL_LOG_DEBUGLOW("%s: returning threadId=%lu", __func__, threadId);

    return threadId;
}


/** ========================================================================
 * lock_or_unlock_cb(): callback function registered via
 * CRYPTO_set_locking_callback()
 * 
 * @param mode
 * @param type
 * @param file
 * @param line
 * 
 * =========================================================================
 */
static void
lock_or_unlock_cb(int const mode, int const type, const char* const file,
                  int const line)
{
    PSL_LOG_DEBUGLOW("%s: threadId=%lu, mode=0x%X, type=%d (%s), caller=%s:%d",
                     __func__, CRYPTO_thread_id(), (unsigned)mode, type,
                     CRYPTO_get_lock_name(type), file, line);

    if (mode & CRYPTO_LOCK) {
        pthread_mutex_lock(&(gInitState.opensslData.threadSafety.pLocks[type].mutex));
    }
    else {
        pthread_mutex_unlock(&(gInitState.opensslData.threadSafety.pLocks[type].mutex));
    }
}

