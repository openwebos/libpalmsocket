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

/** 
 * *****************************************************************************
 * @file CommonUtils.h
 * @ingroup psl_test
 * 
 * @brief  Common utilities for libpalmsocket Debug/test blade.
 * 
 * *****************************************************************************
 */

#ifndef PSL_TEST_BLADE_COMMON_UTILS_H
#define PSL_TEST_BLADE_COMMON_UTILS_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h> // For clock_gettime()
#include <errno.h>
#include <assert.h>
#include <pthread.h>

#include <glib.h>
#include <glib/gprintf.h>

#include <stdexcept>
#include <algorithm>
#include <tr1/functional>

#include <PmWirelessSystemFramework/Utils/RuntimeDispatcher/RuntimeDispatcher.h>
#include <PmWirelessSystemFramework/Utils/RuntimeDispatcher/RdAsyncBridge.h>
#include <PmWsfTestUtils/CommandShell.h>

#if 0
#include <PmWirelessSystemFramework/Utils/RuntimeDispatcher/RdDescriptorMonitor.h>
#include <PmWirelessSystemFramework/Utils/RuntimeDispatcher/RdTimer.h>
#include <PmWirelessSystemFramework/Utils/Mutex.h>
#include <PmWirelessSystemFramework/Utils/RuntimeDispatcher/RdAsyncBridge.h>
#include <PmWirelessSystemFramework/Utils/Logger.h>
#include <PmWirelessSystemFramework/Utils/DiagnosticRegister.h>

#include <PmWsfTestUtils/ProgressReporter.h>
#endif //0

#include <palmsocket.h>
#include <palmsocklog.h>



namespace psl_test_blade {


#define UNCOPYABLE_CLASS_DECL(className__) \
    private: \
        className__ (const className__ &); \
        className__ & operator=(const className__ &)


#define UTIL_PRINT_LINE_HELPER(pFile__, ...)                            \
    do {                                                                \
            FILE* const f__ = pFile__;                                  \
            gchar* const msg__ = g_strdup_printf(__VA_ARGS__);          \
            fprintf(f__, "%s (logging thread=%lu)\n", msg__,            \
                (unsigned long)pthread_self());                         \
            fflush(f__);                                                \
            g_free(msg__);                                              \
    } while (0)


#define UTIL_PRINT_LINE(...)  \
    UTIL_PRINT_LINE_HELPER(stdout, __VA_ARGS__)


#define UTIL_PRINT_ERROR(...)                                           \
    do {                                                                \
        ::fflush(stdout);                                               \
        gchar* const errMsg__ = g_strdup_printf(__VA_ARGS__);           \
        UTIL_PRINT_LINE_HELPER(stderr, "ERROR: '%s', "                  \
                               "func='%s', file='%s', line=%d",         \
                               errMsg__, __func__, __FILE__, __LINE__); \
        g_free(errMsg__);                                               \
    } while ( 0 )


#define UTIL_THROW_FATAL(label__, msg__)                                \
    do {                                                                \
        gchar* const msgBuf__ = g_strdup_printf(                        \
            "%s: FATAL ERROR: '%s', func='%s', file='%s', line=%d",     \
            (label__), (msg__),                                         \
            __func__, __FILE__, __LINE__                                \
            );                                                          \
        ::fflush(stdout);                                               \
        UTIL_PRINT_LINE_HELPER(stderr, msgBuf__);                       \
        throw new std::runtime_error(msgBuf__);                         \
        g_free(msgBuf__);                                               \
    } while ( 0 )


#define UTIL_GIOCONDITION_ERROR_FLAGS = (G_IO_ERR | G_IO_HUP | G_IO_NVAL)

#define UTIL_IS_BIT_SET(value__, bit__)  (0 != ((value__) & (bit__)))


/**
 * UtilRxPmSockBytes():
 * 
 * @param pChan
 * @param dst
 * @param dstCnt
 * @param pRxCnt
 * @param isVerbose
 * @param userLabel
 * 
 * @return ::GIOStatus
 */
::GIOStatus
UtilRxPmSockBytes(::PmSockIOChannel*    pChan,
              void*                 dst,
              uint32_t              dstCnt,
              uint32_t*             pRxCnt,
              bool                  isVerbose,
              const char*           userLabel);


/**
 * UtilTxPmSockBytes():
 * 
 * @param pChan
 * @param src
 * @param srcCnt
 * @param isVerbose
 * @param userLabel
 * 
 * @return ::GIOStatus
 */
::GIOStatus
UtilTxPmSockBytes(::PmSockIOChannel*    pChan,
                  const void*           src,
                  uint32_t              srcCnt,
                  uint32_t*             pSentCnt,
                  bool                  isVerbose,
                  const char*           userLabel);



/**
 * UtilCreatePmSockWatch(): Creates a channel watch
 * and prepares it for operation (sets callbac, attaches to
 * gmain context, etc.).
 * 
 * @return PmSockWatch*
 */
::PmSockWatch*
UtilCreatePmSockWatch(::PmSockIOChannel*   pChan,
                  ::GIOCondition       cond,
                  ::GIOFunc            cbFunc,
                  void*                cbArg,
                  const char*          userLabel);

/**
 * UtilDestroyPmSockWatch): Destroys a watch that was created via
 * UtilCreatePmSockWatch.
 * 
 * @param pWatch
 */
void
UtilDestroyPmSockWatch(::PmSockWatch* const pWatch);


/**
 * UtilUpdatePmSockWatch():
 * 
 * @param cond
 */
void
UtilUpdatePmSockWatch(::PmSockWatch* pWatch,
                  ::GIOCondition cond,
                  const char*    userLabel);

/**
 * UtilInitOpenssl(): initializes openssl; throws an 
 * exception on error. 
 *  
 * @note Call PmSockOpensslUninit() directly to uninitialize 
 *       openssl.  The calls to UtilInitOpenssl and
 *       PmSockOpensslUninit MUST balance.
 */
void
UtilInitOpenssl(const char* userLabel);


/**
 * UtilMakeSSLCtx(); Creates a new PmSockSSLContext 
 * instance; throws an exception on error.
 *  
 * @param userLabel
 * 
 * @return PmSockSSLContext*
 */
::PmSockSSLContext*
UtilMakeSSLCtx(const char* userLabel);


/**
 * UtilMakeServerSSLCtx(): Creates and configures an SSL Context 
 * instance for use by the server side 
 * 
 * @param rPrivkeyPath Non-empty path to the RSA private key 
 *                     file; the file MUST exist.
 * @param userLabel 
 * 
 * @return PmSockSSLContext* 
 */
::PmSockSSLContext*
UtilMakeServerSSLCtx(const std::string& rPrivkeyPath, const char* userLabel);


/**
 * UtilTriggerSSLRenegotiation():
 * 
 * @param pChan 
 * @param userLabel 
 */
void
UtilTriggerSSLRenegotiation(::PmSockIOChannel* pChan,
                            ::PmSockRenegOpts  opts,
                            const char*        userLabel);

/**
 * UtilDumpPeerVerifyErrorInfo() 
 *  
 * @note May be called _only_ after SSL/TLS connection 
 *       completion callback (also from that callback) and while
 *       still in SSL mode.
 * 
 * @param pChan 
 * @param userLabel 
 */
void
UtilDumpPeerVerifyErrorInfo(::PmSockIOChannel* pChan,
                            const char*        userLabel);


/**
 * Maps the given string to an PmSockLogOptions value
 * 
 * @param pLogOptStr Non-NULL string to map to PmSockLogOptions.
 * 
 * @param pLogOpt Non-NULL ptr to variable to receive the 
 *                PmSockLogOptions value on success; undefined
 *                on failure.
 * 
 * @return bool True on success; false on error (string not
 *         recognized)
 */
bool
UtilPslLogOptionFromStr(const char*       pLogOptStr,
                        PmSockLogOptions* pLogOpt);


/**
 * Return a static const string corresponding to the given
 * GIOStatus value.
 * 
 * @param giostatus
 * 
 * @return const char*
 */
const char*
UtilStringFromGIOStatus(GIOStatus giostatus, const char* userLabel);



/** ***************************************************************************
 * class PeerBase
 * 
 * Defines the test peer interface and implements helper
 * function for stopping the peer.
 * ***************************************************************************
 */
class PeerBase {
public:
    PeerBase(const char peerName[], bool const isVerbose)
    :   isVerbose_(isVerbose),
        myName_(peerName),
        rd_(),
        stopEvt_(this, &PeerBase::OnStopTrigger, 0, rd_)
    {
    }

    virtual ~PeerBase()
    {
        if (isVerbose_) {
            UTIL_PRINT_LINE("%s/%s (this=%p): exiting destructor",
                       MyName(), __func__, this);
        }
    }


    const char* MyName()
    {
        return myName_.c_str();
    }

    virtual void Start() = 0;

    virtual void Stop() = 0;

    virtual bool IsDone() = 0;

    virtual bool IsSuccess() = 0;

    virtual void PrintStats() = 0;

protected:

    void Run()
    {
        if (isVerbose_) {
            UTIL_PRINT_LINE("%s/%s: Running...", MyName(), __func__);
        }

        rd_.Run();

        if (isVerbose_) {
            UTIL_PRINT_LINE("%s/%s: Stopped running...", MyName(), __func__);
        }
    }


    wsf::RuntimeDispatcher* GetRd()
    {
        return &rd_;
    }

    void RequestStop()
    {
        if (isVerbose_) {
            UTIL_PRINT_LINE("%s/%s: Scheduling stop...", MyName(), __func__);
        }

        stopEvt_.Trigger();

        if (isVerbose_) {
            UTIL_PRINT_LINE("%s/%s: returned from stopEvt_.Trigger()", MyName(),
                       __func__);
        }
    }

private:
    /**
     */
    void OnStopTrigger(wsf::RdAsyncBridge*, int)
    {
        if (isVerbose_) {
            UTIL_PRINT_LINE("%s/%s: Requesting rd to stop...", MyName(), __func__);
        }

        rd_.RequestStop();

        if (isVerbose_) {
            UTIL_PRINT_LINE("%s/%s: Returned from rd_.RequestStop()", MyName(), __func__);
        }
    }

private:
    bool                    const   isVerbose_;
    const std::string               myName_;
    wsf::RuntimeDispatcher          rd_;
    wsf::RdAsyncBridge              stopEvt_; ///< thread-safe object
}; // class PeerBase




enum {
    kUtilOneBillion = 1000000000L
};



inline const struct timespec
UtilTimespecFromMillisec(unsigned int const millisec)
{
    struct timespec const ts = {
        tv_sec  : (millisec/1000),
        tv_nsec : ((millisec % 1000) * 1000000)
    };

    return ts;
}


/**
 * Get current time and handle errors
 * 
 * @return struct timespec
 */
inline const struct timespec UtilGetCurrentTime()
{
    struct timespec time;
    const int err = clock_gettime(CLOCK_MONOTONIC, &time);
    if (err) {
        const int saved_errno = errno;

        printf("%s: clock_gettime failed with errno=%d\n", __FUNCTION__,
               (int)saved_errno);
        throw std::runtime_error("clock_gettime failed");
    }
    else {
        return time;
    }
}


inline void UtilNormalizeTime(struct timespec* pTime)
{
    pTime->tv_sec += pTime->tv_nsec / kUtilOneBillion;
    pTime->tv_nsec = pTime->tv_nsec % kUtilOneBillion;
}


/**
 * Calculate the difference between two times
 * 
 * @param start
 * @param end
 * 
 * @return struct timespec
 */
inline const struct timespec UtilGetTimeDifference(struct timespec start,
                                                   struct timespec end)
{
    /**
     * Normalize start and end times
     */
    UtilNormalizeTime(&start);
    UtilNormalizeTime(&end);
    
    /**
     * Compute the difference
     */
    end.tv_sec--;
    end.tv_nsec += kUtilOneBillion;

    struct timespec result;
    result.tv_sec = end.tv_sec - start.tv_sec;
    result.tv_nsec = end.tv_nsec - start.tv_nsec;

    UtilNormalizeTime(&result);

    assert(result.tv_sec >= 0);
    assert(result.tv_nsec >= 0);

    return result;
}


inline const struct timespec UtilGetTimeSum(struct timespec t1,
                                            struct timespec t2)
{
    UtilNormalizeTime(&t1);
    UtilNormalizeTime(&t2);

    t1.tv_sec += t2.tv_sec;
    t1.tv_nsec += t2.tv_nsec;

    UtilNormalizeTime(&t1);

    return t1;
}



/**
 * Stopwatch class
 */

class Stopwatch {
public:
    Stopwatch()
    :   startTimeValid_(false),
        startTime_(),
        endTimeValid_(false),
        endTime_()
    {
        return;
    }

    /**
     * Start the stopwatch
     */
    void Start()
    {
        if (startTimeValid_) {
            printf("%s: WARNING: Stopwatch was already started\n",
                   __FUNCTION__);
        }

        startTimeValid_ = false;
        endTimeValid_ = false;
        startTime_ = UtilGetCurrentTime();
        startTimeValid_ = true;
    }


    bool IsStarted()
    {
        return startTimeValid_;
    }

    /**
     * Returns true if stopwatch was started and is still running
     * (not stopped).
     * 
     * @return bool
     */
    bool IsRunning()
    {
        return startTimeValid_ && !endTimeValid_;
    }

    bool IsStopped()
    {
        return endTimeValid_;
    }

    /**
     * Stop the stopwatch
     */
    void Stop()
    {
        if (!startTimeValid_) {
            throw std::logic_error(
                "Stopwatch.Stop() called, but stopwatch not started yet");
        }

        if (endTimeValid_) {
            printf("%s: WARNING: Stopwatch was already stopped\n",
                   __FUNCTION__);
        }

        endTimeValid_ = false;
        endTime_ = UtilGetCurrentTime();
        endTimeValid_ = true;
    }

    /**
     * Return elapsed time.  If stopwatch was already stopped,
     * returns the time difference between start and stop time.  If
     * stopwatch is still running, returns the time difference
     * between start time and current time.
     * 
     * @note It's a logic error to call this function if clock has
     *       not been started.
     * 
     * @return struct timespec
     */
    const struct timespec GetElapsedTime()
    {
        struct timespec elapsed = {};

        if (!startTimeValid_) {
            throw std::logic_error(
                "GetElapsedTime called, but stopwatch not started yet");
        }

        if (endTimeValid_) {
            elapsed.tv_sec = endTime_.tv_sec - startTime_.tv_sec;
            return UtilGetTimeDifference(startTime_, endTime_);
        }
        else {
            return UtilGetTimeDifference(startTime_, UtilGetCurrentTime());
        }

        return elapsed;
    }


private:
    bool                            startTimeValid_;
    struct timespec                 startTime_;

    /**
     * Timestamp of when we ended transmitting data messages
     */
    bool                            endTimeValid_;
    struct timespec                 endTime_;

};//class Stopwatch



/**
 * class Throughput
 */
class Throughput {
public:
    Throughput()
    :   totalUnits_(0)
    {
        ::memset(&totalTime_, 0, sizeof(totalTime_));
    }

    void AddSample(double const units, const struct timespec& rDuration)
    {
        totalTime_ = UtilGetTimeSum(totalTime_, rDuration);
        totalUnits_ += units;
    }

    const struct timespec GetTotalTime()
    {
        return totalTime_;
    }

    double GetTotalTimeInSeconds()
    {
        double const sec = (totalTime_.tv_sec +
                            ((double)totalTime_.tv_nsec / (double)kUtilOneBillion));
        return sec;
    }


    double GetTotalUnits()
    {
        return totalUnits_;
    }

    double GetUnitsPerSecond()
    {
        double const sec = GetTotalTimeInSeconds();
        if (!sec) {
            return -1;
        }

        return totalUnits_ / sec;
    }

    double GetSecondsPerUnit()
    {
        if (!totalUnits_) {
            return -1;
        }

        return GetTotalTimeInSeconds() / totalUnits_;
    }

private:
    struct timespec                 totalTime_;
    
    double                          totalUnits_;
};//class Throughput



/**
 * class TestCmdMgr
 */
class TestCmdMgr {
    UNCOPYABLE_CLASS_DECL(TestCmdMgr);

public:
    class CommandIface {
    public:
        /// virtual interface destructor for correct polymorphic destruction
        virtual ~CommandIface() {}


        /**
         * GetName(): returns name of the command
         * 
         * @return const std::string 
         */
        virtual const std::string GetName() = 0;

        /**
         * CommandIfaceStartNB(): _non-blocking_ start request
         * 
         * @param pMgr Pointer to the parent test command manager (e.g.,
         *             for stopping test execution)
         * @param pMgrRd Command Manager's RuntimeDispatcher instance; 
         *               the command handler may use it for running its
         *               own logic, if needed.
         */
        virtual void CommandIfaceStartNB(TestCmdMgr* pMgr,
                                         wsf::RuntimeDispatcher* pMgrRd) = 0;

        /**
         * CommandIfaceStopBL(): _blocking_ stop request; MUST stop all 
         * test activity and return _after_ all activity is stopped. 
         *  
         * @note May be called _after_ command has already stopped or if 
         *       it failed to start.  Command implementation is expected
         *       to handle this gracefully.
         */
        virtual void CommandIfaceStopBL() = 0;
    };//class CommandIface

public:
    /**
     * TestCmdMgr constructor
     * 
     * @param pShell ptr to command shell instance
     * @param pCmd ptr to command instance
     */
    TestCmdMgr(wtu::CommandShellT* pShell)
    :   rd_(),
        endTestEvt_(this, &TestCmdMgr::OnEndTestEvent, (void*)NULL, rd_),
        cmdDoneEvt_(this, &TestCmdMgr::OnCmdDoneEvent, (void*)NULL, rd_),
        cmdShellInterruptMon_(
            pShell, &rd_,
            std::tr1::bind(&TestCmdMgr::OnCmdShellInterruptCb, this,
                           std::tr1::placeholders::_1)),
        name_(__func__)
    {
    }

    ~TestCmdMgr()
    {
    }

    /**
     * Run(): runs the command; blocks until the command is finished 
     * or we're interrupted by the shell 
     */
    void Run(CommandIface* pCmd)
    {
        name_ = pCmd->GetName();

        pCmd->CommandIfaceStartNB(this, &rd_);

        rd_.Run();

        pCmd->CommandIfaceStopBL();
    }

    /**
     * For use by CommandIface implementation to notify command 
     * manager that command has finished.  This call _is_ 
     * thread-safe! 
     */
    void CommandIsDone()
    {
        // We use a separate event (instead of endTestEvt_) here in case we
        // wish to do something special for command completion versus other
        // completion sources.
        cmdDoneEvt_.Trigger();
    }

private:
    void OnCmdDoneEvent(wsf::RdAsyncBridge*/*ignore*/, void*/*ignore CXT*/)
    {
        printf("%s/%s: COMMAND FINISHED PROCESSING.\n", name_.c_str(), __func__);
        endTestEvt_.Trigger();
    }

    void OnCmdShellInterruptCb(wtu::CommandShellInterruptMonitor* pMon)
    {
        printf("%s/%s: INTERRUPTED BY CMD SHELL.\n", name_.c_str(), __func__);
        endTestEvt_.Trigger();
    }

    void OnEndTestEvent(wsf::RdAsyncBridge*/*ignore*/, void*/*ignore CXT*/)
    {
        rd_.RequestStop();
    }

private:
    wsf::RuntimeDispatcher              rd_;
    wsf::RdAsyncBridge                  endTestEvt_;
    wsf::RdAsyncBridge                  cmdDoneEvt_;

    wtu::CommandShellInterruptMonitor   cmdShellInterruptMon_;

    std::string                         name_;
};//class TestCmdMgr


} // end of namespace psl_test_blade

#endif // PSL_TEST_BLADE_COMMON_UTILS_H
