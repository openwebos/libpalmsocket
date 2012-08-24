/** 
 * *****************************************************************************
 * @file TestCmdStressCommon.hpp
 * @ingroup psl_test
 * 
 * @brief  Common definitions for the libplamsocket Stress
 *         test command handler for stress-testing 's PmSock API
 *         in a multi-threaded environment.  Also used
 *         by the SSL shutdown test.
 * 
 * *****************************************************************************
 */
#ifndef PSL_TEST_CMD_STRESS_COMMON_HPP
#define PSL_TEST_CMD_STRESS_COMMON_HPP


#include <stdint.h>


namespace { /// anonymous



typedef enum StressTestKind_ {
    kStressTestKind_none,           ///< not doing stress test

    kStressTestKind_dataExg,        ///< data exchange test

    /// uni-directional SSL shut-down test; Data is sent from server to client;
    /// there is no report
    kStressTestKind_SSLShutOneWay,

    /// bi-directional SSL shut-down test; Data is sent from server to client;
    /// there is no report
    kStressTestKind_SSLShutTwoWay
} StressTestKind;


/** 
 * SSL/TLS Renegotiation options; may be bitwise-or'ed together
 *  
 * @{ 
 */
typedef uint32_t    StressSSLRenegFlags;
enum {
    kStressSSLRenegFlag_client     = 0x01, ///< client-initiated
    kStressSSLRenegFlag_server     = 0x02  ///< server-initiated
};
/**@}*/


/**
 * Command from client peer to server peer
 * 
 * @note We're not managing padding and byte order here, since
 *       we expect both client and server to run on compatible
 *       CPU architectures.
 */
typedef struct ServerPeerCmd_ {
    StressTestKind      testKind;      ///< type of test to perform
    uint32_t            groupIndex;    ///< for identification
    uint32_t            loopIndex;     ///< for identification
    uint32_t            targetRxBytes; ///< number of Rx bytes to expect
    uint32_t            targetTxBytes; ///< number of bytes to transmit
    uint32_t            useCrypto;     ///< 1 for SSL/TLS; 0 for plaintext
    uint32_t            sslReneg;      ///< 1=enable SSL/TLS renegotiation; 0=not
    #define SERVER_PEER_CMD_SIGNATURE   'CMND'
    uint32_t            signature;     ///< SERVER_PEER_CMD_SIGNATURE
} ServerPeerCmd;


/**
 * Report sent from server peer to client peer upon successful
 * conclusion of the command (all target bytes
 * received/transmitted)
 * 
 * @note We're not managing padding and byte order here, since
 *       we expect both client and server to run on compatible
 *       CPU architectures.
 */
typedef struct PeerReport_ {
    uint32_t            groupIndex;    ///< for identification
    uint32_t            loopIndex;     ///< for identification
    uint32_t            numRxBytes;    ///< number of bytes received
    struct {
        uint32_t    sec; ///< seconds
        uint32_t    nanosec;///< nanoseconds
    }                   rxDuration;

    #define PEER_REPORT_SIGNATURE   'RPRT'
    uint32_t            signature;     ///< SERVER_PEER_CMD_SIGNATURE
} PeerReport;



/**
 * class StressHostIface
 */
class StressHostIface {
public:
    virtual ~StressHostIface() {}

    /**
     * Notifies the parent entity that sub-service has finished 
     * processing 
     */
    virtual void StressHostSubserviceIsDone() = 0;
};


} // end of anonymous namespace

#endif //PSL_TEST_CMD_STRESS_COMMON_HPP
