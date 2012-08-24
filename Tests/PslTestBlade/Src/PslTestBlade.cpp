/** 
 * *****************************************************************************
 * @file HllTestBlade.cpp
 * @ingroup psl_test
 * 
 * @brief  HCI Handshake Debug/test blade.
 * 
 * *****************************************************************************
 */

//#include <iostream>
#include <stddef.h>
#include <stdio.h>

#include <tr1/functional>

#include <PmWirelessSystemFramework/Core/ServiceBlade.h>
#include <PmWirelessSystemFramework/Utils/Thread.h>
#include <PmWirelessSystemFramework/Utils/RuntimeDispatcher/RuntimeDispatcher.h>
#include <PmWirelessSystemFramework/Utils/RuntimeDispatcher/RdPortMonitor.h>
#include <PmWirelessSystemFramework/Core/MessageMover/MessageMoverInterface.h>
#include <PmWirelessSystemFramework/Core/MessageMover/MmConnectionPort.h>
#include <PmWirelessSystemFramework/Core/MessageMover/MmConnectionMessageHandle.h>
#include <PmWirelessSystemFramework/Core/WsfBladeControlMessages.h>


#include "PslTestBlade.h"


#ifdef __cplusplus 
extern "C" {
#endif


/**
 * This forward declaration helps ensure that our definition of
 * the function matches that expected by WSF.
 */
wsf::ServiceBladeObjectFactoryFn_t PalmSocketTest_CreateBlade;


/**
 * @brief This is the ServiceBladeObjectFactoryFn_t function for
 *        our Service Blade.  It creates a new instance of our
 *        ServiceBlade-derived object
 * 
 * @note Our blade entry function needs to be declared as a
 *       plain "C" language function (without any C++ name
 *       mangling or any other funny business) in the global
 *       namespace. WSF Shell will look-up and call it after
 *       loading our blade's DLL.
 */
wsf::ServiceBlade*
PalmSocketTest_CreateBlade(const std::string daemonName,
                           const std::string bladeName,
                           const std::string args)
{
    //printf("%s\n", __func__);
    return new psl_test_blade::PslTestBlade;
}


#ifdef __cplusplus
}
#endif




namespace psl_test_blade {





/**
 * ****************************************************************************
 */
PslTestBlade::PslTestBlade()
:   shellHost_("WSF.PALM.SOCKET.TEST.SHELL.HOST", "help")
{
    /*EMPTY*/
}


/**
 * ****************************************************************************
 */
void
PslTestBlade::Run(const wsf::ServiceBladeEnvironment& rBladeEnvironment)
{
    printf("%s: Entering the blade Run function for blade %s\n",
           __func__, rBladeEnvironment.bladeName.c_str());

    SaveBladeName(rBladeEnvironment.bladeName.c_str());

    /// Start our command shell
    shellHost_.RegisterCommands(&PeekHandlerTable()[0],
                                PeekHandlerTable().size());
    shellHost_.Start();

    /**
     * Create Port Monitor for monitoring incoming messages on the
     * Blade Control port
     * 
     * @note We can declare it on the stack here because it will go
     *       out of scope (get destroyed) before the Blade Control
     *       port (which will be destroyed by our caller); so the
     *       PortMonitor object will be deleted before the port,
     *       which is exactly what we need.
     */
    wsf::RdPortMonitor portMon (*rBladeEnvironment.pBladeControlPort, this,
                                &PslTestBlade::BladeControlPortMonCb,
                                &rBladeEnvironment, rd_);
    portMon.SetEventMask(true/*readable*/, false, false);


    /// Run in our own RuntimeDispatcher until we get the "stop"
    /// message from WSF Shell
    rd_.Run();

    printf("%s: Exiting the blade Run function for blade %s\n",
           __func__, rBladeEnvironment.bladeName.c_str());
}


/**
 * ****************************************************************************
 */
void 
PslTestBlade::BladeControlPortMonCb(wsf::RdPortMonitor* pMon,
                                       const wsf::PortEventInterface* pPort,
                                       bool isReadable, bool isWritable,
                                       bool isException,
                                       const wsf::ServiceBladeEnvironment* pBladeEnv)
{
    /// Read and process pending messages
    wsf::MmConnectionPort& rPort = *pBladeEnv->pBladeControlPort;
    wsf::MessageMoverInterface& rMmIface = *pBladeEnv->pMessageMoverInterface;

    bool    gotMsg = false;
    do {
        gotMsg = false;

        /// Attempt to read a message
        wsf::MmConnectionMessageHandle hMsg;
        wsf::WsfError_t err = rPort.ReadMessage (&hMsg);

        if (wsf::kWsfErrTryAgainLater == err) {
            continue;   /**< no more pending messages */
        }

        else if (0 != err) {
            /**
             * This is not supposed to happen, but we try to handle it
             * gracefully anyway.
             */
            printf("ERROR in %s: unexpected error code from " \
                   "ReadMessage <%#lx>.\n", __func__, (long)err);

            /// Request the main RuntimeDispatcher to stop
            rd_.RequestStop();

            continue;
        }

        gotMsg = true;  /**< we got a message! */

        /// Process the message
        wsf::MmMessageName   msgName;
        hMsg.GetMessageName (&msgName);

        if (wsf::kWsfBladeStopEvtMsg == msgName) {
            /// The Shell wants our Blade to stop and exit
            /// Request the main RuntimeDispatcher to stop
            rd_.RequestStop();
        }

        else {
            printf("ERROR in %s: unexpected message received from " \
                          "Service Blade - protocol=<%ld>; msgId=<%#lx>.\n",
                          __func__, (long)msgName.protocolId,
                          (long)msgName.messageId);
        }

        rMmIface.FreeMessage (hMsg);

    } while (gotMsg);

}



} // end of namespace psl_test_blade

