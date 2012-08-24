################################################################################
# Automatically-generated file. Do not edit!
################################################################################

-include ../makefile.init

RM := rm -rf

# All of the sources participating in the build are defined here
-include sources.mk
-include subdir.mk
-include src/util/subdir.mk
-include src/subdir.mk
-include src/cxxtest/subdir.mk
-include src/crc/subdir.mk
-include src/Tasks/subdir.mk
-include src/Observer/subdir.mk
-include src/Data/subdir.mk
-include objects.mk

ifneq ($(MAKECMDGOALS),clean)
ifneq ($(strip $(C++_DEPS)),)
-include $(C++_DEPS)
endif
ifneq ($(strip $(CC_DEPS)),)
-include $(CC_DEPS)
endif
ifneq ($(strip $(CPP_DEPS)),)
-include $(CPP_DEPS)
endif
ifneq ($(strip $(C_DEPS)),)
-include $(C_DEPS)
endif
ifneq ($(strip $(CXX_DEPS)),)
-include $(CXX_DEPS)
endif
ifneq ($(strip $(C_UPPER_DEPS)),)
-include $(C_UPPER_DEPS)
endif
endif

-include ../makefile.defs

# Add inputs and outputs from these tool invocations to the build variables 
EXECUTABLES += \
CxxTests \


# All Target
all: CxxTests secondary-outputs

# Tool invocations
CxxTests: $(OBJS) $(USER_OBJS)
	@echo 'Building target: $@'
	@echo 'Invoking: Sourcery G++ C++ Linker'
	arm-none-linux-gnueabi-g++ "@objs.rsp" "@user_objs.rsp" "@libs.rsp" -L../../lib/lib -L../../lib/usr/lib -o  "CxxTests"
	@echo 'Finished building target: $@'
	@echo ' '
	$(MAKE) --no-print-directory post-build

# Other Targets
clean:
	-$(RM) $(C++_DEPS)$(EXECUTABLES)$(CC_DEPS)$(CPP_DEPS)$(C_DEPS)$(CXX_DEPS)$(C_UPPER_DEPS)
	-$(RM) "/home/sv/svn/PalmSSL/trunk/PalmCxxTests/Debug/src/util/BandwidthMeter.o" "/home/sv/svn/PalmSSL/trunk/PalmCxxTests/Debug/src/util/CommonUtils.o" "/home/sv/svn/PalmSSL/trunk/PalmCxxTests/Debug/src/util/PipeFd.o" "/home/sv/svn/PalmSSL/trunk/PalmCxxTests/Debug/src/ClientPeerDeferredSSL.o" "/home/sv/svn/PalmSSL/trunk/PalmCxxTests/Debug/src/ClientPeerFullDuplexSSL.o" "/home/sv/svn/PalmSSL/trunk/PalmCxxTests/Debug/src/ClientPeerHalfDuplexPlainIn.o" "/home/sv/svn/PalmSSL/trunk/PalmCxxTests/Debug/src/ClientPeerHalfDuplexPlainOut.o" "/home/sv/svn/PalmSSL/trunk/PalmCxxTests/Debug/src/ClientPeerHalfDuplexSSLIn.o" "/home/sv/svn/PalmSSL/trunk/PalmCxxTests/Debug/src/ClientPeerHalfDuplexSSLOut.o" "/home/sv/svn/PalmSSL/trunk/PalmCxxTests/Debug/src/ClientPeerLeafFallbackNeg.o" "/home/sv/svn/PalmSSL/trunk/PalmCxxTests/Debug/src/ClientPeerShouldFailSSL.o" "/home/sv/svn/PalmSSL/trunk/PalmCxxTests/Debug/src/ClientSetUp.o" "/home/sv/svn/PalmSSL/trunk/PalmCxxTests/Debug/src/ConfigFile.o" 
	-$(RM) "/home/sv/svn/PalmSSL/trunk/PalmCxxTests/Debug/src/PalmTestSuite.o" "/home/sv/svn/PalmSSL/trunk/PalmCxxTests/Debug/src/PeerBase.o" "/home/sv/svn/PalmSSL/trunk/PalmCxxTests/Debug/src/PeerBaseParams.o" "/home/sv/svn/PalmSSL/trunk/PalmCxxTests/Debug/src/PeerFullDuplex.o" "/home/sv/svn/PalmSSL/trunk/PalmCxxTests/Debug/src/PeerFullDuplexPlain.o" "/home/sv/svn/PalmSSL/trunk/PalmCxxTests/Debug/src/PeerFullDuplexPlainSingleWatch.o" "/home/sv/svn/PalmSSL/trunk/PalmCxxTests/Debug/src/ServerPeerDeferredSSL.o" "/home/sv/svn/PalmSSL/trunk/PalmCxxTests/Debug/src/ServerPeerFullDuplexSSL.o" "/home/sv/svn/PalmSSL/trunk/PalmCxxTests/Debug/src/ServerPeerHalfDuplexPlainIn.o" "/home/sv/svn/PalmSSL/trunk/PalmCxxTests/Debug/src/ServerPeerHalfDuplexPlainOut.o" "/home/sv/svn/PalmSSL/trunk/PalmCxxTests/Debug/src/ServerPeerHalfDuplexSSLIn.o" "/home/sv/svn/PalmSSL/trunk/PalmCxxTests/Debug/src/ServerPeerHalfDuplexSSLOut.o" "/home/sv/svn/PalmSSL/trunk/PalmCxxTests/Debug/src/ServerPeerShouldFailSSL.o" 
	-$(RM) "/home/sv/svn/PalmSSL/trunk/PalmCxxTests/Debug/src/ServerSetUp.o" "/home/sv/svn/PalmSSL/trunk/PalmCxxTests/Debug/src/SetupBase.o" "/home/sv/svn/PalmSSL/trunk/PalmCxxTests/Debug/src/TestCertnameHostnameMatch.o" "/home/sv/svn/PalmSSL/trunk/PalmCxxTests/Debug/src/runner.o" "/home/sv/svn/PalmSSL/trunk/PalmCxxTests/Debug/src/cxxtest/Descriptions.o" "/home/sv/svn/PalmSSL/trunk/PalmCxxTests/Debug/src/cxxtest/DummyDescriptions.o" "/home/sv/svn/PalmSSL/trunk/PalmCxxTests/Debug/src/cxxtest/GlobalFixture.o" "/home/sv/svn/PalmSSL/trunk/PalmCxxTests/Debug/src/cxxtest/LinkedList.o" "/home/sv/svn/PalmSSL/trunk/PalmCxxTests/Debug/src/cxxtest/RealDescriptions.o" "/home/sv/svn/PalmSSL/trunk/PalmCxxTests/Debug/src/cxxtest/Root.o" "/home/sv/svn/PalmSSL/trunk/PalmCxxTests/Debug/src/cxxtest/TestSuite.o" "/home/sv/svn/PalmSSL/trunk/PalmCxxTests/Debug/src/cxxtest/TestTracker.o" "/home/sv/svn/PalmSSL/trunk/PalmCxxTests/Debug/src/cxxtest/ValueTraits.o" 
	-$(RM) "/home/sv/svn/PalmSSL/trunk/PalmCxxTests/Debug/src/crc/crc.o" "/home/sv/svn/PalmSSL/trunk/PalmCxxTests/Debug/src/crc/main.o" "/home/sv/svn/PalmSSL/trunk/PalmCxxTests/Debug/src/Tasks/ServerTaskSendAndShutdown.o" "/home/sv/svn/PalmSSL/trunk/PalmCxxTests/Debug/src/Observer/Callback.o" "/home/sv/svn/PalmSSL/trunk/PalmCxxTests/Debug/src/Data/Data.o" "/home/sv/svn/PalmSSL/trunk/PalmCxxTests/Debug/src/Data/DataAllocator.o" "/home/sv/svn/PalmSSL/trunk/PalmCxxTests/Debug/src/Data/DataIn.o" "/home/sv/svn/PalmSSL/trunk/PalmCxxTests/Debug/src/Data/DataOut.o" "/home/sv/svn/PalmSSL/trunk/PalmCxxTests/Debug/src/Data/DataReceiver.o" "/home/sv/svn/PalmSSL/trunk/PalmCxxTests/Debug/src/Data/DataSender.o" "/home/sv/svn/PalmSSL/trunk/PalmCxxTests/Debug/src/Data/DummyDataReceiver.o"  CxxTests CxxTests
post-build:
	-arm-none-linux-gnueabi-size "CxxTests"
	-@echo ' '

secondary-outputs:

.PHONY: all clean dependents
.SECONDARY: post-build

-include ../makefile.targets
