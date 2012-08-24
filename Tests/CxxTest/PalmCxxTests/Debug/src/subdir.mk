################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
../src/ClientPeerDeferredSSL.cpp \
../src/ClientPeerFullDuplexSSL.cpp \
../src/ClientPeerHalfDuplexPlainIn.cpp \
../src/ClientPeerHalfDuplexPlainOut.cpp \
../src/ClientPeerHalfDuplexSSLIn.cpp \
../src/ClientPeerHalfDuplexSSLOut.cpp \
../src/ClientPeerLeafFallbackNeg.cpp \
../src/ClientPeerShouldFailSSL.cpp \
../src/ClientSetUp.cpp \
../src/ConfigFile.cpp \
../src/PalmTestSuite.cpp \
../src/PeerBase.cpp \
../src/PeerBaseParams.cpp \
../src/PeerFullDuplex.cpp \
../src/PeerFullDuplexPlain.cpp \
../src/PeerFullDuplexPlainSingleWatch.cpp \
../src/ServerPeerDeferredSSL.cpp \
../src/ServerPeerFullDuplexSSL.cpp \
../src/ServerPeerHalfDuplexPlainIn.cpp \
../src/ServerPeerHalfDuplexPlainOut.cpp \
../src/ServerPeerHalfDuplexSSLIn.cpp \
../src/ServerPeerHalfDuplexSSLOut.cpp \
../src/ServerPeerShouldFailSSL.cpp \
../src/ServerSetUp.cpp \
../src/SetupBase.cpp \
../src/TestCertnameHostnameMatch.cpp \
../src/runner.cpp 

OBJS += \
./src/ClientPeerDeferredSSL.o \
./src/ClientPeerFullDuplexSSL.o \
./src/ClientPeerHalfDuplexPlainIn.o \
./src/ClientPeerHalfDuplexPlainOut.o \
./src/ClientPeerHalfDuplexSSLIn.o \
./src/ClientPeerHalfDuplexSSLOut.o \
./src/ClientPeerLeafFallbackNeg.o \
./src/ClientPeerShouldFailSSL.o \
./src/ClientSetUp.o \
./src/ConfigFile.o \
./src/PalmTestSuite.o \
./src/PeerBase.o \
./src/PeerBaseParams.o \
./src/PeerFullDuplex.o \
./src/PeerFullDuplexPlain.o \
./src/PeerFullDuplexPlainSingleWatch.o \
./src/ServerPeerDeferredSSL.o \
./src/ServerPeerFullDuplexSSL.o \
./src/ServerPeerHalfDuplexPlainIn.o \
./src/ServerPeerHalfDuplexPlainOut.o \
./src/ServerPeerHalfDuplexSSLIn.o \
./src/ServerPeerHalfDuplexSSLOut.o \
./src/ServerPeerShouldFailSSL.o \
./src/ServerSetUp.o \
./src/SetupBase.o \
./src/TestCertnameHostnameMatch.o \
./src/runner.o 

CPP_DEPS += \
./src/ClientPeerDeferredSSL.d \
./src/ClientPeerFullDuplexSSL.d \
./src/ClientPeerHalfDuplexPlainIn.d \
./src/ClientPeerHalfDuplexPlainOut.d \
./src/ClientPeerHalfDuplexSSLIn.d \
./src/ClientPeerHalfDuplexSSLOut.d \
./src/ClientPeerLeafFallbackNeg.d \
./src/ClientPeerShouldFailSSL.d \
./src/ClientSetUp.d \
./src/ConfigFile.d \
./src/PalmTestSuite.d \
./src/PeerBase.d \
./src/PeerBaseParams.d \
./src/PeerFullDuplex.d \
./src/PeerFullDuplexPlain.d \
./src/PeerFullDuplexPlainSingleWatch.d \
./src/ServerPeerDeferredSSL.d \
./src/ServerPeerFullDuplexSSL.d \
./src/ServerPeerHalfDuplexPlainIn.d \
./src/ServerPeerHalfDuplexPlainOut.d \
./src/ServerPeerHalfDuplexSSLIn.d \
./src/ServerPeerHalfDuplexSSLOut.d \
./src/ServerPeerShouldFailSSL.d \
./src/ServerSetUp.d \
./src/SetupBase.d \
./src/TestCertnameHostnameMatch.d \
./src/runner.d 


# Each subdirectory must supply rules for building sources it contributes
src/%.o: ../src/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Sourcery G++ C++ Compiler'
	arm-none-linux-gnueabi-g++ -I../src -I../src/Data -I../src/Observer -I../src/Tasks -I../src/util -I../../lib/inc/glib-2.6.0/glib -I../../lib/inc/glib-2.6.0 -I../../lib/inc/palmsocket -I../../lib/inc/openssl-0.9.7F -O0 -g3 -Wall -c -fmessage-length=0 -fcommon -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


