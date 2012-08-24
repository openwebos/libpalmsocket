################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
../src/cxxtest/Descriptions.cpp \
../src/cxxtest/DummyDescriptions.cpp \
../src/cxxtest/GlobalFixture.cpp \
../src/cxxtest/LinkedList.cpp \
../src/cxxtest/RealDescriptions.cpp \
../src/cxxtest/Root.cpp \
../src/cxxtest/TestSuite.cpp \
../src/cxxtest/TestTracker.cpp \
../src/cxxtest/ValueTraits.cpp 

OBJS += \
./src/cxxtest/Descriptions.o \
./src/cxxtest/DummyDescriptions.o \
./src/cxxtest/GlobalFixture.o \
./src/cxxtest/LinkedList.o \
./src/cxxtest/RealDescriptions.o \
./src/cxxtest/Root.o \
./src/cxxtest/TestSuite.o \
./src/cxxtest/TestTracker.o \
./src/cxxtest/ValueTraits.o 

CPP_DEPS += \
./src/cxxtest/Descriptions.d \
./src/cxxtest/DummyDescriptions.d \
./src/cxxtest/GlobalFixture.d \
./src/cxxtest/LinkedList.d \
./src/cxxtest/RealDescriptions.d \
./src/cxxtest/Root.d \
./src/cxxtest/TestSuite.d \
./src/cxxtest/TestTracker.d \
./src/cxxtest/ValueTraits.d 


# Each subdirectory must supply rules for building sources it contributes
src/cxxtest/%.o: ../src/cxxtest/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Sourcery G++ C++ Compiler'
	arm-none-linux-gnueabi-g++ -I../src -I../src/Data -I../src/Observer -I../src/Tasks -I../src/util -I../../lib/inc/glib-2.6.0/glib -I../../lib/inc/glib-2.6.0 -I../../lib/inc/palmsocket -I../../lib/inc/openssl-0.9.7F -O0 -g3 -Wall -c -fmessage-length=0 -fcommon -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


