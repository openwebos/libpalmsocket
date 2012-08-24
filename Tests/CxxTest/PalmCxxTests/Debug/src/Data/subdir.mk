################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
../src/Data/Data.cpp \
../src/Data/DataAllocator.cpp \
../src/Data/DataIn.cpp \
../src/Data/DataOut.cpp \
../src/Data/DataReceiver.cpp \
../src/Data/DataSender.cpp \
../src/Data/DummyDataReceiver.cpp 

OBJS += \
./src/Data/Data.o \
./src/Data/DataAllocator.o \
./src/Data/DataIn.o \
./src/Data/DataOut.o \
./src/Data/DataReceiver.o \
./src/Data/DataSender.o \
./src/Data/DummyDataReceiver.o 

CPP_DEPS += \
./src/Data/Data.d \
./src/Data/DataAllocator.d \
./src/Data/DataIn.d \
./src/Data/DataOut.d \
./src/Data/DataReceiver.d \
./src/Data/DataSender.d \
./src/Data/DummyDataReceiver.d 


# Each subdirectory must supply rules for building sources it contributes
src/Data/%.o: ../src/Data/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Sourcery G++ C++ Compiler'
	arm-none-linux-gnueabi-g++ -I../src -I../src/Data -I../src/Observer -I../src/Tasks -I../src/util -I../../lib/inc/glib-2.6.0/glib -I../../lib/inc/glib-2.6.0 -I../../lib/inc/palmsocket -I../../lib/inc/openssl-0.9.7F -O0 -g3 -Wall -c -fmessage-length=0 -fcommon -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


