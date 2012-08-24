################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
../src/Observer/Callback.cpp 

OBJS += \
./src/Observer/Callback.o 

CPP_DEPS += \
./src/Observer/Callback.d 


# Each subdirectory must supply rules for building sources it contributes
src/Observer/%.o: ../src/Observer/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Sourcery G++ C++ Compiler'
	arm-none-linux-gnueabi-g++ -I../src -I../src/Data -I../src/Observer -I../src/Tasks -I../src/util -I../../lib/inc/glib-2.6.0/glib -I../../lib/inc/glib-2.6.0 -I../../lib/inc/palmsocket -I../../lib/inc/openssl-0.9.7F -O0 -g3 -Wall -c -fmessage-length=0 -fcommon -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


