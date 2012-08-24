##
#  Component PalmSocketTestBlade (runs in PmWsfDaemon)
#
#  Makefile
##


#ifeq "$(findstring qemu, $(BB_MACHINE_TYPE))" "qemu"
#	IsEmulatorBuild := yes
#else
#	IsEmulatorBuild := no
#endif


##
# COMPONENT is the name of your component.

COMPONENT            := PalmSocketTestBlade

BUILD_MODEL          := LinuxSharedLibrary

DEPENDS_ON_PUBLIC    := \
	PmLogLib \
	palmsocket \
	luna-service \
	glib-2.0 \
	uriparser

#	cjson

DEPENDS_ON_PROTECTED := \
	PmWirelessSystemFramework \
	PmWsfTestBlade
	

# EXTRA_HEADER_DIRS += $(INCLUDE_DIR)/glib-2.0 
#EXTRA_HEADER_DIRS += 

# Add in header dirs specified by our bitbake files.
#EXTRA_HEADER_DIRS += $(BB_EXTRA_HEADER_DIRS)


##
# Additional cflags needed for this component.
#
# for -fvisibility - see http://gcc.gnu.org/wiki/Visibility
#

COMPONENT_CXXFLAGS     := \
	`pkg-config --cflags glib-2.0`


#	-fvisibility-inlines-hidden \
#	-fvisibility-inlines-hidden \
#	-fvisibility=hidden \
#	`pkg-config --cflags json`



VPATH = Src

OBJS := \
	CommonUtils.o \
	TestCmdCreateChannel.o \
	TestCmdCertnameHostnameMatch.o \
	TestCmdShutSSL.o \
	TestCmdStress.o \
	TestCmdHTTPGet.o \
	TestCmdHostLookup.o \
	TestCmdLogLevel.o \
	PslTestBlade.o \
	PslTestCmdShell.o


#ifeq ($(IsEmulatorBuild),no)
#	OBJS += \
#		DeviceResetModemTest.o \
#endif



COMPONENT_LINKFLAGS := \
	-Wl,-soname,libPalmSocketTestBlade.so \
	`pkg-config --libs glib-2.0` \
	-lpalmsocket \
	-luriparser

#	-llunaservice \
#	-lcjson
#	`pkg-config --libs json`
#	-L$(LIB_DIR)


##
# Include file that contains common make rules and variables
# * MAKEFILES_DIR is defined by our "package" Makefile

include $(MAKEFILES_DIR)/LinuxBuildEngine.mk
