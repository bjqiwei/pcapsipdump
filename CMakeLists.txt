cmake_minimum_required(VERSION 3.14 FATAL_ERROR)

project(pcapsipdump) # 设置工程名称
message(STATUS "Project version: ${PROJECT_VERSION}")

option(USE_TCP "use tcp" OFF)
set(CMAKE_VERBOSE_MAKEFILE ON)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_EXTENSIONS Off)

if(CMAKE_HOST_APPLE)
	set(PLATFORM_APPLE 1)
	set(TARGET_OS "APPLE")
elseif(CMAKE_HOST_UNIX)
	set(PLATFORM_LINUX 1)
	set(TARGET_OS "LINUX")
elseif(CMAKE_HOST_WIN32)
	set(PLATFORM_WINDOWS 1)
	set(TARGET_OS "WINDOWS")
else()
	message(FATAL_ERROR "Do not support unknown host OS")
endif()


add_compile_options("-g")
#if ((${CMAKE_BUILD_TYPE} MATCHES "Debug") OR (${CMAKE_BUILD_TYPE} MATCHES "DEBUG"))
add_compile_options("-O0")
#endif()

if (NOT ENABLE_RTTI)
list(APPEND CMAKE_CXX_FLAGS "-fno-rtti")
endif()
	
add_executable(pcapsipdump pcapsipdump.cpp
	calltable.cpp
	pcapsipdump_lib.cpp
	pcapsipdump_strlib.cpp
	trigger.cpp) # 添加可执行文件

set(CMAKE_EXE_LINKER_FLAGS "-Wl,--gc-sections -static-libstdc++ -static-libgcc")
target_link_libraries(pcapsipdump pcap)