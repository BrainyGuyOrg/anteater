# Copyright 2022 Carlos Reyes
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cmake_minimum_required(VERSION 3.21)

project(BgLogger
  VERSION 0.1.1
  DESCRIPTION "A logging and profiling library for C and C++"
  LANGUAGES C)

# -------------------------------------------------------------------
file(GLOB LIB_HEADER_LIST CONFIGURE_DEPENDS "${BgLogger_SOURCE_DIR}/include/brainyguy/*.h")
file(GLOB LIB_SOURCE_LIST CONFIGURE_DEPENDS "${BgLogger_SOURCE_DIR}/src/*.c")

add_library(bglogger SHARED ${LIB_HEADER_LIST} ${LIB_SOURCE_LIST})

# -------------------------------------------------------------------
target_include_directories(bglogger
    PUBLIC
        $<INSTALL_INTERFACE:include>
        $<BUILD_INTERFACE:${BgLogger_SOURCE_DIR}/include>
)

target_compile_options(bglogger PRIVATE -Werror)
target_compile_features(bglogger PRIVATE c_std_11)
target_link_libraries(bglogger PUBLIC m)

# -------------------------------------------------------------------
file(GLOB TEST_SOURCE_LIST CONFIGURE_DEPENDS "${BgLogger_SOURCE_DIR}/test/*.c")
add_executable(bglogger_test "${TEST_SOURCE_LIST}")

target_include_directories(bglogger_test
    PUBLIC
        $<INSTALL_INTERFACE:include>
        $<BUILD_INTERFACE:${BgLogger_SOURCE_DIR}/include>
)

target_link_libraries(bglogger_test PUBLIC bglogger)

include(CTest)

# -------------------------------------------------------------------
# https://gitlab.kitware.com/cmake/community/-/wikis/doc/tutorials/How-To-Write-Platform-Checks
if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    add_compile_definitions(BG_PLATFORM_WINDOWS=1)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_compile_definitions(BG_PLATFORM_LINUX=1)
elseif(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
    add_compile_definitions(BG_PLATFORM_BSD=1)
else()
    message(SEND_ERROR "ERROR: Platform name not recognized: ${CMAKE_SYSTEM_NAME}")
endif()

# -------------------------------------------------------------------
# https://cmake.org/cmake/help/latest/variable/CMAKE_LANG_COMPILER_ID.html
if(CMAKE_C_COMPILER_ID STREQUAL "MSVC")
    add_compile_definitions(BG_COMPILER_MSVC=1)
elseif(CMAKE_C_COMPILER_ID STREQUAL "GNU")
    add_compile_definitions(BG_COMPILER_GCC=1)
elseif(CMAKE_C_COMPILER_ID STREQUAL "Clang")
    add_compile_definitions(BG_COMPILER_CLANG=1)
elseif(CMAKE_C_COMPILER_ID STREQUAL "Intel")
    add_compile_definitions(BG_COMPILER_ICC=1)
else()
    message(SEND_ERROR "ERROR: Compiler id not recognized: ${CMAKE_C_COMPILER_ID}")
endif()

# -------------------------------------------------------------------
add_compile_definitions(PRIVATE BG_BUILD_MODE_PROFILE=1)
