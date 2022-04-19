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
set(CMAKE_CXX_STANDARD 20)

project(Anteater
  VERSION 0.1.1
  DESCRIPTION "A profiling, logging, and testing library for C++ and C"
  LANGUAGES CXX C)

include(CTest)

# -----------------------------------------------------------------------------
file(GLOB LIB_HEADER_LIST CONFIGURE_DEPENDS "${Anteater_SOURCE_DIR}/include/brainyguy/*.h")
file(GLOB LIB_SOURCE_LIST CONFIGURE_DEPENDS "${Anteater_SOURCE_DIR}/library/*.c")

add_library(anteater SHARED ${LIB_HEADER_LIST} ${LIB_SOURCE_LIST})

# -----------------------------------------------------------------------------
target_include_directories(anteater
    PUBLIC
        $<INSTALL_INTERFACE:include>
        $<BUILD_INTERFACE:${Anteater_SOURCE_DIR}/include>
)

target_compile_options(anteater PRIVATE -Werror)
target_compile_features(anteater PRIVATE c_std_11)
target_link_libraries(anteater PUBLIC m)

# -------------------------------------------------------------------
file(GLOB TEST_SOURCE_LIST CONFIGURE_DEPENDS "${Anteater_SOURCE_DIR}/test/*.c")
add_executable(anteater_test "${TEST_SOURCE_LIST}")

target_include_directories(anteater_test
    PUBLIC
        $<INSTALL_INTERFACE:include>
        $<BUILD_INTERFACE:${Anteater_SOURCE_DIR}/include>
)

target_link_libraries(anteater_test PUBLIC anteater)

# -------------------------------------------------------------------
file(GLOB MAT_MULT_C_SOURCE_LIST CONFIGURE_DEPENDS "${BgLogger_SOURCE_DIR}/sample/matrix_mult.c")
add_executable(matrix_mult_c "${MAT_MULT_C_SOURCE_LIST}")

target_include_directories(matrix_mult_c
    PUBLIC
        $<INSTALL_INTERFACE:include>
        $<BUILD_INTERFACE:${Anteater_SOURCE_DIR}/include>
)

target_link_libraries(matrix_mult_c PUBLIC anteater)

# -------------------------------------------------------------------
file(GLOB THREADS_SOURCE_LIST CONFIGURE_DEPENDS "${Anteater_SOURCE_DIR}/sample/threads.cpp")
add_executable(threads "${THREADS_SOURCE_LIST}")

target_include_directories(threads
    PUBLIC
        $<INSTALL_INTERFACE:include>
        $<BUILD_INTERFACE:${Anteater_SOURCE_DIR}/include>
)

target_compile_features(threads PRIVATE cxx_std_20)
target_link_libraries(threads PUBLIC anteater)

# -----------------------------------------------------------------------------
# -----------------------------------------------------------------------------
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

# -----------------------------------------------------------------------------
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

# -----------------------------------------------------------------------------
# https://cmake.org/cmake/help/latest/variable/CMAKE_SYSTEM_PROCESSOR.html
# https://cmake.org/cmake/help/latest/variable/CMAKE_HOST_SYSTEM_PROCESSOR.html
# https://superuser.com/questions/305901/possible-values-of-processor-architecture/1441469#1441469
if(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
    add_compile_definitions(BG_PROCESSOR_x86_64=1)
elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "AMD64")
    add_compile_definitions(BG_PROCESSOR_x86_64=1)
elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "ARM64")
    add_compile_definitions(BG_PROCESSOR_ARM_64=1)
elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "X86")
    add_compile_definitions(BG_PROCESSOR_X86_32=1)
else()
    message(SEND_ERROR "ERROR: CPU architecture not recognized: ${CMAKE_SYSTEM_PROCESSOR}")
endif()

# -----------------------------------------------------------------------------
#add_compile_definitions(PRIVATE BG_BUILD_MODE_PROFILE=1)
add_compile_definitions(PRIVATE ANTEATER_BUILD_MODE_PROFILE=1)

# -----------------------------------------------------------------------------
if(BUILD_TESTING)
  add_test(NAME ackermann_ackermann4_1 COMMAND bglogger_test ackermann ackermann4_1)
endif()
