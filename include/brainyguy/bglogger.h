#pragma once
#ifndef BG_LOGGER_H
#define BG_LOGGER_H 1

/*
 *   Copyright 2022 Carlos Reyes
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

#if !defined(__cplusplus)
// ------------------------------------------------------------------
// Configuration
// ------------------------------------------------------------------
#define BG_FILE_NAME            __FILE__
#define BG_LINE_NUMBER          __LINE__

// https://gcc.gnu.org/onlinedocs/cpp/Predefined-Macros.html
// https://www.edg.com/docs/edg_cpp.pdf
#if defined(BG_COMPILER_GCC) || defined(BG_COMPILER_CLANG) || defined(BG_COMPILER_ICC)
    #define BG_FUNCTION_NAME        __func__
    #define BG_FUNCTION_SIGNATURE   __PRETTY_FUNCTION__
#elif defined(BG_COMPILER_MSVC)
    #define BG_FUNCTION_NAME        __FUNCTION__
    #define BG_FUNCTION_SIGNATURE   __FUNCSIG__
#else
    #error Unsupported compiler.
#endif

// https://gcc.gnu.org/onlinedocs/gcc-11.2.0/gcc/Common-Variable-Attributes.html
// https://docs.microsoft.com/en-us/cpp/cpp/try-finally-statement
#if defined(BG_COMPILER_GCC) || defined(BG_COMPILER_CLANG) || defined(BG_COMPILER_ICC)
    #define BG_CLEANUP_ATTRIBUTE 1
#elif defined(BG_COMPILER_MSVC)
    #define BG_C_TRY_FINALLY 1
#else
    #error Unsupported compiler.
#endif

// ------------------------------------------------------------------
// Includes
// ------------------------------------------------------------------
#include <assert.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <threads.h>
#include <time.h>

#if defined(BG_PLATFORM_LINUX)
#define _GNU_SOURCE 1
#include <syslog.h>
#include <errno.h>

extern char *program_invocation_name;
extern char *program_invocation_short_name;
#endif

// ------------------------------------------------------------------
const char* get_program_name();

// ------------------------------------------------------------------
// Data Sinks
// ------------------------------------------------------------------
typedef enum {
    BG_RECORDTYPE_COLUMNINFO            = 0xDEAD0001,
    BG_RECORDTYPE_COLUMNDATA            = 0xDEAD0002,
    BG_RECORDTYPE_FILTER                = 0xDEAD0003,
    BG_RECORDTYPE_DATASINK              = 0xDEAD0004,
    BG_RECORDTYPE_TEXTDATASINK          = 0xDEAD0005,

    BG_RECORDTYPE_PROGRAM               = 0xDEAD0011,
    BG_RECORDTYPE_FUNCTION              = 0xDEAD0012
} bg_RecordType;

// ------------------------------------------------------------------
typedef enum {
    BG_DATATYPE_CATEGORY    = 1,
    BG_DATATYPE_INTERVAL    = 2,
    BG_DATATYPE_RATIO       = 3
} bg_DataType;

typedef struct bg_VariableInfo_struct bg_VariableInfo;
typedef struct bg_VariableInfo_struct {
    bg_RecordType           _record_type;
    bg_VariableInfo*        _next;

    const char*             _name;
    bg_DataType             _data_type;
} bg_ColumnInfo;

typedef struct bg_RecordColumn_struct bg_RecordColumn;
typedef struct bg_RecordColumn_struct {
    bg_RecordType           _record_type;
    bg_RecordColumn*        _next;

    const char*             _label;
    bg_DataType             _data_type;
    const char*             _category_value;
    double                  _double_value;
} bg_ColumnData;

typedef enum {
    BG_FILTER_EQUAL         = 1,
    BG_FILTER_LESSEQUAL     = 2,
    BG_FILTER_MOREEQUAL     = 3
} bg_FilterCondition;

typedef struct bg_Filter_struct bg_Filter;
typedef struct bg_Filter_struct {
    bg_RecordType           _record_type;
    bg_Filter*              _next;

    const char*             _label;
    bg_FilterCondition      _filter_condition;
    bg_DataType             _data_type;
    const char*             _category_value;
    double                  _double_value;
} bg_Filter;

typedef struct bg_DataSink_struct bg_DataSink;
typedef struct bg_DataSink_struct {
    bg_RecordType           _record_type;
    bg_DataSink*            _next;

    const char*             _options;
    bg_ColumnInfo*          _column_infos;
    bg_Filter*              _filters;
    void*                   _private;

    void (*_close_sink)(bg_DataSink* datasink);
    void (*_start_record)(bg_DataSink* datasink);
    void (*_end_record)(bg_DataSink* datasink);

    void (*_add_category)(bg_DataSink* datasink, const char* label, const char* value);
    void (*_add_interval)(bg_DataSink* datasink, const char* label, double value);
    void (*_add_ratio)(bg_DataSink* datasink, const char* label, double value);
} bg_DataSink;

// ------------------------------------------------------------------
// dest=stdout, stderr, syslog, file
// options=space-separated list, sink-specific
// Note: takes ownership of column_infos and filters
void bg_add_sink(const char* dest, const char* name, const char* options,
                 bg_ColumnInfo* column_infos, bg_Filter* filters);
void bg_delete_sinks();
// Note: takes ownership of column_datas
void bg_log_record(bg_ColumnData* column_datas);

// ------------------------------------------------------------------
typedef struct {
    bg_RecordType   _record_type;
    FILE*           _file_handle;
    bool            _is_csv;
    bool            _is_json;
    bool            _use_header;
} bg_TextDataSink;

// Note: takes ownership of column_infos and filters
bg_DataSink* bg_new_text_sink(const char* dest, const char* name, const char* options,
                              bg_ColumnInfo* column_infos, bg_Filter* filters);
// name=directory name
// options=csv, json, header, noheader
void text_close_sink(bg_DataSink* datasink);
void text_start_record(bg_DataSink* datasink);
void text_end_record(bg_DataSink* datasink);

void text_add_category(bg_DataSink* datasink, const char* label, const char* value);
void text_add_interval(bg_DataSink* datasink, const char* label, double value);
void text_add_ratio(bg_DataSink* datasink, const char* label, double value);

// ------------------------------------------------------------------
// Assertions
// ------------------------------------------------------------------
enum { BG_ERROR_BUFFER_SIZE = 4096 };
void bg_print_stderr(const char* severity, const char* file_name, uint32_t line_number,
                     const char* function_name, const char* function_signature,
                     const char* message, ...);

#if !defined(BG_BUILD_MODE_OFF)
    #define bg_internal_error(severity, message, ...) \
        bg_print_stderr(severity, BG_FILE_NAME, BG_LINE_NUMBER, \
                        BG_FUNCTION_NAME, BG_FUNCTION_SIGNATURE, \
                        message, __VA_ARGS__)
#else
    #define bg_internal_error(severity, message, ...)   ((void)0)
#endif

// ------------------------------------------------------------------
void bg_assert_fail(const char* expr, const char* file_name, uint32_t line_number,
                    const char* function_name, const char* function_signature);

#if defined(BG_BUILD_MODE_OFF) || defined(BG_BUILD_MODE_DEBUG) || \
    defined(BG_BUILD_MODE_TEST) || defined(BG_BUILD_MODE_QA)
    #define bg_assert(expr) \
        { \
            if (!(expr))   bg_assert_fail(#expr, \
                BG_FILE_NAME, BG_LINE_NUMBER, \
                BG_FUNCTION_NAME, BG_FUNCTION_SIGNATURE); \
        }
#else
    #define bg_assert(expr)   ((void)0)
#endif

// ------------------------------------------------------------------
void bg_verify_fail(const char* expr, const char* file_name, uint32_t line_number,
                    const char* function_name, const char* function_signature);

#if !defined(BG_BUILD_MODE_OFF)
    #define bg_verify(expr) \
        { \
            if (!(expr))   bg_verify_fail(#expr, \
                BG_FILE_NAME, BG_LINE_NUMBER, \
                BG_FUNCTION_NAME, BG_FUNCTION_SIGNATURE); \
        }
#else
    #define bg_verify(expr)   ((void)0)
#endif

// ------------------------------------------------------------------
// Loggers
// ------------------------------------------------------------------
typedef struct {
    struct timespec ts;
} bg_TimeStamp;

// ------------------------------------------------------------------
typedef struct bg_Program_struct bg_Program;
typedef struct bg_Program_struct {
    bg_RecordType   _record_type;
    double          _ts;
    const char*     _file_name;
    uint32_t        _line_number;
    const char*     _function_name;
    const char*     _function_signature;
    uint16_t        _argc;
    const char**    _argv;
    const char**    _envp;
} bg_Program;

void bg_program_constructor(bg_Program* bg_program_variable,
                            const char* file_name, uint32_t line_number,
                            const char* function_name, const char* function_signature,
                            uint16_t argc, const char** argv, const char** envp);

void bg_program_destructor(bg_Program* bg_program_variable);

// ------------------------------------------------------------------
#if !defined(BG_BUILD_MODE_PROFILE)
    #define bg_program(argc, argv, envp, code)  ((void)0)
#elif defined(BG_C_TRY_FINALLY)
    #define bg_program(argc, argv, envp, code)  ((void)0)
    #warn No Microsoft C++ support yet
#elif defined(BG_CLEANUP_ATTRIBUTE)
    #define bg_program(argc, argv, envp, code) \
        bg_Program __attribute__(( cleanup(bg_program_destructor) )) bg_program_variable; \
        bg_program_constructor(&bg_program_variable, \
            BG_FILE_NAME, BG_LINE_NUMBER, \
            BG_FUNCTION_NAME, BG_FUNCTION_SIGNATURE, \
            argc, argv, envp); \
        code
#endif

// ------------------------------------------------------------------
typedef struct bg_Function_struct bg_Function;
typedef struct bg_Function_struct {
    bg_RecordType   _record_type;
    bg_Function*    _next;

    double          _ts;
    const char*     _file_name;
    uint32_t        _line_number;
    const char*     _function_name;
    const char*     _function_signature;
} bg_Function;

void bg_function_constructor(bg_Function* bg_function_variable,
                            const char* file_name, uint32_t line_number,
                            const char* function_name, const char* function_signature,
                            const char* subsystem, const char* session);

void bg_function_destructor(bg_Function* bg_function_variable);

// ------------------------------------------------------------------
#if !defined(BG_BUILD_MODE_PROFILE)
    #define bg_function(subsystem, session, code)  ((void)0)
#elif defined(BG_C_TRY_FINALLY)
    #define bg_function(subsystem, session, code)  ((void)0)
    #warn No Microsoft C++ support yet
#elif defined(BG_CLEANUP_ATTRIBUTE)
    #define bg_function(subsystem, session, code) \
        bg_Function __attribute__(( cleanup(bg_function_destructor) )) bg_function_variable; \
        bg_function_constructor(&bg_function_variable, \
            BG_FILE_NAME, BG_LINE_NUMBER, \
            BG_FUNCTION_NAME, BG_FUNCTION_SIGNATURE, \
            subsystem, session); \
        code
#endif

// bg_thread

// bg_line

// ------------------------------------------------------------------
#endif // defined(__cplusplus)

#endif // BG_LOGGER_H
