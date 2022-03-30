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

#if defined(__cplusplus)
extern "C" {
#endif

// ------------------------------------------------------------------------------------------------
// Configuration
// ------------------------------------------------------------------------------------------------
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
#error Unsupported compiler
#endif

// https://gcc.gnu.org/onlinedocs/gcc-11.2.0/gcc/Common-Variable-Attributes.html
// https://docs.microsoft.com/en-us/cpp/cpp/try-finally-statement
#if defined(BG_COMPILER_GCC) || defined(BG_COMPILER_CLANG) || defined(BG_COMPILER_ICC)
#define BG_CLEANUP_ATTRIBUTE 1
#elif defined(BG_COMPILER_MSVC)
#define BG_C_TRY_FINALLY 1
#else
#error Unsupported compiler
#endif

// ------------------------------------------------------------------------------------------------
// Includes
// ------------------------------------------------------------------------------------------------
#include <assert.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <threads.h>
#include <time.h>

// ------------------------------------------------------------------------------------------------
void bg_print_stderr(const char *severity, const char *file_name, uint32_t line_number,
                     const char *function_name, const char *function_signature,
                     const char *message, ...);

// ------------------------------------------------------------------------------------------------
#if defined(BG_BUILD_MODE_OFF)
#define bg_internal_assert(expr)   ((void)0)
#else
#define bg_internal_assert(expr)                                                                    \
        {                                                                                           \
            if (!(expr))   bg_print_stderr("ASSERTION FAILED",                                      \
                BG_FILE_NAME, BG_LINE_NUMBER,                                                       \
                BG_FUNCTION_NAME, BG_FUNCTION_SIGNATURE,                                            \
                "%s", #expr);                                                                       \
        }
#endif

// ------------------------------------------------------------------------------------------------
#if defined(BG_BUILD_MODE_OFF)
#define bg_internal_error(severity, message, ...)   ((void)0)
#else
#define bg_internal_error(severity, message, ...)                                                   \
        bg_print_stderr(severity, BG_FILE_NAME, BG_LINE_NUMBER,                                     \
                        BG_FUNCTION_NAME, BG_FUNCTION_SIGNATURE,                                    \
                        message, __VA_ARGS__)
#endif

// ------------------------------------------------------------------------------------------------
#if defined(BG_BUILD_MODE_OFF)
#define bg_internal_errno(severity)   ((void)0)
#else
#define bg_internal_errno(severity)                                                                 \
        bg_print_stderr(severity, BG_FILE_NAME, BG_LINE_NUMBER,                                     \
                        BG_FUNCTION_NAME, BG_FUNCTION_SIGNATURE,                                    \
                        "(%d) %s", errno, strerror(errno))
#endif

// ------------------------------------------------------------------------------------------------
// Data Sinks
// ------------------------------------------------------------------------------------------------
typedef enum {
    BG_RECORDTYPE_COLUMNINFO = 0xDEAD0001,
    BG_RECORDTYPE_COLUMNDATA = 0xDEAD0002,
    BG_RECORDTYPE_FILTER = 0xDEAD0003,
    BG_RECORDTYPE_DATASINK = 0xDEAD0004,
    BG_RECORDTYPE_TEXTDATASINK = 0xDEAD0005,

    BG_RECORDTYPE_PROGRAM = 0xDEAD0011,
    BG_RECORDTYPE_THREAD = 0xDEAD0012,
    BG_RECORDTYPE_FUNCTION = 0xDEAD0013,
    BG_RECORDTYPE_TEST = 0xDEAD0014
} bg_RecordType;

// ------------------------------------------------------------------------------------------------
typedef enum {
    BG_DATATYPE_CATEGORY = 1,
    BG_DATATYPE_INTERVAL = 2,
    BG_DATATYPE_RATIO = 3
} bg_DataType;

typedef struct bg_ColumnInfo_struct bg_ColumnInfo;
typedef struct bg_ColumnInfo_struct {
    bg_RecordType _record_type;
    bg_ColumnInfo *_next;

    const char *_name;
    bg_DataType _data_type;
} bg_ColumnInfo;

typedef struct bg_ColumnData_struct bg_ColumnData;
typedef struct bg_ColumnData_struct {
    bg_RecordType _record_type;
    bg_ColumnData *_next;

    const char *_label;
    bg_DataType _data_type;
    const char *_category_value;
    double _double_value;
} bg_ColumnData;

typedef enum {
    BG_FILTER_EQUAL = 1,
    BG_FILTER_LESSEQUAL = 2,
    BG_FILTER_MOREEQUAL = 3
} bg_FilterCondition;

typedef struct bg_Filter_struct bg_Filter;
typedef struct bg_Filter_struct {
    bg_RecordType _record_type;
    bg_Filter *_next;

    const char *_label;
    bg_FilterCondition _filter_condition;
    bg_DataType _data_type;
    const char *_category_value;
    double _double_value;
} bg_Filter;

typedef struct bg_DataSink_struct bg_DataSink;
typedef struct bg_DataSink_struct {
    bg_RecordType _record_type;
    bg_DataSink *_next;

    const char *_options;
    bg_ColumnInfo *_column_infos;
    bg_Filter *_filters;
    void *_private;

    void (*_close_sink)(bg_DataSink *data_sink);

    // Note: does NOT take ownership of column_datas
    void (*_log_record)(bg_DataSink *data_sink, bg_ColumnData *column_datas);
} bg_DataSink;

// ------------------------------------------------------------------------------------------------
// dest=stdout, stderr, syslog, file
// options=space-separated list, sink-specific
// Note: takes ownership of column_infos and filters
void bg_add_sink(const char *device, const char *name, const char *options,
                 bg_ColumnInfo *column_infos, bg_Filter *filters);

void bg_delete_sinks();

// Note: takes ownership of column_datas
void bg_log_record(bg_ColumnData *column_datas);

// ------------------------------------------------------------------------------------------------
typedef struct {
    bg_RecordType _record_type;
    bool _is_stdout;
    bool _is_stderr;
    bool _is_syslog;
    bool _is_file;
    FILE *_file_handle;

    bool _is_csv;
    bool _is_spaces;
    bool _is_json;
    bool _use_header;
    bool _use_comments;
} bg_TextDataSink;

// name=directory name
// options=csv, spaces, or json; header, or noheader; comments, or nocomments
// #=CSV comment char, //=JSON comment chars
// Note: takes ownership of column_infos and filters
bg_DataSink *bg_new_text_sink(const char *device, const char *name, const char *options,
                              bg_ColumnInfo *column_infos, bg_Filter *filters);

void text_close_sink(bg_DataSink *data_sink);

// Note: does NOT take ownership of column_datas
void text_log_record(bg_DataSink *data_sink, bg_ColumnData *column_datas);

// ------------------------------------------------------------------------------------------------
// Assertions
// ------------------------------------------------------------------------------------------------
void bg_assert_fail(const char *expr, const char *file_name, uint32_t line_number,
                    const char *function_name, const char *function_signature);

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

// ------------------------------------------------------------------------------------------------
void bg_verify_fail(const char *expr, const char *file_name, uint32_t line_number,
                    const char *function_name, const char *function_signature);

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

// ------------------------------------------------------------------------------------------------
// Loggers
// ------------------------------------------------------------------------------------------------
typedef struct {
    struct timespec ts;
} bg_TimeStamp;

// ------------------------------------------------------------------------------------------------
typedef struct bg_Program_struct bg_Program;
typedef struct bg_Program_struct {
    bg_RecordType _record_type;
    double _ts_start;

    const char *_file_name;
    uint32_t _line_number;
    const char *_function_name;
    const char *_function_signature;

    uint16_t _argc;
    const char **_argv;
    const char **_envp;
} bg_Program;

void bg_program_constructor(bg_Program *bg_program_variable,
                            const char *file_name, uint32_t line_number,
                            const char *function_name, const char *function_signature,
                            uint16_t argc, const char **argv, const char **envp);

void bg_program_destructor(bg_Program *bg_program_variable);

// ------------------------------------------------------------------------------------------------
#if !defined(BG_BUILD_MODE_PROFILE)
#define bg_program(argc, argv, envp, code)  { code }
#elif defined(BG_C_TRY_FINALLY)
#define bg_program(argc, argv, envp, code)                                                          \
        {                                                                                           \
            Bg_Program bg_program_variable;                                                         \
            bg_program_constructor(&bg_program_variable,                                            \
                BG_FILE_NAME, BG_LINE_NUMBER,                                                       \
                BG_FUNCTION_NAME, BG_FUNCTION_SIGNATURE,                                            \
                argc, argv, envp);                                                                  \
            __try { code }                                                                          \
            __finally { bg_program_destructor(&bg_program_variable); }                              \
        }
#elif defined(BG_CLEANUP_ATTRIBUTE)
#define bg_program(argc, argv, envp, code)                                                          \
        bg_Program __attribute__(( cleanup(bg_program_destructor) )) bg_program_variable;           \
        bg_program_constructor(&bg_program_variable,                                                \
            BG_FILE_NAME, BG_LINE_NUMBER,                                                           \
            BG_FUNCTION_NAME, BG_FUNCTION_SIGNATURE,                                                \
            argc, argv, envp);                                                                      \
        { code }
#endif

// ------------------------------------------------------------------------------------------------
typedef struct bg_Thread_struct bg_Thread;
typedef struct bg_Thread_struct {
    bg_RecordType _record_type;

    double _ts_start;
    const char *_file_name;
    uint32_t _line_number;
    const char *_function_name;
    const char *_function_signature;

    const char *_subsystem;
    const char *_session;
} bg_Thread;

void bg_thread_constructor(bg_Thread *bg_program_variable,
                           const char *file_name, uint32_t line_number,
                           const char *function_name, const char *function_signature,
                           const char *subsystem, const char *session);

void bg_thread_destructor(bg_Thread *bg_program_variable);

// ------------------------------------------------------------------------------------------------
#if !defined(BG_BUILD_MODE_PROFILE)
#define bg_thread(argc, argv, envp, code)  { code }
#elif defined(BG_C_TRY_FINALLY)
#define bg_thread(argc, argv, envp, code)                                                           \
        {                                                                                           \
            bg_Thread bg_thread_variable;                                                           \
            bg_thread_constructor(&bg_thread_variable,                                              \
                BG_FILE_NAME, BG_LINE_NUMBER,                                                       \
                BG_FUNCTION_NAME, BG_FUNCTION_SIGNATURE,                                            \
                subsystem, session);                                                                \
            __try { code }                                                                          \
            __finally { bg_thread_destructor(&bg_thread_variable); }                                \
        }
#elif defined(BG_CLEANUP_ATTRIBUTE)
#define bg_thread(argc, argv, envp, code)                                                           \
        bg_Thread __attribute__(( cleanup(bg_thread_destructor) )) bg_thread_variable;              \
        bg_thread_constructor(&bg_thread_variable,                                                  \
            BG_FILE_NAME, BG_LINE_NUMBER,                                                           \
            BG_FUNCTION_NAME, BG_FUNCTION_SIGNATURE,                                                \
            subsystem, session);                                                                    \
        { code }
#endif

// ------------------------------------------------------------------------------------------------
typedef struct bg_Function_struct bg_Function;
typedef struct bg_Function_struct {
    bg_RecordType _record_type;
    bg_Function *_next;

    double _ts_start;
    const char *_file_name;
    uint32_t _line_number;
    const char *_function_name;
    const char *_function_signature;

    const char *_subsystem;
    const char *_session;
} bg_Function;

void bg_function_constructor(bg_Function *bg_function_variable,
                             const char *file_name, uint32_t line_number,
                             const char *function_name, const char *function_signature,
                             const char *subsystem, const char *session);

void bg_function_destructor(bg_Function *bg_function_variable);

// ------------------------------------------------------------------------------------------------
#if !defined(BG_BUILD_MODE_PROFILE)
#define bg_function(subsystem, session, code)  { code }
#elif defined(BG_C_TRY_FINALLY)
#define bg_function(subsystem, session, code)  { code }
#warn No Microsoft C++ support yet
#elif defined(BG_CLEANUP_ATTRIBUTE)
#define bg_function(subsystem, session, code)                                                       \
        bg_Function __attribute__(( cleanup(bg_function_destructor) )) bg_function_variable;        \
        bg_function_constructor(&bg_function_variable,                                              \
            BG_FILE_NAME, BG_LINE_NUMBER,                                                           \
            BG_FUNCTION_NAME, BG_FUNCTION_SIGNATURE,                                                \
            subsystem, session);                                                                    \
        { code }
#endif

// ------------------------------------------------------------------------------------------------
typedef struct bg_Numerical_struct bg_Numerical;
typedef struct bg_Numerical_struct {
    bg_RecordType _record_type;

    double _ts_start;
    const char *_file_name;
    uint32_t _line_number;
    const char *_function_name;
    const char *_function_signature;

    bool _is_ratio;
    const char *_label;
    double _value;
} bg_Numerical;

void bg_numerical_constructor(bg_Numerical *bg_numerical_variable,
                              const char *file_name, uint32_t line_number,
                              const char *function_name, const char *function_signature,
                              bool is_ratio, const char *label, double value);

void bg_numerical_destructor(bg_Numerical *bg_numerical_variable);

// ------------------------------------------------------------------------------------------------
#if !defined(BG_BUILD_MODE_PROFILE)
#define bg_interval(label, value, code)  { code }
#define bg_ratio(label, value, code)  { code }
#elif defined(BG_C_TRY_FINALLY)
#define bg_interval(label, value, code)  ((void)0)
#define bg_ratio(label, value, code)  ((void)0)
#warn No Microsoft C++ support yet
#elif defined(BG_CLEANUP_ATTRIBUTE)
#define bg_interval(label, value, code)                                                             \
        bg_Numerical __attribute__(( cleanup(bg_numerical_destructor) )) bg_numerical_variable;     \
        bg_numerical_constructor(&bg_numerical_variable,                                            \
            BG_FILE_NAME, BG_LINE_NUMBER,                                                           \
            BG_FUNCTION_NAME, BG_FUNCTION_SIGNATURE,                                                \
            false, label, value);                                                                   \
        { code }
#define bg_ratio(label, value, code)                                                                \
        bg_Numerical __attribute__(( cleanup(bg_numerical_destructor) )) bg_numerical_variable;     \
        bg_numerical_constructor(&bg_numerical_variable,                                            \
            BG_FILE_NAME, BG_LINE_NUMBER,                                                           \
            BG_FUNCTION_NAME, BG_FUNCTION_SIGNATURE,                                                \
            true, label, value);                                                                    \
        { code }
#endif

// ------------------------------------------------------------------------------------------------
// Testing
// ------------------------------------------------------------------------------------------------
typedef int (*bg_test_pointer)();

typedef struct bg_Test_struct bg_Test;
typedef struct bg_Test_struct {
    bg_RecordType _record_type;
    bg_Test *_next;

    bool _is_suite_setup;
    const char *_suite_name;
    const char *_test_name;
    bg_test_pointer _test_function;
} bg_Test;

void bg_add_test_suite_setup(const char *suite_name, bg_test_pointer test_function);

void bg_add_test(const char *suite_name, const char *test_name, bg_test_pointer test_function);

int bg_run_test(const char *suite_name, const char *test_name);

// ------------------------------------------------------------------------------------------------
#if !defined(BG_BUILD_MODE_TEST)
#define bg_test_suite_setup(name, code)   /* nothing */
#else
#define bg_test_suite_setup(suite, code)                                                            \
        static int bg_test_suite_setup_##suite() {                                                  \
            { code }                                                                                \
            return 0;                                                                               \
        }                                                                                           \
        static void __attribute__(( constructor )) register_test_suite_setup_##suite() {            \
            bg_add_test_suite_setup(#suite, bg_test_suite_setup_##suite);                           \
        }
#endif

// ------------------------------------------------------------------------------------------------
#if !defined(BG_BUILD_MODE_TEST)
#define bg_test(name, code)   /* nothing */
#else
#define bg_test(suite, name, code)                                                                  \
        static int bg_test_##suite_##name() {                                                       \
            { code }                                                                                \
            return 0;                                                                               \
        }                                                                                           \
        static void __attribute__(( constructor )) register_test_##suite_##name() {                 \
            bg_add_test(#suite, #name, bg_test_##suite_##name);                                     \
        }
#endif

// ------------------------------------------------------------------------------------------------
#if defined(__cplusplus)
}   // extern "C"
#endif

#endif // BG_LOGGER_H
