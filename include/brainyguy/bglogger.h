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

// -----------------------------------------------------------------------------
// Includes
// -----------------------------------------------------------------------------
#include <assert.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <threads.h>
#include <time.h>

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------
#if defined(BG_COMPILER_GCC) || defined(BG_COMPILER_CLANG) || \
    defined(BG_COMPILER_ICC)
#define BG_COMPILER_GCC_FAMILY 1
#endif

// these should work with all compilers
#define BG_FILE_NAME __FILE__
#define BG_LINE_NUMBER __LINE__

// https://gcc.gnu.org/onlinedocs/cpp/Predefined-Macros.html
// https://www.edg.com/docs/edg_cpp.pdf
#if defined(BG_COMPILER_GCC_FAMILY)
#define BG_FUNCTION_NAME __func__
#define BG_FUNCTION_SIGNATURE __PRETTY_FUNCTION__
#elif defined(BG_COMPILER_MSVC)
#define BG_FUNCTION_NAME __FUNCTION__
#define BG_FUNCTION_SIGNATURE __FUNCSIG__
#else
#error Unsupported compiler
#endif

// this is the C mechanism available for poor man's RAII
// https://gcc.gnu.org/onlinedocs/gcc-11.2.0/gcc/Common-Variable-Attributes.html
// https://docs.microsoft.com/en-us/cpp/cpp/try-finally-statement
#if defined(BG_COMPILER_GCC_FAMILY)
#define BG_CLEANUP_ATTRIBUTE 1
#elif defined(BG_COMPILER_MSVC)
#define BG_C_TRY_FINALLY 1
#else
#error Unsupported compiler
#endif

// -----------------------------------------------------------------------------
// Record Types
// -----------------------------------------------------------------------------
// Major record types have a pointer to a destructor function
// as their first member.
// Their second member is a unique signature for identifying the record type.
// Constructor functions initialize but do not allocate records.
// Destructor functions clean up but do not deallocate records.

// destructor function to put first into every major record
// poor man's virtual method
typedef void (*bg_Destructor)(void *record);

typedef enum {
  BG_STRUCTTYPE_HASHMAP = 0xDEADBE01,
  BG_STRUCTTYPE_STRINGS = 0xDEADBE02,
  BG_STRUCTTYPE_STRINGVALUE = 0xDEADBE03,
  BG_STRUCTTYPE_COUNTERS = 0xDEADBE04,
  BG_STRUCTTYPE_COUNTERHANDLES = 0xDEADBE05,

  BG_STRUCTTYPE_COLUMNINFO = 0xDEADBE11,
  BG_STRUCTTYPE_COLUMNDATA = 0xDEADBE12,
  BG_STRUCTTYPE_FILTER = 0xDEADBE13,
  BG_STRUCTTYPE_DATASINK = 0xDEADBE14,
  BG_STRUCTTYPE_TEXTDATASINK = 0xDEADBE15,

  BG_STRUCTTYPE_PROGRAM = 0xDEADBE21,
  BG_STRUCTTYPE_THREAD = 0xDEADBE22,
  BG_STRUCTTYPE_FUNCTION = 0xDEADBE23,
  BG_STRUCTTYPE_TEST = 0xDEADBE24
} bg_StructType;

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------
extern void bg_get_random_bytes(uint8_t *buffer, int buffer_size);
extern bool bg_approx_equal_double(double a, double b);
extern uint64_t bg_get_next_power2(uint64_t value);

// -----------------------------------------------------------------------------
// CRC64-ECMA
// -----------------------------------------------------------------------------
// cyclic redundancy check works reasonably well as a hash function
enum { BG_VALUES_IN_BYTE = 256 };
extern uint64_t g_crc64_table[BG_VALUES_IN_BYTE];

// one time initialization of lookup table
extern void
bg_crc64_constructor(uint64_t* crc64_table);

// calculate the CRC64-ECMA of the given bytes
// pass in zero for the crc parameter for an initial set of bytes
// crc parameter is for multiple calls for the same CRC calculation
extern uint64_t
bg_crc64_calc(const uint8_t *buf, size_t size, uint64_t crc);

// -----------------------------------------------------------------------------
// Hash Map
// -----------------------------------------------------------------------------
// A very simple hash map implementation.
// Open addressing with double hashing using CRC64 as the hash function.
// Doubles the size of the hash table when the capacity used reaches 50%.
// Limitation: does not implement a delete operation - not needed for this
// application. Limitation: only the 64-bit hash of the keys are compared for
// matches, not the keys themselves

typedef struct bg_HashMapEntry_struct bg_HashMapEntry;
typedef struct bg_HashMapEntry_struct {
  uint64_t _key_hash;
  void *_value;
} bg_HashMapEntry;

typedef struct bg_HashMap_struct bg_HashMap;
typedef struct bg_HashMap_struct {
  bg_Destructor _destructor;
  bg_StructType _struct_type;
  size_t _size;   // number of used entries
  size_t _allocated;   // total space reserved for entries
  bg_HashMapEntry *_entries;
} bg_HashMap;

// -----------------------------------------------------------------------------
// start_size must be a power of two
extern void
bg_hash_constructor(bg_HashMap *map, size_t start_size);

extern void
bg_hash_destructor(void *map);

// insert function without hash table size check
// used to avoid a potentially mutually recursive call
extern void
bg_hash_internal_insert(bg_HashMap *map, uint64_t key_hash, void *value);

// internal function to double the size of the hash table
extern void
bg_map_enlarge(bg_HashMap *map);

extern void *
bg_hash_find(bg_HashMap *map, uint64_t key_hash);

// value must be a struct
// takes ownership of the value and calls the destructor function in the struct
extern void
bg_hash_insert(bg_HashMap *map, uint64_t key_hash, void *value);

// -----------------------------------------------------------------------------
// Strings Hash
// -----------------------------------------------------------------------------
typedef struct bg_StringValue_struct bg_StringValue;
typedef struct bg_StringValue_struct {
  bg_Destructor _destructor;
  bg_StructType _struct_type;

  bool _ref_value;   // false=need to malloc and free
  const char* _string_value;
} bg_StringValue;

typedef struct bg_Strings_struct bg_Strings;
typedef struct bg_Strings_struct {
  bg_Destructor _destructor;
  bg_StructType _struct_type;

  bg_HashMap _hash_map;
} bg_Strings;

// -----------------------------------------------------------------------------
void bg_string_value_constructor(bg_StringValue* string_value, bool ref_value, const char* value);
void bg_string_value_destructor(void* string_value_void);

void bg_strings_constructor(bg_Strings* strings, size_t start_size);
void bg_strings_destructor(void* strings_void);

// if the string has previously been interned, return a pointer to it
// otherwise copy the string, intern it, and return a pointer to it
const char* bg_strings_intern(bg_Strings* strings, bool ref_value, const char* string);

// -----------------------------------------------------------------------------
// Assertions
// -----------------------------------------------------------------------------
// internal function to print a message to stderr
extern void
bg_print_stderr(const char *severity, const char *file_name,
                uint32_t line_number, const char *function_name,
                const char *function_signature,
                const char *message, ...);

// -----------------------------------------------------------------------------
#if defined(BG_BUILD_MODE_DEBUG) || defined(BG_BUILD_MODE_TEST) ||             \
    defined(BG_BUILD_MODE_QA)
#define bg_internal_assert(expr)                                               \
  (expr)                                                                       \
      ? ((void)0)                                                              \
      : bg_print_stderr("ASSERTION FAILED", BG_FILE_NAME, BG_LINE_NUMBER,      \
                        BG_FUNCTION_NAME, BG_FUNCTION_SIGNATURE, "%s", #expr)
#else
#define bg_internal_assert(expr) ((void)0)
#endif

// -----------------------------------------------------------------------------
#if defined(BG_BUILD_MODE_DEBUG) || defined(BG_BUILD_MODE_TEST) ||             \
    defined(BG_BUILD_MODE_QA) || defined(BG_BUILD_MODE_PROFILE) ||             \
    defined(BG_BUILD_MODE_RELEASE)
#define bg_internal_verify(expr)                                               \
  (expr)                                                                       \
      ? ((void)0)                                                              \
      : bg_print_stderr("RUNTIME ASSERTION FAILED",                            \
                        BG_FILE_NAME, BG_LINE_NUMBER,                          \
                        BG_FUNCTION_NAME, BG_FUNCTION_SIGNATURE, "%s", #expr)
#else
#define bg_internal_verify(expr) ((void)0)
#endif

// -----------------------------------------------------------------------------
#if defined(BG_BUILD_MODE_DEBUG) || defined(BG_BUILD_MODE_TEST) ||             \
    defined(BG_BUILD_MODE_QA) || defined(BG_BUILD_MODE_PROFILE) ||             \
    defined(BG_BUILD_MODE_RELEASE)
#define bg_internal_error(severity, message, ...)                              \
  bg_print_stderr(severity, BG_FILE_NAME, BG_LINE_NUMBER, BG_FUNCTION_NAME,    \
                  BG_FUNCTION_SIGNATURE, message, __VA_ARGS__)
#else
#define bg_internal_error(severity, message, ...) ((void)0)
#endif

// -----------------------------------------------------------------------------
#if defined(BG_BUILD_MODE_DEBUG) || defined(BG_BUILD_MODE_TEST) ||             \
    defined(BG_BUILD_MODE_QA) || defined(BG_BUILD_MODE_PROFILE) ||             \
    defined(BG_BUILD_MODE_RELEASE)
#define bg_internal_errno(severity)                                            \
  bg_print_stderr(severity, BG_FILE_NAME, BG_LINE_NUMBER, BG_FUNCTION_NAME,    \
                  BG_FUNCTION_SIGNATURE, "(%d) %s", errno, strerror(errno))
#else
#define bg_internal_errno(severity) ((void)0)
#endif

// -----------------------------------------------------------------------------
// Performance Counters
// -----------------------------------------------------------------------------
typedef struct bg_CounterHandles_struct bg_CounterHandles;
typedef struct bg_CounterHandles_struct {
  bg_Destructor _destructor;
  bg_StructType _struct_type;

  int _fd_sw_cpu_clock;         // This reports the CPU clock, a high-resolution per-CPU timer.
  int _fd_sw_task_clock;        // This reports a clock count specific to the task that is running.
  int _fd_sw_page_faults;       // This reports the number of page faults.
  int _fd_sw_context_switches;  // This counts context switches.
  int _fd_sw_cpu_migrations;    // This reports the number of times the process has migrated to a new CPU.
  int _fd_sw_page_faults_min;   // This counts the number of minor page faults.
  int _fd_sw_page_faults_maj;   // This counts the number of major page faults. These required disk I/O to handle.
  int _fd_sw_alignment_faults;  // This counts the number of alignment faults.
  int _fd_sw_emulation_faults;  // This  counts the number of emulation faults.

  int _fd_hw_cpu_cycles;        // Total cycles.
  int _fd_hw_instructions;      // Retired instructions.

  int _fd_hw_cache_references;  // Cache accesses.  Usually this indicates Last Level Cache accesses.
  int _fd_hw_cache_misses;      // Cache misses.  Usually this indicates Last Level Cache misses.

  int _fd_hw_branch_instructions; // Retired branch instructions.
  int _fd_hw_branch_misses;       // Mispredicted branch instructions.

  int _fd_hw_stalled_cycles_frontend; // Stalled cycles during issue.
  int _fd_hw_stalled_cycles_backend;  // Stalled cycles during retirement.
} bg_CounterHandles;

// -----------------------------------------------------------------------------
typedef struct bg_Counters_struct bg_Counters;
typedef struct bg_Counters_struct {
  bg_Destructor _destructor;
  bg_StructType _struct_type;

  uint64_t _sw_cpu_clock;         // This reports the CPU clock, a high-resolution per-CPU timer.
  uint64_t _sw_task_clock;        // This reports a clock count specific to the task that is running.
  uint64_t _sw_page_faults;       // This reports the number of page faults.
  uint64_t _sw_context_switches;  // This counts context switches.
  uint64_t _sw_cpu_migrations;    // This reports the number of times the process has migrated to a new CPU.
  uint64_t _sw_page_faults_min;   // This counts the number of minor page faults.
  uint64_t _sw_page_faults_maj;   // This counts the number of major page faults. These required disk I/O to handle.
  uint64_t _sw_alignment_faults;  // This counts the number of alignment faults.
  uint64_t _sw_emulation_faults;  // This  counts the number of emulation faults.

  // four flexible (unpinned) groups are created
  uint64_t _hw_cpu_cycles;        // Cycles when thread is not halted.
  uint64_t _hw_instructions;      // Retired (executed) instructions.

  uint64_t _hw_cache_references;  // Cache accesses.  Usually this indicates Last Level Cache accesses.
  uint64_t _hw_cache_misses;      // Cache misses.  Usually this indicates Last Level Cache misses.

  uint64_t _hw_branch_instructions; // Retired branch instructions.
  uint64_t _hw_branch_misses;       // Mispredicted branch instructions.

  uint64_t _hw_stalled_cycles_frontend; // Stalled cycles during issue.
  uint64_t _hw_stalled_cycles_backend;  // Stalled cycles during retirement.
} bg_Counters;

// -----------------------------------------------------------------------------
extern void
bg_counter_handles_constructor(bg_CounterHandles *counter_handles);

extern void
bg_counter_handles_destructor(void *counter_handles_void);

extern void
bg_counters_constructor(bg_Counters *counters);

extern void
bg_counters_destructor(void *counters_void);

extern void
bg_read_counters(bg_CounterHandles *counter_handles, bg_Counters *counters);

// stores delta in counters_start
extern void
bg_calc_thread_counters_delta(bg_Counters *counters_start,
                              bg_Counters *counters_end);

// -----------------------------------------------------------------------------
// Data Sinks
// -----------------------------------------------------------------------------
typedef enum {
  BG_DATATYPE_NONE = 0,

  // string
  BG_DATATYPE_CATEGORICAL = 1000,
  BG_DATATYPE_ORDINAL = 1100,
  BG_DATATYPE_ORDINAL_BOOL = 1110,
  BG_DATATYPE_NOMINAL = 1500,
  BG_DATATYPE_NOMINAL_INT = 1510,

  // double
  BG_DATATYPE_NUMERICAL = 2000,
  BG_DATATYPE_INTERVAL = 2100,
  BG_DATATYPE_INTERVAL_TIMESTAMP = 2110,
  BG_DATATYPE_RATIO = 2500,
  BG_DATATYPE_RATIO_COUNT = 2510,
  BG_DATATYPE_RATIO_CURRENCY = 2520
} bg_DataType;

typedef struct bg_ColumnInfo_struct bg_ColumnInfo;
typedef struct bg_ColumnInfo_struct {
  bg_Destructor _destructor;
  bg_StructType _struct_type;
  bg_ColumnInfo *_next;

  const char *_label;
  bg_DataType _data_type;
} bg_ColumnInfo;

typedef struct bg_ColumnData_struct bg_ColumnData;
typedef struct bg_ColumnData_struct {
  bg_Destructor _destructor;
  bg_StructType _struct_type;
  bg_ColumnData *_next;

  const char *_label;
  bg_DataType _data_type;
  const char *_string_value;
  double _double_value;
} bg_ColumnData;

typedef enum {
  BG_FILTER_EQUAL = 1,
  BG_FILTER_LESSEQUAL = 2,
  BG_FILTER_MOREEQUAL = 3
} bg_FilterCondition;

typedef struct bg_Filter_struct bg_Filter;
typedef struct bg_Filter_struct {
  bg_Destructor _destructor;
  bg_StructType _struct_type;
  bg_Filter *_next;

  const char *_label;
  bg_FilterCondition _filter_condition;
  bg_DataType _data_type;
  const char *_category_value;
  double _double_value;
} bg_Filter;

typedef struct bg_DataSink_struct bg_DataSink;
typedef struct bg_DataSink_struct {
  bg_Destructor _destructor;
  bg_StructType _struct_type;
  bg_DataSink *_next;

  const char *_options;
  bg_ColumnInfo *_column_infos;
  bg_Filter *_filters;
  void *_device_data;

  void (*_close_sink)(bg_DataSink *data_sink);

  // Note: does NOT take ownership of column_datas
  void (*_log_record)(bg_DataSink *data_sink, bg_ColumnData *column_datas);
} bg_DataSink;

// -----------------------------------------------------------------------------
// dest=stdout, stderr, syslog, file
// options=space-separated list, sink-specific
// Note: takes ownership of column_infos and filters
extern void
bg_add_sink(const char *device, const char *name, const char *options,
            bg_ColumnInfo *column_infos, bg_Filter *filters);

extern void
bg_delete_sinks();

// Note: takes ownership of column_datas
extern void
bg_log_record(bg_ColumnData *column_datas);

// -----------------------------------------------------------------------------
typedef struct {
  bg_Destructor _destructor;
  bg_StructType _struct_type;
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
  bool _use_quotes;
} bg_TextDataSink;

// name=directory name
// options=csv, spaces, or json; header, or noheader; comments, or nocomments;
// quotes or noquotes
// #=CSV comment char, //=JSON comment chars
// Note: takes ownership of column_infos and filters
extern void
bg_new_text_sink(bg_DataSink *data_sink, const char *device,
                 const char *name, const char *options,
                 bg_ColumnInfo *column_infos, bg_Filter *filters);

extern void
text_close_sink(bg_DataSink *data_sink);

// Note: does NOT take ownership of column_datas
extern void
text_log_record(bg_DataSink *data_sink, bg_ColumnData *column_datas);

// -----------------------------------------------------------------------------
// Assertions
// -----------------------------------------------------------------------------
extern void
bg_assert_fail(const char *expr, const char *file_name,
               uint32_t line_number, const char *function_name,
               const char *function_signature);

#if defined(BG_BUILD_MODE_OFF) || defined(BG_BUILD_MODE_DEBUG) || \
    defined(BG_BUILD_MODE_TEST) || defined(BG_BUILD_MODE_QA)
#define bg_assert(expr)                                                        \
  (expr) ? ((void)0)                                                           \
         : bg_assert_fail(#expr, BG_FILE_NAME, BG_LINE_NUMBER,                 \
                          BG_FUNCTION_NAME, BG_FUNCTION_SIGNATURE)
#else
#define bg_assert(expr) ((void)0)
#endif

// -----------------------------------------------------------------------------
extern void
bg_verify_fail(const char *expr, const char *file_name,
               uint32_t line_number, const char *function_name,
               const char *function_signature);

#if !defined(BG_BUILD_MODE_OFF)
#define bg_verify(expr)                                                        \
  (expr) ? ((void)0)                                                           \
         : bg_verify_fail(#expr, BG_FILE_NAME, BG_LINE_NUMBER,                 \
                          BG_FUNCTION_NAME, BG_FUNCTION_SIGNATURE)
#else
#define bg_verify(expr) ((void)0)
#endif

// -----------------------------------------------------------------------------
// Record Columns
// -----------------------------------------------------------------------------
typedef struct bg_DebugRecord_struct bg_DebugRecord;
typedef struct bg_DebugRecord_struct {
  bg_Destructor _destructor;
  bg_StructType _struct_type;

} bg_DebugRecord;

// -----------------------------------------------------------------------------
typedef struct bg_ProfileRecord_struct bg_ProfileRecord;
typedef struct bg_ProfileRecord_struct {
  bg_Destructor _destructor;
  bg_StructType _struct_type;

  const char *_file_name;
  uint32_t _line_number;
  const char *_function_name;
  const char *_function_signature;

  const char *_subsystem;
  const char *_session;

  const char *_numeric_label;
  bool _is_ratio;
  double _numeric_value;

} bg_ProfileRecord;

// -----------------------------------------------------------------------------
// Loggers
// -----------------------------------------------------------------------------
typedef struct bg_Program_struct bg_Program;
typedef struct bg_Program_struct {
  bg_Destructor _destructor;
  bg_StructType _struct_type;

} bg_Program;

extern bg_Program* g_bg_program;

// -----------------------------------------------------------------------------
extern void bg_program_constructor(bg_Program *program);
extern void bg_program_destructor(void *program_void);
extern void bg_program_once();

// -----------------------------------------------------------------------------
typedef struct bg_Function_struct bg_Function;
typedef struct bg_Function_struct {
  bg_Destructor _destructor;
  bg_StructType _struct_type;
  bg_Function *_next;   // parent function

  const char *_file_name;
  uint32_t _line_number;
  const char *_function_name;
  const char *_function_signature;

  const char *_subsystem;
  const char *_session;
  double count;
} bg_Function;

// -----------------------------------------------------------------------------
extern void
bg_function_constructor(bg_Function *bg_function_variable,
                        const char *file_name, uint32_t line_number,
                        const char *function_name,
                        const char *function_signature,
                        const char *subsystem,
                        const char *session,
                        double count);
extern void
bg_function_destructor(void *function_void);

// -----------------------------------------------------------------------------
#if !defined(BG_BUILD_MODE_PROFILE)
#define bg_function(subsystem, session, count, code)                           \
  { code }
#elif defined(BG_C_TRY_FINALLY)
#define bg_function(subsystem, session, count, code)                           \
  { code }
#warn No Microsoft C++ support yet
#elif defined(BG_CLEANUP_ATTRIBUTE)
#define bg_function(subsystem, session, count, code)                           \
  bg_Function __attribute__((cleanup(bg_function_destructor)))                 \
              bg_function_variable;                                            \
  bg_function_constructor(&bg_function_variable, BG_FILE_NAME, BG_LINE_NUMBER, \
                          BG_FUNCTION_NAME, BG_FUNCTION_SIGNATURE, subsystem,  \
                          session, count);                                     \
  { code }
#endif

// -----------------------------------------------------------------------------
// Testing
// -----------------------------------------------------------------------------
typedef int (*bg_test_pointer)();

typedef struct bg_Test_struct bg_Test;
typedef struct bg_Test_struct {
  bg_Destructor _destructor;
  bg_StructType _struct_type;
  bg_Test *_next;

  bool _is_suite_setup;
  const char *_suite_name;
  const char *_test_name;
  bg_test_pointer _test_function;
} bg_Test;

extern void
bg_add_test_suite_setup(const char *suite_name,
                        bg_test_pointer test_function);

extern void
bg_add_test(const char *suite_name, const char *test_name,
            bg_test_pointer test_function);

extern int
bg_run_test(const char *suite_name, const char *test_name);

// -----------------------------------------------------------------------------
#if !defined(BG_BUILD_MODE_TEST)
#define bg_test_suite_setup(name, code) /* nothing */
#else
#define bg_test_suite_setup(suite, code)                                       \
  static int bg_test_suite_setup_##suite() {                                   \
    { code }                                                                   \
    return 0;                                                                  \
  }                                                                            \
  static void __attribute__((constructor))                                     \
  register_test_suite_setup_##suite() {                                        \
    bg_add_test_suite_setup(#suite, bg_test_suite_setup_##suite);              \
  }
#endif

// -----------------------------------------------------------------------------
#if !defined(BG_BUILD_MODE_TEST)
#define bg_test(suite, name, code) /* nothing */
#else
#define bg_test(suite, name, code)                                             \
  static int bg_test_##suite_##name() {                                        \
    { code }                                                                   \
    return 0;                                                                  \
  }                                                                            \
  static void __attribute__((constructor)) register_test_##suite_##name() {    \
    bg_add_test(#suite, #name, bg_test_##suite_##name);                        \
  }
#endif

// -----------------------------------------------------------------------------
#if defined(__cplusplus)
} // extern "C"
#endif

// -----------------------------------------------------------------------------
#if defined(__cplusplus)
// TODO
#endif

#endif // BG_LOGGER_H
