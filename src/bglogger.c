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

#include "brainyguy/bglogger.h"

#include <math.h>

// ------------------------------------------------------------------------------------------------
void bg_print_stderr(const char* severity, const char* file_name, uint32_t line_number,
                     const char* function_name, const char* function_signature, const char* message, ...) {
    (void)function_signature;
    char buffer[BG_ERROR_BUFFER_SIZE];

    va_list args;
    va_start(args, message);
    const int num_chars1 = vsnprintf(buffer, BG_ERROR_BUFFER_SIZE, message, args);
    va_end(args);
    assert(num_chars1 > 0);

    const int num_chars2 = fprintf(stderr, "%s: %s(%u): %s: %s",
                                    severity, file_name, line_number, function_name, buffer);
    assert(num_chars2 > 0);
}

// ------------------------------------------------------------------------------------------------
void get_random_bytes(uint8_t* buffer, const int buffer_size) {
    assert(RAND_MAX >= 255);   // should always be at least 32767
    for (int byte = 0; byte < buffer_size; ++byte) {
        buffer[byte] = (uint8_t)(rand() & 0xff);
    }
}

// ------------------------------------------------------------------------------------------------
#define DBL_EPSILON     (2.2204460492503131e-16)

bool approx_equal_double(const double a, const double b) {
    const double delta = fabs(a - b);
    if (delta <= DBL_EPSILON)   return true;
    const double relative_error = DBL_EPSILON * fmin(fabs(a), fabs(b));
    if (delta <= relative_error)   return true;
    return a == b;
}

// ------------------------------------------------------------------------------------------------
double get_timestamp_now() {
    struct timespec ts;
    const int base = timespec_get(&ts, TIME_UTC);
    assert(base == TIME_UTC);
    const uint64_t seconds     = ts.tv_sec;
    const uint64_t nanoseconds = ts.tv_nsec;
    return (double)(seconds) + (double)(nanoseconds) / 1000000000UL;
}

void print_timestamp(char* buffer, const uint16_t buffer_size, const double timestamp) {
    struct timespec ts;
    double int_dbl;
    const double frac_dbl = modf(timestamp, &int_dbl);
    ts.tv_sec  = (int64_t)lround(timestamp);
    ts.tv_nsec = (int64_t)lround(frac_dbl * 1000000000.0);

    struct tm utc_time;
    const struct tm* tm_status = gmtime_r(&ts.tv_sec, &utc_time);
    assert(tm_status != NULL);
    strftime(buffer, buffer_size, "%DT%T", &utc_time);
    const int chars_written = snprintf(&buffer[strlen(buffer)], buffer_size,".%09ldZ", ts.tv_nsec);
    assert(chars_written < buffer_size);
}

// ------------------------------------------------------------------------------------------------
static const char* g_program_path_name;
static const char* g_program_base_name;

#if defined(BG_PLATFORM_LINUX)
#define _GNU_SOURCE 1
#include <syslog.h>
#include <errno.h>
extern char *program_invocation_name;
extern char *program_invocation_short_name;
#endif

void set_program_name(const char* argv0) {
#if defined(BG_PLATFORM_LINUX)
    g_program_path_name = strdup(program_invocation_name);
    g_program_base_name = strdup(program_invocation_short_name);
#elif defined(BG_PLATFORM_WINDOWS)
    g_program_path_name = strdup(argv0);

    char* last_slash    = strrchr(argv0, '/');
    g_program_base_name = strdup(last_slash ? last_slash+1 : argv0);
#else
#error Unrecognized platform
#endif
}

// ------------------------------------------------------------------------------------------------
#if defined(BG_PLATFORM_LINUX) || defined(BG_PLATFORM_BSD)
#include <unistd.h>
#endif

uint32_t get_process_id() {
#if defined(BG_PLATFORM_LINUX) || defined(BG_PLATFORM_BSD)
    return getpid();
#elif defined(BG_PLATFORM_WINDOWS)
#error Windows not supported yet
#else
#error Unrecognized platform
#endif
}

// ------------------------------------------------------------------------------------------------
static const char* g_base_log_dir;

void create_base_log_dir() {
#if defined(BG_PLATFORM_LINUX) || defined(BG_PLATFORM_BSD)
    char buffer[FILENAME_MAX];
    uint16_t salt;
    get_random_bytes((uint8_t*)&salt, sizeof(salt));
    const int chars_written =
        sprintf(buffer, "/tmp/%s-%.8x-%.4hx.log", g_program_base_name, get_process_id(), salt);
    assert(chars_written > 0 && chars_written < FILENAME_MAX);
    g_base_log_dir = strdup(buffer);
#elif defined(BG_PLATFORM_WINDOWS)
#error Windows not supported yet
#else
#error Unrecognized platform
#endif
}

// ------------------------------------------------------------------------------------------------
// Data Sinks
// ------------------------------------------------------------------------------------------------
bg_DataSink* g_data_sinks;

// ------------------------------------------------------------------------------------------------
void bg_add_sink(const char* device, const char* name, const char* options,
                 bg_ColumnInfo* column_infos, bg_Filter* filters) {
    if (strcmp(device, "stdout") == 0 ||
        strcmp(device, "stderr") == 0 ||
        strcmp(device, "syslog") == 0 ||
        strcmp(device, "file")   == 0) {
        bg_DataSink* data_sink  = bg_new_text_sink(device, name, options, column_infos, filters);
        data_sink->_next        = g_data_sinks;
        g_data_sinks            = data_sink;
    } else {
        bg_internal_error("FATAL", "bad sink type: %s", device);
    }
}

// ------------------------------------------------------------------------------------------------
void bg_delete_sinks() {

}

// ------------------------------------------------------------------------------------------------
bool is_record_filtered(bg_ColumnData* column_datas, bg_Filter* filters) {
    for (bg_Filter* filter = filters; filter != NULL; filter = filter->_next) {
        for (bg_ColumnData* column_data; column_data != NULL; column_data = column_data->_next) {
            // TODO
        }
    }

    return false;
}

// ------------------------------------------------------------------------------------------------
void bg_log_record(bg_ColumnData* column_datas) {
    for (bg_DataSink* data_sink = g_data_sinks; data_sink != NULL; data_sink = data_sink->_next) {
        const bool record_filtered = is_record_filtered(column_datas, data_sink->_filters);
        if (record_filtered)   continue;

    }

}

// ------------------------------------------------------------------------------------------------
// ------------------------------------------------------------------------------------------------
void create_temp_file_name(char* buffer, const int buffer_size,
                           const char* path, const char* base_name, const char* extension) {
    const size_t path_len    = strlen(path);
    const bool add_path_sep  = (path_len > 0 && path[path_len-1] != '/');
    uint16_t salt;
    get_random_bytes((uint8_t*)&salt, sizeof(salt));

    const uint32_t rand_uint = rand() % 10000;
    const int chars_written = snprintf(buffer, buffer_size, "%s%s%s_%.4u.%s",
                                        path, add_path_sep ? "/" : "", base_name, salt, extension);
    assert(chars_written < buffer_size);
}

// ------------------------------------------------------------------------------------------------
bg_DataSink* bg_new_text_sink(const char* device, const char* name, const char* options,
                              bg_ColumnInfo* column_infos, bg_Filter* filters) {
    bg_DataSink* data_sink = calloc(1, sizeof(bg_DataSink));
    assert(data_sink);
    data_sink->_record_type         = BG_RECORDTYPE_DATASINK;
    data_sink->_options             = strdup(options);
    data_sink->_column_infos        = column_infos;
    data_sink->_filters             = filters;
    data_sink->_close_sink          = text_close_sink;
    data_sink->_log_record          = text_log_record;

    bg_TextDataSink* text_data_sink = calloc(1, sizeof(bg_TextDataSink));
    assert(text_data_sink);
    data_sink->_private             = text_data_sink;
    text_data_sink->_record_type    = BG_RECORDTYPE_TEXTDATASINK;

    if (strcmp(device, "file") == 0) {
        char file_path[FILENAME_MAX];
        create_temp_file_name(file_path, FILENAME_MAX,
                              g_base_log_dir, g_program_base_name, ".log");
        text_data_sink->_file_handle = fopen(file_path, "w");
        if (text_data_sink->_file_handle == NULL) {
            bg_internal_error("ERROR", "cannot open for writing: %s", file_path);
        }
    }

    if (strstr(options, "csv")) {
        text_data_sink->_is_csv = true;
    } else if (strstr(options, "json")) {
        text_data_sink->_is_json = true;
    }

    if (strstr(options, "noheader")) {
        text_data_sink->_use_header = false;
    } else if (strstr(options, "header")) {
        text_data_sink->_use_header = true;
    }

    if (text_data_sink->_use_header) {
        if (data_sink->_column_infos == NULL) {
            bg_internal_error("ERROR", "%s", "requested file header but provided no column information");
        } else if (text_data_sink->_is_json) {
            bg_internal_error("ERROR", "%s", "requested file header but using JSON format");
        } else {
            const int status = fputs("# ", text_data_sink->_file_handle);
            // TODO
        }
    }
}

// ------------------------------------------------------------------------------------------------
void text_close_sink(bg_DataSink* data_sink) {
    assert(data_sink->_record_type == BG_RECORDTYPE_DATASINK);
    bg_TextDataSink* text_data_sink = (bg_TextDataSink*) data_sink->_private;
    assert(text_data_sink->_record_type == BG_RECORDTYPE_TEXTDATASINK);

    if (text_data_sink->_file_handle) {
        const int status = fclose(text_data_sink->_file_handle);
        assert(status == 0);
        text_data_sink->_file_handle = NULL;
    }
}

// ------------------------------------------------------------------------------------------------
// Note: does NOT take ownership of column_datas
void text_log_record(bg_DataSink* data_sink, bg_ColumnData* column_datas) {

}

// ------------------------------------------------------------------------------------------------
// ------------------------------------------------------------------------------------------------
void bg_assert_fail(const char* expr, const char* file_name, uint32_t line_number,
                    const char* function_name, const char* function_signature) {

}

// ------------------------------------------------------------------------------------------------
void bg_verify_fail(const char* expr, const char* file_name, uint32_t line_number,
                    const char* function_name, const char* function_signature) {

}

// ------------------------------------------------------------------------------------------------
void bg_program_constructor(bg_Program* bg_program_variable,
                            const char* file_name, const uint32_t line_number,
                            const char* function_name, const char* function_signature,
                            const uint16_t argc, const char** argv, const char** envp) {
    bg_program_variable->_record_type           = BG_RECORDTYPE_PROGRAM;
    bg_program_variable->_ts_start              = get_timestamp_now();
    bg_program_variable->_file_name             = file_name;
    bg_program_variable->_line_number           = line_number;
    bg_program_variable->_function_name         = function_name;
    bg_program_variable->_function_signature    = function_signature;
    bg_program_variable->_argc                  = argc;
    bg_program_variable->_argv                  = argv;
    bg_program_variable->_envp                  = envp;

    srand(time(NULL));   // seed random number generator
    set_program_name(argv[0]);
    create_base_log_dir();
}

// ------------------------------------------------------------------------------------------------
void bg_program_destructor(bg_Program* bg_program_variable) {
    for (bg_DataSink* data_sink = g_data_sinks; data_sink != NULL; data_sink = data_sink->_next) {
        data_sink->_close_sink(data_sink);
    }
}

// ------------------------------------------------------------------------------------------------
thread_local bg_Thread* g_bg_Thread;

// ------------------------------------------------------------------------------------------------
void bg_thread_constructor(bg_Thread* bg_program_variable,
                           const char* file_name, uint32_t line_number,
                           const char* function_name, const char* function_signature,
                           const char* subsystem, const char* session) {

}

// ------------------------------------------------------------------------------------------------
void bg_thread_destructor(bg_Thread* bg_program_variable) {

}

// ------------------------------------------------------------------------------------------------
void bg_function_constructor(bg_Function* bg_function_variable,
                            const char* file_name, uint32_t line_number,
                            const char* function_name, const char* function_signature,
                            const char* subsystem, const char* session) {

}

// ------------------------------------------------------------------------------------------------
void bg_function_destructor(bg_Function* bg_function_variable) {

}
