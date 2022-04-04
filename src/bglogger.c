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

#if defined(BG_PLATFORM_LINUX)
#include <syslog.h>
#endif

// ------------------------------------------------------------------------------------------------
// Internal Utility functions
// ------------------------------------------------------------------------------------------------
enum {
    BG_ERROR_BUFFER_SIZE = 4096
};

// ------------------------------------------------------------------------------------------------
int min_int(const int a, const int b) {
    return (a < b) ? a : b;
}

int max_int(const int a, const int b) {
    return (a > b) ? a : b;
}

// ------------------------------------------------------------------------------------------------
size_t min_size(const size_t a, const size_t b) {
    return (a < b) ? a : b;
}

size_t max_size(const size_t a, const size_t b) {
    return (a > b) ? a : b;
}

// ------------------------------------------------------------------------------------------------
void bg_print_stderr(const char* severity, const char* file_name, uint32_t line_number,
                     const char* function_name, const char* function_signature, const char* message, ...) {
    (void)function_signature;
    char buffer1[BG_ERROR_BUFFER_SIZE];

    va_list args;
    va_start(args, message);
    const int num_chars1 = vsnprintf(buffer1, BG_ERROR_BUFFER_SIZE, message, args);
    va_end(args);
    bg_internal_verify(num_chars1 > 0);

    char buffer2[BG_ERROR_BUFFER_SIZE];
    const int num_chars2 = snprintf(buffer2,BG_ERROR_BUFFER_SIZE, "%s: %s(%u): %s: %s",
                                    severity, file_name, line_number, function_name, buffer1);
    bg_internal_verify(num_chars2 > 0);

    const int status = fputs(buffer2, stderr);
    bg_internal_verify(status != EOF);
}

// ------------------------------------------------------------------------------------------------
void get_random_bytes(uint8_t* buffer, const int buffer_size) {
    bg_internal_verify(RAND_MAX >= 255);   // should always be at least 32767
    for (int byte = 0; byte < buffer_size; ++byte) {
        buffer[byte] = (uint8_t)(rand() & 0xff);
    }
}

// ------------------------------------------------------------------------------------------------
bool approx_equal_double(const double a, const double b) {
    static const double DBL_EPSILON = 2.2204460492503131e-16;
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
    bg_internal_verify(base == TIME_UTC);
    const uint64_t seconds     = ts.tv_sec;
    const uint64_t nanoseconds = ts.tv_nsec;
    return (double)(seconds) + (double)(nanoseconds) / 1000000000UL;
}

// ------------------------------------------------------------------------------------------------
int print_timestamp(char* buffer, const size_t buffer_size, const double timestamp) {
    double int_dbl;
    const double frac_dbl = modf(timestamp, &int_dbl);
    struct timespec ts;
    ts.tv_sec  = (int64_t)lround(timestamp);
    ts.tv_nsec = (int64_t)lround(frac_dbl * 1000000000.0);

    struct tm utc_time;
    const struct tm* tm_status = gmtime_r(&ts.tv_sec, &utc_time);
    bg_internal_verify(tm_status != NULL);
    strftime(buffer, buffer_size, "%DT%T", &utc_time);
    const int chars_written = snprintf(&buffer[strlen(buffer)], buffer_size,".%09ldZ", ts.tv_nsec);
    bg_internal_verify(chars_written > 0);
    return chars_written;
}

// ------------------------------------------------------------------------------------------------
// returns the number of characters written
int print_column(char* buffer, const size_t buffer_size,
                    bg_ColumnInfo* column_info, bg_ColumnData* column_data,
                    const bool use_quotes) {
    switch (column_info->_data_type) {
        case BG_DATATYPE_CATEGORICAL:
        case BG_DATATYPE_ORDINAL:
        case BG_DATATYPE_NOMINAL: {
            const int chars_written = snprintf(buffer, buffer_size, (use_quotes ? "\"%s\"" : "%s"),
                                               column_data->_string_value);
            bg_internal_verify(chars_written > 0);
            return chars_written;
        }

        case BG_DATATYPE_ORDINAL_BOOL: {
            const int chars_written = snprintf(buffer, buffer_size, "%s",
                                               column_data->_string_value);
            bg_internal_verify(chars_written > 0);
            return chars_written;
        }

        case BG_DATATYPE_NUMERICAL:
        case BG_DATATYPE_INTERVAL:
        case BG_DATATYPE_RATIO: {
            const int chars_written = snprintf(buffer, buffer_size, "%g", column_data->_double_value);
            bg_internal_verify(chars_written > 0);
            return chars_written;
        }

        case BG_DATATYPE_RATIO_CURRENCY: {
            const int chars_written = snprintf(buffer, buffer_size, "%.2f", column_data->_double_value);
            bg_internal_verify(chars_written > 0);
            return chars_written;
        }

        case BG_DATATYPE_INTERVAL_TIMESTAMP: {
            const int chars_written = print_timestamp(buffer, buffer_size, column_data->_double_value);
            bg_internal_verify(chars_written > 0);
            return chars_written;
        }

        case BG_DATATYPE_RATIO_COUNT: {
            const uint64_t count_value = llround(column_data->_double_value);
            const int chars_written = snprintf(buffer, buffer_size,
                                               "%lu", count_value);
            bg_internal_verify(chars_written > 0);
            return chars_written;
        }

        default:
            bg_internal_error("ERROR", "bad data type: %d", column_info->_data_type);
    }
}

// ------------------------------------------------------------------------------------------------
// Configuration
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
    bg_internal_verify(chars_written > 0 && chars_written < FILENAME_MAX);
    g_base_log_dir = strdup(buffer);
#elif defined(BG_PLATFORM_WINDOWS)
#error Windows not supported yet
#else
#error Unrecognized platform
#endif
}

// ------------------------------------------------------------------------------------------------
// CRC64
// ------------------------------------------------------------------------------------------------
// modified from xz library src/liblzma/check/crc64_small.c
// https://en.wikipedia.org/wiki/Cyclic_redundancy_check

static uint64_t crc64_table[256];

static void bg_crc64_init() {
    // CRC-64-ECMA, reversed polynomial
	static const uint64_t poly64 = 0xC96C5795D7870F42ull;

	for (size_t b = 0; b < 256; ++b) {
		uint64_t r = b;
		for (size_t i = 0; i < 8; ++i) {
			if (r & 1)
				r = (r >> 1) ^ poly64;
			else
				r >>= 1;
		}

		crc64_table[b] = r;
	}
}

// ------------------------------------------------------------------------------------------------
uint64_t bg_calc_crc64(const uint8_t *buf, size_t size, uint64_t crc) {
	crc = ~crc;

	while (size != 0) {
		crc = crc64_table[*buf++ ^ (crc & 0xFF)] ^ (crc >> 8);
		--size;
	}

	return ~crc;
}

// ------------------------------------------------------------------------------------------------
// Hash Map
// ------------------------------------------------------------------------------------------------
// start_size needs to be a power of two
void bg_hash_constructor(bg_Map* map, size_t start_size) {
    enum {MAP_START_SIZE = 512};
    map->_allocated = MAP_START_SIZE;
    map->_entries = calloc(MAP_START_SIZE, sizeof(bg_MapEntry));
}

// ------------------------------------------------------------------------------------------------
void bg_hash_destructor(bg_Map* map) {
    free(map->_entries);
}

// ------------------------------------------------------------------------------------------------
void bg_hash_internal_insert(bg_Map* map, uint64_t key_hash, void* value) {
    uint64_t hash = key_hash;
    size_t index = hash & (map->_size - 1);
    while (map->_entries[index]._key_hash != key_hash && map->_entries[index]._value != NULL) {
        hash = bg_calc_crc64((uint8_t*)&hash, sizeof(hash), 0);
        index = hash & (map->_size - 1);
    }

    bg_assert(map->_entries[index]._value == NULL);
    map->_entries[index]._key_hash = key_hash;
    map->_entries[index]._value = value;
}

// ------------------------------------------------------------------------------------------------
void bg_map_enlarge(bg_Map* map) {
    bg_Map new_map;
    bg_hash_constructor(&new_map, map->_allocated << 1);

    for (size_t index = 0; index < map->_size; ++index) {
        if (map->_entries[index]._value) {
            bg_hash_internal_insert(&new_map, map->_entries[index]._key_hash, map->_entries[index]._value);
        }
    }

    bg_hash_destructor(map);
    memcpy(map, &new_map, sizeof(bg_Map));
}

// ------------------------------------------------------------------------------------------------
void* bg_hash_find(bg_Map* map, uint64_t key_hash) {
    uint64_t hash = key_hash;
    size_t index = hash & (map->_size - 1);
    while (map->_entries[index]._key_hash != key_hash && map->_entries[index]._value != NULL) {
        hash = bg_calc_crc64((uint8_t*)&hash, sizeof(hash), 0);
        index = hash & (map->_size - 1);
    }

    return (map->_entries[index]._value == NULL) ? NULL : &map->_entries[index];
}

// ------------------------------------------------------------------------------------------------
void bg_hash_insert(bg_Map* map, uint64_t key_hash, void* value) {
    if (map->_size >= (map->_allocated >> 1)) {
        bg_map_enlarge(map);
    }

    bg_hash_internal_insert(map, key_hash, value);
}

// ------------------------------------------------------------------------------------------------
// Data Sinks
// ------------------------------------------------------------------------------------------------
bg_DataSink* g_data_sinks;

// ------------------------------------------------------------------------------------------------
void bg_add_sink(const char* device, const char* name, const char* options,
                 bg_ColumnInfo* column_infos, bg_Filter* filters) {
    bg_DataSink* data_sink = calloc(1, sizeof(bg_DataSink));
    bg_internal_verify(data_sink);
    data_sink->_record_type         = BG_RECORDTYPE_DATASINK;
    data_sink->_options             = strdup(options);
    data_sink->_column_infos        = column_infos;
    data_sink->_filters             = filters;

    if (strcmp(device, "stdout") == 0 ||
        strcmp(device, "stderr") == 0 ||
        strcmp(device, "syslog") == 0 ||
        strcmp(device, "file")   == 0) {
        bg_new_text_sink(data_sink, device, name, options, column_infos, filters);
        data_sink->_next        = g_data_sinks;
        g_data_sinks            = data_sink;
    } else {
        bg_internal_error("FATAL", "bad sink type: %s", device);
    }
}

// ------------------------------------------------------------------------------------------------
void delete_column_infos(bg_ColumnInfo *column_infos) {
    while (column_infos) {
        bg_internal_verify(column_infos->_record_type == BG_RECORDTYPE_COLUMNINFO);
        bg_ColumnInfo *next_column_infos = column_infos->_next;
        free((void*)column_infos->_label);
        free((void*)column_infos);
        column_infos = next_column_infos;
    }
}

// ------------------------------------------------------------------------------------------------
void delete_filters(bg_Filter *filters) {
    while (filters) {
        bg_internal_verify(filters->_record_type == BG_RECORDTYPE_FILTER);
        bg_Filter* next_filters = filters->_next;
        free((void*)filters->_label);
        free((void*)filters->_category_value);
        free((void*)filters);
        filters = next_filters;
    }
}

// ------------------------------------------------------------------------------------------------
void delete_sink(bg_DataSink* data_sink) {
    bg_internal_verify(data_sink->_record_type == BG_RECORDTYPE_DATASINK);
    data_sink->_close_sink(data_sink);
    free(data_sink->_device_data);
    free((void*)data_sink->_options);
    delete_column_infos(data_sink->_column_infos);
    delete_filters(data_sink->_filters);
}

// ------------------------------------------------------------------------------------------------
void bg_delete_sinks() {
    bg_DataSink* data_sink_last = NULL;
    bg_DataSink* data_sink      = g_data_sinks;

    while (data_sink != NULL) {
        delete_sink(data_sink);

        data_sink_last = data_sink;
        data_sink = data_sink->_next;
        free(data_sink_last);
    }

    g_data_sinks = NULL;
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
        (*data_sink->_log_record)(data_sink, column_datas);
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
    bg_internal_verify(chars_written < buffer_size);
}

// ------------------------------------------------------------------------------------------------
static void parse_text_device(bg_TextDataSink* text_data_sink, const char* device) {
    if (strcmp(device, "stderr") == 0) {
        text_data_sink->_is_stderr = true;
    } else if (strcmp(device, "stdout") == 0) {
        text_data_sink->_is_stdout = true;
    } else if (strcmp(device, "syslog") == 0) {
        text_data_sink->_is_syslog = true;
    } else if (strcmp(device, "file") == 0) {
        text_data_sink->_is_file = true;
    } else {
        bg_internal_error("FATAL", "invalid text device: %s", device);
    }
}

// ------------------------------------------------------------------------------------------------
static void parse_text_options(bg_TextDataSink* text_data_sink, const char* options) {
    if (strstr(options, "csv")) {
        text_data_sink->_is_csv = true;
    } else if (strstr(options, "spaces")) {
        text_data_sink->_is_spaces = true;
    } else if (strstr(options, "json")) {
        text_data_sink->_is_json = true;
    } else {
        text_data_sink->_is_csv = true;
    }

    if (strstr(options, "noheader")) {
        text_data_sink->_use_header = false;
    } else if (strstr(options, "header")) {
        text_data_sink->_use_header = true;
    } else {
        text_data_sink->_use_header = false;
    }

    if (strstr(options, "nocomments")) {
        text_data_sink->_use_comments = false;
    } else if (strstr(options, "comments")) {
        text_data_sink->_use_comments = true;
    } else {
        text_data_sink->_use_comments = false;
    }

    if (strstr(options, "noquotes")) {
        text_data_sink->_use_quotes = false;
    } else if (strstr(options, "quotes")) {
        text_data_sink->_use_quotes = true;
    } else {
        text_data_sink->_use_quotes = false;
    }
}

// ------------------------------------------------------------------------------------------------
void bg_new_text_sink(bg_DataSink* data_sink, const char* device, const char* name, const char* options,
                      bg_ColumnInfo* column_infos, bg_Filter* filters) {
    data_sink->_close_sink          = text_close_sink;
    data_sink->_log_record          = text_log_record;

    bg_TextDataSink* text_data_sink = calloc(1, sizeof(bg_TextDataSink));
    bg_internal_verify(text_data_sink);
    data_sink->_device_data         = text_data_sink;
    text_data_sink->_record_type    = BG_RECORDTYPE_TEXTDATASINK;

    parse_text_device(text_data_sink, device);
    parse_text_options(text_data_sink, options);

    if (text_data_sink->_is_file) {
        char file_path[FILENAME_MAX];
        create_temp_file_name(file_path, FILENAME_MAX,
                              g_base_log_dir, g_program_base_name, ".log");
        text_data_sink->_file_handle = fopen(file_path, "w");
        if (text_data_sink->_file_handle == NULL) {
            bg_internal_error("ERROR", "cannot open for writing: %s", file_path);
        }
    } else if (text_data_sink->_is_stdout) {
        text_data_sink->_file_handle = stdout;
    } else if (text_data_sink->_is_stderr) {
        text_data_sink->_file_handle = stderr;
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
    bg_internal_verify(data_sink->_record_type == BG_RECORDTYPE_DATASINK);
    bg_TextDataSink* text_data_sink = (bg_TextDataSink*) data_sink->_device_data;
    bg_internal_verify(text_data_sink->_record_type == BG_RECORDTYPE_TEXTDATASINK);

    if (text_data_sink->_file_handle) {
        const int status = fclose(text_data_sink->_file_handle);
        bg_internal_verify(status == 0);
        text_data_sink->_file_handle = NULL;
    }
}

// ------------------------------------------------------------------------------------------------
enum {
    BG_TEXT_RECORD_BUFFER_SIZE = 65536   // 64KB
};

// ------------------------------------------------------------------------------------------------
void text_print_string(bg_TextDataSink* text_data_sink, const char* buffer, int buffer_chars) {
    if (text_data_sink->_is_syslog) {
#if defined(BG_PLATFORM_LINUX)
        syslog(LOG_USER|LOG_NOTICE, "%s", buffer);
#endif
    } else {
        const size_t chars_written = fwrite(buffer, sizeof(char), buffer_chars, text_data_sink->_file_handle);
        bg_internal_verify(chars_written > 0);
    }
}

// ------------------------------------------------------------------------------------------------
// Note: does NOT take ownership of column_datas
// TODO: create hash table over column data labels
void text_log_record(bg_DataSink* data_sink, bg_ColumnData* column_datas) {
    bg_TextDataSink* text_data_sink = (bg_TextDataSink*)data_sink->_device_data;
    bg_internal_verify(text_data_sink->_record_type == BG_RECORDTYPE_TEXTDATASINK);

    char buffer[BG_TEXT_RECORD_BUFFER_SIZE];
    int buffer_chars = 0;
    bool first_column = true;

    for (bg_ColumnInfo *column_info = data_sink->_column_infos;
         column_info != NULL;
         column_info = column_info->_next) {
        for (bg_ColumnData *column_data = column_datas;
             column_data != NULL;
             column_data = column_data->_next) {
            if (strcmp(column_info->_label, column_data->_label) == 0) {
                if (!first_column) {
                    buffer[buffer_chars++] = text_data_sink->_is_csv ? ',' : ' ';
                } else {
                    first_column = false;
                }

                const int chars_written =
                        print_column(&buffer[buffer_chars], BG_TEXT_RECORD_BUFFER_SIZE - buffer_chars,
                                     column_info, column_data, text_data_sink->_use_quotes);
                buffer_chars += chars_written;
                bg_internal_verify(buffer_chars < BG_TEXT_RECORD_BUFFER_SIZE);
                break;
            }
        }
    }

    if (buffer_chars) {
        buffer[buffer_chars++] = '\n';
        buffer[buffer_chars]   = '\0';
        text_print_string(text_data_sink, buffer, buffer_chars);
    }
}

// ------------------------------------------------------------------------------------------------
// ------------------------------------------------------------------------------------------------
void bg_assert_fail(const char* expr, const char* file_name, uint32_t line_number,
                    const char* function_name, const char* function_signature) {
    // TODO
}

// ------------------------------------------------------------------------------------------------
void bg_verify_fail(const char* expr, const char* file_name, uint32_t line_number,
                    const char* function_name, const char* function_signature) {
    // TODO
}

// ------------------------------------------------------------------------------------------------
typedef struct bg_ColumnInfoStatic_struct bg_ColumnInfoStatic;
typedef struct bg_ColumnInfoStatic_struct {
    const char *_label;
    bg_DataType _data_type;
} bg_ColumnInfoStatic;

static const bg_ColumnInfoStatic constructor_column_info[] = {
    {"timestamp", BG_DATATYPE_INTERVAL_TIMESTAMP},
    {"duration", BG_DATATYPE_RATIO},

    { NULL, BG_DATATYPE_NONE}
};

// ------------------------------------------------------------------------------------------------
bg_ColumnInfo* create_column_infos(const bg_ColumnInfoStatic column_info_statics[]) {
    bg_ColumnInfo* column_info_head = NULL;
    bg_ColumnInfo* column_info_tail = NULL;

    while (column_info_statics) {
        bg_ColumnInfo* column_info = calloc(1, sizeof(bg_ColumnInfo));
        bg_internal_verify(column_info);
        column_info->_record_type = BG_RECORDTYPE_COLUMNINFO;
        column_info->_label = strdup(column_info_statics->_label);
        column_info->_data_type = column_info_statics->_data_type;
        column_info_statics++;

        if (column_info_head == NULL) {
            column_info_head = column_info_tail = column_info;
        } else {
            column_info_tail->_next = column_info;
            column_info_tail = column_info;
        }
    }

    return column_info_head;
}

// ------------------------------------------------------------------------------------------------
bg_ColumnData* add_column_data_double(bg_ColumnData* previous_column_data, const char* label, const double value) {
    bg_ColumnData* column_data = calloc(1, sizeof(bg_ColumnData));
    bg_internal_verify(column_data);
    column_data->_record_type = BG_RECORDTYPE_COLUMNDATA;
    column_data->_label = strdup(label);
    column_data->_double_value = value;
    if (previous_column_data) {
        previous_column_data->_next = column_data;
    }
    return column_data;
}

// ------------------------------------------------------------------------------------------------
bg_ColumnData* add_column_data_string(bg_ColumnData* previous_column_data, const char* label, const char* value) {
    bg_ColumnData* column_data = calloc(1, sizeof(bg_ColumnData));
    bg_internal_verify(column_data);
    column_data->_record_type = BG_RECORDTYPE_COLUMNDATA;
    column_data->_label = strdup(label);
    column_data->_string_value = strdup(value);
    if (previous_column_data) {
        previous_column_data->_next = column_data;
    }
    return column_data;
}

// ------------------------------------------------------------------------------------------------
void bg_program_constructor(bg_Program* bg_program_variable,
                            const char* file_name, const uint32_t line_number,
                            const char* function_name, const char* function_signature,
                            const int argc, const char** argv, const char** envp) {
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
    bg_crc64_init();   // initialize CRC64 hash table
    set_program_name(argv[0]);
    create_base_log_dir();
}

// ------------------------------------------------------------------------------------------------
void bg_program_destructor(bg_Program* bg_program_variable) {
    // TODO - log program info


    bg_delete_sinks();
}

// ------------------------------------------------------------------------------------------------
thread_local bg_Thread* g_bg_Thread;

// ------------------------------------------------------------------------------------------------
void bg_thread_constructor(bg_Thread* bg_program_variable,
                           const char* file_name, uint32_t line_number,
                           const char* function_name, const char* function_signature,
                           const char* subsystem, const char* session) {
     // TODO
}

// ------------------------------------------------------------------------------------------------
void bg_thread_destructor(bg_Thread* bg_program_variable) {
     // TODO
}

// ------------------------------------------------------------------------------------------------
void bg_function_constructor(bg_Function* bg_function_variable,
                            const char* file_name, uint32_t line_number,
                            const char* function_name, const char* function_signature,
                            const char* subsystem, const char* session) {
     // TODO
}

// ------------------------------------------------------------------------------------------------
void bg_function_destructor(bg_Function* bg_function_variable) {
     // TODO
}

// ------------------------------------------------------------------------------------------------
void bg_numerical_constructor(bg_Numerical* bg_numerical_variable,
                              const char* file_name, uint32_t line_number,
                              const char* function_name, const char* function_signature,
                              bool is_ratio, const char* label, const double value) {
     // TODO
}

// ------------------------------------------------------------------------------------------------
void bg_numerical_destructor(bg_Numerical* bg_numerical_variable) {
     // TODO
}

// ------------------------------------------------------------------------------------------------
// Testing
// ------------------------------------------------------------------------------------------------
static bg_Test* g_bg_test;

// ------------------------------------------------------------------------------------------------
void bg_add_test_suite_setup(const char* suite_name, bg_test_pointer test_function) {
    bg_Test* test                   = calloc(1, sizeof(bg_Test));
    bg_internal_verify(test);
    test->_record_type              = BG_RECORDTYPE_TEST;
    test->_is_suite_setup           = true;
    test->_suite_name               = strdup(suite_name);
    test->_test_function            = test_function;

    test->_next                     = g_bg_test;
    g_bg_test                       = test;
}

// ------------------------------------------------------------------------------------------------
void bg_add_test(const char* suite_name, const char* test_name, bg_test_pointer test_function) {
    bg_Test* test                   = calloc(1, sizeof(bg_Test));
    bg_internal_verify(test);
    test->_record_type              = BG_RECORDTYPE_TEST;
    test->_is_suite_setup           = false;
    test->_suite_name               = strdup(suite_name);
    test->_test_name               = strdup(test_name);
    test->_test_function            = test_function;

    test->_next                     = g_bg_test;
    g_bg_test                       = test;
}

// ------------------------------------------------------------------------------------------------
int bg_run_test(const char* suite_name, const char* test_name) {
    for (bg_Test* test = g_bg_test; test != NULL; test = test->_next) {
        if (test->_is_suite_setup && strcmp(test->_suite_name, suite_name) == 0) {
            test->_test_function();
            break;
        }
    }

    for (bg_Test* test = g_bg_test; test != NULL; test = test->_next) {
        if (!test->_is_suite_setup &&
            strcmp(test->_suite_name, suite_name) == 0 && strcmp(test->_test_name, test_name) == 0) {
            return test->_test_function();
        }
    }

    bg_internal_error("ERROR", "suite %s: test not found: %s", suite_name, test_name);
    return 1; // test not found - signal failure
}
