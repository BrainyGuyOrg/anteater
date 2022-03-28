#ifndef APP_PERF_COUNTERS_LOGGER_HPP
#define APP_PERF_COUNTERS_LOGGER_HPP

#define _GNU_SOURCE
#include <errno.h>

#include <unistd.h>

#include <cstring>
#include <cstdio>

#include <charconv>
#include <string>
#include <fstream>
#include <chrono>

#define BG_FILE_NAME            __FILE__
#define BG_LINE_NUMBER          __LINE__
#define BG_FUNCTION_NAME        __func__
#define BG_FUNCTION_SIGNATURE   __PRETTY_FUNCTION__

namespace brainyguy::logger
{
    // monitoring
    // debugging
    // optimization
    // security
    // recovery
    // legal

    // production logging vs development logging
    // main goals: debugging, testing, error logging, profiling
    // mode: debug, profile, test, qa, release

    enum class FaultLevel {
        none,
        exception,
        fatal,
        error,
        warning,
        lint,
        all
    };

    enum class DataLevel {
        none,
        constructor,
        request,
        transfer,
        all
    };

    enum class CodeLevel {
        none,
        program,
        function,
        line,
        all
    };

    std::to_chars_result to_chars(char* first, char* last, char ch) {
        if (sizeof(char) > static_cast<std::size_t>(last - first)) {
            return std::to_chars_result{last, std::errc::value_too_large};
        } else {
            *first++ = ch;
            return std::to_chars_result{first, std::errc()};
        }
    }

    // https://en.wikipedia.org/wiki/ISO_8601
    // 2015-09-04T12:19:46.240549
    std::to_chars_result to_chars_timestamp(char* first, char* last) {
        const auto now = std::chrono::system_clock::now();


    }

   std::to_chars_result to_chars_program_path(char* first, char* last) {
        static const std::size_t program_path_len = std::strlen(program_invocation_name);
        if (program_path_len > (last - first)) {
            return std::to_chars_result{last, std::errc::value_too_large};
        } else {
            std::strcpy(first, program_invocation_name);
            return std::to_chars_result{first+program_path_len, std::errc()};
        }
    }

    std::to_chars_result to_chars_program_name(char* first, char* last) {
        static const std::size_t program_name_len = std::strlen(program_invocation_short_name);
        if (program_name_len > (last - first)) {
            return std::to_chars_result{last, std::errc::value_too_large};
        } else {
            std::strcpy(first, program_invocation_short_name);
            return std::to_chars_result{first+program_name_len, std::errc()};
        }
    }

    std::to_chars_result to_chars_process_id(char* first, char* last) {
        static const std::string process_id = std::to_string(getpid());
        static const std::size_t process_id_len = process_id.size();
        if (process_id_len > (last - first)) {
            return std::to_chars_result{last, std::errc::value_too_large};
        } else {
            process_id.copy(first, process_id_len);
            return std::to_chars_result{first+process_id_len, std::errc()};
        }
    }

    //  - timestamp
    //  - session id
    //  - process id
    //  - thread id

    //  - program path
    //  - program name
    //  - subsystem
    //  - file name
    //  - line number
    //  - function name
    //  - function signature

    //  - log level
    //  - topic
    //  - value
    //  - units
    //  - message

    void log_all() {
        constexpr std::size_t BUFFER_SIZE = 4096;
        char buffer[BUFFER_SIZE];
        char* first = buffer;
        char* last  = buffer+BUFFER_SIZE;

        auto [ptr, ec] = ;
    }

    class Program
    {
        std::string   log_filename_;
        std::ofstream logstream_;

        void open_log() {
            char temp_name_buffer[L_tmpnam];
            char* temp_name = tmpnam(temp_name_buffer);
            log_filename_ = temp_name;
            logstream_.open(log_filename_, std::ios::binary);
        }

    public:
        Program() {
            open_log();
        }

        void add_log_line(const char* szLine) {
            logstream_ << szLine << std::endl;
        }

        ~Program() = default;
    };

    inline static Program program;
}

#if defined(NDEBUG)
#define BG_LOG_ALL(level, subsystem, topic, type, value, session, message, ...)   static_cast<void>(0)
#else
#define BG_LOG_ALL(level, subsystem, topic, type, value, session, message, ...) \
    brainyguy::logger::log_all(BG_FILE_NAME, BG_LINE_NUMBER, \
        BG_FUNCTION_NAME, BG_FUNCTION_SIGNATURE, \
        level, subsystem, topic, type, value, session, message __VA_OPT__(,) __VA_ARGS__)
#endif

#if defined(NDEBUG)
#define BG_PROGRAM(argc, argv, envp)   ((void)0)
#else
#define BG_PROGRAM(argc, argv, envp) \
    brainyguy::logger::program(BG_FILE_NAME, BG_LINE_NUMBER, \
        BG_FUNCTION_NAME, BG_FUNCTION_SIGNATURE,             \
        argc, argv, envp)
#endif

#if defined(NDEBUG)
#define BG_FUNCTION(subsystem, request)   ((void)0)
#else
#define BG_FUNCTION(subsystem, session) \
    brainyguy::logger::Function(BG_FILE_NAME, BG_LINE_NUMBER, \
        BG_FUNCTION_NAME, BG_FUNCTION_SIGNATURE, subsystem, session)
#endif

// BG_EXCEPTION()

#endif //APP_PERF_COUNTERS_LOGGER_HPP
