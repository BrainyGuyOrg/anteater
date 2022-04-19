#ifndef ANTEATER_ANTEATER_HPP
#define ANTEATER_ANTEATER_HPP

#if __cplusplus < 202002L
#error C++20 support required to use this library.
#endif

#include <atomic>
#include <deque>
#include <functional>
#include <iostream>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <source_location>
#include <sstream>
#include <stack>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>

#include <cassert>
#include <cerrno>
#include <cstdlib>
#include <cstring>

namespace brainyguy {
// ---------------------------------------------------------------------------
enum class BuildMode { off, debug, test, qa, profile, release };
#if defined(ANTEATER_BUILD_MODE_OFF)
constexpr static BuildMode g_build_mode = BuildMode::off;
#elif defined(ANTEATER_BUILD_MODE_DEBUG)
constexpr static BuildMode g_build_mode = BuildMode::debug;
#elif defined(ANTEATER_BUILD_MODE_TEST)
constexpr static BuildMode g_build_mode = BuildMode::test;
#elif defined(ANTEATER_BUILD_MODE_QA)
constexpr static BuildMode g_build_mode = BuildMode::qa;
#elif defined(ANTEATER_BUILD_MODE_PROFILE)
constexpr static BuildMode g_build_mode = BuildMode::profile;
#elif defined(ANTEATER_BUILD_MODE_RELEASE)
constexpr static BuildMode g_build_mode = BuildMode::release;
#else
#warning Anteater build mode not defiled. Disabling library.
constexpr static BuildMode g_build_mode = BuildMode::off;
#endif

// ---------------------------------------------------------------------------
#if defined(__linux__)                    // Linux kernel; could be GNU or Android
constinit static bool g_have_pmc = true;  // Performance Monitoring Counters
#include <linux/perf_event.h>             // Definition of PERF_* constants
#include <linux/hw_breakpoint.h>          // Definition of HW_* constants
#include <sys/syscall.h>                  // Definition of SYS_* constants
#include <unistd.h>
#include <sys/ioctl.h>
#else
constinit static bool g_have_pmc = false;   // Performance Monitoring Counters
#endif

// ---------------------------------------------------------------------------
// https://stackoverflow.com/questions/2590677/how-do-i-combine-hash-values-in-c0x
template <typename T, typename... Rest>
void hash_combine(std::size_t& seed, const T& v, const Rest&... rest)
{
    seed ^= std::hash<T>{}(v) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
    (hash_combine(seed, rest), ...);
}

struct pair_hash
{
  template <class T1, class T2>
  std::size_t operator() (const std::pair<T1, T2> &pair) const
  {
    std::size_t seed = 0;
    hash_combine(seed, pair.first, pair.second);
    return seed;
  }
};

// ---------------------------------------------------------------------------
class LinuxEvent
{
 public:
  LinuxEvent() : _is_group(false), _fd_first(-1), _fd_second(-1)  {}

  explicit LinuxEvent(const std::string_view name, const uint32_t event_type, const uint64_t event)
  {
    _is_group = false;
    _name_first = name;
    _fd_first = open_event(name, event_type, event, -1);
  }

  explicit LinuxEvent(const std::string_view name1, const uint32_t event_type1, const uint64_t event1,
                      const std::string_view name2, const uint32_t event_type2, const uint64_t event2)
  {
    _is_group = true;
    _name_first = name1;
    _fd_first = open_event(name1, event_type1, event1, -1);
    _name_second = name2;
    _fd_second = open_event(name2, event_type2, event2, _fd_first);

    reset_event(name1, _fd_first, true);
  }

  ~LinuxEvent() {
    if (!_is_group) {
      disable_event(_name_first, _fd_first, false);
      close_event(_name_first, _fd_first);
    } else {
      disable_event(_name_first, _fd_first, true);
      close_event(_name_second, _fd_second);
      close_event(_name_first, _fd_first);
    }
  }

  void reset_events() {
    if (!_is_group) {
      reset_event(_name_first, _fd_first, false);
    } else {
      reset_event(_name_first, _fd_first, true);
    }
  }

  void enable_events() {
    if (!_is_group) {
      enable_event(_name_first, _fd_first, false);
    } else {
      enable_event(_name_first, _fd_first, true);
    }
  }

  uint64_t read_event_first() {
    return read_event(_name_first, _fd_first);
  }

  uint64_t read_event_second() {
    assert(_is_group);
    return read_event(_name_second, _fd_second);;
  }

 private:
    bool _is_group;
    std::string_view _name_first;
    std::string_view _name_second;
    int _fd_first;
    int _fd_second;

    static int perf_event_open(struct perf_event_attr *hw_event, pid_t pid, int cpu,
                               int group_fd, unsigned long flags)
    {
      return static_cast<int>(syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags));
    }

    static int open_event(const std::string_view name,
                          const uint32_t event_type, const uint64_t event, const int group_fd) {
      struct perf_event_attr perf_event_attr{};

      perf_event_attr.size = sizeof(perf_event_attr);
      perf_event_attr.type = event_type;
      perf_event_attr.config = event;
      perf_event_attr.disabled = 1;
      perf_event_attr.exclude_kernel = 1;
      perf_event_attr.exclude_hv = 1;

      const int fd = perf_event_open(&perf_event_attr, 0, -1, group_fd, 0);
      if (fd == -1) {
        std::cerr << "ERROR: LinuxEvent::open_event: " << name << ": " << std::strerror(errno) << std::endl;
        std::exit(EXIT_FAILURE);
      }

      return fd;
    }

    static void reset_event(const std::string_view name, const int fd, const bool is_group_leader) {
      const int status = ioctl(fd, PERF_EVENT_IOC_RESET, is_group_leader ? PERF_IOC_FLAG_GROUP : 0);
      if (status == -1) {
        std::cerr << "ERROR: LinuxEvent::reset_event: " << name << ": " << std::strerror(errno) << std::endl;
        std::exit(EXIT_FAILURE);
      }
    }

    static void disable_event(const std::string_view name, const int fd, const bool is_group_leader) {
      const int status = ioctl(fd, PERF_EVENT_IOC_DISABLE, is_group_leader ? PERF_IOC_FLAG_GROUP : 0);
      if (status == -1) {
        std::cerr << "ERROR: LinuxEvent::disable_event: " << name << ": " << std::strerror(errno) << std::endl;
        std::exit(EXIT_FAILURE);
      }
    }

    static void enable_event(const std::string_view name, const int fd, const bool is_group_leader) {
      const int status = ioctl(fd, PERF_EVENT_IOC_ENABLE, is_group_leader ? PERF_IOC_FLAG_GROUP : 0);
      if (status == -1) {
        std::cerr << "ERROR: LinuxEvent::enable_event: " << name << ": " << std::strerror(errno) << std::endl;
        std::exit(EXIT_FAILURE);
      }
    }

    static void close_event(const std::string_view name, const int fd) {
      const int status = close(fd);
      if (status == -1) {
        std::cerr << "ERROR: LinuxEvent::close_event: " << name << ": " << std::strerror(errno) << std::endl;
        std::exit(EXIT_FAILURE);
      }
    }

    static uint64_t read_event(const std::string_view name, const int fd) {
      uint64_t count;
      const ssize_t bytes_read = read(fd, &count, sizeof(count));
      if (bytes_read == -1) {
        std::cerr << "ERROR: LinuxEvent::read_event: " << name << ": " << std::strerror(errno) << std::endl;
        std::exit(EXIT_FAILURE);
      }
      return count;
    }
};

// ---------------------------------------------------------------------------
class LinuxEventsData
{
 public:
  explicit LinuxEventsData() = default;

  LinuxEventsData& operator+=(const LinuxEventsData& rhs)
  {
    _fd_sw_cpu_clock += rhs._fd_sw_cpu_clock;
    _fd_sw_task_clock += rhs._fd_sw_task_clock;
    _fd_sw_page_faults += rhs._fd_sw_page_faults;
    _fd_sw_context_switches += rhs._fd_sw_context_switches;
    _fd_sw_cpu_migrations += rhs._fd_sw_cpu_migrations;
    _fd_sw_page_faults_min += rhs._fd_sw_page_faults_min;
    _fd_sw_page_faults_maj += rhs._fd_sw_page_faults_maj;
    _fd_sw_alignment_faults += rhs._fd_sw_alignment_faults;
    _fd_sw_emulation_faults += rhs._fd_sw_emulation_faults;
    _fd_hw_cpu_cycles += rhs._fd_hw_cpu_cycles;
    _fd_hw_instructions += rhs._fd_hw_instructions;
    _fd_hw_cache_references += rhs._fd_hw_cache_references;
    _fd_hw_cache_misses += rhs._fd_hw_cache_misses;
    _fd_hw_branch_instructions += rhs._fd_hw_branch_instructions;
    _fd_hw_branch_misses += rhs._fd_hw_branch_misses;
    _fd_hw_stalled_cycles_frontend += rhs._fd_hw_stalled_cycles_frontend;
    _fd_hw_stalled_cycles_backend += rhs._fd_hw_stalled_cycles_backend;
    return *this;
  }

  friend LinuxEventsData operator+(LinuxEventsData lhs, const LinuxEventsData& rhs)
  {
    lhs += rhs;
    return lhs;
  }

  LinuxEventsData& operator-=(const LinuxEventsData& rhs)
  {
    _fd_sw_cpu_clock -= rhs._fd_sw_cpu_clock;
    _fd_sw_task_clock -= rhs._fd_sw_task_clock;
    _fd_sw_page_faults -= rhs._fd_sw_page_faults;
    _fd_sw_context_switches -= rhs._fd_sw_context_switches;
    _fd_sw_cpu_migrations -= rhs._fd_sw_cpu_migrations;
    _fd_sw_page_faults_min -= rhs._fd_sw_page_faults_min;
    _fd_sw_page_faults_maj -= rhs._fd_sw_page_faults_maj;
    _fd_sw_alignment_faults -= rhs._fd_sw_alignment_faults;
    _fd_sw_emulation_faults -= rhs._fd_sw_emulation_faults;
    _fd_hw_cpu_cycles -= rhs._fd_hw_cpu_cycles;
    _fd_hw_instructions -= rhs._fd_hw_instructions;
    _fd_hw_cache_references -= rhs._fd_hw_cache_references;
    _fd_hw_cache_misses -= rhs._fd_hw_cache_misses;
    _fd_hw_branch_instructions -= rhs._fd_hw_branch_instructions;
    _fd_hw_branch_misses -= rhs._fd_hw_branch_misses;
    _fd_hw_stalled_cycles_frontend -= rhs._fd_hw_stalled_cycles_frontend;
    _fd_hw_stalled_cycles_backend -= rhs._fd_hw_stalled_cycles_backend;
    return *this;
  }

  friend LinuxEventsData operator-(LinuxEventsData lhs, const LinuxEventsData& rhs)
  {
    lhs -= rhs;
    return lhs;
  }

  uint64_t _fd_sw_cpu_clock;         // This reports the CPU clock, a high-resolution per-CPU timer.
  uint64_t _fd_sw_task_clock;        // This reports a clock count specific to the task that is running.
  uint64_t _fd_sw_page_faults;       // This reports the number of page faults.
  uint64_t _fd_sw_context_switches;  // This counts context switches.
  uint64_t _fd_sw_cpu_migrations;    // This reports the number of times the process has migrated to a new CPU.
  uint64_t _fd_sw_page_faults_min;   // This counts the number of minor page faults.
  uint64_t _fd_sw_page_faults_maj;   // This counts the number of major page faults. These required disk I/O to handle.
  uint64_t _fd_sw_alignment_faults;  // This counts the number of alignment faults.
  uint64_t _fd_sw_emulation_faults;  // This  counts the number of emulation faults.

  uint64_t _fd_hw_cpu_cycles;        // Total cycles.
  uint64_t _fd_hw_instructions;      // Retired instructions.

  uint64_t _fd_hw_cache_references;  // Cache accesses.  Usually this indicates Last Level Cache accesses.
  uint64_t _fd_hw_cache_misses;      // Cache misses.  Usually this indicates Last Level Cache misses.

  uint64_t _fd_hw_branch_instructions; // Retired branch instructions.
  uint64_t _fd_hw_branch_misses;       // Mispredicted branch instructions.

  uint64_t _fd_hw_stalled_cycles_frontend; // Stalled cycles during issue.
  uint64_t _fd_hw_stalled_cycles_backend;  // Stalled cycles during retirement.
};

// ---------------------------------------------------------------------------
class LinuxEvents
{
  public:
    explicit LinuxEvents()
    {
      open_events();
    }

    ~LinuxEvents() = default;

    void enable_events() {
      _fd_sw_cpu_clock.enable_events();
      _fd_sw_task_clock.enable_events();
      _fd_sw_page_faults.enable_events();
      _fd_sw_context_switches.enable_events();
      _fd_sw_cpu_migrations.enable_events();
      _fd_sw_page_faults_min.enable_events();
      _fd_sw_page_faults_maj.enable_events();
      _fd_sw_alignment_faults.enable_events();
      _fd_sw_emulation_faults.enable_events();

      _fd_hw_cpu_cycles_instr_group.enable_events();
      _fd_hw_cache_references_misses_group.enable_events();
      _fd_hw_branch_instructions_misses_group.enable_events();
      _fd_hw_stalled_cycles_frontend_backend_group.enable_events();
    }

    LinuxEventsData get_snapshot()
    {
      LinuxEventsData data{};
      data._fd_sw_cpu_clock = _fd_sw_cpu_clock.read_event_first();
      data._fd_sw_task_clock = _fd_sw_task_clock.read_event_first();
      data._fd_sw_page_faults = _fd_sw_page_faults.read_event_first();
      data._fd_sw_context_switches = _fd_sw_context_switches.read_event_first();
      data._fd_sw_cpu_migrations = _fd_sw_cpu_migrations.read_event_first();
      data._fd_sw_page_faults_min = _fd_sw_page_faults_min.read_event_first();
      data._fd_sw_page_faults_maj = _fd_sw_page_faults_maj.read_event_first();
      data._fd_sw_alignment_faults = _fd_sw_alignment_faults.read_event_first();
      data._fd_sw_emulation_faults = _fd_sw_emulation_faults.read_event_first();

      data._fd_hw_cpu_cycles = _fd_hw_cpu_cycles_instr_group.read_event_first();
      data._fd_hw_instructions = _fd_hw_cpu_cycles_instr_group.read_event_second();
      data._fd_hw_cache_references = _fd_hw_cache_references_misses_group.read_event_first();
      data._fd_hw_cache_misses = _fd_hw_cache_references_misses_group.read_event_second();
      data._fd_hw_branch_instructions = _fd_hw_branch_instructions_misses_group.read_event_first();
      data._fd_hw_branch_misses = _fd_hw_branch_instructions_misses_group.read_event_second();
      data._fd_hw_stalled_cycles_frontend = _fd_hw_stalled_cycles_frontend_backend_group.read_event_first();
      data._fd_hw_stalled_cycles_backend = _fd_hw_stalled_cycles_frontend_backend_group.read_event_second();
      return data;
    }

  private:
    LinuxEvent _fd_sw_cpu_clock;         // This reports the CPU clock, a high-resolution per-CPU timer.
    LinuxEvent _fd_sw_task_clock;        // This reports a clock count specific to the task that is running.
    LinuxEvent _fd_sw_page_faults;       // This reports the number of page faults.
    LinuxEvent _fd_sw_context_switches;  // This counts context switches.
    LinuxEvent _fd_sw_cpu_migrations;    // This reports the number of times the process has migrated to a new CPU.
    LinuxEvent _fd_sw_page_faults_min;   // This counts the number of minor page faults.
    LinuxEvent _fd_sw_page_faults_maj;   // This counts the number of major page faults. These required disk I/O to handle.
    LinuxEvent _fd_sw_alignment_faults;  // This counts the number of alignment faults.
    LinuxEvent _fd_sw_emulation_faults;  // This  counts the number of emulation faults.

    // Total cycles.
    // Retired instructions.
    LinuxEvent _fd_hw_cpu_cycles_instr_group;

    // Cache accesses.  Usually this indicates Last Level Cache accesses.
    // Cache misses.  Usually this indicates Last Level Cache misses.
    LinuxEvent _fd_hw_cache_references_misses_group;

    // Retired branch instructions.
    // Mispredicted branch instructions.
    LinuxEvent _fd_hw_branch_instructions_misses_group;

    // Stalled cycles during issue.
    // Stalled cycles during retirement.
    LinuxEvent _fd_hw_stalled_cycles_frontend_backend_group;

  void open_events() {
    _fd_sw_cpu_clock = LinuxEvent("PERF_COUNT_SW_CPU_CLOCK",
                                  PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CPU_CLOCK);
    _fd_sw_task_clock = LinuxEvent("PERF_COUNT_SW_TASK_CLOCK",
                                   PERF_TYPE_SOFTWARE, PERF_COUNT_SW_TASK_CLOCK);
    _fd_sw_page_faults = LinuxEvent("PERF_COUNT_SW_PAGE_FAULTS",
                                    PERF_TYPE_SOFTWARE, PERF_COUNT_SW_PAGE_FAULTS);
    _fd_sw_context_switches = LinuxEvent("PERF_COUNT_SW_CONTEXT_SWITCHES",
                                         PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CONTEXT_SWITCHES);
    _fd_sw_cpu_migrations = LinuxEvent("PERF_COUNT_SW_CPU_MIGRATIONS",
                                       PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CPU_MIGRATIONS);
    _fd_sw_page_faults_min = LinuxEvent("PERF_COUNT_SW_PAGE_FAULTS_MIN",
                                        PERF_TYPE_SOFTWARE, PERF_COUNT_SW_PAGE_FAULTS_MIN);
    _fd_sw_page_faults_maj = LinuxEvent("PERF_COUNT_SW_PAGE_FAULTS_MAJ",
                                        PERF_TYPE_SOFTWARE, PERF_COUNT_SW_PAGE_FAULTS_MAJ);
    _fd_sw_alignment_faults = LinuxEvent("PERF_COUNT_SW_ALIGNMENT_FAULTS",
                                         PERF_TYPE_SOFTWARE, PERF_COUNT_SW_ALIGNMENT_FAULTS);
    _fd_sw_emulation_faults = LinuxEvent("PERF_COUNT_SW_EMULATION_FAULTS",
                                         PERF_TYPE_SOFTWARE, PERF_COUNT_SW_EMULATION_FAULTS);

    _fd_hw_cpu_cycles_instr_group =
        LinuxEvent("PERF_COUNT_HW_CPU_CYCLES",
                   PERF_TYPE_HARDWARE, PERF_COUNT_HW_CPU_CYCLES,
                   "PERF_COUNT_HW_INSTRUCTIONS",
                   PERF_TYPE_HARDWARE, PERF_COUNT_HW_INSTRUCTIONS);
    _fd_hw_cache_references_misses_group =
        LinuxEvent("PERF_COUNT_HW_CACHE_REFERENCES",
                   PERF_TYPE_HARDWARE, PERF_COUNT_HW_CACHE_REFERENCES,
                   "PERF_COUNT_HW_CACHE_MISSES",
                   PERF_TYPE_HARDWARE, PERF_COUNT_HW_CACHE_MISSES);
    _fd_hw_branch_instructions_misses_group =
        LinuxEvent("PERF_COUNT_HW_BRANCH_INSTRUCTIONS",
                   PERF_TYPE_HARDWARE, PERF_COUNT_HW_BRANCH_INSTRUCTIONS,
                   "PERF_COUNT_HW_BRANCH_MISSES",
                   PERF_TYPE_HARDWARE, PERF_COUNT_HW_BRANCH_MISSES);
    _fd_hw_stalled_cycles_frontend_backend_group =
        LinuxEvent("PERF_COUNT_HW_STALLED_CYCLES_FRONTEND",
                   PERF_TYPE_HARDWARE, PERF_COUNT_HW_STALLED_CYCLES_FRONTEND,
                   "PERF_COUNT_HW_STALLED_CYCLES_BACKEND",
                   PERF_TYPE_HARDWARE, PERF_COUNT_HW_STALLED_CYCLES_BACKEND);
  }
};

// ---------------------------------------------------------------------------
class Program
{
 public:
  explicit Program() {
    _output_stream = &std::clog;
  }

  ~Program() {
    _output_stream->flush();
  }

  static void check_create() {
    std::call_once(_once_flag_create, call_once_create);
  }

  static void check_destroy() {
    std::call_once(_once_flag_destroy, call_once_destroy);
  }

  void print_line(const std::string_view line) {
    _output_stream->write(line.data(), line.size());
  }

 private:
  static inline std::once_flag _once_flag_create, _once_flag_destroy;
  static inline Program* _p_program;
  std::ostream* _output_stream;

  static void call_once_create() {
    _p_program = new Program;
  }

  static void call_once_destroy() {
    delete _p_program;
    _p_program = nullptr;
  }
};

// ---------------------------------------------------------------------------
class Thread
{
 public:
  explicit Thread() {
    const uint_fast64_t prev_threads_created = std::atomic_fetch_add(&_threads_created, 1);
    _thread_id = prev_threads_created+1;
    std::atomic_fetch_add(&_threads_active, 1);
  }

  ~Thread() {
    std::atomic_fetch_sub(&_threads_active, 1);
  }

  static void check_create() {
    if (_p_thread == nullptr) {
      _p_thread = new Thread;
    }
  }

  static void destroy() {
    delete _p_thread;
    _p_thread = nullptr;
  }

  static bool all_threads_done() {
    return _threads_active == 0;
  }

  uint64_t get_id() {
    return _thread_id;
  }

 private:
  static thread_local inline Thread* _p_thread;
  static inline std::atomic_uint_fast64_t _threads_created;
  static inline std::atomic_uint_fast64_t _threads_active;
  uint_fast64_t _thread_id;
  LinuxEvents _linux_events;
};

// ---------------------------------------------------------------------------
class ProfileRecord {
 public:
  explicit ProfileRecord(const std::string_view parent_function_signature,
                         const std::string_view function_signature)
                         :
                         _parent_function_signature(parent_function_signature),
                         _function_signature(function_signature)
  {
  }

 private:
  const std::string_view _parent_function_signature;
  const std::string_view _function_signature;
  uint64_t _function_call_count;
};

// ---------------------------------------------------------------------------
template <BuildMode build_mode = g_build_mode>
class Function
{
public:
  explicit Function([[maybe_unused]] const std::string_view subsystem = "",
                    [[maybe_unused]] const double count = 0.0,
                    [[maybe_unused]] std::string session = "",
                    [[maybe_unused]] const std::source_location& location =
                        std::source_location::current())
    requires (build_mode == BuildMode::off)
  {
  }

  explicit Function(const std::string_view subsystem = "",
                    const double count = 0.0,
                    std::string session = "",
                    const std::source_location& location = std::source_location::current())
    requires (build_mode == BuildMode::profile)
  {
    check_create_program_thread();
  }

  ~Function()
  {
    check_destroy_program_thread();
  }

 private:
  static thread_local inline std::stack<Function<build_mode>> _functions;
  static thread_local inline std::stack<std::string> _subsystems;
  static thread_local inline std::stack<std::string> _sessions;

  void check_create_program_thread()
  {
    Program::check_create();
    Thread::check_create();
  }

  void check_destroy_program_thread()
  {
    if (_functions.empty()) {
      Thread::destroy();
    }
    if (Thread::all_threads_done()) {
      Program::check_destroy();
    }
  }
};

  // std::unordered_map<pair, int, pair_hash> unordered_map

//    for (auto const &entry: unordered_map)
//    {
//        auto key_pair = entry.first;
//        std::cout << "{" << key_pair.first << "," << key_pair.second << "}, "
//                  << entry.second << std::endl;
//    }

}

#endif // ANTEATER_ANTEATER_HPP


// ---------------------------------------------------------------------------
int test(const int instance)
{
  brainyguy::Function f{"test"};
  std::cerr << "inside test " << instance << std::endl;
  if (instance > 1) {
    test(instance-1);
  }
  return 0;
}

// ---------------------------------------------------------------------------
int main() {
  brainyguy::Function f;

  //const int t1_result = test();
  std::thread t2 = std::thread(test, 1);
  std::thread t3 = std::thread(test, 2);
  std::thread t4 = std::thread(test, 3);
  t2.join();
  t3.join();
  t4.join();
}
