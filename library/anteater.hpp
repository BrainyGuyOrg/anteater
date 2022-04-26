#ifndef ANTEATER_ANTEATER_HPP
#define ANTEATER_ANTEATER_HPP

#if __cplusplus < 202002L
#error C++20 support required to use this library.
#endif

#include <atomic>
#include <chrono>
#include <deque>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
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
template<typename T, typename... Rest>
void hash_combine(std::size_t &seed, const T &v, const Rest &... rest) {
  seed ^= std::hash<T>{}(v) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
  (hash_combine(seed, rest), ...);
}

struct pair_hash {
  template<class T1, class T2>
  std::size_t operator()(const std::pair<T1, T2> &pair) const {
    std::size_t seed = 0;
    hash_combine(seed, pair.first, pair.second);
    return seed;
  }
};

// ---------------------------------------------------------------------------
class Sink {
 public:
  Sink() {
    _output_stream = &std::clog;
  }

  ~Sink() {
    _output_stream->flush();
  }

  void write_line(const std::string_view line) {
    _output_stream->write(line.data(), line.size());
  }

 private:
  std::ostream *_output_stream;
};

static Sink g_sink = Sink();

// ---------------------------------------------------------------------------
class Program {
 public:
  explicit Program() {
    _start = std::chrono::steady_clock::now();
  }

  ~Program() {
    const std::chrono::time_point<std::chrono::steady_clock> end = std::chrono::steady_clock::now();
    std::chrono::duration<double> diff = end - _start;
    _duration_secs = diff.count();
  }

  static void check_create() {
    std::call_once(_once_flag_create, call_once_create);
  }

  static void check_destroy() {
    std::call_once(_once_flag_destroy, call_once_destroy);
  }

 private:
  static inline std::once_flag _once_flag_create, _once_flag_destroy;
  static inline Program *_p_program;
  std::chrono::time_point<std::chrono::steady_clock> _start;
  static double _duration_secs;   // program duration

  static void call_once_create() {
    _p_program = new Program;
  }

  static void call_once_destroy() {
    delete _p_program;
    _p_program = nullptr;
  }
};

// ---------------------------------------------------------------------------
class LinuxEvent {
 public:
  LinuxEvent() : _num_events(0) {}

  explicit LinuxEvent(const std::string_view name, const uint32_t event_type, const uint64_t event) {
    _num_events = 1;
    _name1 = name;
    _fd1 = open_event(name, event_type, event, -1);
  }

  explicit LinuxEvent(const std::string_view name1, const uint32_t event_type1, const uint64_t event1,
                      const std::string_view name2, const uint32_t event_type2, const uint64_t event2) {
    _num_events = 2;
    _name1 = name1;
    _fd1 = open_event(name1, event_type1, event1, -1);
    _name2 = name2;
    _fd2 = open_event(name2, event_type2, event2, _fd1);

    reset_event(name1, _fd1, (_num_events == 1 ? Group::single : Group::leader));
  }

  explicit LinuxEvent(const std::string_view name1, const uint32_t event_type1, const uint64_t event1,
                      const std::string_view name2, const uint32_t event_type2, const uint64_t event2,
                      const std::string_view name3, const uint32_t event_type3, const uint64_t event3) {
    _num_events = 3;
    _name1 = name1;
    _fd1 = open_event(name1, event_type1, event1, -1);
    _name2 = name2;
    _fd2 = open_event(name2, event_type2, event2, _fd1);
    _name3 = name3;
    _fd3 = open_event(name3, event_type3, event3, _fd1);

    reset_event(name1, _fd1, (_num_events == 1 ? Group::single : Group::leader));
  }

  explicit LinuxEvent(const std::string_view name1, const uint32_t event_type1, const uint64_t event1,
                      const std::string_view name2, const uint32_t event_type2, const uint64_t event2,
                      const std::string_view name3, const uint32_t event_type3, const uint64_t event3,
                      const std::string_view name4, const uint32_t event_type4, const uint64_t event4) {
    _num_events = 4;
    _name1 = name1;
    _fd1 = open_event(name1, event_type1, event1, -1);
    _name2 = name2;
    _fd2 = open_event(name2, event_type2, event2, _fd1);
    _name3 = name3;
    _fd3 = open_event(name3, event_type3, event3, _fd1);
    _name4 = name4;
    _fd4 = open_event(name4, event_type4, event4, _fd1);

    reset_event(name1, _fd1, (_num_events == 1 ? Group::single : Group::leader));
  }

  ~LinuxEvent() {
    disable_event(_name1, _fd1, (_num_events == 1 ? Group::single : Group::leader));

    switch (_num_events) {
      case 4: close_event(_name4, _fd4);   /* fall-through */
      case 3: close_event(_name3, _fd3);   /* fall-through */
      case 2: close_event(_name2, _fd2);   /* fall-through */
      case 1: close_event(_name1, _fd1);
    }
  }

  void reset_events() {
    reset_event(_name1, _fd1, (_num_events == 1 ? Group::single : Group::leader));
  }

  void enable_events() {
    enable_event(_name1, _fd1, (_num_events == 1 ? Group::single : Group::leader));
  }

  uint64_t read_event1() {
    assert(_num_events >= 1);
    return read_event(_name1, _fd1);
  }

  uint64_t read_event2() {
    assert(_num_events >= 2);
    return read_event(_name2, _fd2);
  }

  uint64_t read_event3() {
    assert(_num_events >= 3);
    return read_event(_name3, _fd3);
  }

  uint64_t read_event4() {
    assert(_num_events >= 4);
    return read_event(_name4, _fd4);
  }

 private:
  enum class Group { leader, single };
  int _num_events;
  std::string_view _name1, _name2, _name3, _name4;
  int _fd1, _fd2, _fd3, _fd4;

  static int perf_event_open(struct perf_event_attr *hw_event, pid_t pid, int cpu,
                             int group_fd, unsigned long flags) {
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

  static void reset_event(const std::string_view name, const int fd, const Group group) {
    const int status = ioctl(fd, PERF_EVENT_IOC_RESET, (group == Group::leader ? PERF_IOC_FLAG_GROUP : 0));
    if (status == -1) {
      std::cerr << "ERROR: LinuxEvent::reset_event: " << name << ": " << std::strerror(errno) << std::endl;
      std::exit(EXIT_FAILURE);
    }
  }

  static void disable_event(const std::string_view name, const int fd, const Group group) {
    const int status = ioctl(fd, PERF_EVENT_IOC_DISABLE,  (group == Group::leader ? PERF_IOC_FLAG_GROUP : 0));
    if (status == -1) {
      std::cerr << "ERROR: LinuxEvent::disable_event: " << name << ": " << std::strerror(errno) << std::endl;
      std::exit(EXIT_FAILURE);
    }
  }

  static void enable_event(const std::string_view name, const int fd, const Group group) {
    const int status = ioctl(fd, PERF_EVENT_IOC_ENABLE,  (group == Group::leader ? PERF_IOC_FLAG_GROUP : 0));
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
class LinuxEventsData {
 public:
  explicit LinuxEventsData() = default;

  static void write_header(std::ostream &os) {
    os << "TotalCpuSec,TotalTaskIdlePct,TotalPageFaultMajorPerSec,"
       << "TotalCyclesPerInstr,TotalIssueStallPct,TotalRetireStallPct,TotalCacheMissPct,TotalBranchMissPct,"
       << "SelfCpuSec,SelfTaskIdlePct,SelfPageFaultMajorPerSec,"
       << "SelfCyclesPerInstr,SelfIssueStallPct,SelfRetireStallPct,SelfCacheMissPct,SelfBranchMissPct";
  }

  void write_data(std::ostream &os) {
    os << get_cpu_seconds() << ','
       << get_task_idle_pct() << ','
       << get_page_fault_major_per_sec() << ','
       << get_cycles_per_instr() << ','
       << get_issue_stall_pct() << ','
       << get_retire_stall_pct() << ','
       << get_cache_miss_pct() << ','
       << get_branch_miss_pct();
  }

  LinuxEventsData &operator+=(const LinuxEventsData &rhs) {
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
    _fd_hw_stalled_cycles_frontend += rhs._fd_hw_stalled_cycles_frontend;
    _fd_hw_stalled_cycles_backend += rhs._fd_hw_stalled_cycles_backend;
    _fd_hw_cache_references += rhs._fd_hw_cache_references;
    _fd_hw_cache_misses += rhs._fd_hw_cache_misses;
    _fd_hw_branch_instructions += rhs._fd_hw_branch_instructions;
    _fd_hw_branch_misses += rhs._fd_hw_branch_misses;
    return *this;
  }

  friend LinuxEventsData operator+(LinuxEventsData lhs, const LinuxEventsData &rhs) {
    lhs += rhs;
    return lhs;
  }

  LinuxEventsData &operator-=(const LinuxEventsData &rhs) {
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
    _fd_hw_stalled_cycles_frontend -= rhs._fd_hw_stalled_cycles_frontend;
    _fd_hw_stalled_cycles_backend -= rhs._fd_hw_stalled_cycles_backend;
    _fd_hw_cache_references -= rhs._fd_hw_cache_references;
    _fd_hw_cache_misses -= rhs._fd_hw_cache_misses;
    _fd_hw_branch_instructions -= rhs._fd_hw_branch_instructions;
    _fd_hw_branch_misses -= rhs._fd_hw_branch_misses;
    return *this;
  }

  friend LinuxEventsData operator-(LinuxEventsData lhs, const LinuxEventsData &rhs) {
    lhs -= rhs;
    return lhs;
  }

  double get_cpu_seconds() {
    return static_cast<double>(_fd_sw_cpu_clock) / 1'000'000'000.0;
  }

  double get_task_idle_pct() {
    return 1.0 - (static_cast<double>(_fd_sw_task_clock) / static_cast<double>(_fd_sw_cpu_clock));
  }

  double get_page_fault_major_per_sec() {
    return static_cast<double>(_fd_sw_page_faults_maj) / get_cpu_seconds();
  }

  double get_cycles_per_instr() {
    return static_cast<double>(_fd_hw_cpu_cycles) / static_cast<double>(_fd_hw_instructions);
  }

  double get_issue_stall_pct() {
    return static_cast<double>(_fd_hw_stalled_cycles_frontend) / static_cast<double>(_fd_hw_cpu_cycles);
  }

  double get_retire_stall_pct() {
    return static_cast<double>(_fd_hw_stalled_cycles_backend) / static_cast<double>(_fd_hw_cpu_cycles);
  }

  double get_cache_miss_pct() {
    return static_cast<double>(_fd_hw_cache_misses) / static_cast<double>(_fd_hw_cache_references);
  }

  double get_branch_miss_pct() {
    return static_cast<double>(_fd_hw_branch_misses) / static_cast<double>(_fd_hw_branch_instructions);
  }

// ---------------------------------------------------------------------------
  uint64_t _fd_sw_cpu_clock;         // This reports the CPU clock, a high-resolution per-CPU timer. (nanos)
  uint64_t _fd_sw_task_clock;        // This reports a clock count specific to the task that is running. (nanos)
  uint64_t _fd_sw_page_faults;       // This reports the number of page faults.
  uint64_t _fd_sw_context_switches;  // This counts context switches.
  uint64_t _fd_sw_cpu_migrations;    // This reports the number of times the process has migrated to a new CPU.
  uint64_t _fd_sw_page_faults_min;   // This counts the number of minor page faults.
  uint64_t _fd_sw_page_faults_maj;   // This counts the number of major page faults. These required disk I/O to handle.
  uint64_t _fd_sw_alignment_faults;  // This counts the number of alignment faults. Zero on x86.
  uint64_t _fd_sw_emulation_faults;  // This counts the number of emulation faults.

  uint64_t _fd_hw_cpu_cycles;               // Total cycles.
  uint64_t _fd_hw_instructions;             // Retired instructions.
  uint64_t _fd_hw_stalled_cycles_frontend;  // Stalled cycles during issue.
  uint64_t _fd_hw_stalled_cycles_backend;   // Stalled cycles during retirement.

  uint64_t _fd_hw_cache_references;  // Cache accesses.  Usually this indicates Last Level Cache accesses.
  uint64_t _fd_hw_cache_misses;      // Cache misses.  Usually this indicates Last Level Cache misses.

  uint64_t _fd_hw_branch_instructions; // Retired branch instructions.
  uint64_t _fd_hw_branch_misses;       // Mispredicted branch instructions.
};

// ---------------------------------------------------------------------------
class LinuxEvents {
 public:
  explicit LinuxEvents() {
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
  }

  LinuxEventsData get_snapshot() {
    LinuxEventsData data{};
    data._fd_sw_cpu_clock = _fd_sw_cpu_clock.read_event1();
    data._fd_sw_task_clock = _fd_sw_task_clock.read_event1();
    data._fd_sw_page_faults = _fd_sw_page_faults.read_event1();
    data._fd_sw_context_switches = _fd_sw_context_switches.read_event1();
    data._fd_sw_cpu_migrations = _fd_sw_cpu_migrations.read_event1();
    data._fd_sw_page_faults_min = _fd_sw_page_faults_min.read_event1();
    data._fd_sw_page_faults_maj = _fd_sw_page_faults_maj.read_event1();
    data._fd_sw_alignment_faults = _fd_sw_alignment_faults.read_event1();
    data._fd_sw_emulation_faults = _fd_sw_emulation_faults.read_event1();

    data._fd_hw_cpu_cycles = _fd_hw_cpu_cycles_instr_group.read_event1();
    data._fd_hw_instructions = _fd_hw_cpu_cycles_instr_group.read_event2();
    data._fd_hw_stalled_cycles_frontend = _fd_hw_cpu_cycles_instr_group.read_event3();
    data._fd_hw_stalled_cycles_backend = _fd_hw_cpu_cycles_instr_group.read_event4();

    data._fd_hw_cache_references = _fd_hw_cache_references_misses_group.read_event1();
    data._fd_hw_cache_misses = _fd_hw_cache_references_misses_group.read_event2();
    data._fd_hw_branch_instructions = _fd_hw_branch_instructions_misses_group.read_event1();
    data._fd_hw_branch_misses = _fd_hw_branch_instructions_misses_group.read_event2();
    return data;
  }

 private:
  LinuxEvent _fd_sw_cpu_clock;         // This reports the CPU clock, a high-resolution per-CPU timer.
  LinuxEvent _fd_sw_task_clock;        // This reports a clock count specific to the task that is running.
  LinuxEvent _fd_sw_page_faults;       // This reports the number of page faults.
  LinuxEvent _fd_sw_context_switches;  // This counts context switches.
  LinuxEvent _fd_sw_cpu_migrations;    // This reports the number of times the process has migrated to a new CPU.
  LinuxEvent _fd_sw_page_faults_min;   // This counts the number of minor page faults.
  LinuxEvent
      _fd_sw_page_faults_maj;   // This counts the number of major page faults. These required disk I/O to handle.
  LinuxEvent _fd_sw_alignment_faults;  // This counts the number of alignment faults.
  LinuxEvent _fd_sw_emulation_faults;  // This  counts the number of emulation faults.

  // Total cycles.
  // Retired instructions.
  // Stalled cycles during issue.
  // Stalled cycles during retirement.
  LinuxEvent _fd_hw_cpu_cycles_instr_group;

  // Cache accesses.  Usually this indicates Last Level Cache accesses.
  // Cache misses.  Usually this indicates Last Level Cache misses.
  LinuxEvent _fd_hw_cache_references_misses_group;

  // Retired branch instructions.
  // Mispredicted branch instructions.
  LinuxEvent _fd_hw_branch_instructions_misses_group;

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
                   PERF_TYPE_HARDWARE, PERF_COUNT_HW_INSTRUCTIONS,
                   "PERF_COUNT_HW_STALLED_CYCLES_FRONTEND",
                   PERF_TYPE_HARDWARE, PERF_COUNT_HW_STALLED_CYCLES_FRONTEND,
                   "PERF_COUNT_HW_STALLED_CYCLES_BACKEND",
                   PERF_TYPE_HARDWARE, PERF_COUNT_HW_STALLED_CYCLES_BACKEND);

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
  }
};

// ---------------------------------------------------------------------------
class Thread {
 public:
  explicit Thread() {
    const uint_fast64_t prev_threads_created = std::atomic_fetch_add(&_threads_created, 1);
    _thread_id = prev_threads_created + 1;
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
  static thread_local inline Thread *_p_thread;
  static inline std::atomic_uint_fast64_t _threads_created;
  static inline std::atomic_uint_fast64_t _threads_active;
  uint_fast64_t _thread_id;
  LinuxEvents _linux_events;
};

// ---------------------------------------------------------------------------
class ProfileData {
 public:
  explicit ProfileData(const std::string_view parent_function_signature,
                       const std::string_view function_signature)
      :
      _parent_function_signature(parent_function_signature),
      _function_signature(function_signature),
      _function_calls(),
      _sum_of_count(),
      _linux_event_data_total(),
      _linux_event_data_self() {
  }

  static void write_header(std::ostream &os) {
    os << "Subsystem,ParentFunction,Function,Calls,Count,";
    LinuxEventsData::write_header(os);
  }

  void write_data(std::ostream &os) {

  }

  ProfileData &operator+=(const ProfileData &rhs) {
    _sum_of_count += rhs._sum_of_count;
    _linux_event_data_total += rhs._linux_event_data_total;
    _linux_event_data_self += rhs._linux_event_data_self;
    return *this;
  }

  friend ProfileData operator+(ProfileData lhs, const ProfileData &rhs) {
    lhs += rhs;
    return lhs;
  }

  ProfileData &operator-=(const ProfileData &rhs) {
    _sum_of_count -= rhs._sum_of_count;
    _linux_event_data_total -= rhs._linux_event_data_total;
    _linux_event_data_self -= rhs._linux_event_data_self;
    return *this;
  }

  friend ProfileData operator-(ProfileData lhs, const ProfileData &rhs) {
    lhs -= rhs;
    return lhs;
  }

 private:
  const std::string_view _parent_function_signature;
  const std::string_view _function_signature;
  uint64_t _function_calls;
  double _sum_of_count;
  LinuxEventsData _linux_event_data_total;
  LinuxEventsData _linux_event_data_self;
};

// ---------------------------------------------------------------------------
template<BuildMode build_mode = g_build_mode>
class Function {
 public:
  explicit Function([[maybe_unused]] const std::string_view subsystem = "",
                    [[maybe_unused]] const double count = 0.0,
                    [[maybe_unused]] std::string session = "",
                    [[maybe_unused]] const std::source_location &location =
                    std::source_location::current())requires (build_mode == BuildMode::off) {
  }

  explicit Function(const std::string_view subsystem = "",
                    const double count = 0.0,
                    std::string session = "",
                    const std::source_location &location = std::source_location::current())requires (build_mode
      == BuildMode::profile) {
    check_create_program_thread();
  }

  ~Function() {
    check_destroy_program_thread();
  }

 private:
  using ProfileKey = std::pair<std::string_view, std::string_view>;
  static std::unordered_map<ProfileKey, ProfileData> _profile_map;
  static std::mutex _map_mutex;

  static thread_local inline std::stack<Function<build_mode>> _functions;
  static thread_local inline std::stack<std::string> _subsystems;
  static thread_local inline std::stack<std::string> _sessions;

  // all accesses require modifying data
  // no advantage to use a readers-writer lock (a.k.a. shared_mutex)
  static void upsert_profile_map(const ProfileData &profile_record) {

  }

  void write_profile_map() {
    // sort descending by key
    std::multimap<double, ProfileKey, std::greater<>> sorted_profiles;
    sorted_profiles.reserve (_profile_map.size());

    // or sorted_profiles.copy(_profile_map.keys())
    //    sorted_profiles.sort()

    for (const auto& profile : _profile_map) {
        sorted_profiles.push_back(profile.first);
    }

    for (const auto& profile : sorted_profiles) {
        // std::cout << _profile_map[profile] << ' ';
    }
  }

  void check_create_program_thread() {
    Program::check_create();
    Thread::check_create();
  }

  void check_destroy_program_thread() {
    if (_functions.empty()) {
      Thread::destroy();
    }
    if (Thread::all_threads_done()) {
      write_profile_map();
      Program::check_destroy();
    }
  }
};

#endif // ANTEATER_ANTEATER_HPP

// ---------------------------------------------------------------------------
int test(const int instance) {
  brainyguy::Function _{"test", 123, "hello"};
  std::cerr << "inside test " << instance << std::endl;
  if (instance > 1) {
    test(instance - 1);
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
