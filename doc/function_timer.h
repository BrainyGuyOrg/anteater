#ifndef FUNCTION_TIMER_H_
#define FUNCTION_TIMER_H_
#pragma once

#if __cplusplus < 201703L
    #error "C++17 or newer is required"
#endif

#if !defined(__linux__)
    #error "Linux operating system is required"
#endif

// g++ -dM -E -x c++ - < /dev/null
#if !defined(__GNUC__) && !defined(__clang__)
    #error "GNU Compiler Collection or Clang is required"
#endif

#if !defined(__x86_64__)
    #error "x86-64 CPU is required"
#endif

// inline the function independent of any restrictions that otherwise apply to inlining
// https://gcc.gnu.org/onlinedocs/gcc/Attribute-Syntax.html
// https://clang.llvm.org/docs/AttributeReference.html
#define ATTR_ALWAYS_INLINE [[gnu::always_inline]]

// ------------------------------------------------------------------
#define _GNU_SOURCE
#include <sched.h>                      // getcpu()
#include <pthread.h>
#include <thread>
#include <cerrno>
#include <iostream>
#include <fstream>

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string>
#include <system_error>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>

namespace brainyguy::profiler
{
// get CPU and node for the current thread
static uint32_t
get_thread_cpu() {
    uint32_t cpu, node;
    const int status = getcpu(&cpu, &node);
    if (status == -1) {
        throw std::system_error(errno, std::generic_category(), "get_thread_cpu");
    }
    return (node << 16) | cpu;   // 12 bits for the CPU and 8 bits for the node
}

// https://www.kernel.org/doc/Documentation/ABI/testing/sysfs-devices-system-cpu
static void
disable_cpu(const int32_t cpu)
{
    std::string str_cpu   = std::to_string(cpu);
    std::string file_path = std::string("/sys/devices/system/cpu/cpu") + str_cpu + "/online";
    std::ofstream ostrm(file_path);
    ostrm << "0";
}

static void
enable_cpu(const int32_t cpu)
{
    std::string str_cpu   = std::to_string(cpu);
    std::string file_path = std::string("/sys/devices/system/cpu/cpu") + str_cpu + "/online";
    std::ofstream ostrm(file_path);
    ostrm << "1";
}

// set the CPU affinity for the current thread
static void
set_thread_cpu(const int32_t cpu)
{
    pthread_t thread = pthread_self();   // always succeeds
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu, &cpuset);
    const int status = pthread_setaffinity_np(thread, sizeof(cpuset), &cpuset);
    if (status) {
        throw std::system_error(errno, std::generic_category(), "set_thread_cpu");
    }
}

// returns the new file descriptor
static int
perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
                int cpu, int group_fd, unsigned long flags)
{
    const int fd = syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
    if (fd == -1) {
        throw std::system_error(errno, std::generic_category(), "perf_event_open");
    }
    return fd;
}

// https://github.com/google/benchmark/blob/main/include/benchmark/benchmark.h

// Force the compiler to flush pending writes to global memory.
// Acts as an effective read/write barrier.
static inline ATTR_ALWAYS_INLINE void
clobber_memory()
{
    std::atomic_signal_fence(std::memory_order_acq_rel);
}

// get the hyperthreading sibling for the given CPU
// https://www.kernel.org/doc/Documentation/cputopology.txt
// TODO: should use lscpu
static int32_t
get_cpu_sibling(const int32_t cpu)
{

}

// The DoNotOptimize(...) function can be used to prevent a value or
// expression from being optimized away by the compiler. This function is
// intended to add little to no overhead.
template <class Tp>
static inline ATTR_ALWAYS_INLINE void
do_not_optimize(Tp const& value)
{
    asm volatile("" : : "r,m"(value) : "memory");
}

// returns the 64-bit Time Stamp Counter (TSC)
// rdtsc counts reference cycles, not CPU core clock cycles
// Linux encodes numa id (<<12) and core id (8bit) into tsc_aux
// rdtscp is a serializing instruction
static inline ATTR_ALWAYS_INLINE uint64_t
read_tsc_p(uint32_t& tsc_aux)
{
    uint64_t rax, rdx;
    asm volatile ( "rdtscp\n" : "=a" (rax), "=d" (rdx), "=c" (tsc_aux) : : );
    return (rdx << 32) + rax;
}

// https://stackoverflow.com/questions/51919219/determine-tsc-frequency-on-linux
static int
get_tsc_freq() {

}

// http://web.eece.maine.edu/~vweaver/projects/perf_events/index.html
// https://www.brendangregg.com/blog/2017-05-04/the-pmcs-of-ec2.html
// https://github.com/brendangregg/pmc-cloud-tools
// https://stackoverflow.com/questions/13772567/how-to-get-the-cpu-cycle-count-in-x86-64-from-c
// https://stackoverflow.com/questions/51818655/clflush-to-invalidate-cache-line-via-c-function
// https://stackoverflow.com/questions/3830883/cpu-cycle-count-based-profiling-in-c-c-linux-x86-64
// https://stackoverflow.com/questions/13313510/quick-way-to-count-number-of-instructions-executed-in-a-c-program

// https://stackoverflow.com/questions/37786547/enforcing-statement-order-in-c

template<class F, typename... Args>
void function_thread(const char[] tag, F f, Args&&... args)
{
    set_thread_cpu(0);
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    f(std::forward<Args>(args)...);
}

template<class F, typename... Args>
void profile(const char[] tag, F f, Args&&... args) {
    std::thread thread(function_thread, f, std::forward<Args>(args)...);
    thread.join();
}

// don't take the mean time, take the median (there will be very high outliers).

}

# endif   // FUNCTION_TIMER_H_
