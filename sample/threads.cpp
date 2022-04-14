#include <atomic>
#include <iostream>
#include <mutex>
#include <shared_mutex>
#include <source_location>
#include <sstream>
#include <unordered_map>
#include <utility>

namespace brainyguy {
  enum class BuildMode { off, debug, test, qa, profile, release };
  constexpr auto BG_BUILD_MODE = BuildMode::profile;


  template <BuildMode build_mode = BG_BUILD_MODE>
  class Function
  {
    static std::once_flag program_once_flag;
    thread_local static Function<BG_BUILD_MODE>* g_function;
    static std::atomic_uint_fast64_t g_thread_count;

    static void program_constructor() {

    }

    static void program_destructor() {

    }

    void check_thread_constructor() {
      if (g_function == nullptr) {
        const uint_fast64_t prev_thread_count = std::atomic_fetch_add(&g_thread_count, 1);
        if (prev_thread_count == 0) {
          std::call_once(program_once_flag, program_constructor);
        }
      }
    }

    void check_thread_destructor() {
      if (g_function == nullptr) {
        const uint_fast64_t prev_thread_count = std::atomic_fetch_sub(&g_thread_count, 1);
        if (prev_thread_count == 1) {
          program_destructor();
        }
      }
    }


  public:
    explicit Function(const std::string_view subsystem = "",
                      const double count = 0.0,
                      std::string session = "",
                      const std::source_location& location = std::source_location::current())
      requires (build_mode == BuildMode::off)
    {
      std::cerr << "inside Function() none" << std::endl;
    }

    explicit Function(const std::string_view subsystem = "",
                      const double count = 0.0,
                      std::string session = "",
                      const std::source_location& location = std::source_location::current())
      requires (build_mode == BuildMode::profile)
    {
      std::cerr << "inside Function() profile" << std::endl;

      std::cout << "file: "
		<< location.file_name() << "("
		<< location.line() << ":"
		<< location.column() << ") `"
		<< location.function_name() << "`: "
		<< subsystem << ": "
		<< count << ": "
		<< session << std::endl;
    }

    ~Function()
    {
      std::cerr << "inside ~Function()" << std::endl;
    }
  };

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

  // std::unordered_map<pair, int, pair_hash> unordered_map

    for (auto const &entry: unordered_map)
    {
        auto key_pair = entry.first;
        std::cout << "{" << key_pair.first << "," << key_pair.second << "}, "
                  << entry.second << std::endl;
    }

}

int test()
{
  brainyguy::Function f{"test"};
  std::cerr << "inside test()" << std::endl;
  return 0;
}

int
main() {
  brainyguy::Function f;

  return test();
}
