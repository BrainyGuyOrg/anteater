#include <iostream>
#include <sstream>
#include <source_location>

namespace brainyguy {
  enum class BuildMode {
    OFF,
    DEBUG,
    TEST,
    QA,
    PROFILE,
    RELEASE
  };

  constexpr auto BG_BUILD_MODE = BuildMode::PROFILE;

  template <BuildMode build_mode = BG_BUILD_MODE>
  class Function
  {
  public:
    explicit Function(const std::string_view subsystem = "",
                      const double count = 0.0,
                      std::string session = "",
                      const std::source_location& location = std::source_location::current())
      requires (build_mode == BuildMode::OFF)
    {
      std::cerr << "inside Function() none" << std::endl;
    }

    explicit Function(const std::string_view subsystem = "",
                      const double count = 0.0,
                      std::string session = "",
                      const std::source_location& location = std::source_location::current())
      requires (build_mode == BuildMode::PROFILE)
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
