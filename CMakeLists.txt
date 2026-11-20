cmake_minimum_required(VERSION 3.24)
project(file_wrapper_windows LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)


add_library(file_lib STATIC file.cpp)
target_include_directories(file_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_definitions(file_lib PUBLIC UNICODE _UNICODE NOMINMAX WIN32_LEAN_AND_MEAN)

# --- Тесты ---
include(FetchContent)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/refs/tags/v1.15.2.tar.gz
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)  # MSVC: тот же CRT, что у проекта
FetchContent_MakeAvailable(googletest)

enable_testing()
add_executable(file_tests tests/file_test_windows.cpp)
target_link_libraries(file_tests PRIVATE file_lib GTest::gtest_main)

if(MSVC)
  # /utf-8 обязателен: в тестах есть пути и сообщения на кириллице.
  target_compile_options(file_lib PRIVATE /utf-8 /W4 /EHsc)
  target_compile_options(file_tests PRIVATE /utf-8 /W4 /EHsc)
else()
  target_compile_options(file_tests PRIVATE -Wall -Wextra)
endif()

include(GoogleTest)
gtest_discover_tests(file_tests DISCOVERY_MODE PRE_TEST)
