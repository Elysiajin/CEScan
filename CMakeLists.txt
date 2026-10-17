cmake_minimum_required(VERSION 3.15)
project(CEScan CXX)

# ---------------------------------------------------------------------------
#  CEScan —— Cheat Engine 内存搜索 / 区域排除工具（VC++ 移植版）
#  用法：
#     cmake -S . -B build -G "Visual Studio 17 2022" -A x64
#     cmake --build build --config Release
#  或（MinGW）：
#     cmake -S . -B build -G "MinGW Makefiles"
#     cmake --build build -j
# ---------------------------------------------------------------------------

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

add_executable(CEScan
  src/main.cpp
  src/CETypes.cpp
  src/CEUtil.cpp
  src/ProcessMemory.cpp
  src/RegionFilter.cpp
  src/PatternScan.cpp
  src/ScanEngine.cpp
)

target_include_directories(CEScan PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

if(MSVC)
  target_compile_options(CEScan PRIVATE /utf-8 /W3 /permissive- /MP)
  target_compile_definitions(CEScan PRIVATE _CRT_SECURE_NO_WARNINGS NOMINMAX WIN32_LEAN_AND_MEAN)
  target_link_libraries(CEScan PRIVATE psapi)
else()
  target_compile_options(CEScan PRIVATE -Wall -Wextra -finput-charset=UTF-8 -fexec-charset=UTF-8)
  if(MINGW)
    # 静态链接，避免发布时还需要 libstdc++ / winpthread 的 DLL
    target_link_options(CEScan PRIVATE -static -static-libgcc -static-libstdc++)
    target_link_libraries(CEScan PRIVATE psapi)
  endif()
endif()

set_target_properties(CEScan PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin
  RUNTIME_OUTPUT_DIRECTORY_DEBUG ${CMAKE_CURRENT_SOURCE_DIR}/bin
  RUNTIME_OUTPUT_DIRECTORY_RELEASE ${CMAKE_CURRENT_SOURCE_DIR}/bin
)
