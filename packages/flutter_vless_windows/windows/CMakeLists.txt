# Project-level configuration.
cmake_minimum_required(VERSION 3.14)
project(runner LANGUAGES CXX)

# Define build configuration option.
get_property(IS_MULTICONFIG GLOBAL PROPERTY GENERATOR_IS_MULTI_CONFIG)
if(IS_MULTICONFIG)
  set(CMAKE_CONFIGURATION_TYPES "Debug;Profile;Release" CACHE STRING "" FORCE)
else()
  if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE
      STRING "Build mode" FORCE)
  endif()
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
    "Debug" "Profile" "Release")
endif()

# Use Unicode
add_definitions(-DUNICODE -D_UNICODE)

# Set C++ standard to C++17 for std::filesystem, std::optional, etc.
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Define the plugin name. This must match the pubspec.yaml
# `plugin.platforms[].name` entry.
set(PLUGIN_NAME "flutter_vless_windows")

# Define the plugin library. Its name must match `plugin.platforms[].name`.
add_library(${PLUGIN_NAME}_plugin SHARED
  "diagnostics_log.cpp"
  "flutter_vless_plugin.cpp"
  "v2ray_manager.cpp"
  "proxy_service.cpp"
  "vpn_service.cpp"
)

# Apply a standard set of build settings. This can be removed for plugins
# that want to provide their own build settings.
apply_standard_settings(${PLUGIN_NAME}_plugin)

# Ensure Windows import library is created
set_target_properties(${PLUGIN_NAME}_plugin PROPERTIES
  WINDOWS_EXPORT_ALL_SYMBOLS ON
)

# Add /FS flag for parallel PDB writes
if(MSVC)
  target_compile_options(${PLUGIN_NAME}_plugin PRIVATE /FS)
endif()

# Add preprocessor definitions for the build.
target_compile_definitions(${PLUGIN_NAME}_plugin PRIVATE "FLUTTER_PLUGIN_IMPL")
target_compile_definitions(${PLUGIN_NAME}_plugin PRIVATE "NOMINMAX")

# Add include directories for the plugin.
target_include_directories(${PLUGIN_NAME}_plugin INTERFACE
  "${CMAKE_CURRENT_SOURCE_DIR}/include")

# Link the plugin to Flutter's library.
target_link_libraries(${PLUGIN_NAME}_plugin PRIVATE flutter flutter_wrapper_plugin)

# List of absolute paths to libraries that should be bundled with the plugin.
# This list could contain prebuilt libraries, or libraries created by an
# external build triggered from this build file.
set(flutter_vless_bundled_libraries
  ""
  PARENT_SCOPE
)

# Ensure the plugin target is available to parent CMakeLists.txt for linking
set(${PLUGIN_NAME}_plugin ${PLUGIN_NAME}_plugin PARENT_SCOPE)
