cmake_minimum_required(VERSION 3.10)

find_program(CCACHE_FOUND ccache)
if(CCACHE_FOUND AND NOT DISABLE_CCACHE)
  message("Using ccache")
  set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE ccache)
  set_property(GLOBAL PROPERTY RULE_LAUNCH_LINK ccache)
else()
  message("Not using ccache")
endif()

project(rubbishrsa VERSION 0.0.1)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

file(GLOB_RECURSE ${PROJECT_NAME}_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp)
add_library(${PROJECT_NAME} ${${PROJECT_NAME}_SOURCES})

# This enables the logging functionality
target_compile_definitions(${PROJECT_NAME} PUBLIC RUBBISHRSA_VERBOSITY=1)

# Begin requirements
find_package(Boost REQUIRED COMPONENTS system random program_options)
if (WIN32)
  find_package(MPIR REQUIRED)
  set(MP_LIB MPIR::mpir)
  add_compile_options("/std:c++latest")
else()
  find_package(GMP REQUIRED)
  set(MP_LIB GMP::gmp)
endif()
# We parallise prime generation so we can aid low end computers (and Windows)
find_package(Threads REQUIRED)
# End requirements

target_link_libraries(${PROJECT_NAME}
PUBLIC # Libraries needed to use this library
Boost::boost
Boost::system
Boost::random
Boost::program_options
Threads::Threads
${MP_LIB}
PRIVATE # Libraries only needed to build this library
)

target_compile_features(${PROJECT_NAME} PUBLIC cxx_std_20)

target_include_directories(${PROJECT_NAME} PUBLIC
  $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

file(GLOB_RECURSE ${PROJECT_NAME}_CLI_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/cli/*.cpp)

add_executable(${PROJECT_NAME}-cli ${${PROJECT_NAME}_CLI_SOURCES})
target_link_libraries(${PROJECT_NAME}-cli ${PROJECT_NAME} Boost::system)
target_compile_features(${PROJECT_NAME}-cli PUBLIC cxx_std_20)
