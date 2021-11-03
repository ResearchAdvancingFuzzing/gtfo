# DISTRIBUTION STATEMENT A. Approved for public release. Distribution is unlimited.
#
# This material is based upon work supported by the Department of the Air Force under Air Force Contract No. FA8702-15-D-0001. Any opinions, findings, conclusions or recommendations expressed in this material are those of the author(s) and do not necessarily reflect the views of the Department of the Air Force.
#
# © 2019 Massachusetts Institute of Technology.
# 
# Subject to FAR52.227-11 Patent Rights - Ownership by the contractor (May 2014)
# 
# The software/firmware is provided to you on an As-Is basis
# 
# Delivered to the U.S. Government with Unlimited Rights, as defined in DFARS Part 252.227-7013 or 7014 (Feb 2014). Notwithstanding any copyright notice, U.S. Government rights in this work are defined by DFARS 252.227-7013 or DFARS 252.227-7014 as detailed above. Use of this work other than as specifically authorized by the U.S. Government may violate any copyrights that exist in this work.

cmake_minimum_required(VERSION 3.5)
include(CheckSymbolExists)

project(tap_tester)

set(CMAKE_C_FLAGS_DEBUG "-Werror -Wno-padded -O0 -ggdb3 -maes -msse4.2 -march=native -std=c11 -DDEBUG")
set(CMAKE_C_FLAGS "-Werror -Wno-padded -O0 -fno-common -maes -msse4.2 -march=native -std=c11")

if ("${CMAKE_C_COMPILER_ID}" STREQUAL "Clang")
  set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fsanitize=address -Weverything -Wno-unknown-warning-option")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Weverything -Wno-unknown-warning-option")
else()
  message(FATAL_ERROR "UNSUPPORTED COMPILER ${CMAKE_C_COMPILER_ID}, exiting.")
  return()
endif()

if(UNIX AND NOT APPLE)
	set(LINUX TRUE)
endif()

if(APPLE)
	set(LIB_SUFFIX ".dylib")
elseif(CYGWIN)
	set(LIB_SUFFIX ".dll")
elseif(LINUX)
	set(LIB_SUFFIX ".so")
	add_definitions(-D_GNU_SOURCE)
endif()

include_directories(
  "${CMAKE_CURRENT_SOURCE_DIR}/tap/include"
  "${CMAKE_CURRENT_SOURCE_DIR}/testfile/include"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../ooze/include"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../the_fuzz/components/analysis/include"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../the_fuzz/components/jig/include"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../common/include"
)

# add test_runner's source and compile it
file(GLOB OOZE_SOURCE ooze/src/*.c tap/src/*.c testfile/src/*.c)
add_executable(ooze_tap ${OOZE_SOURCE})

file(GLOB ANALYSIS_SOURCE analysis/src/*.c tap/src/*.c testfile/src/*.c)
add_executable(analysis_tap ${ANALYSIS_SOURCE})

file(GLOB JIG_SOURCE jig/src/*.c tap/src/*.c testfile/src/*.c)
add_executable(jig_tap ${JIG_SOURCE})


# Avoid cmake error from attempting to build gtfo_common.so twice due to an add_subdirectory of this CMakeLists.txt file into another.
if (NOT TARGET gtfo_common)
  add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/../../common" "${CMAKE_CURRENT_SOURCE_DIR}/../../common/build")
endif()

if(LINUX)
	target_link_libraries(ooze_tap dl)
	target_link_libraries(analysis_tap dl)
	target_link_libraries(jig_tap dl)
endif()
