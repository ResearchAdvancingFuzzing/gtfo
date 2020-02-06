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

project(the_fuzz)

set(CMAKE_C_FLAGS_DEBUG "-Werror -Wno-padded -O0 -ggdb3 -maes -msse4.2 -march=native -std=c11 -DDEBUG")
set(CMAKE_C_FLAGS "-Werror -Wno-padded -Ofast -flto -fno-common -maes -msse4.2 -march=native -std=c11")

if ("${CMAKE_C_COMPILER_ID}" STREQUAL "Clang")
  set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fsanitize=address -Weverything -Wno-unknown-warning-option")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Weverything -Wno-unknown-warning-option")
else()
  message(FATAL_ERROR "UNSUPPORTED COMPILER ${CMAKE_C_COMPILER_ID}, exiting.")
  return()
endif()

set(LIB_SUFFIX ".so")
add_definitions(-D_GNU_SOURCE)

include_directories(
	"${CMAKE_CURRENT_SOURCE_DIR}/../ooze/include"
	"${CMAKE_CURRENT_SOURCE_DIR}/../common/include"
	"${CMAKE_CURRENT_SOURCE_DIR}/components/analysis/include"
	"${CMAKE_CURRENT_SOURCE_DIR}/components/jig/include"
)

add_executable(the_fuzz "${CMAKE_CURRENT_SOURCE_DIR}/components/the_fuzz/the_fuzz.c")
set_target_properties(the_fuzz PROPERTIES COMPILE_FLAGS "-DMODULE=the_fuzz")

target_link_libraries(the_fuzz PUBLIC gtfo_common yaml dl)
install(TARGETS the_fuzz DESTINATION bin)

# Avoid cmake error from attempting to build gtfo_common.so twice due to an add_subdirectory of this CMakeLists.txt file into another.
if (NOT TARGET gtfo_common)
  add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/../common" "${CMAKE_CURRENT_SOURCE_DIR}/../common/build")
endif()

# BEGIN Analysis library build rules

set(DEMO_ANALYSIS_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/components/analysis/src/demo_analysis.c")
set(FALK_FILTER_ANALYSIS_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/components/analysis/src/analysis_common.c" "${CMAKE_CURRENT_SOURCE_DIR}/components/analysis/src/falk_filter_analysis.c")
set(AFL_BITMAP_ANALYSIS_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/components/analysis/src/analysis_common.c" "${CMAKE_CURRENT_SOURCE_DIR}/components/analysis/src/afl_bitmap_analysis.c")
set(PT_HASH_ANALYSIS_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/components/analysis/src/pt_hash_analysis.c")

add_library(demo_analysis SHARED ${DEMO_ANALYSIS_SOURCE})
target_link_libraries(demo_analysis PUBLIC gtfo_common)
set_target_properties(demo_analysis PROPERTIES PREFIX "")
set_target_properties(demo_analysis PROPERTIES COMPILE_FLAGS "-DMODULE=demo_analysis")
# demo_analysis is not to be installed.
# install(TARGETS demo_analysis DESTINATION gtfo/analysis)

add_library(falk_filter_analysis SHARED ${FALK_FILTER_ANALYSIS_SOURCE})
target_link_libraries(falk_filter_analysis PUBLIC gtfo_common)
set_target_properties(falk_filter_analysis PROPERTIES PREFIX "")
set_target_properties(falk_filter_analysis PROPERTIES COMPILE_FLAGS "-DMODULE=falk_filter_analysis")
install(TARGETS falk_filter_analysis DESTINATION gtfo/analysis)

add_library(afl_bitmap_analysis SHARED ${AFL_BITMAP_ANALYSIS_SOURCE})
target_link_libraries(afl_bitmap_analysis PUBLIC gtfo_common)
set_target_properties(afl_bitmap_analysis PROPERTIES PREFIX "")
set_target_properties(afl_bitmap_analysis PROPERTIES COMPILE_FLAGS "-DMODULE=afl_bitmap_analysis")
install(TARGETS afl_bitmap_analysis DESTINATION gtfo/analysis)

add_library(pt_hash_analysis SHARED ${PT_HASH_ANALYSIS_SOURCE})
target_link_libraries(pt_hash_analysis PUBLIC gtfo_common)
set_target_properties(pt_hash_analysis PROPERTIES PREFIX "")
set_target_properties(pt_hash_analysis PROPERTIES COMPILE_FLAGS "-DMODULE=pt_hash_analysis")
install(TARGETS pt_hash_analysis DESTINATION gtfo/analysis)

# BEGIN jig build rules
set(DUMMY_JIG_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/components/jig/src/dummy_jig.c")
set(AFL_JIG_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/components/jig/src/afl_jig.c")

add_library(dummy_jig SHARED ${DUMMY_JIG_SOURCE})
target_link_libraries(dummy_jig PUBLIC gtfo_common)
set_target_properties(dummy_jig PROPERTIES PREFIX "")
set_target_properties(dummy_jig PROPERTIES COMPILE_FLAGS "-DMODULE=dummy_jig")
# The dummy_jig is not to be installed. It is just a dummy for internal use.
# install(TARGETS dummy_jig DESTINATION jig)

add_library(afl_jig SHARED ${AFL_JIG_SOURCE})
target_link_libraries(afl_jig PUBLIC gtfo_common)
set_target_properties(afl_jig PROPERTIES PREFIX "")
set_target_properties(afl_jig PROPERTIES COMPILE_FLAGS "-DMODULE=afl_jig")
install(TARGETS afl_jig DESTINATION gtfo/the_fuzz)

