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
project(ooze)

set(STRATEGY_NAME "det_four_byte_drop")

set(CMAKE_C_FLAGS_DEBUG "-Werror -Wno-padded -O0 -ggdb3 -maes -msse4.2 -march=native -std=c11 -DDEBUG")
set(CMAKE_C_FLAGS "-Werror -Wno-padded -Ofast -flto -fno-common -maes -msse4.2 -march=native -std=c11")

if ("${CMAKE_C_COMPILER_ID}" STREQUAL "Clang")
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fsanitize=address -Weverything -Wno-unknown-warning-option")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Weverything -Wno-unknown-warning-option")
elseif ("${CMAKE_C_COMPILER_ID}" STREQUAL "AppleClang")
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fsanitize=address -Weverything -Wno-unknown-warning-option")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Weverything -Wno-unknown-warning-option")
elseif ("${CMAKE_C_COMPILER_ID}" STREQUAL "GNU")
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -Wall -Wextra -Wno-unknown-pragmas")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wno-unknown-pragmas")
else ()
    message(FATAL_ERROR "UNSUPPORTED COMPILER ${CMAKE_C_COMPILER_ID}, exiting.")
    return()
endif ()

if (UNIX AND NOT APPLE)
    set(LINUX TRUE)
endif ()

if (APPLE)
    set(LIB_SUFFIX ".dylib")
elseif (CYGWIN)
    set(LIB_SUFFIX ".dll")
elseif (LINUX)
    set(LIB_SUFFIX ".so")
    add_definitions(-D_GNU_SOURCE)
endif ()

add_library(${STRATEGY_NAME} SHARED ${MUTATE_SRC} ${STRATEGY_SRC} "${STRATEGY_NAME}.c"
        ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../common/src/yaml_helper.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../common/src/yaml_decoder.c)

target_link_libraries(${STRATEGY_NAME} PUBLIC yaml)

set_target_properties(${STRATEGY_NAME} PROPERTIES PREFIX "")
set_target_properties(${STRATEGY_NAME} PROPERTIES COMPILE_FLAGS "-DMODULE=${STRATEGY_NAME}")
install(TARGETS ${STRATEGY_NAME} DESTINATION gtfo/ooze)

if (NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_custom_command(TARGET ${STRATEGY_NAME} POST_BUILD COMMAND strip -x ${STRATEGY_NAME}${LIB_SUFFIX})
endif ()

# Avoid cmake error from attempting to build gtfo_common.so twice due to an add_subdirectory of this CMakeLists.txt file into another.
if (NOT TARGET gtfo_common)
    add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/../../../../../common" "${CMAKE_CURRENT_SOURCE_DIR}/../../../../../common/build")
endif ()
