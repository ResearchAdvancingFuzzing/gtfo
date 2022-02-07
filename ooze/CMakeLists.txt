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

file(GLOB MUTATION_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/strategies/src/mutations/*.c")
include_directories("${CMAKE_CURRENT_SOURCE_DIR}/include" "${CMAKE_CURRENT_SOURCE_DIR}/strategies/include" "${CMAKE_CURRENT_SOURCE_DIR}/../common/include")

install(DIRECTORY DESTINATION gtfo DIRECTORY_PERMISSIONS
        OWNER_WRITE OWNER_READ OWNER_EXECUTE
        GROUP_READ GROUP_EXECUTE
        WORLD_READ WORLD_EXECUTE)

set(MUTATE_SRC "${CMAKE_CURRENT_SOURCE_DIR}/strategies/src/mutations/mutate.c")
set(STRATEGY_SRC "${CMAKE_CURRENT_SOURCE_DIR}/strategies/src/strategy.c")
set(PRNG_SRC "${CMAKE_CURRENT_SOURCE_DIR}/strategies/src/prng.c")
set(DICTIONARY_SRC "${CMAKE_CURRENT_SOURCE_DIR}/strategies/src/dictionary.c")
set(AFL_SRC "${CMAKE_CURRENT_SOURCE_DIR}/strategies/src/afl.c")

set(STRATEGIES
        ${CMAKE_CURRENT_SOURCE_DIR}/strategies/src/strategies/afl_arith
        ${CMAKE_CURRENT_SOURCE_DIR}/strategies/src/strategies/afl_bit_flip
        ${CMAKE_CURRENT_SOURCE_DIR}/strategies/src/strategies/afl_dictionary
        ${CMAKE_CURRENT_SOURCE_DIR}/strategies/src/strategies/afl_dictionary_insert
        ${CMAKE_CURRENT_SOURCE_DIR}/strategies/src/strategies/afl_dictionary_overwrite
        ${CMAKE_CURRENT_SOURCE_DIR}/strategies/src/strategies/afl_havoc
        ${CMAKE_CURRENT_SOURCE_DIR}/strategies/src/strategies/afl_interesting
        ${CMAKE_CURRENT_SOURCE_DIR}/strategies/src/strategies/det_bit_flip
        ${CMAKE_CURRENT_SOURCE_DIR}/strategies/src/strategies/det_byte_add
        ${CMAKE_CURRENT_SOURCE_DIR}/strategies/src/strategies/det_byte_arith
        ${CMAKE_CURRENT_SOURCE_DIR}/strategies/src/strategies/det_byte_dec
        ${CMAKE_CURRENT_SOURCE_DIR}/strategies/src/strategies/det_byte_drop
        ${CMAKE_CURRENT_SOURCE_DIR}/strategies/src/strategies/det_byte_flip
        ${CMAKE_CURRENT_SOURCE_DIR}/strategies/src/strategies/det_byte_inc
        ${CMAKE_CURRENT_SOURCE_DIR}/strategies/src/strategies/det_byte_ins
        ${CMAKE_CURRENT_SOURCE_DIR}/strategies/src/strategies/det_byte_interesting
        ${CMAKE_CURRENT_SOURCE_DIR}/strategies/src/strategies/det_byte_subtract
        ${CMAKE_CURRENT_SOURCE_DIR}/strategies/src/strategies/det_four_bit_flip
        ${CMAKE_CURRENT_SOURCE_DIR}/strategies/src/strategies/det_four_byte_arith_be
        ${CMAKE_CURRENT_SOURCE_DIR}/strategies/src/strategies/det_four_byte_arith_le
        ${CMAKE_CURRENT_SOURCE_DIR}/strategies/src/strategies/det_four_byte_dec_be
        ${CMAKE_CURRENT_SOURCE_DIR}/strategies/src/strategies/det_four_byte_dec_le
        ${CMAKE_CURRENT_SOURCE_DIR}/strategies/src/strategies/det_four_byte_drop
        ${CMAKE_CURRENT_SOURCE_DIR}/strategies/src/strategies/det_four_byte_flip
        ${CMAKE_CURRENT_SOURCE_DIR}/strategies/src/strategies/det_four_byte_inc_be
        ${CMAKE_CURRENT_SOURCE_DIR}/strategies/src/strategies/det_four_byte_inc_le
        ${CMAKE_CURRENT_SOURCE_DIR}/strategies/src/strategies/det_four_byte_ins
        ${CMAKE_CURRENT_SOURCE_DIR}/strategies/src/strategies/det_four_byte_interesting_be
        ${CMAKE_CURRENT_SOURCE_DIR}/strategies/src/strategies/det_four_byte_interesting_le
        ${CMAKE_CURRENT_SOURCE_DIR}/strategies/src/strategies/det_two_bit_flip
        ${CMAKE_CURRENT_SOURCE_DIR}/strategies/src/strategies/det_two_byte_arith_be
        ${CMAKE_CURRENT_SOURCE_DIR}/strategies/src/strategies/det_two_byte_arith_le
        ${CMAKE_CURRENT_SOURCE_DIR}/strategies/src/strategies/det_two_byte_dec_be
        ${CMAKE_CURRENT_SOURCE_DIR}/strategies/src/strategies/det_two_byte_dec_le
        ${CMAKE_CURRENT_SOURCE_DIR}/strategies/src/strategies/det_two_byte_drop
        ${CMAKE_CURRENT_SOURCE_DIR}/strategies/src/strategies/det_two_byte_flip
        ${CMAKE_CURRENT_SOURCE_DIR}/strategies/src/strategies/det_two_byte_inc_be
        ${CMAKE_CURRENT_SOURCE_DIR}/strategies/src/strategies/det_two_byte_inc_le
        ${CMAKE_CURRENT_SOURCE_DIR}/strategies/src/strategies/det_two_byte_ins
        ${CMAKE_CURRENT_SOURCE_DIR}/strategies/src/strategies/det_two_byte_interesting_be
        ${CMAKE_CURRENT_SOURCE_DIR}/strategies/src/strategies/det_two_byte_interesting_le
        ${CMAKE_CURRENT_SOURCE_DIR}/strategies/src/strategies/nop
        ${CMAKE_CURRENT_SOURCE_DIR}/strategies/src/strategies/rand_byte_ins
        ${CMAKE_CURRENT_SOURCE_DIR}/strategies/src/strategies/rand_byte_replace
        ${CMAKE_CURRENT_SOURCE_DIR}/strategies/src/strategies/restrict_bytes
        ${CMAKE_CURRENT_SOURCE_DIR}/strategies/src/strategies/sage_test
        ${CMAKE_CURRENT_SOURCE_DIR}/strategies/src/strategies/zero)


foreach (STRATEGY_DIR ${STRATEGIES})

    if (NOT TARGET ${STRATEGY_DIR})
        add_subdirectory(${STRATEGY_DIR})
    endif ()

    # This is a hack, we need a cleaner way to get the strategy name
    string(REPLACE "/" ";" STRATEGY_DIR_LIST ${STRATEGY_DIR})
    list(GET STRATEGY_DIR_LIST -1 STRATEGY_NAME)
    # End hack
    string(TOUPPER "${STRATEGY_NAME}_IS_MASTER" MASTER_NAME)
    # This is used to specify which strategy is the top-level strategy.
    # In doing so, we specify which strategy object the get_fuzzing_strategy function should populate.
    target_compile_definitions(${STRATEGY_NAME} PRIVATE ${MASTER_NAME}=1)

endforeach (STRATEGY_DIR)

if (NOT TARGET gtfo_common)
    add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/../common" "${CMAKE_CURRENT_SOURCE_DIR}/../common/build")
endif ()
