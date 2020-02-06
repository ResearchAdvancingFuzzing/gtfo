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
  "${CMAKE_CURRENT_SOURCE_DIR}/../../nocturne/include/"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../nocturne/kvm/include/"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../nocturne/plugins/include/"
  "${CMAKE_CURRENT_SOURCE_DIR}/nocturne/include"
)

# add test_runner's source and compile it
file(GLOB OOZE_SOURCE ooze/src/*.c tap/src/*.c testfile/src/*.c)
add_executable(ooze_tap ${OOZE_SOURCE})

file(GLOB ANALYSIS_SOURCE analysis/src/*.c tap/src/*.c testfile/src/*.c)
add_executable(analysis_tap ${ANALYSIS_SOURCE})

file(GLOB JIG_SOURCE jig/src/*.c tap/src/*.c testfile/src/*.c)
add_executable(jig_tap ${JIG_SOURCE})

set(
  NOCTURNE_PATH
  "${CMAKE_CURRENT_SOURCE_DIR}/../../nocturne"
)

set(
  NOCTURNE_SOURCE
  "${NOCTURNE_PATH}/kvm/src/kvmcore/vcpu.c"
  "${NOCTURNE_PATH}/kvm/src/kvmcore/vm.c"
  "${NOCTURNE_PATH}/kvm/src/kvmcore/engine.c"
  "${NOCTURNE_PATH}/kvm/src/kvmcore/emu_devices/dummy_device.c"
  "${NOCTURNE_PATH}/kvm/src/serialization/vcpu_serialize.c"
  "${NOCTURNE_PATH}/kvm/src/deserialization/vcpu_deserialize.c"
  "${NOCTURNE_PATH}/kvm/src/serialization/vm_serialize.c"
  "${NOCTURNE_PATH}/kvm/src/deserialization/vm_deserialize.c"
  "${NOCTURNE_PATH}/kvm/src/nocturne.c"
)

set(
  NOCTURNE_KVM_TAP_SOURCE
  "${CMAKE_CURRENT_SOURCE_DIR}/tap/src/tap.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/nocturne/src/kvm_vcpu_tap.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/nocturne/src/kvm_vcpu_record_tap.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/nocturne/src/kvm_vcpu_snapshot_tap.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/nocturne/src/kvm_vm_record_tap.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/nocturne/src/kvm_vm_tap.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/nocturne/src/kvm_vm_snapshot_tap.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/nocturne/src/kvm_vm_serialization_tap.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/nocturne/src/kvm_engine_tap.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/nocturne/src/breakpoint_single_step_tap.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/nocturne/src/nocturne_tap.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/nocturne/src/build_test_vm.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/nocturne/src/main.c"
)

check_symbol_exists(KVM_VMX_PT_SUPPORTED "linux/kvm.h" HAVE_KVM_VMX_PT)
if (HAVE_KVM_VMX_PT)
	set(
	  NOCTURNE_KVM_TAP_SOURCE
	  ${NOCTURNE_KVM_TAP_SOURCE}
	  "${CMAKE_CURRENT_SOURCE_DIR}/nocturne/src/intel_pt_tap.c"
	  "${CMAKE_CURRENT_SOURCE_DIR}/nocturne/src/kvm_vcpu_pt_tap.c"
	)
	file(
	  COPY ${CMAKE_CURRENT_SOURCE_DIR}/nocturne/testfiles/intel_pt_execution_one_expected_packet_decode.txt
	  DESTINATION ${CMAKE_CURRENT_BINARY_DIR}
	)
	file(
	  COPY ${CMAKE_CURRENT_SOURCE_DIR}/nocturne/testfiles/intel_pt_execution_multi_expected_packet_decode.txt
	  DESTINATION ${CMAKE_CURRENT_BINARY_DIR}
	)
endif()

add_executable(nocturne_kvm_tap  ${NOCTURNE_SOURCE} ${NOCTURNE_KVM_TAP_SOURCE})

add_library(dummy_plugin MODULE "${CMAKE_CURRENT_SOURCE_DIR}/nocturne/src/dummy_plugin.c")
add_library(dummy2_plugin MODULE "${CMAKE_CURRENT_SOURCE_DIR}/nocturne/src/dummy2_plugin.c")
# Avoid cmake error from attempting to build gtfo_common.so twice due to an add_subdirectory of this CMakeLists.txt file into another.
if (NOT TARGET gtfo_common)
  add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/../../common" "${CMAKE_CURRENT_SOURCE_DIR}/../../common/build")
endif()

if(LINUX)
	target_link_libraries(ooze_tap dl)
	target_link_libraries(analysis_tap dl)
	target_link_libraries(jig_tap dl)
	target_link_libraries(nocturne_kvm_tap yaml pthread gtfo_common dl)
endif()
