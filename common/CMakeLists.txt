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

# This produces the gtfo_common.so shared library.
# You may install it to /usr/local/lib by adding "-DCMAKE_INSTALL_PREFIX=/usr/local" to your cmake command, then "make install".
# Alternatively, when building something else, just set your LD_LIBRARY_PATH variable to include pointing to its directory.a

cmake_minimum_required(VERSION 3.5)
include(CheckSymbolExists)

project(gtfo_common)

set(LIBRARY_NAME "gtfo_common")

set(CMAKE_C_FLAGS_DEBUG "-Werror -Wno-padded -O0 -ggdb3 -maes -msse4.2 -march=native -std=c11 -DDEBUG -D_POSIX_C_SOURCE=200809L")
set(CMAKE_C_FLAGS "-Werror -Wno-padded -Ofast -flto -fno-common -maes -msse4.2 -march=native -std=c11 -D_POSIX_C_SOURCE=200809L")

include_directories("${CMAKE_CURRENT_SOURCE_DIR}/include")
add_library(${LIBRARY_NAME} SHARED
        "${CMAKE_CURRENT_SOURCE_DIR}/src/logger.c"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/sized_buffer.c"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/yaml_helper.c")

install(DIRECTORY DESTINATION gtfo DIRECTORY_PERMISSIONS
        OWNER_WRITE OWNER_READ OWNER_EXECUTE
        GROUP_READ GROUP_EXECUTE
        WORLD_READ WORLD_EXECUTE)

install(FILES
        "include/common/annotations.h/"
        "include/common.h/"
        "include/common/definitions.h"
        "include/common/logger.h"
        "include/common/sized_buffer.h" DESTINATION gtfo/include/)

check_symbol_exists(KVM_VMX_PT_SUPPORTED "linux/kvm.h" HAVE_KVM_VMX_PT)

# If our intel-pt kernel patch has been applied to the kernel
if (HAVE_KVM_VMX_PT)

    include_directories("/usr/local/include/xed")
    target_sources(${LIBRARY_NAME} PRIVATE "src/intel_pt/fastdecode.c" "src/intel_pt/ptxed.c" "src/intel_pt/pt_cpu.c" "src/intel_pt/pt_cpuid.c")
    target_link_libraries(${LIBRARY_NAME} yaml ssl crypto -lssl -lcrypto /usr/local/lib/libipt.so /usr/local/lib/libxed.so)

    install(FILES
            "include/intel_pt/pt_cpu.h"
            "include/intel_pt/pt_cpuid.h"
            "include/intel_pt/pt_version.h" DESTINATION gtfo/include/)

endif ()

set_target_properties(${LIBRARY_NAME} PROPERTIES COMPILE_FLAGS "-DMODULE=${LIBRARY_NAME}")

install(TARGETS ${LIBRARY_NAME}
        LIBRARY DESTINATION lib
        PUBLIC_HEADER DESTINATION include)

# This corrects permissions on gtfo/include messed up by "install(FILES...".
install(DIRECTORY DESTINATION gtfo/include DIRECTORY_PERMISSIONS
        OWNER_WRITE OWNER_READ OWNER_EXECUTE
        GROUP_READ GROUP_EXECUTE
        WORLD_READ WORLD_EXECUTE)

# Avoid cmake error from attempting to build gtfo_common.so twice due to an add_subdirectory of this CMakeLists.txt file into another.
if (NOT TARGET gtfo_common)
    add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/../../../../common" "${CMAKE_CURRENT_SOURCE_DIR}/../../../../common/build")
endif ()
  
