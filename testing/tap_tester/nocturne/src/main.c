// DISTRIBUTION STATEMENT A. Approved for public release. Distribution is unlimited.
//
// This material is based upon work supported by the Department of the Air Force under Air Force Contract No. FA8702-15-D-0001. Any opinions, findings, conclusions or recommendations expressed in this material are those of the author(s) and do not necessarily reflect the views of the Department of the Air Force.
//
// © 2019 Massachusetts Institute of Technology.
//
// Subject to FAR52.227-11 Patent Rights - Ownership by the contractor (May 2014)
//
// The software/firmware is provided to you on an As-Is basis
//
// Delivered to the U.S. Government with Unlimited Rights, as defined in DFARS Part 252.227-7013 or 7014 (Feb 2014). Notwithstanding any copyright notice, U.S. Government rights in this work are defined by DFARS 252.227-7013 or DFARS 252.227-7014 as detailed above. Use of this work other than as specifically authorized by the U.S. Government may violate any copyrights that exist in this work.

#include "kvm_vcpu_record_tap.h"
#include "breakpoint_single_step_tap.h"
#include "build_test_vm.h"
#include "kvm_engine_tap.h"
#include "kvm_vcpu_snapshot_tap.h"
#include "kvm_vcpu_tap.h"
#include "kvm_vm_record_tap.h"
#include "kvm_vm_serialization_tap.h"
#include "kvm_vm_snapshot_tap.h"
#include "kvm_vm_tap.h"
#include "nocturne_tap.h"

#ifdef KVM_VMX_PT_SUPPORTED
#include "intel_pt_tap.h"
#endif

int
main(int argc, char **argv)
{
    // count of total number of tests
    u32 total_tests = 338;
	init_logging();

	// update total test count for plugin tests.
    if (argc > 1) {
        int arg_itr = 1;
        for(; arg_itr < argc; arg_itr++) {
            if (strstr(argv[arg_itr], "breakpoint_single_step.so")) {
                total_tests += 15;
            }
#ifdef KVM_VMX_PT_SUPPORTED
            else if(strstr(argv[arg_itr], "intel_pt.so")) {
                total_tests += 29;
            }
#endif
        }
    }
    setvbuf(stdout, NULL, _IONBF, 0);
	plan(total_tests);
	print_tap_header();
	// test kvm_vcpu_record API
	test_kvm_vcpu_record();
	// test kvm_vcpu_snapshot API
	test_kvm_vcpu_snapshot();
	// test kvm_vcpu API
	test_kvm_vcpu();
	// test kvm_vm_record API
	test_kvm_vm_record();
	// test kvm_vm_snapshot API
	test_kvm_vm_snapshot();

	char * s_vm_path = build_paged_protected_mode_x86_test_vm();

	// rename serialized test vm.
	// a race condition exists between this dirname and the serialized vm dir created in the
	// test_kvm_vm_serialization unit tests.
	rename(s_vm_path, "s_test_vm");
	rmrf(s_vm_path);
	free(s_vm_path);

	s_vm_path = "s_test_vm";

    // test serialization and deserialization of VMs
    test_kvm_vm_serialization(s_vm_path);
    // test kvm_vm API
    test_kvm_vm(s_vm_path);
    // test kvm engine using mock plugins.
    test_kvm_engine(s_vm_path);
    // test kvm_manager API
    test_nocturne(s_vm_path);

	// 1st argument is assumed to be a path to a serialized vm to use for testing.
	if (argc > 1) {
        int arg_itr = 1;
        for(; arg_itr < argc; arg_itr++) {
            if (strstr(argv[arg_itr], "breakpoint_single_step.so")) {
                test_breakpoint_single_step_plugin(s_vm_path, argv[arg_itr]);
            }
#ifdef KVM_VMX_PT_SUPPORTED
            else if(strstr(argv[arg_itr], "intel_pt.so")) {
                test_intel_pt_plugin(s_vm_path, argv[arg_itr]);
            }
#endif
        }
	}
	rmrf(s_vm_path);
}
