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

#include "kvm_vcpu_snapshot_tap.h"

/*
  This file contains unit tests for the kvm_vcpu_snapshot API.
*/
bool
kvm_vcpu_snapshot_isequal(kvm_vcpu_snapshot *s1, kvm_vcpu_snapshot *s2)
{
	if (
	    s1->flags.regs_present != s2->flags.regs_present ||
	    s1->flags.sregs_present != s2->flags.sregs_present ||
	    s1->flags.dregs_present != s2->flags.dregs_present ||
	    s1->flags.events_present != s2->flags.events_present ||
	    s1->flags.xsave_present != s2->flags.xsave_present ||
	    s1->flags.xcrs_present != s2->flags.xcrs_present ||
	    s1->flags.fpu_present != s2->flags.fpu_present ||
	    s1->flags.mp_state_present != s2->flags.mp_state_present ||
	    s1->flags.lapic_state_present != s2->flags.lapic_state_present ||
	    s1->flags.freq_present != s2->flags.freq_present ||
	    s1->flags.msrs_present != s2->flags.msrs_present) {
		return false;
	}

	if (s1->flags.regs_present && memcmp(&s1->regs, &s2->regs, sizeof(struct kvm_regs)) != 0) {

		// second bit is reserved and unused, generally always true.
		// we don't care if this bit is different between snaps.
		u64 s1_rflags = s1->regs.rflags | 0x2;
		u64 s2_rflags = s2->regs.rflags | 0x2;
		if (s1_rflags != s2_rflags) {
			return false;
		}
	}
	if (memcmp(&s1->sregs, &s2->sregs, sizeof(struct kvm_sregs)) != 0) {
		return false;
	}
	if (memcmp(&s1->dregs, &s2->dregs, sizeof(struct kvm_debugregs)) != 0) {
		return false;
	}
	if (memcmp(&s1->events, &s2->events, sizeof(struct kvm_vcpu_events)) != 0) {
		return false;
	}
	if (memcmp(&s1->xsave, &s2->xsave, sizeof(struct kvm_xsave)) != 0) {
		return false;
	}
	if (memcmp(&s1->xcrs, &s2->xcrs, sizeof(struct kvm_xcrs)) != 0) {
		return false;
	}
	if (memcmp(&s1->fpu, &s2->fpu, sizeof(struct kvm_fpu)) != 0) {
		return false;
	}
	if (memcmp(&s1->mp_state, &s2->mp_state, sizeof(struct kvm_mp_state)) != 0) {
		return false;
	}
	if (memcmp(&s1->lapic_state, &s2->lapic_state, sizeof(struct kvm_lapic_state)) != 0) {
		return false;
	}
	if (s1->freq != s2->freq) {
		return false;
	}
	if (s1->flags.msrs_present) {

		if (s1->msrs && s2->msrs && s1->msrs->nmsrs == s2->msrs->nmsrs) {
			size_t msrs_size = sizeof(struct kvm_msrs) + (s1->msrs->nmsrs * sizeof(struct kvm_msr_entry));
			if (memcmp(s1->msrs, s2->msrs, msrs_size) != 0) {
				return false;
			}
		} else {
			return false;
		}
	}

	if (kvm_vcpu_record_isequal(&s1->record, &s2->record) == false) {
		return false;
	}
	return true;
}

// checks that a new kvm_vcpu_snapshot struct was created properly.
void
check_new_kvm_vcpu_snapshot(kvm_vcpu_snapshot *s)
{
	kvm_vcpu_snapshot *foo = calloc(1, sizeof(kvm_vcpu_snapshot));

	if (kvm_vcpu_snapshot_isequal(foo, s)) {
		ok(true, "new kvm_vcpu_snapshot object is created correctly.");
	} else {
		ok(false, "new kvm_vcpu_snapshot object is created incorrectly.");
	}
	free(foo);
}

static void
test_kvm_vcpu_snapshot_create_and_free()
{
	kvm_vcpu_snapshot *s = kvm_vcpu_snapshot_create(0);
	check_new_kvm_vcpu_snapshot(s);
	check_new_kvm_vcpu_record(&s->record);
	kvm_vcpu_snapshot_free(s);
}

void
test_kvm_vcpu_snapshot()
{
	diagnostics("Testing kvm_vcpu_snapshot API.");
	test_kvm_vcpu_snapshot_create_and_free();
	diagnostics("kvm_vcpu_snapshot API tests complete.");
}
