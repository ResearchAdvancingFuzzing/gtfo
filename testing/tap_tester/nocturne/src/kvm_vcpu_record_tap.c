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

/*
  This file contains unit tests for the kvm_vcpu_record API.
*/
bool
kvm_vcpu_record_isequal(kvm_vcpu_record *r1, kvm_vcpu_record *r2)
{
	if (!r1 || !r2) {
		return false;
	}

	if (
	    r1->flags.guest_debug_present != r2->flags.guest_debug_present ||
	    r1->flags.tpr_ctl_present != r2->flags.tpr_ctl_present ||
	    r1->flags.vapic_addr_present != r2->flags.vapic_addr_present ||
	    r1->flags.mcg_cap_present != r2->flags.mcg_cap_present ||
	    r1->flags.cpuid_present != r2->flags.cpuid_present ||
	    r1->flags.cpuid2_present != r2->flags.cpuid2_present ||
	    r1->flags.signal_mask_present != r2->flags.signal_mask_present ||
	    r1->flags.clock_paused != r2->flags.clock_paused ||
	    r1->flags.cap_list_present != r2->flags.cap_list_present ||
	    r1->nmsrs != r2->nmsrs ||
	    r1->capability_count != r2->capability_count) {
		return false;
	}

	if (memcmp(&r1->guest_debug, &r2->guest_debug, sizeof(struct kvm_guest_debug)) != 0) {
		return false;
	}
	if (memcmp(&r1->tpr_ctl, &r2->tpr_ctl, sizeof(struct kvm_tpr_access_ctl)) != 0) {
		return false;
	}
	if (memcmp(&r1->vapic_addr, &r2->vapic_addr, sizeof(struct kvm_vapic_addr)) != 0) {
		return false;
	}
	if (r1->mcg_cap != r2->mcg_cap) {
		return false;
	}
	if (memcmp(&r1->mce, &r2->mce, sizeof(struct kvm_x86_mce)) != 0) {
		return false;
	}
	if (r1->flags.cpuid_present) {
		if (r1->cpuid && r2->cpuid && r1->cpuid->nent == r2->cpuid->nent) {
			size_t cpuid_size = sizeof(struct kvm_cpuid) + (r1->cpuid->nent * sizeof(struct kvm_cpuid_entry));
			if (memcmp(r1->cpuid, r2->cpuid, cpuid_size) != 0) {
				return false;
			}
		} else {
			return false;
		}
	}
	if (r1->flags.cpuid2_present) {
		if (r1->cpuid2 && r2->cpuid2 && r1->cpuid2->nent == r2->cpuid2->nent) {
			size_t cpuid2_size = sizeof(struct kvm_cpuid2) + (r1->cpuid2->nent * sizeof(struct kvm_cpuid_entry2));
			if (memcmp(r1->cpuid2, r2->cpuid2, cpuid2_size) != 0) {
				return false;
			}
		} else {
			return false;
		}
	}
	if (r1->flags.signal_mask_present) {
		if (r1->signal_mask && r2->signal_mask && r1->signal_mask->len == r2->signal_mask->len) {
			size_t signal_mask_size = sizeof(struct kvm_signal_mask) + r1->signal_mask->len;
			if (memcmp(r1->signal_mask, r2->signal_mask, signal_mask_size) != 0) {
				return false;
			}
		} else {
			return false;
		}
	}

	if (r1->capability_count) {
		bool retval;
		TAILQ_COMPARE_FIXEDSIZE(
		    r1->cap_record_head,
		    r2->cap_record_head,
		    cap_record,
		    kvm_enable_cap,
		    enable_cap,
		    retval)
		if (retval == false) {
			return false;
		}
	}
	return true;
}

// tests that a new kvm_vcpu_record object was created properly.
void
check_new_kvm_vcpu_record(kvm_vcpu_record *r)
{
	kvm_vcpu_record *f = calloc(1, sizeof(kvm_vcpu_record));

	bool retval = kvm_vcpu_record_isequal(r, f);
	ok(retval, "new_kvm_vcpu_record test.");
	free(f);
}

// fills in a kvm_vcpu_record struct with random bytes, creates substructs.
static kvm_vcpu_record *
create_dummy_kvm_vcpu_record()
{
	kvm_vcpu_record *r = kvm_vcpu_record_create();

	memset(&r->guest_debug, 0x41, sizeof(struct kvm_guest_debug));
	memset(&r->tpr_ctl, 0x42, sizeof(struct kvm_tpr_access_ctl));
	memset(&r->vapic_addr, 0x43, sizeof(struct kvm_vapic_addr));
	r->mcg_cap = 0x4444444444444444;
	memset(&r->mce, 0x45, sizeof(struct kvm_x86_mce));

	u8     cpuid_count = 3;
	size_t cpuid_size  = sizeof(struct kvm_cpuid) + (cpuid_count * sizeof(struct kvm_cpuid_entry));
	r->cpuid           = calloc(1, cpuid_size);
	r->cpuid->nent     = cpuid_count;
	memset(&r->cpuid->entries[0], 0x61, sizeof(struct kvm_cpuid_entry));
	memset(&r->cpuid->entries[1], 0x62, sizeof(struct kvm_cpuid_entry));
	memset(&r->cpuid->entries[2], 0x63, sizeof(struct kvm_cpuid_entry));

	u8     cpuid2_count = 4;
	size_t cpuid2_size  = sizeof(struct kvm_cpuid2) + (cpuid2_count * sizeof(struct kvm_cpuid_entry2));
	r->cpuid2           = calloc(1, cpuid2_size);
	r->cpuid2->nent     = cpuid2_count;
	memset(&r->cpuid2->entries[0], 0x61, sizeof(struct kvm_cpuid_entry2));
	memset(&r->cpuid2->entries[1], 0x62, sizeof(struct kvm_cpuid_entry2));
	memset(&r->cpuid2->entries[2], 0x63, sizeof(struct kvm_cpuid_entry2));
	memset(&r->cpuid2->entries[3], 0x64, sizeof(struct kvm_cpuid_entry2));

	u8     signal_mask_count = 5;
	size_t signal_mask_size  = sizeof(struct kvm_signal_mask) + signal_mask_count;
	r->signal_mask           = calloc(1, signal_mask_size);
	r->signal_mask->len      = signal_mask_count;
	memset(r->signal_mask->sigset, 0x61, 5);

	TEST_TAILQ_RECORD(
	    r,
	    cap_record_head,
	    capability_count,
	    cap_record,
	    cap_list_present,
	    enable_cap,
	    kvm_enable_cap,
	    4,
	    kvm_vcpu_record_capability)

	r->nmsrs                     = 3;
	r->flags.guest_debug_present = true;
	r->flags.tpr_ctl_present     = true;
	r->flags.vapic_addr_present  = true;
	r->flags.mcg_cap_present     = true;
	r->flags.mce_present         = true;
	r->flags.cpuid_present       = true;
	r->flags.cpuid2_present      = true;
	r->flags.signal_mask_present = true;
	r->flags.cap_list_present    = true;

	return r;
}

// tests the kvm_vcpu_record constructor.
static void
test_kvm_vcpu_record_create()
{
	kvm_vcpu_record *r = kvm_vcpu_record_create();
	check_new_kvm_vcpu_record(r);
	kvm_vcpu_record_free(r);
}

// test kvm_vcpu_record_copy function.
static void
test_kvm_vcpu_record_clone()
{
	kvm_vcpu_record *orig = create_dummy_kvm_vcpu_record();
	kvm_vcpu_record *copy = kvm_vcpu_record_clone(orig);

	// copy original
	if (!kvm_vcpu_record_isequal(orig, copy)) {
		ok(false, "kvm_vcpu_record_clone test failure!");
	} else {
		ok(true, "kvm_vcpu_record_clone test success!");
	}
	kvm_vcpu_record_free(copy);
	kvm_vcpu_record_free(orig);
}

// test kvm_vcpu_record_capability function
static void
test_kvm_vcpu_record_capability()
{
	kvm_vcpu_record *r = kvm_vcpu_record_create();

	// run kvm_vcpu_record_capability 4 times with four fake cap_record structs
	TEST_TAILQ_RECORD(
	    r,
	    cap_record_head,
	    capability_count,
	    cap_record,
	    cap_list_present,
	    enable_cap,
	    kvm_enable_cap,
	    4,
	    kvm_vcpu_record_capability)

	kvm_vcpu_record_free(r);
}

// test kvm_vcpu_record_mcg_cap
static void
test_kvm_vcpu_record_mcg_cap()
{
	kvm_vcpu_record *r       = kvm_vcpu_record_create();
	u64              mcg_cap = 0x4141414142424242;

	// record a fake mcg_cap
	kvm_vcpu_record_mcg_cap(r, mcg_cap);
	// flag still set
	if (!r->flags.mcg_cap_present) {
		ok(false, "kvm_vcpu_record_mcg_cap failed to set flag correctly.");
	} else {
		ok(true, "kvm_vcpu_record_mce_cap set flag correctly.");
	}
	// saved correct value
	if (r->mcg_cap == mcg_cap) {
		ok(true, "kvm_vcpu_record_mcg_cap recorded mcg_cap correctly.");
	} else {
		ok(false, "kvm_vcpu_record_mcg_cap recorded mcg_cap incorrectly.");
	}
	kvm_vcpu_record_free(r);
}

// test kvm_vcpu_record_signal_mask function
static void
test_kvm_vcpu_record_signal_mask()
{
	kvm_vcpu_record *r = kvm_vcpu_record_create();

	// create a fake kvm_signal_mask struct
	u8                      signal_mask_count = 5;
	size_t                  signal_mask_size  = sizeof(struct kvm_signal_mask) + signal_mask_count;
	struct kvm_signal_mask *signal_mask       = calloc(1, signal_mask_size);
	signal_mask->len                          = signal_mask_count;
	memset(signal_mask->sigset, 0x61, signal_mask_count);

	// record fake struct
	kvm_vcpu_record_signal_mask(r, signal_mask);

	if (!r->flags.signal_mask_present) {
		ok(false, "kvm_vcpu_record_signal_mask failed to set flag correctly.");
	} else {
		ok(true, "kvm_vcpu_record_signal_mask set flag correctly.");
	}
	if (!memcmp(r->signal_mask, signal_mask, signal_mask_size)) {
		ok(true, "kvm_vcpu_record_signal_mask recorded signal_mask correctly.");
	} else {
		ok(false, "kvm_vcpu_record_signal_mask recorded signal_mask incorrectly.");
	}

	kvm_vcpu_record_free(r);
	free(signal_mask);
}

static void
test_kvm_vcpu_record_nmsrs()
{
	kvm_vcpu_record *r    = kvm_vcpu_record_create();
	struct kvm_msrs *msrs = calloc(1, sizeof(struct kvm_msrs));
	msrs->nmsrs           = 4;

	kvm_vcpu_record_nmsrs(r, msrs);

	if (r->nmsrs != 4) {
		ok(false, "kvm_vcpu_record_nmsrs failed to record the correct number of msrs!");
	} else {
		ok(true, "kvm_vcpu_record_nmsrs recorded the correct number of msrs!");
	}
	free(msrs);
	kvm_vcpu_record_free(r);
}

void
test_kvm_vcpu_record()
{
	diagnostics("Beginning kvm_vcpu_record API tests.");
	test_kvm_vcpu_record_create();
	test_kvm_vcpu_record_clone();
	test_kvm_vcpu_record_capability();
	TEST_VCPU_RECORD_SUBSTRUCT_FIXEDSIZE(kvm_guest_debug, guest_debug, guest_debug_present, kvm_vcpu_record_guest_debug)
	TEST_VCPU_RECORD_SUBSTRUCT_FIXEDSIZE(kvm_tpr_access_ctl, tpr_ctl, tpr_ctl_present, kvm_vcpu_record_tpr_ctl)
	TEST_VCPU_RECORD_SUBSTRUCT_FIXEDSIZE(kvm_vapic_addr, vapic_addr, vapic_addr_present, kvm_vcpu_record_vapic_addr)
	test_kvm_vcpu_record_mcg_cap();
	TEST_VCPU_RECORD_SUBSTRUCT_VARSIZE(kvm_cpuid, cpuid, cpuid_present, nent, kvm_cpuid_entry, entries, 3, kvm_vcpu_record_cpuid)
	TEST_VCPU_RECORD_SUBSTRUCT_VARSIZE(kvm_cpuid2, cpuid2, cpuid2_present, nent, kvm_cpuid_entry2, entries, 3, kvm_vcpu_record_cpuid2)
	test_kvm_vcpu_record_signal_mask();
	TEST_VCPU_RECORD_SUBSTRUCT_FIXEDSIZE(kvm_x86_mce, mce, mce_present, kvm_vcpu_record_mce)
	test_kvm_vcpu_record_nmsrs();
	diagnostics("Finished testing kvm_vcpu_record API.");
}
