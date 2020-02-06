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

#include "kvm_vm_snapshot_tap.h"

/*
  This file contains unit tests for the kvm_vm_snapshot API.
  see kvm_vm_serialization_tap.c and kvm_vm_tap.c for more pragmatic tests.
*/

static bool
patch_point_isequal(patch_point *p1, patch_point *p2)
{
	if (
	    p1->paddr != p2->paddr ||
	    p1->size != p2->size ||
	    !p1->orig_bytes ||
	    !p2->orig_bytes ||
	    !p1->patch ||
	    !p2->patch ||
	    memcmp(p1->orig_bytes, p2->orig_bytes, p1->size) != 0 ||
	    memcmp(p1->patch, p2->patch, p1->size) != 0) {
		return false;
	}
	return true;
}
static bool
hook_point_isequal(hook_point *h1, hook_point *h2)
{
	if (!patch_point_isequal(h1->patch, h2->patch)) {
		return false;
	}
	if (h1->hook_func != h2->hook_func) {
		return false;
	}
	return true;
}

bool
kvm_vm_snapshot_isequal(kvm_vm_snapshot *s1, kvm_vm_snapshot *s2)
{
	if (!kvm_vm_record_isequal(&s1->record, &s2->record)) {
		return false;
	}
	if (
	    s1->flags.pit_state2_present != s2->flags.pit_state2_present ||
	    s1->flags.pic_master_present != s2->flags.pic_master_present ||
	    s1->flags.pic_slave_present != s2->flags.pic_slave_present ||
	    s1->flags.ioapic_present != s2->flags.ioapic_present ||
	    s1->flags.clock_data_present != s2->flags.clock_data_present ||
	    s1->flags.emu_devices_present != s2->flags.emu_devices_present ||
	    s1->memory_snapshot_count != s2->memory_snapshot_count ||
	    s1->emu_device_count != s2->emu_device_count ||
	    s1->patch_point_count != s2->patch_point_count ||
	    s1->stop_point_count != s2->stop_point_count ||
	    s1->hook_point_count != s2->hook_point_count) {
		return false;
	}

	// check for content mismatch
	if (memcmp(&s1->pit_state2, &s2->pit_state2, sizeof(struct kvm_pit_state2)) != 0) {

		// the count_load_times subfields are allowed to mismatch between snapshots.
		bool count_load_times_match = true;
		int  i                      = 0;
		for (; i < 3; i++) {
			if (s1->pit_state2.channels[i].count_load_time != s2->pit_state2.channels[i].count_load_time) {
				count_load_times_match = false;
				break;
			}
		}
		// if all count_load_times subfields match but the structs do not match, then
		// the structs truly do not match each other.
		if (count_load_times_match) {
			return false;
		}
	}

	if (memcmp(&s1->pic_master, &s2->pic_master, sizeof(struct kvm_irqchip)) != 0) {
		return false;
	}
	if (memcmp(&s1->pic_slave, &s2->pic_slave, sizeof(struct kvm_irqchip)) != 0) {
		return false;
	}
	if (memcmp(&s1->ioapic, &s2->ioapic, sizeof(struct kvm_irqchip)) != 0) {

		// irr register is allowed to mismatch.
		if (s1->ioapic.chip.ioapic.irr == s2->ioapic.chip.ioapic.irr) {
			return false;
		}
	}
	// Don't check clock_data, it will never match.

	if (s1->memory_snapshot_count) {

		memory_region_record *itr1 = TAILQ_FIRST(&s1->memory_snapshot_record_head);
		memory_region_record *itr2 = TAILQ_FIRST(&s2->memory_snapshot_record_head);
		if (!itr1 || !itr2) {
			return false;
		}
		while (itr1 && itr2) {
			if (
			    itr1->region.slot != itr2->region.slot ||
			    itr1->region.flags != itr2->region.flags ||
			    itr1->region.memory_size != itr2->region.memory_size ||
			    itr1->region.guest_phys_addr != itr2->region.guest_phys_addr ||
			    memcmp(
			        (void *)itr1->region.userspace_addr,
			        (void *)itr2->region.userspace_addr,
			        itr1->region.memory_size) != 0) {
				return false;
			}
			itr1 = TAILQ_NEXT(itr1, record_list);
			itr2 = TAILQ_NEXT(itr2, record_list);
		}
		if (itr1 != NULL) {
			return false;
		}
		if (itr2 != NULL) {
			return false;
		}
	}
	if (s1->flags.emu_devices_present) {
		if (s1->emu_device_count != s2->emu_device_count) {
			return false;
		}
	}
	if (s1->patch_point_count) {
		patch_point *itr1 = RECORD_LIST_FIRST(s1->snapshot_patch_point_head);
		patch_point *itr2 = RECORD_LIST_FIRST(s2->snapshot_patch_point_head);

		if (!itr1 || !itr2) {
			return false;
		}
		while (itr1 && itr2) {
			if (!patch_point_isequal(itr1, itr2)) {
				return false;
			}
			itr1 = RECORD_LIST_NEXT(itr1);
			itr2 = RECORD_LIST_NEXT(itr2);
		}
		if (itr1 != NULL || itr2 != NULL) {
			return false;
		}
	}
	if (s1->stop_point_count) {
		patch_point *itr1 = RECORD_LIST_FIRST(s1->snapshot_stop_point_head);
		patch_point *itr2 = RECORD_LIST_FIRST(s2->snapshot_stop_point_head);

		if (!itr1 || !itr2) {
			return false;
		}
		while (itr1 && itr2) {
			if (!patch_point_isequal(itr1, itr2)) {
				return false;
			}
			itr1 = RECORD_LIST_NEXT(itr1);
			itr2 = RECORD_LIST_NEXT(itr2);
		}
		if (itr1 != NULL || itr2 != NULL) {
			return false;
		}
	}
	if (s1->hook_point_count) {
		hook_point *itr1 = RECORD_LIST_FIRST(s1->snapshot_hook_point_head);
		hook_point *itr2 = RECORD_LIST_FIRST(s2->snapshot_hook_point_head);

		if (!itr1 || !itr2) {
			return false;
		}
		while (itr1 && itr2) {
			if (!hook_point_isequal(itr1, itr2)) {
				return false;
			}
			itr1 = RECORD_LIST_NEXT(itr1);
			itr2 = RECORD_LIST_NEXT(itr2);
		}
		if (itr1 != NULL || itr2 != NULL) {
			return false;
		}
	}

	return true;
}

// check that a new kvm_vm_snapshot object was initialized correctly.
void
check_new_kvm_vm_snapshot(kvm_vm_snapshot *s, u64 id)
{
	if (
	    id != s->id ||
	    s->flags.pit_state2_present ||
	    s->flags.pic_master_present ||
	    s->flags.pic_slave_present ||
	    s->flags.ioapic_present ||
	    s->flags.clock_data_present ||
	    s->flags.emu_devices_present ||
	    s->memory_snapshot_count ||
	    s->emu_device_count ||
	    s->patch_point_count ||
	    s->stop_point_count ||
	    s->hook_point_count) {
		ok(false, "snapshot id or flags mismatch");
	} else {
		ok(true, "snapshot id and flags match");
	}
}

// tests creation and freeing of kvm_vm_snapshot objects.
static void
test_kvm_vm_snapshot_create_and_free()
{
	u64 id = 0;

	kvm_vm_snapshot *s = kvm_vm_snapshot_create(id);
	check_new_kvm_vm_snapshot(s, id);
	kvm_vm_snapshot_free(s);
}

static void
test_kvm_vm_snapshot_insert_emu_device()
{
	u64              id = 0;
	kvm_vm_snapshot *s  = kvm_vm_snapshot_create(id);

	emu_device *dummy_device = emu_device_create(DEVICE_TYPE_DUMMY, 0);
	kvm_vm_snapshot_insert_emu_device(s, dummy_device);

	emu_device *emu_device_ptr = RECORD_LIST_FIRST(s->emu_device_snapshot_head);

	if (
	    s->emu_device_count == 1 &&
	    s->flags.emu_devices_present &&
	    emu_device_ptr == dummy_device) {
		ok(true, "kvm_vm_take_snapshot correctly copied an emulated device into a new kvm_vm_snapshot object.");
	} else {
		ok(false, "kvm_vm_take_snapshot failed to correctly copy an emulated device into a new kvm_vm_snapshot object.");
	}

	kvm_vm_snapshot_free(s);
}

void
test_kvm_vm_snapshot()
{
	diagnostics("Testing kvm_vm_snapshot API.");
	test_kvm_vm_snapshot_create_and_free();
	test_kvm_vm_snapshot_insert_emu_device();
	diagnostics("Finished testing the kvm_vm_snapshot API.");
}
