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

#include "kvm_vm_record_tap.h"

/*
  This file contains unit tests for the kvm_vm_record API.
*/
bool
kvm_vm_record_isequal(kvm_vm_record *r1, kvm_vm_record *r2)
{
	// check flags, can't use memcmp because these are single bit width fields.
	if (
	    r1->flags.boot_cpu_id_present != r2->flags.boot_cpu_id_present ||
	    r1->flags.guest_tss_addr_present != r2->flags.guest_tss_addr_present ||
	    r1->flags.identity_map_addr_present != r2->flags.identity_map_addr_present ||
	    r1->flags.irqchip_enabled != r2->flags.irqchip_enabled ||
	    r1->flags.irq_routing_present != r2->flags.irq_routing_present ||
	    r1->flags.pit_config_present != r2->flags.pit_config_present ||
	    r1->flags.reinject_control_present != r2->flags.reinject_control_present ||
	    r1->flags.xen_hvm_config_present != r2->flags.xen_hvm_config_present ||
	    r1->flags.cmz_list_present != r2->flags.cmz_list_present ||
	    r1->flags.ioeventfd_list_present != r2->flags.ioeventfd_list_present ||
	    r1->flags.irqfd_list_present != r2->flags.irqfd_list_present ||
	    r1->flags.device_list_present != r2->flags.device_list_present ||
	    r1->flags.memory_map_present != r2->flags.memory_map_present ||
	    r1->cmz_count != r2->cmz_count ||
	    r1->ioeventfd_count != r2->ioeventfd_count ||
	    r1->irqfd_count != r2->irqfd_count ||
	    r1->device_count != r2->device_count ||
	    r1->memmap_size != r2->memmap_size) {
		return false;
	}
	if (r1->boot_cpu_id != r2->boot_cpu_id) {
		return false;
	}
	if (r1->guest_tss_addr != r2->guest_tss_addr) {
		return false;
	}
	if (r1->identity_map_addr != r2->identity_map_addr) {
		return false;
	}
	// if irq routing is present and mismatched number of entries
	if (r1->irq_routing) {

		if (!r2->irq_routing) {
			return false;
		}

		if (r1->irq_routing->nr != r2->irq_routing->nr) {
			return false;
		}
		if (r1->irq_routing == r2->irq_routing) {
			return false;
		}
		// if present and matching number of entries, compare memory.

		size_t irq_routing_size = sizeof(struct kvm_irq_routing) + (r1->irq_routing->nr * sizeof(struct kvm_irq_routing_entry));
		if (memcmp(r1->irq_routing, r2->irq_routing, irq_routing_size) != 0) {
			return false;
		}
	}
	if (memcmp(&r1->pit_config, &r2->pit_config, sizeof(struct kvm_pit_config)) != 0) {
		return false;
	}
	if (memcmp(&r1->reinject_control, &r2->reinject_control, sizeof(struct kvm_reinject_control)) != 0) {
		return false;
	}
	if (memcmp(&r1->xen_hvm_config, &r2->xen_hvm_config, sizeof(struct kvm_xen_hvm_config)) != 0) {
		return false;
	}
	if (r1->cmz_count) {
		bool retval;
		TAILQ_COMPARE_FIXEDSIZE(r1->cmz_record_head, r2->cmz_record_head, cmz_record, kvm_coalesced_mmio_zone, zone, retval)
		if (!retval) {
			return false;
		}
	}
	if (r1->ioeventfd_count) {
		bool retval;
		TAILQ_COMPARE_FIXEDSIZE(r1->ioeventfd_record_head, r2->ioeventfd_record_head, ioeventfd_record, kvm_ioeventfd, ioeventfd, retval)
		if (!retval) {
			return false;
		}
	}
	if (r1->irqfd_count) {
		bool retval;
		TAILQ_COMPARE_FIXEDSIZE(r1->irqfd_record_head, r2->irqfd_record_head, irqfd_record, kvm_irqfd, irqfd, retval)
		if (!retval) {
			return false;
		}
	}
	if (r1->device_count) {
		bool retval;
		TAILQ_COMPARE_FIXEDSIZE(r1->device_record_head, r2->device_record_head, device_record, kvm_create_device, device, retval)
		if (!retval) {
			return false;
		}
	}
	if (r1->flags.memory_map_present) {
		if (r1->memmap_size != r2->memmap_size) {
			return false;
		}
		if (!r2->memory_map) {
			return false;
		}
		if (strncmp(r1->memory_map, r2->memory_map, r1->memmap_size) != 0) {
			return false;
		}
	}
	return true;
}

// empty function, used when testing coalesced_mmio_zone functions.
// Test macro requires a function pointer be passed to it.
static void
cmz_helper(__attribute__((unused)) struct kvm_coalesced_mmio_zone *zone)
{
}

static void
test_kvm_vm_record_irqchip_enabled()
{
	kvm_vm_record *s = kvm_vm_record_create();
	kvm_vm_record_irqchip_enabled(s);

	if (s->flags.irqchip_enabled) {
		ok(true, "kvm_vm_record_irqchip_enabled records present flag correctly.");
	} else {
		ok(false, "kvm_vm_record_irqchip records present flag incorrectly.");
	}
	kvm_vm_record_free(s);
}

// tests recording and unrecording of a coalesced mmio zone
static void
test_kvm_vm_record_cmz_list()
{
	kvm_vm_record *s = kvm_vm_record_create();
	// inserts 3 fake coalesced mmio zone records into the kvm_vm_record object using the kvm_vm_record_coalesced_mmio_zone function.
	TEST_TAILQ_RECORD(s, cmz_record_head, cmz_count, cmz_record, cmz_list_present, zone, kvm_coalesced_mmio_zone, 3, kvm_vm_record_coalesced_mmio_zone)
	// removes previously-inserted record from the kvm_vm_record object using kvm_vm_unrecord_coalesced_mmio_zone
	TEST_TAILQ_UNRECORD(s, cmz_count, cmz_list_present, kvm_coalesced_mmio_zone, kvm_vm_unrecord_coalesced_mmio_zone, cmz_helper)
	kvm_vm_record_free(s);
}

static void
ioeventfd_helper(struct kvm_ioeventfd *ioeventfd)
{
	ioeventfd->flags |= KVM_IOEVENTFD_FLAG_DEASSIGN;
}

// tests recording and unrecording of ioventfd_records
static void
test_kvm_vm_record_ioeventfd_list()
{
	kvm_vm_record *s = kvm_vm_record_create();
	// tests recording of 3 ioeventfd_records
	TEST_TAILQ_RECORD(s, ioeventfd_record_head, ioeventfd_count, ioeventfd_record, ioeventfd_list_present, ioeventfd, kvm_ioeventfd, 3, kvm_vm_record_ioeventfd)
	// tests unrecording of all new records. helper is executed before unrecord.
	TEST_TAILQ_UNRECORD(s, ioeventfd_count, ioeventfd_list_present, kvm_ioeventfd, kvm_vm_unrecord_ioeventfd, ioeventfd_helper)

	kvm_vm_record_free(s);
}

static void
irqfd_helper(struct kvm_irqfd *irqfd)
{
	irqfd->flags |= KVM_IRQFD_FLAG_DEASSIGN;
}

// tests recording and unrecording of irqfd_records
static void
test_kvm_vm_record_irqfd_list()
{
	kvm_vm_record *s = kvm_vm_record_create();
	// tests recording of 3 irqfd_records
	TEST_TAILQ_RECORD(s, irqfd_record_head, irqfd_count, irqfd_record, irqfd_list_present, irqfd, kvm_irqfd, 3, kvm_vm_record_irqfd)
	// tests unrecording of all new records. helper is executed before unrecord.
	TEST_TAILQ_UNRECORD(s, irqfd_count, irqfd_list_present, kvm_irqfd, kvm_vm_unrecord_irqfd, irqfd_helper)
	kvm_vm_record_free(s);
}
// tests recording and unrecording of device_records
static void
test_kvm_vm_record_device_list()
{
	kvm_vm_record *s = kvm_vm_record_create();
	// tests recording of 3 device_records
	TEST_TAILQ_RECORD(s, device_record_head, device_count, device_record, device_list_present, device, kvm_create_device, 3, kvm_vm_record_device)
	// free all the new records.
	RECORD_LIST_DESTROY(s->device_record_head, device_record, s->device_count, free)
	kvm_vm_record_free(s);
}

// checks that a new kvm_vm_record object was initialized properly.
void
check_new_kvm_vm_record(kvm_vm_record *r)
{
	if (
	    r->flags.boot_cpu_id_present ||
	    r->flags.guest_tss_addr_present ||
	    r->flags.identity_map_addr_present ||
	    r->flags.irqchip_enabled ||
	    r->flags.irq_routing_present ||
	    r->flags.pit_config_present ||
	    r->flags.reinject_control_present ||
	    r->flags.xen_hvm_config_present ||
	    r->flags.cmz_list_present ||
	    r->flags.ioeventfd_list_present ||
	    r->flags.irqfd_list_present ||
	    r->flags.device_list_present ||
	    r->cmz_count ||
	    r->ioeventfd_count ||
	    r->irqfd_count ||
	    r->device_count ||
	    r->memmap_size) {
		ok(false, "kvm_vm_record struct initialized improperly!");
	} else {
		ok(true, "kvm_vm_record struct initialized properly!");
	}
}

static void
test_kvm_vm_record_constructor()
{
	kvm_vm_record *s = kvm_vm_record_create();
	check_new_kvm_vm_record(s);
	kvm_vm_record_free(s);
}

// creates a fake kvm_vm_record object, filling every possible field and setting every presence flag.
static kvm_vm_record *
create_dummy_kvm_vm_record()
{
	kvm_vm_record *dummy = kvm_vm_record_create();

	dummy->boot_cpu_id       = 0x41414141;
	dummy->guest_tss_addr    = 0x42424242;
	dummy->identity_map_addr = 0x43434343;

	size_t irq_routing_size   = sizeof(struct kvm_irq_routing) + (3 * sizeof(struct kvm_irq_routing_entry));
	dummy->irq_routing        = calloc(1, irq_routing_size);
	dummy->irq_routing->nr    = 3;
	dummy->irq_routing->flags = 0x44444444;
	memset(&dummy->irq_routing->entries[0], 0x45, sizeof(struct kvm_irq_routing_entry));
	memset(&dummy->irq_routing->entries[1], 0x46, sizeof(struct kvm_irq_routing_entry));
	memset(&dummy->irq_routing->entries[2], 0x47, sizeof(struct kvm_irq_routing_entry));

	memset(&dummy->pit_config, 0x4a, sizeof(struct kvm_pit_config));
	memset(&dummy->reinject_control, 0x4b, sizeof(struct kvm_reinject_control));
	memset(&dummy->xen_hvm_config, 0x4c, sizeof(struct kvm_xen_hvm_config));

	// Use our testing macro to insert some record objects into linked lists.
	TEST_TAILQ_RECORD(dummy, ioeventfd_record_head, ioeventfd_count, ioeventfd_record, ioeventfd_list_present, ioeventfd, kvm_ioeventfd, 4, kvm_vm_record_ioeventfd)
	TEST_TAILQ_RECORD(dummy, irqfd_record_head, irqfd_count, irqfd_record, irqfd_list_present, irqfd, kvm_irqfd, 3, kvm_vm_record_irqfd)
	TEST_TAILQ_RECORD(dummy, cmz_record_head, cmz_count, cmz_record, cmz_list_present, zone, kvm_coalesced_mmio_zone, 12, kvm_vm_record_coalesced_mmio_zone)
	TEST_TAILQ_RECORD(dummy, device_record_head, device_count, device_record, device_list_present, device, kvm_create_device, 1, kvm_vm_record_device)

	dummy->memmap_size = 0x80;
	dummy->memory_map  = calloc(1, 0x81);
	memset(dummy->memory_map, 0x4d, 0x80);

	dummy->flags.boot_cpu_id_present       = true;
	dummy->flags.guest_tss_addr_present    = true;
	dummy->flags.identity_map_addr_present = true;
	dummy->flags.irqchip_enabled           = true;
	dummy->flags.irq_routing_present       = true;
	dummy->flags.pit_config_present        = true;
	dummy->flags.reinject_control_present  = true;
	dummy->flags.xen_hvm_config_present    = true;
	dummy->flags.memory_map_present        = true;

	return dummy;
}

// tests copying of a kvm_vm_record object.
static void
test_kvm_vm_record_clone()
{
	kvm_vm_record *orig = create_dummy_kvm_vm_record();
	kvm_vm_record *copy = kvm_vm_record_clone(orig);

	if (!kvm_vm_record_isequal(orig, copy)) {
		ok(false, "kvm_vm_record_copy test failure!");
	} else {
		ok(true, "kvm_vm_record_copy test success!");
	}

	kvm_vm_record_free(orig);
	kvm_vm_record_free(copy);
}

void
test_kvm_vm_record()
{
	diagnostics("Testing kvm_vm_record API.");
	TEST_SUBSTRUCT_FUNC(kvm_vm_record, boot_cpu_id, boot_cpu_id_present, u64, kvm_vm_record_boot_cpu_id)
	TEST_SUBSTRUCT_FUNC(kvm_vm_record, guest_tss_addr, guest_tss_addr_present, u32, kvm_vm_record_guest_tss_addr)
	TEST_SUBSTRUCT_FUNC(kvm_vm_record, identity_map_addr, identity_map_addr_present, u32, kvm_vm_record_identity_map_addr)
	TEST_KVM_PSUBSTRUCT_FUNC(kvm_vm_record, irq_routing, irq_routing_present, kvm_irq_routing, kvm_vm_record_irq_routing)
	TEST_KVM_SUBSTRUCT_FUNC(kvm_vm_record, pit_config, pit_config_present, kvm_pit_config, kvm_vm_record_pit_config)
	TEST_KVM_SUBSTRUCT_FUNC(kvm_vm_record, reinject_control, reinject_control_present, kvm_reinject_control, kvm_vm_record_reinject_control)
	TEST_KVM_SUBSTRUCT_FUNC(kvm_vm_record, xen_hvm_config, xen_hvm_config_present, kvm_xen_hvm_config, kvm_vm_record_xen_hvm_config)

	test_kvm_vm_record_irqchip_enabled();
	test_kvm_vm_record_cmz_list();
	test_kvm_vm_record_ioeventfd_list();
	test_kvm_vm_record_irqfd_list();
	test_kvm_vm_record_device_list();
	test_kvm_vm_record_constructor();
	test_kvm_vm_record_clone();

	diagnostics("kvm_vm_record API tests complete.");
}
