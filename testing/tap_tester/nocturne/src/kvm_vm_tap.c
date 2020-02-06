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

#include "kvm_vm_tap.h"
#include <sys/mman.h>
/*
  This file contains unit tests for the kvm_vm API
*/

// check that a new kvm_vm object was initialized correctly.
void
check_new_kvm_vm(kvm_vm *vm)
{
	if (
	    vm->vcpu_count ||
	    vm->memory_region_count ||
	    vm->snapshot_count ||
	    vm->patch_point_count ||
	    vm->stop_point_count ||
	    vm->hook_point_count ||
	    vm->emu_device_count) {
		ok(false, "new kvm_vm object initialized incorrectly.");
	} else {
		ok(true, "new kvm_vm object initialized correctly.");
	}
	check_new_kvm_vm_record(&vm->record);
}

// test creation of an unrealized vm object.
static void
test_kvm_vm_create_unrealized()
{
	kvm_vm *vm = kvm_vm_create_unrealized();
	check_new_kvm_vm(vm);
	kvm_vm_free(vm);
}

// test creation of a realized kvm_vm object
static void
test_kvm_vm_create()
{
	kvm_vm *vm = kvm_vm_create();
	check_new_kvm_vm(vm);
	kvm_vm_free(vm);
}

// test insertion of a new vcpu.
static void
test_kvm_vm_insert_vcpu()
{
	kvm_vm *vm = kvm_vm_create();
	// create and insert an unrealized vcpu
	kvm_vcpu *vcpu = kvm_vcpu_create_unrealized(0);
	kvm_vm_insert_vcpu(vm, vcpu);

	// get the vcpu back.
	kvm_vcpu *same_vcpu = kvm_vm_get_vcpu_with_id(vm, 0);

	// check vcpu count and that the point we got matches teh pointer we put in.
	if (
	    vm->vcpu_count != 1 ||
	    vcpu != same_vcpu) {
		ok(false, "vcpu not inserted correctly by kvm_vm_insert_vcpu.");
	} else {
		ok(true, "vcpu inserted correctly by kvm_vm_insert_vcpu.");
	}
	kvm_vm_free(vm);

	vm          = kvm_vm_create();
	vcpu        = kvm_vcpu_create(vm->kvm_fd, vm->vm_fd, vm->vcpu_count);
	int vcpu_fd = vcpu->fd;
	kvm_vm_insert_vcpu(vm, vcpu);

	same_vcpu = kvm_vm_get_vcpu_with_fd(vm, vcpu_fd);

	if (
	    vm->vcpu_count != 1 ||
	    vcpu != same_vcpu) {
		ok(false, "vcpu not retrieved correctly by kvm_vm_get_vcpu_with_fd.");
	} else {
		ok(true, "vcpu retrieved correctly by kvm_vm_get_vcpu_with_fd.");
	}

	kvm_vm_free(vm);
}

static void
test_kvm_vm_insert_emu_device()
{
	kvm_vm *  vm   = kvm_vm_create();
	kvm_vcpu *vcpu = kvm_vcpu_create(vm->kvm_fd, vm->vm_fd, vm->vcpu_count);
	kvm_vm_insert_vcpu(vm, vcpu);

	emu_device *dummy_device = emu_device_create(DEVICE_TYPE_DUMMY, 0);
	kvm_vm_insert_emu_device(vm, dummy_device);

	emu_device *emu_device_ptr = RECORD_LIST_FIRST(vm->emu_device_head);

	if (vm->emu_device_count == 1 && dummy_device == emu_device_ptr) {
		ok(true, "Emulated device correctly inserted into kvm_vm object.");
	} else {
		ok(false, "Failed to correctly insert an emulated device into kvm_vm object.");
	}

	u64              snapshot_id = kvm_vm_take_snapshot(vm);
	kvm_vm_snapshot *s           = kvm_vm_get_snapshot_with_id(vm, snapshot_id);

	emu_device_ptr = RECORD_LIST_FIRST(s->emu_device_snapshot_head);

	if (
	    s->emu_device_count == 1 &&
	    s->flags.emu_devices_present &&
	    emu_device_ptr != dummy_device &&
	    !strcmp(emu_device_ptr->name, dummy_device->name) &&
	    emu_device_ptr->type == dummy_device->type &&
	    emu_device_ptr->size == dummy_device->size &&
	    emu_device_ptr->addr == dummy_device->addr &&
	    !memcmp(emu_device_ptr->state, dummy_device->state, dummy_device->size)) {
		ok(true, "kvm_vm_take_snapshot correctly copied an emulated device into a new kvm_vm_snapshot object.");
	} else {
		ok(false, "kvm_vm_take_snapshot failed to correctly copy an emulated device into a new kvm_vm_snapshot object.");
	}

	kvm_vm_free(vm);
}

static void
test_kvm_vm_set_timeout()
{
	kvm_vm *  vm     = kvm_vm_create();
	kvm_vcpu *vcpu_0 = kvm_vcpu_create(vm->kvm_fd, vm->vm_fd, vm->vcpu_count);
	kvm_vm_insert_vcpu(vm, vcpu_0);

	struct timespec duration = {0};

	duration.tv_sec  = 2;
	duration.tv_nsec = 10000000;

	kvm_vm_set_timeout(vm, &duration);

	kvm_vcpu *vcpu_itr = NULL;

	RECORD_LIST_FOREACH(vcpu_itr, vm->kvm_vcpu_head)
	{
		if (vcpu_itr->timeout.duration.tv_sec == 2 &&
		    vcpu_itr->timeout.duration.tv_nsec == 10000000) {
			ok(true, "kvm_vm_set_timeout set tv_sec and tv_nsec fields correctly!");
		} else {
			ok(false, "kvm_vm_set_timeout did not set the tv_sec and tv_nsec fields correctly!");
		}

		if (vcpu_itr->timeout.thread_keepalive) {
			ok(true, "kvm_vm_set_timeout set thread_keepalive correctly!");
		} else {
			ok(false, "kvm_vm_set_timeout did not set thread_keepalive correctly!");
		}

		if (!pthread_mutex_trylock(&vcpu_itr->timeout.vcpu_running_mutex)) {
			ok(true, "Correctly obtained vcpu_running_mutex mutex.");
			pthread_mutex_unlock(&vcpu_itr->timeout.vcpu_running_mutex);
		} else {
			ok(false, "vcpu_running_mutex is incorrectly locked.");
		}

		if (!pthread_mutex_trylock(&vcpu_itr->timeout.hangup_timer_mutex)) {
			ok(true, "Correctly obtained hangup_timer_mutex.");
			pthread_mutex_unlock(&vcpu_itr->timeout.hangup_timer_mutex);
		} else {
			ok(false, "hangup_timer_mutex is incorrectly locked.");
		}
	}

	kvm_vm_free(vm);
}

// test unrealized insertion of a memory region.
static void
test_kvm_vm_insert_userspace_memory_region()
{
	// create a vm and a fake memory region
	kvm_vm *                           vm = kvm_vm_create();
	struct kvm_userspace_memory_region region;
	memset(&region, 0, sizeof(struct kvm_userspace_memory_region));

	region.slot            = 0;
	region.guest_phys_addr = 0;
	region.memory_size     = 0x1000;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wbad-function-cast"
	region.userspace_addr = (uint64_t)mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
#pragma clang diagnostic pop

	// insert fake memory region
	kvm_vm_insert_userspace_memory_region(vm, &region, false);

	// check counter
	if (
	    vm->memory_region_count != 1) {
		ok(false, "memory region not inserted correctly by kvm_vm_insert_userspace_memory_region.");
	} else {
		ok(true, "memory region inserted correctly by kvm_vm_insert_userspace_memory_region.");
	}
	kvm_vm_free(vm);
}

// test kvm_vm_enable_dirty_page_logging api function
static void
test_kvm_vm_enable_dirty_page_logging()
{
	// create a new vm
	kvm_vm *vm = kvm_vm_create();

	// create a memory region
	struct kvm_userspace_memory_region region;
	memset(&region, 0, sizeof(struct kvm_userspace_memory_region));

	region.slot            = 0;
	region.guest_phys_addr = 0;
	region.memory_size     = 0x1000;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wbad-function-cast"
	region.userspace_addr = (uint64_t)mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
#pragma clang diagnostic pop

	// insert new memory region.
	kvm_vm_insert_userspace_memory_region(vm, &region, true);

	kvm_vm_enable_dirty_page_logging(vm);

	// check that dirty logging was enabled correctly for every memory region.
	memory_region_record *itr = NULL;
	TAILQ_FOREACH(itr, &vm->memory_region_record_head, record_list)
	{
		if (!(itr->region.flags & KVM_MEM_LOG_DIRTY_PAGES)) {
			ok(false, "dirty page logging not properly enabled.");
		} else {
			ok(true, "dirty page logging properly enabled.");
		}
	}

	munmap((void *)region.userspace_addr, 0x1000);
	kvm_vm_free(vm);
}
// test insertion of a new kvm_vm_snapshot
static void
test_kvm_vm_insert_snapshot()
{
	kvm_vm *         vm             = kvm_vm_create();
	kvm_vm_snapshot *empty_snapshot = kvm_vm_snapshot_create(0);

	kvm_vm_insert_snapshot(vm, empty_snapshot);

	if (vm->snapshot_count != 1) {
		ok(false, "snapshot incorrectly inserted into vm!");
	} else {
		ok(true, "snapshot correctly inserted into vm!");
	}

	kvm_vm_free(vm);
}

// test freeing of a kvm_vm_snapshot
static void
test_kvm_vm_free_snapshot()
{
	kvm_vm *         vm             = kvm_vm_create();
	kvm_vm_snapshot *empty_snapshot = kvm_vm_snapshot_create(0);

	kvm_vm_insert_snapshot(vm, empty_snapshot);

	kvm_vm_free_snapshot(vm, 0);

	if (vm->snapshot_count != 0) {
		ok(false, "snapshot incorrectly freed from vm!");
	} else {
		ok(true, "snapshot correctly freed from vm!");
	}

	kvm_vm_free(vm);
}

static void
test_kvm_vm_original_snapshot(const char *serialized_vm_dir)
{
	kvm_vm *vm = kvm_vm_deserialize(serialized_vm_dir);
	// take a new snapshot
	u64 snapshot_id = kvm_vm_take_snapshot(vm);

	// snapshot id should be id_of_deserialized_snapshot++.
	if (snapshot_id != 1) {
		ok(false, "new snapshot was not taken correctly!");

	} else {
		ok(true, "new snapshot taken correctly!");
	}

	// get newly taken snapshot.
	kvm_vm_snapshot *snapshot0 = kvm_vm_get_snapshot_with_id(vm, 0);
	kvm_vm_snapshot *snapshot1 = kvm_vm_get_snapshot_with_id(vm, snapshot_id);

	// compare contents of newest snapshot with the snapshot taken after deserialization.
	if (kvm_vm_snapshot_isequal(snapshot0, snapshot1)) {
		ok(true, "new snapshot matches original, deserialized snapshot!");
	} else {
		ok(false, "new snapshot does not match original, deserialized snapshot!");
	}
	kvm_vm_free(vm);
}

// test taking of a new snapshot.
static void
test_kvm_vm_take_snapshot(const char *serialized_vm_dir)
{
	// deserialize the vm snapshot, assign it an id of 0.
	kvm_vm *vm = kvm_vm_deserialize(serialized_vm_dir);
	// take a new snapshot
	u64 snapshot_id = kvm_vm_take_snapshot(vm);

	// snapshot id should be id_of_deserialized_snapshot++.
	if (snapshot_id != 1) {
		ok(false, "new snapshot was not taken correctly!");
	} else {
		ok(true, "new snapshot taken correctly!");
	}

	// get newly taken snapshot.
	kvm_vm_snapshot *snapshot1 = kvm_vm_get_snapshot_with_id(vm, snapshot_id);

	// take another snapshot
	u64 snapshot2_id = kvm_vm_take_snapshot(vm);
	// get pointer
	kvm_vm_snapshot *snapshot2 = kvm_vm_get_snapshot_with_id(vm, snapshot2_id);

	// compare contents of newest snapshot with the snapshot taken after deserialization.
	if (kvm_vm_snapshot_isequal(snapshot1, snapshot2)) {
		ok(true, "duplicate snapshot was taken correctly!");
	} else {
		ok(false, "duplicate snapshot was not taken correctly!");
	}

	kvm_vm_free(vm);
}
// test restoring of a snapshot
static void
test_kvm_vm_restore_snapshot(const char *serialized_vm_dir)
{
	// deserialize
	kvm_vm *vm = kvm_vm_deserialize(serialized_vm_dir);
	// take new snapshot and get pointer.
	u64              snapshot1_id = kvm_vm_take_snapshot(vm);
	kvm_vm_snapshot *snapshot1    = kvm_vm_get_snapshot_with_id(vm, snapshot1_id);

	// restore to newly taken snapshot.
	kvm_vm_restore_snapshot(vm, snapshot1_id);

	if (kvm_vm_record_isequal(&snapshot1->record, &vm->record)) {
		ok(true, "kvm_vm_restore_snapshot restores kvm_vm_record correctly.");
	} else {
		ok(false, "kvm_vm_restore_snapshot does not restore kvm_vm_record correctly.");
	}
	kvm_vm_free(vm);
}

// test snapshot restoration with dirty bitmap enabled.
static void
test_kvm_vm_restore_snapshot_memory(const char *serialized_vm_dir)
{
	// deserialized vm, purge debugging settings and enable dirty page bitmap
	kvm_vm *vm = kvm_vm_deserialize(serialized_vm_dir);

	kvm_vm_clear_guest_debug(vm);
	kvm_vm_enable_dirty_page_logging(vm);

	diagnostics("Checking memory restoration with dirty bitmap enabled.");
	kvm_vm_take_snapshot(vm);

	// launch the vcpu, dirty bitmap only tracks memory that was edited by the vm
	// during execution.
	kvm_vcpu *vcpu = kvm_vm_get_vcpu_with_id(vm, 0);
	IOCTL1(vcpu->fd, KVM_RUN, NULL)

	// restore memory.
	kvm_vm_restore_snapshot(vm, 1);

	kvm_vm_snapshot *s1 = kvm_vm_get_snapshot_with_id(vm, 1);

	memory_region_record *vm_itr = TAILQ_FIRST(&vm->memory_region_record_head);
	memory_region_record *s_itr  = TAILQ_FIRST(&s1->memory_snapshot_record_head);

	// compare working memory of the vm with memory of the snapshot.
	while (vm_itr && s_itr) {
		if (
		    vm_itr->region.slot != s_itr->region.slot ||
		    vm_itr->region.guest_phys_addr != s_itr->region.guest_phys_addr ||
		    vm_itr->region.flags != s_itr->region.flags ||
		    vm_itr->region.memory_size != s_itr->region.memory_size) {
			ok(false, "userspace region configuration mismatch between snapshot and vm.");
		} else {
			ok(true, "userspace region configuration match between snapshot and vm.");
			if (memcmp((void *)vm_itr->region.userspace_addr, (void *)s_itr->region.userspace_addr, vm_itr->region.memory_size) != 0) {
				ok(false, "userspace region content mismatch between snapshot and vm.");
			} else {
				ok(true, "userspace region content match between snapshot and vm.");
			}
		}
		vm_itr = TAILQ_NEXT(vm_itr, record_list);
		s_itr  = TAILQ_NEXT(s_itr, record_list);
	}
	// ensure that all memory regions were checked and that
	// both the vm and the snapshot have the same number of memory regions.
	if (vm_itr == NULL && s_itr == NULL) {
		ok(true, "userspace regions line up correctly between snapshot and vm.");
	} else {
		ok(false, "userspace regions lined up incorrectly between snapshot and vm.");
	}
	diagnostics("Done checking memory restoration with dirty bitmap enabled.");

	kvm_vm_free(vm);
}

// test kvm_vcpu_snapshot API using a real, deserialized snapshot.
static void
test_kvm_vcpu_snapshot_substructs(const char *serialized_vm_dir)
{
	diagnostics("Testing contents of state-recording structures after snapshot restoration.");
	kvm_vm *vm = kvm_vm_deserialize(serialized_vm_dir);

	kvm_vcpu *vcpu = kvm_vm_get_vcpu_with_id(vm, 0);

	test_kvm_vcpu_take_and_restore_snapshot_with_id(vcpu, 0);

	diagnostics("Done testing contents of state-recording structures after snapshot restoration.");
	kvm_vm_free(vm);
}

// run all snapshot tests that require a real deserialized vm snapshot.
static void
test_kvm_vm_take_and_restore_snapshot(const char *serialized_vm_dir)
{
	test_kvm_vm_take_snapshot(serialized_vm_dir);
	test_kvm_vm_original_snapshot(serialized_vm_dir);
	test_kvm_vm_restore_snapshot(serialized_vm_dir);
	test_kvm_vm_restore_snapshot_memory(serialized_vm_dir);
	test_kvm_vcpu_snapshot_substructs(serialized_vm_dir);
}

static void
test_kvm_vm_get_vcpu_with_id()
{
	kvm_vm *vm = kvm_vm_create_unrealized();

	// insert 8 vcpus
	u8 i = 0;
	for (; i < 8; i++) {
		kvm_vcpu *vcpu = kvm_vcpu_create_unrealized(i);
		kvm_vm_insert_vcpu(vm, vcpu);
	}
	// get vcpu with id 4 from vm
	kvm_vcpu *test = kvm_vm_get_vcpu_with_id(vm, 4);

	if (test->id == 4) {
		ok(true, "kvm_vm_get_vcpu_with_id was successful!");
	} else {
		ok(false, "kvm_vm_get_vcpu_With_id was unsuccessful!");
	}

	kvm_vm_free(vm);
}

static void
test_kvm_vm_get_snapshot_with_id()
{
	kvm_vm *vm = kvm_vm_create_unrealized();

	// insert 8 snapshots
	u8 i = 0;
	for (; i < 8; i++) {
		kvm_vm_snapshot *snapshot = kvm_vm_snapshot_create(i);
		kvm_vm_insert_snapshot(vm, snapshot);
	}
	// get snapshot with id 5 from vm
	kvm_vm_snapshot *test = kvm_vm_get_snapshot_with_id(vm, 5);

	if (test->id == 5) {
		ok(true, "kvm_vm_get_snapshot_with_id was successful!");
	} else {
		ok(false, "kvm_vm_get_snapshot_with_id was unsuccessful!");
	}
	kvm_vm_free(vm);
}

static void
test_kvm_vm_clear_guest_debug()
{

	struct kvm_guest_debug empty_guest_debug_struct;
	struct kvm_guest_debug fake_guest_dbg;

	memset(&empty_guest_debug_struct, 0, sizeof(struct kvm_guest_debug));
	memset(&fake_guest_dbg, 0, sizeof(struct kvm_guest_debug));

	// fill in the fake guest_debug structure.
	fake_guest_dbg.arch.debugreg[0] = 0x4141414141414141;
	fake_guest_dbg.arch.debugreg[1] = 0x4141414141414141;
	fake_guest_dbg.arch.debugreg[2] = 0x4141414141414141;
	fake_guest_dbg.arch.debugreg[3] = 0x4141414141414141;
	fake_guest_dbg.arch.debugreg[4] = 0x4141414141414141;
	fake_guest_dbg.arch.debugreg[5] = 0x4141414141414141;
	fake_guest_dbg.arch.debugreg[6] = 0x4141414141414141;
	fake_guest_dbg.arch.debugreg[7] = 0x4141414141414141;
	fake_guest_dbg.control          = 0x42424242;
	fake_guest_dbg.pad              = 0x43434343;

	memset(&empty_guest_debug_struct, 0, sizeof(struct kvm_guest_debug));

	// begin single vcpu, no snapshot test.
	kvm_vm *  vm     = kvm_vm_create();
	kvm_vcpu *vcpu_0 = kvm_vcpu_create(vm->kvm_fd, vm->vm_fd, vm->vcpu_count);
	kvm_vm_insert_vcpu(vm, vcpu_0);

	kvm_vcpu_record_guest_debug(&vcpu_0->record, &fake_guest_dbg);

	kvm_vm_clear_guest_debug(vm);

	if (!memcmp(&vcpu_0->record.guest_debug, &empty_guest_debug_struct, sizeof(struct kvm_guest_debug))) {
		ok(true, "kvm_vm_clear_guest_debug correctly cleared guest debug settings of a single vcpu!");
	} else {
		ok(false, "kvm_vm_clear_guest_debug incorrectly cleared guest debug settings of a single vcpu!");
	}

	kvm_vm_free(vm);

	vm     = kvm_vm_create();
	vcpu_0 = kvm_vcpu_create(vm->kvm_fd, vm->vm_fd, vm->vcpu_count);

	kvm_vm_insert_vcpu(vm, vcpu_0);
	kvm_vcpu_record_guest_debug(&vcpu_0->record, &fake_guest_dbg);

	kvm_vm_take_snapshot(vm);
	kvm_vcpu_snapshot *vcpu_0_s_0 = kvm_vcpu_get_snapshot_with_id(vcpu_0, 0);

	kvm_vm_clear_guest_debug(vm);

	if (
	    !memcmp(&vcpu_0->record.guest_debug, &empty_guest_debug_struct, sizeof(struct kvm_guest_debug)) &&
	    !memcmp(&vcpu_0_s_0->record.guest_debug, &empty_guest_debug_struct, sizeof(struct kvm_guest_debug))) {
		ok(true, "kvm_vm_clear_guest_debug correctly cleared the guest debug settings of a single vcpu with a single vcpu snapshot!");
	} else {
		ok(false, "kvm_vcpu_clear_guest_debug incorrectly cleared the guest debug settings of a single vcpu with a single vcpu snapshot!");
	}

	kvm_vm_free(vm);

	vm     = kvm_vm_create();
	vcpu_0 = kvm_vcpu_create(vm->kvm_fd, vm->vm_fd, vm->vcpu_count);

	kvm_vm_insert_vcpu(vm, vcpu_0);
	kvm_vcpu_record_guest_debug(&vcpu_0->record, &fake_guest_dbg);

	kvm_vm_take_snapshot(vm);
	kvm_vm_take_snapshot(vm);

	vcpu_0_s_0                    = kvm_vcpu_get_snapshot_with_id(vcpu_0, 0);
	kvm_vcpu_snapshot *vcpu_0_s_1 = kvm_vcpu_get_snapshot_with_id(vcpu_0, 1);

	kvm_vm_clear_guest_debug(vm);

	if (
	    !memcmp(&vcpu_0->record.guest_debug, &empty_guest_debug_struct, sizeof(struct kvm_guest_debug)) &&
	    !memcmp(&vcpu_0_s_0->record.guest_debug, &empty_guest_debug_struct, sizeof(struct kvm_guest_debug)) &&
	    !memcmp(&vcpu_0_s_1->record.guest_debug, &empty_guest_debug_struct, sizeof(struct kvm_guest_debug))) {
		ok(true, "kvm_vm_clear_guest_debug correctly cleared the guest debug settings of a single vcpu with multiple vcpu snapshots!");
	} else {
		ok(false, "kvm_vcpu_clear_guest_debug incorrectly cleared the guest debug settings of a single vcpu with multiple vcpu snapshots!");
	}

	kvm_vm_free(vm);
}

// test patching and unpatching api
static void
test_kvm_vm_memory_operations(const char *serialized_vm_path)
{

	kvm_vm *vm = kvm_vm_deserialize(serialized_vm_path);

	// get value of IP
	struct kvm_regs regs;
	memset(&regs, 0, sizeof(struct kvm_regs));
	kvm_vcpu *vcpu = kvm_vm_get_vcpu_with_id(vm, 0);
	IOCTL1(vcpu->fd, KVM_GET_REGS, &regs)

	// get original bytes at IP
	u8 *orig = kvm_vm_read_vaddr(vm, regs.rip, 4, 0);

	// patch contents that IP points to with 0xDEADBEEF
	kvm_vm_patch_vaddr(vm, regs.rip, (u8 *)"\xDE\xAD\xBE\xEF", 4, 0);

	if (vm->patch_point_count != 1) {
		ok(false, "kvm_vm patch_point_count field not updated correctly!");
	} else {
		ok(true, "kvm_vm patch_point_count field updated correctly!");
	}

	// get contents at IP after patch
	u8 *new = kvm_vm_read_vaddr(vm, regs.rip, 4, 0);

	// check contents
	if (!memcmp(new, "\xDE\xAD\xBE\xEF", 4)) {
		ok(true, "kvm_vm_patch_vaddr works as expected!");
	} else {
		ok(false, "kvm_vm_patch_vaddr failed!");
	}
	free(new);

	// unpatch 1 patch made at IP.
	kvm_vm_unpatch_vaddr(vm, regs.rip, 0);

	if (vm->patch_point_count != 0) {
		ok(false, "kvm_vm patch_point_count field not updated correctly!");
	} else {
		ok(true, "kvm_vm patch_point_count field updated correctly!");
	}
	// get contents at IP
	u8 *unpatched = kvm_vm_read_vaddr(vm, regs.rip, 4, 0);

	// compare unpatched contents with original contents.
	if (!memcmp(unpatched, orig, 4)) {
		ok(true, "kvm_vm_unpatch_vaddr worked correctly!");
	} else {
		ok(false, "kvm_vm_unpatch_vaddr failed!");
	}

	free(unpatched);
	free(orig);

	kvm_vm_free(vm);
}

// test stop point insertion
static void
test_kvm_vm_stop_points(const char *serialized_vm_path)
{
	kvm_vm *vm = kvm_vm_deserialize(serialized_vm_path);

	// get value of IP
	struct kvm_regs regs;
	memset(&regs, 0, sizeof(struct kvm_regs));
	kvm_vcpu *vcpu = kvm_vm_get_vcpu_with_id(vm, 0);
	IOCTL1(vcpu->fd, KVM_GET_REGS, &regs)

	// addresses for stop points
	u64 addr1 = regs.rip + 0x10;
	u64 addr2 = regs.rip + 0x14;
	u64 addr3 = regs.rip + 0x18;

	// get original bytes
	u8 *addr1_orig = kvm_vm_read_vaddr(vm, addr1, 2, 0);
	u8 *addr2_orig = kvm_vm_read_vaddr(vm, addr2, 2, 0);
	u8 *addr3_orig = kvm_vm_read_vaddr(vm, addr3, 2, 0);

	// add stop points at addresses
	kvm_vm_add_vaddr_stop_point(vm, addr1, 0);
	kvm_vm_add_vaddr_stop_point(vm, addr2, 0);
	kvm_vm_add_vaddr_stop_point(vm, addr3, 0);

	if (vm->stop_point_count != 3) {
		ok(false, "kvm_vm stop_point_count field not updated correctly!");
	} else {
		ok(true, "kvm_vm stop_point_count field updated correctly!");
	}

	// get patched memory contents
	u8 *addr1_new = kvm_vm_read_vaddr(vm, addr1, 2, 0);
	u8 *addr2_new = kvm_vm_read_vaddr(vm, addr2, 2, 0);
	u8 *addr3_new = kvm_vm_read_vaddr(vm, addr3, 2, 0);

	// check that memory was patched
	if (!memcmp(addr1_new, addr1_orig, 2) ||
	    !memcmp(addr2_new, addr2_orig, 2) ||
	    !memcmp(addr3_new, addr3_orig, 2) ||
	    memcmp(addr1_new, X86_UD, 2) != 0) {
		ok(false, "stop point content is incorrect.");
	} else {
		ok(true, "stop point content is correct.");
	}

	// should only be patch_points of type stop_point.
	patch_point *itr = NULL;
	TAILQ_FOREACH(itr, &vm->stop_point_head, record_list)
	{
		if (itr->size != 2) {
			ok(false, "stop_point struct has an incorrect size field.");
		} else {
			ok(true, "stop_point struct has a correct size field.");
		}
	}
	if (!kvm_vm_vaddr_is_stop_point(vm, addr1, 0)) {
		ok(false, "addr1 should be reported to be a stop point.");
	} else {
		ok(true, "addr1 correctly reported as a stop point.");
	}
	if (!kvm_vm_vaddr_is_stop_point(vm, addr2, 0)) {
		ok(false, "addr2 should be reported to be a stop point.");
	} else {
		ok(true, "addr2 correctly reported as a stop point.");
	}
	if (!kvm_vm_vaddr_is_stop_point(vm, addr3, 0)) {
		ok(false, "addr3 should be reported to be a stop point.");
	} else {
		ok(true, "addr3 correctly reported as a stop point.");
	}

	u64 addr1_phys = 0;
	u64 addr2_phys = 0;
	u64 addr3_phys = 0;

	kvm_vm_guest_vaddr_to_guest_paddr(vm, addr1, &addr1_phys, 0);
	kvm_vm_guest_vaddr_to_guest_paddr(vm, addr1, &addr2_phys, 0);
	kvm_vm_guest_vaddr_to_guest_paddr(vm, addr1, &addr3_phys, 0);

	if (!kvm_vm_paddr_is_stop_point(vm, addr1_phys)) {
		ok(false, "addr1_phys should be reported to be a stop point.");
	} else {
		ok(true, "addr1_phys correctly reported as a stop point.");
	}
	if (!kvm_vm_paddr_is_stop_point(vm, addr2_phys)) {
		ok(false, "addr2_phys should be reported to be a stop point.");
	} else {
		ok(true, "addr2_phys correctly reported as a stop point.");
	}
	if (!kvm_vm_paddr_is_stop_point(vm, addr3_phys)) {
		ok(false, "addr3_phys should be reported to be a stop point.");
	} else {
		ok(true, "addr3_phys correctly reported as a stop point.");
	}

	free(addr1_new);
	free(addr2_new);
	free(addr3_new);

	// remove all stop points
	kvm_vm_remove_all_stop_points(vm);

	if (vm->stop_point_count != 0) {
		ok(false, "kvm_vm stop_point_count field not updated correctly!");
	} else {
		ok(true, "kvm_vm stop_point_count field updated correctly!");
	}

	// get restored memory contents
	u8 *addr1_restored = kvm_vm_read_vaddr(vm, addr1, 2, 0);
	u8 *addr2_restored = kvm_vm_read_vaddr(vm, addr2, 2, 0);
	u8 *addr3_restored = kvm_vm_read_vaddr(vm, addr3, 2, 0);

	// compare restored memory contents with original memory contents
	if (
	    memcmp(addr1_restored, addr1_orig, 2) != 0 ||
	    memcmp(addr2_restored, addr2_orig, 2) != 0||
	    memcmp(addr3_restored, addr3_orig, 2) != 0) {
		ok(false, "stop points were not reverted correctly.");
	} else {
		ok(true, "stop points were reverted correctly.");
	}

	free(addr1_restored);
	free(addr2_restored);
	free(addr3_restored);

	free(addr1_orig);
	free(addr2_orig);
	free(addr3_orig);

	kvm_vm_add_vaddr_stop_point(vm, regs.rip, 0);
	if (!kvm_vm_is_ip_at_stop_point(vm, 0)) {
		ok(false, "kvm_vm_is_ip_at_stop_point should have reported RIP as a stop point.");
	} else {
		ok(true, "RIP correctly reported as a stop point by kvm_vm_is_ip_at_stop_point");
	}

	kvm_vm_free(vm);
}
static bool
hook_test_func(__attribute__((unused)) void *engine)
{
	return true;
}

static void
test_kvm_vm_hook_points(const char *serialized_vm_path)
{
	kvm_vm *vm = kvm_vm_deserialize(serialized_vm_path);

	// get value of IP
	struct kvm_regs regs;
	memset(&regs, 0, sizeof(struct kvm_regs));
	kvm_vcpu *vcpu = kvm_vm_get_vcpu_with_id(vm, 0);
	IOCTL1(vcpu->fd, KVM_GET_REGS, &regs)

	// addresses for hook points
	u64 addr1 = regs.rip;
	u64 addr2 = regs.rip + 0x4;
	u64 addr3 = regs.rip + 0x8;

	// get original bytes, // instruction we use to invoke a vm exit is only 2 bytes long
	u8 *addr1_orig = kvm_vm_read_vaddr(vm, addr1, 2, 0);
	u8 *addr2_orig = kvm_vm_read_vaddr(vm, addr2, 2, 0);
	u8 *addr3_orig = kvm_vm_read_vaddr(vm, addr3, 2, 0);

	// add stop points at addresses
	kvm_vm_hook_vaddr(vm, addr1, 0, &hook_test_func);
	kvm_vm_hook_vaddr(vm, addr2, 0, &hook_test_func);
	kvm_vm_hook_vaddr(vm, addr3, 0, &hook_test_func);

	if (vm->hook_point_count != 3) {
		ok(false, "kvm_vm hook_point_count field not updated correctly!");
	} else {
		ok(true, "kvm_vm hook_point_count field updated correctly!");
	}

	// get patched memory contents
	u8 *addr1_new = kvm_vm_read_vaddr(vm, addr1, 2, 0);
	u8 *addr2_new = kvm_vm_read_vaddr(vm, addr2, 2, 0);
	u8 *addr3_new = kvm_vm_read_vaddr(vm, addr3, 2, 0);

	// check that memory was patched
	if (!memcmp(addr1_new, addr1_orig, 2) ||
	    !memcmp(addr2_new, addr2_orig, 2) ||
	    !memcmp(addr3_new, addr3_orig, 2) ||
	    memcmp(addr1_new, X86_UD, 2) != 0) {
		ok(false, "hook point content is incorrect.");
	} else {
		ok(true, "hook point content is correct.");
	}

	// should only be patch_points of type hook_point.
	hook_point *itr = NULL;
	TAILQ_FOREACH(itr, &vm->hook_point_head, record_list)
	{
		if (itr->patch->size != 2) {
			ok(false, "hook_point struct has an incorrect size field.");
		} else {
			ok(true, "hook_point struct has a correct size field.");
		}
	}

	free(addr1_new);
	free(addr2_new);
	free(addr3_new);

	// remove all hook points
	kvm_vm_unhook_vaddr(vm, addr1, 0);
	kvm_vm_unhook_vaddr(vm, addr2, 0);
	kvm_vm_unhook_vaddr(vm, addr3, 0);
	if (vm->hook_point_count != 0) {
		ok(false, "kvm_vm hook_point_count field not updated correctly!");
	} else {
		ok(true, "kvm_vm hook_point_count field updated correctly!");
	}

	// get restored memory contents
	u8 *addr1_restored = kvm_vm_read_vaddr(vm, addr1, 2, 0);
	u8 *addr2_restored = kvm_vm_read_vaddr(vm, addr2, 2, 0);
	u8 *addr3_restored = kvm_vm_read_vaddr(vm, addr3, 2, 0);

	// compare restored memory contents with original memory contents
	if (
	    memcmp(addr1_restored, addr1_orig, 2) != 0 ||
	    memcmp(addr2_restored, addr2_orig, 2) != 0 ||
	    memcmp(addr3_restored, addr3_orig, 2) != 0) {
		ok(false, "hooks not reverted correctly.");
	} else {
		ok(true, "hooks were reverted correctly.");
	}

	free(addr1_restored);
	free(addr2_restored);
	free(addr3_restored);

	free(addr1_orig);
	free(addr2_orig);
	free(addr3_orig);

	kvm_vm_free(vm);
}
void
test_kvm_vm(const char *serialized_vm_dir)
{
	diagnostics("Testing kvm_vm API.");
	test_kvm_vm_create_unrealized();
	test_kvm_vm_create();
	test_kvm_vm_insert_vcpu();
	test_kvm_vm_insert_emu_device();
	test_kvm_vm_insert_userspace_memory_region();
	test_kvm_vm_enable_dirty_page_logging();
	test_kvm_vm_insert_snapshot();
	test_kvm_vm_free_snapshot();
	test_kvm_vm_get_vcpu_with_id();
	test_kvm_vm_get_snapshot_with_id();
	test_kvm_vm_clear_guest_debug();
	test_kvm_vm_set_timeout();

	if (serialized_vm_dir) {
		diagnostics("begin take_and_restore_snapshot tests.");
		test_kvm_vm_take_and_restore_snapshot(serialized_vm_dir);
		diagnostics("done.");
		diagnostics("begin memory_operation tests.");
		test_kvm_vm_memory_operations(serialized_vm_dir);
		diagnostics("done.");
		diagnostics("begin stop point tests.");
		test_kvm_vm_stop_points(serialized_vm_dir);
		diagnostics("done.");
		diagnostics("begin hook point tests.");
		test_kvm_vm_hook_points(serialized_vm_dir);
		diagnostics("done.");
	}

	diagnostics("kvm_vm API tests complete.");
}
