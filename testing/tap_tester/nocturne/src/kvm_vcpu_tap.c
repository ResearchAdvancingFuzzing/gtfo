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

#include "kvm_vcpu_tap.h"
#include <time.h>
#include <unistd.h>
/*
  This file contains unit tests for the kvm_vcpu API.
*/

bool
kvm_vcpu_isequal(kvm_vcpu *vcpu1, kvm_vcpu *vcpu2)
{
	if (
	    vcpu1->id != vcpu2->id ||
	    vcpu1->snapshot_count != vcpu2->snapshot_count ||
	    vcpu1->mmap_size != vcpu2->mmap_size ||
	    !kvm_vcpu_record_isequal(&vcpu1->record, &vcpu2->record)) {
		return false;
	}

	if (vcpu1->snapshot_count) {
		kvm_vcpu_snapshot *vcpu1_snapshot_itr = NULL;
		kvm_vcpu_snapshot *vcpu2_snapshot_itr = RECORD_LIST_FIRST(vcpu2->kvm_vcpu_snapshot_head);

		RECORD_LIST_FOREACH(vcpu1_snapshot_itr, vcpu1->kvm_vcpu_snapshot_head)
		{
			if (!kvm_vcpu_snapshot_isequal(vcpu1_snapshot_itr, vcpu2_snapshot_itr)) {
				return false;
			}
			vcpu2_snapshot_itr = RECORD_LIST_NEXT(vcpu2_snapshot_itr);
		}
		// false returned if vcpu1 or vcpu2 have differing number of snapshots.
		if (vcpu2_snapshot_itr != NULL) {
			return false;
		}
	}
	return true;
}

void
check_kvm_vcpu_timeout(kvm_vcpu *vcpu, struct timespec *expected_timeout_duration)
{
	if (vcpu->timeout.duration.tv_nsec == expected_timeout_duration->tv_nsec) {
		ok(true, "kvm_vcpu execution timeout nanosecond value set correctly!");
	} else {
		ok(false, "kvm_vcpu execution timeout nanosecond value set incorrectly!");
	}
	if (vcpu->timeout.duration.tv_sec == expected_timeout_duration->tv_sec) {
		ok(true, "kvm_vcpu execution timeout second value set correctly!");
	} else {
		ok(false, "kvm_vcpu execution timeout second value set incorrectly!");
	}

	kvm_vcpu_timeout *empty_timeout = calloc(1, sizeof(kvm_vcpu_timeout));

	// if timeout_nsec was specified, check that the timeout struct was initialized.
	if ((vcpu->timeout.duration.tv_nsec || vcpu->timeout.duration.tv_sec) == !memcmp(&vcpu->timeout, empty_timeout, sizeof(kvm_vcpu_timeout))) {
		ok(false, "struct kvm_vcpu_timeout initialized incorrectly!");
	} else {
		ok(true, "struct kvm_vcpu_timeout initialized correctly!");
	}
	free(empty_timeout);
}

static void
check_new_kvm_vcpu(kvm_vcpu *vcpu, struct timespec *expected_timeout_duration)
{
	if (!vcpu->fd ||
	    !vcpu->mmap_size ||
	    !vcpu->kvm_run) {
		ok(false, "kvm_vcpu was not initialized correctly!");
	} else {
		ok(true, "kvm_vcpu was initialized correctly!");
	}

	check_kvm_vcpu_timeout(vcpu, expected_timeout_duration);
}

// tests creating an empty, unrealized vcpu.
static void
test_kvm_vcpu_create_unrealized()
{
	kvm_vcpu *foo  = calloc(1, sizeof(kvm_vcpu));
	kvm_vcpu *vcpu = kvm_vcpu_create_unrealized(0);

	if (kvm_vcpu_isequal(foo, vcpu)) {
		ok(true, "kvm_vcpu_create_unrealized behaving correctly!");
	} else {
		ok(false, "kvm_vcpu_create_unrealized behaving incorrectly!");
	}
	kvm_vcpu_free(vcpu);
	free(foo);
}

// tests vcpu creation.
static void
test_kvm_vcpu_create()
{
	kvm_vm *vm = kvm_vm_create();

	kvm_vcpu *vcpu = kvm_vcpu_create(vm->kvm_fd, vm->vm_fd, vm->vcpu_count);
	kvm_vm_insert_vcpu(vm, vcpu);

	if (vcpu->id != 0) {
		ok(false, "kvm_vcpu id was set incorrectly!");
	} else {
		ok(true, "kvm_vcpu id was set correctly!");
	}
	struct timespec expected_timeout_duration = {0, 0};
	check_new_kvm_vcpu(vcpu, &expected_timeout_duration);

	kvm_vm_free(vm);
}

// test kvm_vcpu_pause and unpause
static void
test_kvm_vcpu_pausing()
{
	kvm_vm *vm = kvm_vm_create();

	kvm_vcpu *vcpu = kvm_vcpu_create(vm->kvm_fd, vm->vm_fd, vm->vcpu_count);
	kvm_vm_insert_vcpu(vm, vcpu);

	kvm_vcpu_pause(vcpu);

	// check that immediate_exit is set.
	if (vcpu->kvm_run->immediate_exit == 1) {
		ok(true, "kvm_vcpu paused correctly!");
	} else {
		ok(false, "kvm_vcpu was not paused correctly!");
	}
	// check that this func evals to true.
	if (kvm_vcpu_is_paused(vcpu)) {
		ok(true, "kvm_vcpu_is_paused behaved correctly!");
	} else {
		ok(false, "kvm_vcpu_is_paused behaved incorrectly!");
	}
	kvm_vcpu_unpause(vcpu);

	// check that immediate_exit is unset.
	if (vcpu->kvm_run->immediate_exit == 0) {
		ok(true, "kvm_vcpu unpaused correctly!");
	} else {
		ok(false, "kvm_vcpu unpaused incorrectly!");
	}
	// check that this function evals to false.
	if (!kvm_vcpu_is_paused(vcpu)) {
		ok(true, "kvm_vcpu_is_paused behaved correctly!");
	} else {
		ok(false, "kvm_vcpu_is_paused behaved incorrectly!");
	}
	kvm_vm_free(vm);
}

// tests kvm_vcpu_insert_snapshot API function.
static void
test_kvm_vcpu_insert_snapshot()
{
	// create uninitialized vcpu
	kvm_vcpu *vcpu = kvm_vcpu_create_unrealized(0);

	// create an empty snapshot object
	kvm_vcpu_snapshot *snapshot = kvm_vcpu_snapshot_create(0);

	// insert empty snapshot into vcpu
	kvm_vcpu_insert_snapshot(vcpu, snapshot);

	if (vcpu->snapshot_count == 1) {
		ok(true, "kvm_vcpu_snapshot inserted correctly!");
	} else {
		ok(false, "kvm_vcpu_snapshot inserted incorrectly!");
	}
	kvm_vcpu_free(vcpu);
}

// tests kvm_vcpu_get_snapshot_with_id function
static void
test_kvm_vcpu_get_snapshot_with_id()
{

	kvm_vcpu *vcpu = kvm_vcpu_create_unrealized(0);
	// create snapshot with id 0xdeadbeef
	kvm_vcpu_snapshot *snapshot = kvm_vcpu_snapshot_create(0xdeadbeef);

	kvm_vcpu_insert_snapshot(vcpu, snapshot);

	// get snapshot with id 0xdeadbeef
	kvm_vcpu_snapshot *snapshot2 = kvm_vcpu_get_snapshot_with_id(vcpu, 0xdeadbeef);

	// if we got the same pointer back
	if (snapshot == snapshot2) {
		ok(true, "kvm_vcpu_get_snapshot_with_id behaved correctly!");
	} else {
		ok(false, "kvm_vcpu_get_snapshot_with_id behaved incorrectly!");
	}

	kvm_vcpu_free(vcpu);
}

// test kvm_vcpu_free_snapshot_with_id
static void
test_kvm_vcpu_free_snapshot_with_id()
{
	kvm_vcpu *vcpu = kvm_vcpu_create_unrealized(0);
	// create snapshot with id 0xDEADBEEF
	kvm_vcpu_snapshot *snapshot = kvm_vcpu_snapshot_create(0xdeadbeef);

	kvm_vcpu_insert_snapshot(vcpu, snapshot);
	// free the snapshot we just created.
	kvm_vcpu_free_snapshot_with_id(vcpu, 0xdeadbeef);

	if (vcpu->snapshot_count == 0) {
		ok(true, "kvm_vcpu_snapshot freed correctly!");
	} else {
		ok(false, "kvm_vcpu_snapshot freed incorrectly!");
	}
	kvm_vcpu_free(vcpu);
}

// used in kvm_vm_snapshot_tap.c
void
test_kvm_vcpu_take_and_restore_snapshot_with_id(kvm_vcpu *vcpu, u64 original_snapshot_id)
{
	// take a new vcpu snapshot with new id
	kvm_vcpu_take_snapshot_with_id(vcpu, original_snapshot_id + 1);
	// get pointer to new snap
	kvm_vcpu_snapshot *new_snap = kvm_vcpu_get_snapshot_with_id(vcpu, original_snapshot_id + 1);

	// edit the new snapshot a little bit.
	memset(&new_snap->regs, 0x41, sizeof(struct kvm_regs));

	// restore to the edited, new snapshot.
	kvm_vcpu_restore_snapshot_with_id(vcpu, original_snapshot_id + 1);

	// take another new snapshot
	kvm_vcpu_take_snapshot_with_id(vcpu, original_snapshot_id + 2);
	// get pointer to new snap
	kvm_vcpu_snapshot *restored_snap = kvm_vcpu_get_snapshot_with_id(vcpu, original_snapshot_id + 2);

	// compare the current state of the vcpu with the snapshot we edited.
	// if we restored correctly to the edited 'new_snap'
	if (kvm_vcpu_snapshot_isequal(new_snap, restored_snap)) {
		ok(true, "kvm_vcpu_restore_snapshot_with_id behaved correctly!");
	} else {
		ok(false, "kvm_vcpu_restore_snapshot_with_id behaved incorrectly!");
	}
	// might still need to use the vcpu object, so we can't destruct it.
	kvm_vcpu_free_snapshot_with_id(vcpu, original_snapshot_id + 2);
	kvm_vcpu_free_snapshot_with_id(vcpu, original_snapshot_id + 1);
}

// test kvm_vcpu_clear_guest_debug
static void
test_kvm_vcpu_clear_guest_debug()
{
	kvm_vm *vm = kvm_vm_create();

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

	kvm_vcpu *vcpu = kvm_vcpu_create(vm->kvm_fd, vm->vm_fd, vm->vcpu_count);
	kvm_vm_insert_vcpu(vm, vcpu);
	kvm_vcpu_record_guest_debug(&vcpu->record, &fake_guest_dbg);
	kvm_vcpu_clear_guest_debug(vcpu);

	if (!memcmp(&vcpu->record.guest_debug, &empty_guest_debug_struct, sizeof(struct kvm_guest_debug))) {
		ok(true, "kvm_vcpu_clear_guest_debug correctly cleared guest debug settings of a vcpu!");
	} else {
		ok(false, "kvm_vcpu_clear_guest_debug incorrectly cleared guest debug settings of a vcpu!");
	}

	kvm_vm_free(vm);

	vm = kvm_vm_create();

	vcpu = kvm_vcpu_create(vm->kvm_fd, vm->vm_fd, vm->vcpu_count);
	kvm_vm_insert_vcpu(vm, vcpu);
	kvm_vcpu_record_guest_debug(&vcpu->record, &fake_guest_dbg);

	// take a single snapshot.
	kvm_vcpu_take_snapshot_with_id(vcpu, 0);
	kvm_vcpu_snapshot *snapshot_0 = kvm_vcpu_get_snapshot_with_id(vcpu, 0);

	kvm_vcpu_clear_guest_debug(vcpu);

	if (
	    !memcmp(&vcpu->record.guest_debug, &empty_guest_debug_struct, sizeof(struct kvm_guest_debug)) &&
	    !memcmp(&snapshot_0->record.guest_debug, &empty_guest_debug_struct, sizeof(struct kvm_guest_debug))) {
		ok(true, "kvm_vcpu_clear_guest_debug correctly cleared the guest debug settings of a vcpu and a single vcpu snapshot!");
	} else {
		ok(false, "kvm_vcpu_clear_guest_debug incorrectly cleared the guest debug settings of a vcpu and a single vcpu snapshot!");
	}

	kvm_vm_free(vm);

	vm = kvm_vm_create();

	vcpu = kvm_vcpu_create(vm->kvm_fd, vm->vm_fd, vm->vcpu_count);
	kvm_vm_insert_vcpu(vm, vcpu);
	kvm_vcpu_record_guest_debug(&vcpu->record, &fake_guest_dbg);

	// take a single snapshot.
	kvm_vcpu_take_snapshot_with_id(vcpu, 0);
	kvm_vcpu_take_snapshot_with_id(vcpu, 1);
	snapshot_0                    = kvm_vcpu_get_snapshot_with_id(vcpu, 0);
	kvm_vcpu_snapshot *snapshot_1 = kvm_vcpu_get_snapshot_with_id(vcpu, 1);

	kvm_vcpu_clear_guest_debug(vcpu);

	if (
	    !memcmp(&vcpu->record.guest_debug, &empty_guest_debug_struct, sizeof(struct kvm_guest_debug)) &&
	    !memcmp(&snapshot_0->record.guest_debug, &empty_guest_debug_struct, sizeof(struct kvm_guest_debug)) &&
	    !memcmp(&snapshot_1->record.guest_debug, &empty_guest_debug_struct, sizeof(struct kvm_guest_debug))) {
		ok(true, "kvm_vcpu_clear_guest_debug correctly cleared the guest debug settings of a vcpu and a multiple snapshots!");
	} else {
		ok(false, "kvm_vcpu_clear_guest_debug incorrectly cleared the guest debug settings of a vcpu and a multiple snapshots!");
	}

	kvm_vm_free(vm);
}

// this function unit tests the timeout api as much as possible
// without a working, fully configured virtual machine.
static void
test_kvm_vcpu_timeout_functions()
{

	// NEW TIMEOUT TEST
	kvm_vm *  vm   = kvm_vm_create();
	kvm_vcpu *vcpu = kvm_vcpu_create(vm->kvm_fd, vm->vm_fd, vm->vcpu_count);
	kvm_vm_insert_vcpu(vm, vcpu);

	struct timespec duration = {0};

	// 2 seconds and 10 milliseconds
	duration.tv_sec  = 2;
	duration.tv_nsec = 10000000;

	kvm_vcpu_set_timeout(vcpu, &duration);
    usleep(100000);
	if (vcpu->timeout.duration.tv_sec == 2 &&
	    vcpu->timeout.duration.tv_nsec == 10000000) {
		ok(true, "kvm_vcpu_set_timeout set tv_sec and tv_nsec fields correctly!");
	} else {
		ok(false, "kvm_vcpu_set_timeout did not set the tv_sec and tv_nsec fields correctly!");
	}

	if (vcpu->timeout.thread_keepalive) {
		ok(true, "kvm_vcpu_set_timeout set thread_keepalive correctly!");
	} else {
		ok(false, "kvm_vcpu_set_timeout did not set thread_keepalive correctly!");
	}

	if (!pthread_mutex_trylock(&vcpu->timeout.vcpu_running_mutex)) {
		ok(true, "Correctly obtained vcpu_running_mutex mutex.");
		pthread_mutex_unlock(&vcpu->timeout.vcpu_running_mutex);
	} else {
		ok(false, "vcpu_running_mutex is incorrectly locked.");
	}

	if (!pthread_mutex_trylock(&vcpu->timeout.hangup_timer_mutex)) {
		ok(true, "Correctly obtained hangup_timer_mutex.");
		pthread_mutex_unlock(&vcpu->timeout.hangup_timer_mutex);
	} else {
		ok(false, "hangup_timer_mutex is incorrectly locked.");
	}

	kvm_vcpu_timeout_start(vcpu);
	sleep(1);
	if (!pthread_mutex_trylock(&vcpu->timeout.vcpu_running_mutex)) {
		ok(false, "vcpu_running_mutex should be locked after call to kvm_vcpu_timeout_start() but is unlocked.");
		pthread_mutex_unlock(&vcpu->timeout.vcpu_running_mutex);
	} else {
		ok(true, "vcpu_running_mutex is correctly locked after call to kvm_vcpu_timeout_start().");
	}

	if (!pthread_mutex_trylock(&vcpu->timeout.hangup_timer_mutex)) {
		ok(true, "hangup_timer_mutex is correctly locked after call to kvm_vcpu_timeout_start().");
		pthread_mutex_unlock(&vcpu->timeout.hangup_timer_mutex);
	}

	else {
		ok(false, "hangup_timer_mutex is incorrectly locked after call to kvm_vcpu_timeout_start().");
	}

	kvm_vcpu_timeout_stop(vcpu);
    usleep(100000);
    
	if (!pthread_mutex_trylock(&vcpu->timeout.vcpu_running_mutex)) {
		ok(true, "Correctly obtained vcpu_running_mutex mutex after call to kvm_vcpu_timeout_stop().");
		pthread_mutex_unlock(&vcpu->timeout.vcpu_running_mutex);
	} else {
		ok(false, "vcpu_running_mutex is incorrectly locked after call to kvm_vcpu_timeout_stop().");
	}

	if (!pthread_mutex_trylock(&vcpu->timeout.hangup_timer_mutex)) {
		ok(true, "hangup_timer_mutex is correctly locked before timeout expiration.");
		pthread_mutex_unlock(&vcpu->timeout.hangup_timer_mutex);
	} else {
		ok(false, "hangup_timer_mutex is incorrectly unlocked before timeout expiration.");
	}

	sleep(1);

	if (!pthread_mutex_trylock(&vcpu->timeout.hangup_timer_mutex)) {
		ok(true, "Correctly obtained hangup_timer_mutex after timeout expiration.");
		pthread_mutex_unlock(&vcpu->timeout.hangup_timer_mutex);
	} else {
		ok(false, "hangup_timer_mutex is incorrectly locked after timeout expiration.");
	}

	kvm_vm_free(vm);
}

// tests that do not require a already-instantiated vcpu
void
test_kvm_vcpu()
{
	diagnostics("Testing kvm_vcpu API.");
	test_kvm_vcpu_create_unrealized();
	test_kvm_vcpu_create();
	test_kvm_vcpu_pausing();
	test_kvm_vcpu_insert_snapshot();
	test_kvm_vcpu_get_snapshot_with_id();
	test_kvm_vcpu_free_snapshot_with_id();
	test_kvm_vcpu_clear_guest_debug();
	test_kvm_vcpu_timeout_functions();
	diagnostics("kvm_vcpu API tests complete.");
}
