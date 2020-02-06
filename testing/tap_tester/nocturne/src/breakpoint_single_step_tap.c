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

#include "breakpoint_single_step_tap.h"
#include <plugin.h>

static kvmcore_plugin_record *
get_plugin_helper(kvm_engine *engine, u64 plugin_id)
{
	kvmcore_plugin_record *plugin_r = RECORD_LIST_FIRST(engine->kvmcore_plugin_record_head);
    while(plugin_r) {

        if(plugin_r->id == plugin_id) {
            break;
        }
        plugin_r = RECORD_LIST_NEXT(plugin_r);
    }
    if(plugin_r) {
        return plugin_r;
    }
    return NULL;
}

static void
test_breakpoint_single_step_populate(const char * serialized_vm_path, const char *plugin_path)
{
    kvm_engine *e = construct_kvm_engine_helper(serialized_vm_path);
    u64 p_id = (u64)kvm_engine_load_plugin(e, plugin_path, false);

    kvmcore_plugin_record *p_r = get_plugin_helper(e, p_id);
    kvmcore_plugin *p = &p_r->plugin;
    kvmcore_plugin_state *s = &p_r->state;

    if(
        !p->version ||
        !p->name ||
        !p->description ||
        !s->flags.reset_on_snapshot_restore ||
        !p->enable ||
        !p->disable ||
        !p->free_state ||
        !p->reset ||
        !p->extract_data ||
        !p->vcpu_post_launch_hook) {
        ok(false, "breakpoint_single_step_populate: kvm_vm_plugin object was not populated correctly");
    } else {
        ok(true, "breakpoint_single_step_populate: kvm_vm_plugin object was populated correctly.");
    }

    destruct_kvm_engine_helper(e);
}

static void
test_breakpoint_single_step_init(const char * serialized_vm_path, const char *plugin_path)
{
    kvm_engine *e = construct_kvm_engine_helper(serialized_vm_path);
    u64 p_id = (u64)kvm_engine_load_plugin(e, plugin_path, false);

    kvmcore_plugin_record *p_r = get_plugin_helper(e, p_id);
    sized_buffer *s_state = (sized_buffer *)p_r->state.internal_state;
    if(!s_state || s_state->content_size != 0) {
		ok(false, "breakpoint_single_step_init: Did not initialize internal state.");
	} else {
        ok(true, "breakpoint_single_step_init: Initialized internal state.");
    }
    destruct_kvm_engine_helper(e);
}


static void
test_breakpoint_single_step_enable(const char * serialized_vm_path, const char *plugin_path)
{
	kvm_engine *e = construct_kvm_engine_helper(serialized_vm_path);
	kvm_engine_load_plugin(e, plugin_path, true);

    struct kvm_guest_debug expected_guest_debug;
    memset(&expected_guest_debug, 0, sizeof(struct kvm_guest_debug));

    // default configuration, single stepping
    expected_guest_debug.control = KVM_GUESTDBG_ENABLE;
    expected_guest_debug.control |= KVM_GUESTDBG_SINGLESTEP;
    expected_guest_debug.control |= KVM_GUESTDBG_USE_HW_BP;

    kvm_vm *vm = e->vm;
    kvm_vcpu *vcpu_itr = NULL;

    RECORD_LIST_FOREACH(vcpu_itr, vm->kvm_vcpu_head) {

        if(memcmp(&expected_guest_debug, &vcpu_itr->record.guest_debug, sizeof(struct kvm_guest_debug)) != 0) {
            ok(false, "breakpoint_single_step_vcpu_enable: kvm_vcpu_record not updated correctly.");
        } else {
            ok(true, "breakpoint_single_step_vcpu_enable: kvm_vcpu_record was updated correctly.");
        }

        kvm_vcpu_snapshot *vcpu_s_itr = NULL;
        RECORD_LIST_FOREACH(vcpu_s_itr, vcpu_itr->kvm_vcpu_snapshot_head)
        {
            if(memcmp(&expected_guest_debug, &vcpu_s_itr->record.guest_debug, sizeof(struct kvm_guest_debug)) != 0) {
                ok(false, "breakpoint_single_step_vcpu_enable: vcpu snapshot's kvm_vcpu_record not updated correctly.");
            } else {
                ok(true, "breakpoint_single_step_vcpu_enable: vcpu snapshot's kvm_vcpu_record was updated correctly.");
            }
        }
    }

	destruct_kvm_engine_helper(e);
}

static void
test_breakpoint_single_step_disable(const char * serialized_vm_path, const char *plugin_path)
{
	kvm_engine *e = construct_kvm_engine_helper(serialized_vm_path);
    u64 p_id = (u64)kvm_engine_load_plugin(e, plugin_path, true);

	struct kvm_guest_debug expected_guest_debug;
	memset(&expected_guest_debug, 0, sizeof(struct kvm_guest_debug));

	kvm_engine_disable_plugin(e, p_id);

	kvm_vm *  vm       = e->vm;
	kvm_vcpu *vcpu_itr = NULL;

	RECORD_LIST_FOREACH(vcpu_itr, vm->kvm_vcpu_head)
	{

		if (memcmp(&expected_guest_debug, &vcpu_itr->record.guest_debug, sizeof(struct kvm_guest_debug)) != 0) {
			ok(false, "breakpoint_single_step_vcpu_disable: kvm_vcpu_record not updated correctly.");
		} else {
			ok(true, "breakpoint_single_step_vcpu_disable: kvm_vcpu_record was updated correctly.");
		}

		kvm_vcpu_snapshot *vcpu_s_itr = NULL;
		RECORD_LIST_FOREACH(vcpu_s_itr, vcpu_itr->kvm_vcpu_snapshot_head)
		{
			if (memcmp(&expected_guest_debug, &vcpu_s_itr->record.guest_debug, sizeof(struct kvm_guest_debug)) != 0) {
				ok(false, "breakpoint_single_step_vcpu_disable: vcpu snapshot's kvm_vcpu_record not updated correctly.");
			} else {
				ok(true, "breakpoint_single_step_vcpu_disable: vcpu snapshot's kvm_vcpu_record was updated correctly.");
			}
		}
	}

	destruct_kvm_engine_helper(e);
}

static void
test_breakpoint_single_step_execution_one(const char * serialized_vm_path, const char *plugin_path)
{
    kvm_engine *e = construct_kvm_engine_helper(serialized_vm_path);
    u64 p_id = (u64)kvm_engine_load_plugin(e, plugin_path, true);
    kvm_vm *  vm       = e->vm;
    kvm_vcpu *vcpu = RECORD_LIST_FIRST(vm->kvm_vcpu_head);

    struct kvm_regs regs;
    memset(&regs, 0 ,sizeof(struct kvm_regs));

    IOCTL1(vcpu->fd, KVM_GET_REGS, &regs)

    u64 start_ip = regs.rip;

    u8 nop[1];
    u64 end_ip = start_ip + 1;
    memcpy(&nop, X86_NOP, 1);

    kvm_engine_patch_vaddr(e, start_ip, nop, 1, vcpu->id);
    kvm_engine_add_vaddr_stop_point(e, end_ip, 0);

    kvm_engine_launch_vm(e);

    void *out_str = NULL;
    u64 nop_ip = 0;
    size_t out_size = 0;
    out_size = kvm_engine_extract_plugin_data(e, p_id, &out_str);
    if(!out_size) {
        ok(false, "test_breakpoint_single_step_execution: plugin did not return any data.");
    } else {
        ok(true, "test_breakpoint_single_step_execution: plugin returned some data.");
    }
    sscanf((char *)out_str, "RIP: 0x%lx\n", &nop_ip);

    if(nop_ip != start_ip) {
        ok(false, "test_breakpoint_single_step_execution: Incorrect IP value for single step.");
        diagnostics((char *)out_str);
    } else {
        ok(true, "test_breakpoint_single_step_execution: Correct IP value for single step.");
    }
    free(out_str);
    destruct_kvm_engine_helper(e);
}

static void
test_breakpoint_single_step_execution_multi(const char * serialized_vm_path, const char *plugin_path)
{
    kvm_engine *e = construct_kvm_engine_helper(serialized_vm_path);
    u64 p_id = (u64)kvm_engine_load_plugin(e, plugin_path, true);
    kvm_vm *  vm       = e->vm;
    kvm_vcpu *vcpu = RECORD_LIST_FIRST(vm->kvm_vcpu_head);

    struct kvm_regs regs;
    memset(&regs, 0 ,sizeof(struct kvm_regs));

    IOCTL1(vcpu->fd, KVM_GET_REGS, &regs)

    u64 start_ip = regs.rip;

    u8 nop[1];
    u8 xor[2];
    u64 end_ip = start_ip + 3;
    memcpy(&nop, X86_NOP, 1);
    memcpy(&xor, X86_XOR_EAX_EAX, 2);

    kvm_engine_patch_vaddr(e, start_ip, nop, 1, vcpu->id);
    kvm_engine_patch_vaddr(e, start_ip+1, xor, 2, vcpu->id);
    kvm_engine_add_vaddr_stop_point(e, end_ip, 0);

    kvm_engine_launch_vm(e);

    void *out_str = NULL;
    u64 nop_ip = 0;
    u64 xor_ip = 0;
    size_t out_size = 0;
    out_size = kvm_engine_extract_plugin_data(e, p_id, &out_str);
    if(!out_size) {
        ok(false, "test_breakpoint_single_step_execution: plugin did not return any data.");
    } else {
        ok(true, "test_breakpoint_single_step_execution: plugin returned some data.");
    }
    sscanf((char *)out_str, "RIP: 0x%lx\nRIP: 0x%lx\n", &nop_ip, &xor_ip);

    if(nop_ip != start_ip) {
        ok(false, "test_breakpoint_single_step_execution: Incorrect IP value for first single step.");
        diagnostics((char *)out_str);
    } else {
        ok(true, "test_breakpoint_single_step_execution: Correct IP value for first single step.");
    }
    if(xor_ip != start_ip+1) {
        ok(false, "test_breakpoint_single_step_execution: Incorrect IP value for second single step.");
        diagnostics((char *)out_str);
    } else {
        ok(true, "test_breakpoint_single_step_execution: Correct IP value for second single step.");
    }
    free(out_str);
    destruct_kvm_engine_helper(e);
}

static void
test_breakpoint_single_step_reset(const char * serialized_vm_path, const char *plugin_path)
{
    kvm_engine *e = construct_kvm_engine_helper(serialized_vm_path);
    u64 p_id = (u64)kvm_engine_load_plugin(e, plugin_path, true);
    kvm_vm *  vm       = e->vm;
    kvm_vcpu *vcpu = RECORD_LIST_FIRST(vm->kvm_vcpu_head);

    struct kvm_regs regs;
    memset(&regs, 0 ,sizeof(struct kvm_regs));

    IOCTL1(vcpu->fd, KVM_GET_REGS, &regs)

    u64 start_ip = regs.rip;

    u8 nop[1];
    u8 xor[2];
    u64 end_ip = start_ip + 3;
    memcpy(&nop, X86_NOP, 1);
    memcpy(&xor, X86_XOR_EAX_EAX, 2);

    kvm_engine_patch_vaddr(e, start_ip, nop, 1, vcpu->id);
    kvm_engine_add_vaddr_stop_point(e, start_ip+1, 0);

    kvm_engine_launch_vm(e);

    void *out_str = NULL;
    u64 nop_ip = 0;
    u64 xor_ip = 0;
    size_t out_size = 0;
    out_size = kvm_engine_extract_plugin_data(e, p_id, &out_str);
    if(!out_size) {
        ok(false, "test_breakpoint_single_step_reset: plugin did not return any data.");
    } else {
        ok(true, "test_breakpoint_single_step_reset: plugin returned some data.");
    }

    sscanf((char *)out_str, "RIP: 0x%lx\n", &nop_ip);

    if(nop_ip != start_ip) {
        ok(false, "test_breakpoint_single_step_reset: Incorrect IP value for first single step.");
        diagnostics((char *)out_str);
    } else {
        ok(true, "test_breakpoint_single_step_reset: Correct IP value for first single step.");
    }
    free(out_str);
    kvm_engine_remove_all_stop_points(e);

    kvm_engine_reset_plugin(e, p_id);

    kvm_engine_patch_vaddr(e, start_ip+1, xor, 2, vcpu->id);
    kvm_engine_add_vaddr_stop_point(e, end_ip, 0);

    kvm_engine_launch_vm(e);

    out_size = kvm_engine_extract_plugin_data(e, p_id, &out_str);
    if(!out_size) {
        ok(false, "test_breakpoint_single_step_reset: plugin did not return any data.");
    } else {
        ok(true, "test_breakpoint_single_step_reset: plugin returned some data.");
    }

    sscanf((char *)out_str, "RIP: 0x%lx\n", &xor_ip);

    if(xor_ip != end_ip) {
        ok(false, "test_breakpoint_single_step_reset: Incorrect IP value for second single step.");
        diagnostics((char *)out_str);
    } else {
        ok(true, "test_breakpoint_single_step_reset: Correct IP value for second single step.");
    }
    free(out_str);
    destruct_kvm_engine_helper(e);
}


void
test_breakpoint_single_step_plugin(const char * serialized_vm_path,const char *plugin_path)
{
    diagnostics("Testing breakpoint_single_step plugin.");
    test_breakpoint_single_step_populate(serialized_vm_path, plugin_path);
    test_breakpoint_single_step_init(serialized_vm_path, plugin_path);
    test_breakpoint_single_step_enable(serialized_vm_path, plugin_path);
    test_breakpoint_single_step_disable(serialized_vm_path, plugin_path);
    test_breakpoint_single_step_execution_one(serialized_vm_path, plugin_path);
    test_breakpoint_single_step_execution_multi(serialized_vm_path, plugin_path);
    test_breakpoint_single_step_reset(serialized_vm_path, plugin_path);
    diagnostics("breakpoint_single_step unit tests complete.");
}
