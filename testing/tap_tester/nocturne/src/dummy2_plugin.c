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

#include "dummy_plugin.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-parameter"
kvmcore_plugin_init_function kvmcore_plugin_init = dummy_plugin_init;

static bool
dummy_enable(__attribute__((unused))kvm_vm * vm, __attribute__((unused))kvmcore_plugin_state * state)
{
    setenv("DUMMY2_ENABLE_CALLED", "1", true);
	return true;
}

static bool
dummy_disable(__attribute__((unused))kvm_vm * vm, __attribute__((unused))kvmcore_plugin_state * state)
{
    setenv("DUMMY2_DISABLE_CALLED", "1", true);
    return true;
}

static bool
dummy_free_state(void * state) {
    setenv("DUMMY2_FREE_STATE_CALLED", "1", true);
    free(state);
    return true;
}

static bool
dummy_configure(__attribute__((unused))kvm_vm * vm, __attribute__((unused))kvmcore_plugin_state * state, void *config)
{
    setenv("DUMMY2_CONFIGURE_CALLED", "1", true);
    if(config && (u64)config == (u64)0xDEADBEEFCAFEBABE) {
		setenv("DUMMY2_CONFIG_PASSED_CORRECTLY", "1", true);
	}
    return true;
}

static bool
dummy_reset(__attribute__((unused))kvm_vm * vm, __attribute__((unused))kvmcore_plugin_state * state)
{
    setenv("DUMMY2_RESET_CALLED", "1", true);
    setenv("DUMMY2_RESET_STATE_PASSED", "1", true);
    return true;
}

static size_t
dummy_extract(__attribute__((unused))kvm_vm * vm, kvmcore_plugin_state *state, void **data_buf)
{
    setenv("DUMMY2_EXTRACT_CALLED", "1", true);
    if(state) {
		setenv("DUMMY2_EXTRACT_STATE_PASSED_CORRECTLY", "1", true);

		*data_buf       = calloc(1, 0x40);
		dummy_state *st = state->internal_state;

		memcpy(*data_buf, st->buf, 0x40);
		return 0x40;
	}
    return 0;

}

static void
dummy_vm_pre_launch_hook(__attribute__((unused))kvm_vm * vm, __attribute__((unused))kvmcore_plugin_state * state)
{
    setenv("DUMMY2_VM_PRE_LAUNCH_HOOK_CALLED", "1", true);
}
static void
dummy_vm_post_launch_hook(__attribute__((unused))kvm_vm * vm, __attribute__((unused))kvmcore_plugin_state * state)
{
    setenv("DUMMY2_VM_POST_LAUNCH_HOOK_CALLED", "1", true);
}

static void
dummy_vcpu_pre_launch_hook(__attribute__((unused))kvm_vcpu * vcpu, __attribute__((unused))kvmcore_plugin_state * state)
{
    setenv("DUMMY2_VCPU_PRE_LAUNCH_HOOK_CALLED", "1", true);
}

static bool
dummy_vcpu_post_launch_hook(__attribute__((unused))kvm_vcpu * vcpu, __attribute__((unused))kvmcore_plugin_state * state)
{
    setenv("DUMMY2_VCPU_POST_LAUNCH_HOOK_CALLED", "1", true);
    return false;
}



bool dummy_plugin_init(__attribute__((unused)) kvm_vm *vm, kvmcore_plugin *plugin, kvmcore_plugin_state *state)
{
    setenv("DUMMY2_INIT_CALLED", "1", true);

    plugin->version = NOCTURNE_PLUGIN_VERSION_ONE;
    plugin->name = "Test plugin two";
    plugin->description = "This is a test plugin for conducting unit tests on kvm_engine. It is compiled directly into the unit tests for Nocturne.";

    plugin->enable = dummy_enable;
    plugin->disable = dummy_disable;
    plugin->free_state = dummy_free_state;
    plugin->configure             = dummy_configure;
    plugin->reset = dummy_reset;
    plugin->extract_data = dummy_extract;
    plugin->vm_pre_launch_hook = dummy_vm_pre_launch_hook;
    plugin->vm_post_launch_hook = dummy_vm_post_launch_hook;
    plugin->vcpu_pre_launch_hook = dummy_vcpu_pre_launch_hook;
    plugin->vcpu_post_launch_hook = dummy_vcpu_post_launch_hook;

    state->flags.reset_on_snapshot_restore = true;
    dummy_state *d_state = calloc(1, sizeof(dummy_state));
    memset(d_state->buf, 0x42, sizeof(d_state->buf));
    state->internal_state = d_state;

    return true;
}
