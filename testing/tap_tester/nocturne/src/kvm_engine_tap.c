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

#include "kvm_engine_tap.h"

// Checks that a new kvm_engine object was created correctly
static void
check_new_kvm_engine(kvm_engine *engine)
{
    if(
        !engine->vm ||
        engine->plugin_count)
    {
        ok(false, "New kvm_engine object initialized incorrectly.");
    } else {
        ok(true, "New kvm_engine object initialized incorrectly.");
    }
}

// reset environment variables used for communication with dummy plugin #1
static void
reset_dummy_env() {
    unsetenv("DUMMY_INIT_CALLED");
    unsetenv("DUMMY_ENABLE_CALLED");
    unsetenv("DUMMY_DISABLE_CALLED");
    unsetenv("DUMMY_FREE_STATE_CALLED");
    unsetenv("DUMMY_CONFIGURE_CALLED");
    unsetenv("DUMMY_CONFIG_PASSED_CORRECTLY");
    unsetenv("DUMMY_RESET_CALLED");
    unsetenv("DUMMY_RESET_STATE_PASSED");
    unsetenv("DUMMY_EXTRACT_CALLED");
    unsetenv("DUMMY_EXTRACT_STATE_PASSED_CORRECTLY");
    unsetenv("DUMMY_VM_PRE_LAUNCH_HOOK_CALLED");
    unsetenv("DUMMY_VM_POST_LAUNCH_HOOK_CALLED");
    unsetenv("DUMMY_VCPU_PRE_LAUNCH_HOOK_CALLED");
    unsetenv("DUMMY_VCPU_POST_LAUNCH_HOOK_CALLED");
}

// reset environment variables used for communication with dummy plugin #2
static void
reset_dummy2_env() {
    unsetenv("DUMMY2_INIT_CALLED");
    unsetenv("DUMMY2_ENABLE_CALLED");
    unsetenv("DUMMY2_DISABLE_CALLED");
    unsetenv("DUMMY2_FREE_STATE_CALLED");
    unsetenv("DUMMY2_CONFIGURE_CALLED");
    unsetenv("DUMMY2_CONFIG_PASSED_CORRECTLY");
    unsetenv("DUMMY2_RESET_CALLED");
    unsetenv("DUMMY2_RESET_STATE_PASSED");
    unsetenv("DUMMY2_EXTRACT_CALLED");
    unsetenv("DUMMY2_EXTRACT_STATE_PASSED_CORRECTLY");
    unsetenv("DUMMY2_VM_PRE_LAUNCH_HOOK_CALLED");
    unsetenv("DUMMY2_VM_POST_LAUNCH_HOOK_CALLED");
    unsetenv("DUMMY2_VCPU_PRE_LAUNCH_HOOK_CALLED");
    unsetenv("DUMMY2_VCPU_POST_LAUNCH_HOOK_CALLED");
}

// helper to construct a kvm_engine from a serialized vm snapshot.
kvm_engine *
construct_kvm_engine_helper(const char * serialized_vm_path)
{
    kvm_vm *vm = kvm_vm_deserialize(serialized_vm_path);
    return kvm_engine_wrap_vm(vm);
}

// helper to destroy a kvm_engine and it's vm.
void
destruct_kvm_engine_helper(kvm_engine *engine) {
    kvm_vm *vm = kvm_engine_unwrap_vm(engine);
    kvm_vm_free(vm);

    reset_dummy_env();
    reset_dummy2_env();
}

// tests basic instantiation of a kvm_engine
static void
test_kvm_engine_wrap_vm()
{
    kvm_vm *vm = kvm_vm_create();
    kvm_engine *engine = kvm_engine_wrap_vm(vm);
    check_new_kvm_engine(engine);

    kvm_vm_free(vm);
    free(engine);
}

// tests basic destruction of a kvm_engine
static void
test_kvm_engine_unwrap_vm()
{
    kvm_vm *vm = kvm_vm_create();
    kvm_engine *engine = kvm_engine_wrap_vm(vm);
    kvm_vm *vm_retval = kvm_engine_unwrap_vm(engine);
    if(!vm_retval || vm_retval != vm) {
        ok(false, "kvm_engine_unwrap_vm Failed.");
    }
    ok(true, "kvm_engine_unwrap_vm behaved as expected.");
    kvm_vm_free(vm);
}

// tests basic destruction of a kvm_engine
static void
test_kvm_engine_unwrap_vm_dummy_single(const char * serialized_vm_path)
{
    kvm_engine *engine = construct_kvm_engine_helper(serialized_vm_path);
    kvm_vm *vm = engine->vm;
    kvm_engine_load_plugin(engine, "./libdummy_plugin.so", true);
    reset_dummy_env();
    kvm_vm *vm_retval = kvm_engine_unwrap_vm(engine);
    if(!vm_retval || vm_retval != vm) {
        ok(false, "kvm_engine_unwrap_vm: failed.");
    }
    ok(true, "kvm_engine_unwrap_vm: behaved as expected.");

    if(getenv("DUMMY_DISABLE_CALLED")) {
        ok(true, "test_kvm_engine_unwrap_vm_dummy_single: Properly disabled dummy plugin.");
    } else{
        ok(false, "test_kvm_engine_unwrap_vm_dummy_single: Did not disable dummy plugin.");
    }

    if(getenv("DUMMY_FREE_STATE_CALLED")) {
        ok(true, "test_kvm_engine_unwrap_vm_dummy_single: Properly freed dummy plugin internal state.");
    } else{
        ok(false, "test_kvm_engine_unwrap_vm_dummy_single: Did not free dummy plugin internal state.");
    }
    kvm_vm_free(vm);
    reset_dummy_env();
}

// tests basic destruction of a kvm_engine
static void
test_kvm_engine_unwrap_vm_dummy_multi(const char * serialized_vm_path)
{
    kvm_engine *engine = construct_kvm_engine_helper(serialized_vm_path);
    kvm_vm *vm = engine->vm;
    kvm_engine_load_plugin(engine, "./libdummy_plugin.so", true);
    kvm_engine_load_plugin(engine, "./libdummy2_plugin.so", true);
    reset_dummy_env();
    reset_dummy2_env();
    kvm_vm *vm_retval = kvm_engine_unwrap_vm(engine);
    if(!vm_retval || vm_retval != vm) {
        ok(false, "kvm_engine_unwrap_vm: failed.");
    }
    ok(true, "kvm_engine_unwrap_vm: behaved as expected.");

    if(getenv("DUMMY_DISABLE_CALLED")) {
        ok(true, "test_kvm_engine_unwrap_vm_dummy_multi: Properly disabled dummy plugin.");
    } else{
        ok(false, "test_kvm_engine_unwrap_vm_dummy_multi: Did not disable dummy plugin.");
    }

    if(getenv("DUMMY_FREE_STATE_CALLED")) {
        ok(true, "test_kvm_engine_unwrap_vm_dummy_multi: Properly freed dummy plugin internal state.");
    } else{
        ok(false, "test_kvm_engine_unwrap_vm_dummy_multi: Did not free dummy plugin internal state.");
    }

    if(getenv("DUMMY2_DISABLE_CALLED")) {
        ok(true, "test_kvm_engine_unwrap_vm_dummy_multi: Properly disabled dummy2 plugin.");
    } else{
        ok(false, "test_kvm_engine_unwrap_vm_dummy_multi: Did not disable dummy2 plugin.");
    }

    if(getenv("DUMMY2_FREE_STATE_CALLED")) {
        ok(true, "test_kvm_engine_unwrap_vm_dummy_multi: Properly freed dummy2 plugin internal state.");
    } else{
        ok(false, "test_kvm_engine_unwrap_vm_dummy_multi: Did not free dummy2 plugin internal state.");
    }

    kvm_vm_free(vm);
    reset_dummy_env();
    reset_dummy2_env();
}

static void
test_kvm_engine_load_plugin_dummy_single(const char * serialized_vm_path)
{
    // test loading of a plugin, not enabled at load time.
    kvm_engine *e = construct_kvm_engine_helper(serialized_vm_path);
    kvm_engine_load_plugin(e, "./libdummy_plugin.so", false);

    if(getenv("DUMMY_INIT_CALLED")){
        ok(true, "kvm_engine_load_plugin: successfully called dummy plugin's init function.");
    } else {
        ok(false, "kvm_engine_load_plugin: Failed to call dummy plugin's init function.");
    }
    if(getenv("DUMMY_ENABLE_CALLED")){
        ok(false, "kvm_engine_load_plugin: Called dummy plugin's enable function, it should not have.");
    } else {
        ok(true, "kvm_engine_load_plugin: Correctly did not call dummy plugin's enable function.");
    }
    if(e->plugin_count == 1) {
        ok(true, "kvm_engine_load_plugin: Correct plugin count.");
    } else {
        ok(false, "kvm_engine_load_plugin: Incorrect plugin count.");
    }
    reset_dummy_env();

    // tests to see if kvm_engine will load a duplicate plugin.
    kvm_engine_load_plugin(e, "./libdummy_plugin.so", false);
    if(getenv("DUMMY_INIT_CALLED") && !getenv("DUMMY_FREE_STATE_CALLED")){
        ok(false, "kvm_engine_load_plugin: Loaded a duplicate plugin.");
    } else {
        ok(true, "kvm_engine_load_plugin: Did not load a duplicate plugin.");
    }
    if(getenv("DUMMY_ENABLE_CALLED")){
        ok(false, "kvm_engine_load_plugin: Called dummy plugin's enable function, it should not have.");
    } else {
        ok(true, "kvm_engine_load_plugin: Correctly did not call dummy plugin's enable function.");
    }
    if(e->plugin_count == 1) {
        ok(true, "kvm_engine_load_plugin: Correct plugin count.");
    } else {
        ok(false, "kvm_engine_load_plugin: Incorrect plugin count.");
    }
    reset_dummy_env();
    destruct_kvm_engine_helper(e);
    // tests loading of a plugin, enabled at load time.
    e = construct_kvm_engine_helper(serialized_vm_path);
    kvm_engine_load_plugin(e, "./libdummy_plugin.so", true);

    if(getenv("DUMMY_INIT_CALLED")){
        ok(true, "kvm_engine_load_plugin: successfully called dummy plugin's init function.");
    } else {
        ok(false, "kvm_engine_load_plugin: Failed to call dummy plugin's init function.");
    }
    if(getenv("DUMMY_ENABLE_CALLED")){
        ok(true, "kvm_engine_load_plugin: successfully called dummy plugin's enable function.");
    } else {
        ok(false, "kvm_engine_load_plugin: Failed to call dummy plugin's enable function.");
    }
    if(e->plugin_count == 1) {
        ok(true, "kvm_engine_load_plugin: Correct plugin count.");
    } else {
        ok(false, "kvm_engine_load_plugin: Incorrect plugin count.");
    }
    reset_dummy_env();

    // tests to see if kvm_engine will load a duplicate plugin, enabled at load time.
    kvm_engine_load_plugin(e, "./libdummy_plugin.so", true);
    if(getenv("DUMMY_INIT_CALLED") && !getenv("DUMMY_FREE_STATE_CALLED")){
        ok(false, "kvm_engine_load_plugin: Loaded a duplicate plugin, init was called.");
    } else {
        ok(true, "kvm_engine_load_plugin: Did not load a duplicate plugin, init was not called.");
    }
    if(getenv("DUMMY_ENABLE_CALLED")){
        ok(false, "kvm_engine_load_plugin: Loaded a duplicate plugin, enable was called.");
    } else {
        ok(true, "kvm_engine_load_plugin: Did not load a duplicate plugin, enable was not called.");
    }
    if(e->plugin_count == 1) {
        ok(true, "kvm_engine_load_plugin: Correct plugin count.");
    } else {
        ok(false, "kvm_engine_load_plugin: Incorrect plugin count.");
    }
    destruct_kvm_engine_helper(e);
}

static void
test_kvm_engine_load_plugin_dummy_multi(const char * serialized_vm_path)
{
    kvm_engine *e = construct_kvm_engine_helper(serialized_vm_path);
    // test loading of two plugins, not enabled at load time.
    kvm_engine_load_plugin(e, "./libdummy_plugin.so", false);
    kvm_engine_load_plugin(e, "./libdummy2_plugin.so", false);

    if(getenv("DUMMY_INIT_CALLED") && getenv("DUMMY2_INIT_CALLED")){
        ok(true, "kvm_engine_load_plugin: successfully called both dummy plugin's init function.");
    } else {
        ok(false, "kvm_engine_load_plugin: Failed to call either dummy plugin's init function.");
    }
    if(getenv("DUMMY_ENABLE_CALLED") || getenv("DUMMY2_ENABLE_CALLED")){
        ok(false, "kvm_engine_load_plugin: Called a plugin's enable function, it should not have.");
    } else {
        ok(true, "kvm_engine_load_plugin: Correctly did not call either dummy plugin's enable function.");
    }
    if(e->plugin_count == 2) {
        ok(true, "kvm_engine_load_plugin: Correct plugin count.");
    } else {
        ok(false, "kvm_engine_load_plugin: Incorrect plugin count.");
    }
    reset_dummy_env();
    reset_dummy2_env();
    // tests to see if kvm_engine will load a duplicate plugin, not enabled at load time.
    kvm_engine_load_plugin(e, "./libdummy_plugin.so", false);
    if(getenv("DUMMY_INIT_CALLED") && !getenv("DUMMY_FREE_STATE_CALLED")){
        ok(false, "kvm_engine_load_plugin: Loaded a duplicate plugin.");
    } else {
        ok(true, "kvm_engine_load_plugin: Did not load a duplicate plugin.");
    }
    if(getenv("DUMMY_ENABLE_CALLED")){
        ok(false, "kvm_engine_load_plugin: Called dummy plugin's enable function, it should not have.");
    } else {
        ok(true, "kvm_engine_load_plugin: Correctly did not call dummy plugin's enable function.");
    }
    if(getenv("DUMMY2_INIT_CALLED") && !getenv("DUMMY2_FREE_STATE_CALLED")){
        ok(false, "kvm_engine_load_plugin: Loaded a duplicate plugin.");
    } else {
        ok(true, "kvm_engine_load_plugin: Did not load a duplicate plugin.");
    }
    if(getenv("DUMMY2_ENABLE_CALLED")){
        ok(false, "kvm_engine_load_plugin: Called dummy2 plugin's enable function, it should not have.");
    } else {
        ok(true, "kvm_engine_load_plugin: Correctly did not call dummy2 plugin's enable function.");
    }
    if(e->plugin_count == 2) {
        ok(true, "kvm_engine_load_plugin: Correct plugin count.");
    } else {
        ok(false, "kvm_engine_load_plugin: Incorrect plugin count.");
    }

    destruct_kvm_engine_helper(e);
    // test loading of two plugins, enabled at load time.
    e = construct_kvm_engine_helper(serialized_vm_path);
    kvm_engine_load_plugin(e, "./libdummy_plugin.so", true);
    kvm_engine_load_plugin(e, "./libdummy2_plugin.so", true);

    if(getenv("DUMMY_INIT_CALLED") && getenv("DUMMY2_INIT_CALLED")){
        ok(true, "kvm_engine_load_plugin: successfully called both dummy plugin's init functions.");
    } else {
        ok(false, "kvm_engine_load_plugin: Failed to call a dummy plugin's init function.");
    }
    if(getenv("DUMMY_ENABLE_CALLED") && getenv("DUMMY2_ENABLE_CALLED")){
        ok(true, "kvm_engine_load_plugin: successfully called both dummy plugin's enable function.");
    } else {
        ok(false, "kvm_engine_load_plugin: Failed to call a dummy plugin's enable function.");
    }
    if(e->plugin_count == 2) {
        ok(true, "kvm_engine_load_plugin: Correct plugin count.");
    } else {
        ok(false, "kvm_engine_load_plugin: Incorrect plugin count.");
    }
    reset_dummy_env();
    reset_dummy2_env();

    // tests to see if kvm_engine will load a duplicate plugin, enabled at load time.
    kvm_engine_load_plugin(e, "./libdummy_plugin.so", true);
    if(getenv("DUMMY_INIT_CALLED") && !getenv("DUMMY_FREE_STATE_CALLED")){
        ok(false, "kvm_engine_load_plugin: Loaded a duplicate plugin, init was called.");
    } else {
        ok(true, "kvm_engine_load_plugin: Did not load a duplicate plugin, init was not called.");
    }
    if(getenv("DUMMY_ENABLE_CALLED")){
        ok(false, "kvm_engine_load_plugin: Loaded a duplicate plugin, enable was called.");
    } else {
        ok(true, "kvm_engine_load_plugin: Did not load a duplicate plugin, enable was not called.");
    }
    if(e->plugin_count == 2) {
        ok(true, "kvm_engine_load_plugin: Correct plugin count.");
    } else {
        ok(false, "kvm_engine_load_plugin: Incorrect plugin count.");
    }
    destruct_kvm_engine_helper(e);
}

static void
test_kvm_vm_unload_plugin_dummy_single(const char * serialized_vm_path)
{
    kvm_engine *e = construct_kvm_engine_helper(serialized_vm_path);
    // test unloading of a single plugin, not enabled at load time.
    u64 p_id = (u64)kvm_engine_load_plugin(e, "./libdummy_plugin.so", false);
    kvm_engine_unload_plugin(e, p_id);

    if(getenv("DUMMY_DISABLE_CALLED")) {
        ok(false, "kvm_engine_unload_plugin: Called dummy plugin's disable function, it should not have.");
    } else {
        ok(true, "kvm_engine_unload_plugin: Correctly did not call dummy plugin's disable function.");
    }
    if(getenv("DUMMY_FREE_STATE_CALLED")) {
		ok(true, "kvm_engine_unload_plugin: Correctly called dummy plugin's free_state function.");
	}else {
        ok(false, "kvm_engine_unload_plugin: Did not call dummy plugin's free_state function.");
    }
    if(e->plugin_count == 0) {
        ok(true, "kvm_engine_unload_plugin: Correct plugin count.");
    } else {
        ok(false, "kvm_engine_unload_plugin: Incorrect plugin count.");
    }

    destruct_kvm_engine_helper(e);
    // test unloading of a single plugin, enabled at load time.
    e = construct_kvm_engine_helper(serialized_vm_path);
    kvm_engine_load_plugin(e, "./libdummy_plugin.so", true);
    kvm_engine_unload_plugin(e, p_id);

    if(getenv("DUMMY_DISABLE_CALLED")) {
        ok(true, "kvm_engine_unload_plugin: Correctly called dummy plugin's disable function.");
    } else {
        ok(false, "kvm_engine_unload_plugin: Did not call dummy plugin's disable function.");
    }
    if(getenv("DUMMY_FREE_STATE_CALLED")) {
        ok(true, "kvm_engine_unload_plugin: Correctly called dummy plugin's free_state function.");
    }else {
        ok(false, "kvm_engine_unload_plugin: Did not call dummy plugin's free_state function.");
    }
    if(e->plugin_count == 0) {
        ok(true, "kvm_engine_unload_plugin: Correct plugin count.");
    } else {
        ok(false, "kvm_engine_unload_plugin: Incorrect plugin count.");
    }

    destruct_kvm_engine_helper(e);
    // test unloading of non-existent plugin
    e = construct_kvm_engine_helper(serialized_vm_path);
    if(kvm_engine_unload_plugin(e, p_id)) {
        ok(false, "kvm_engine_unload_plugin: unloaded nonexistent plugin.");
    } else {
        ok(true, "kvm_engine_unload_plugin: Correctly did not unload any plugins.");
    }
    if(e->plugin_count == 0) {
        ok(true, "kvm_engine_unload_plugin: Correct plugin count.");
    } else {
        ok(false, "kvm_engine_unload_plugin: Incorrect plugin count.");
    }
    // test double unload of a plugin
    kvm_engine_load_plugin(e, "./libdummy_plugin.so", false);
    kvm_engine_unload_plugin(e, p_id);
    if(kvm_engine_unload_plugin(e, p_id)) {
        ok(false, "kvm_engine_unload_plugin: Double unload.");
    } else {
        ok(true, "kvm_engine_unload_plugin: Correctly did not unload any plugins.");
    }
    if(e->plugin_count == 0) {
        ok(true, "kvm_engine_unload_plugin: Correct plugin count.");
    } else {
        ok(false, "kvm_engine_unload_plugin: Incorrect plugin count.");
    }
    destruct_kvm_engine_helper(e);
}

static void
test_kvm_vm_unload_plugin_dummy_multi(const char * serialized_vm_path)
{
    kvm_engine *e = construct_kvm_engine_helper(serialized_vm_path);

    u64 p1_id = (u64)kvm_engine_load_plugin(e, "./libdummy_plugin.so", false);
    kvm_engine_load_plugin(e, "./libdummy2_plugin.so", false);

    // given two loaded plugins, test unloading of first plugin, not enabled at load time
    kvm_engine_unload_plugin(e, p1_id);

    if(getenv("DUMMY_DISABLE_CALLED")) {
        ok(false, "kvm_engine_unload_plugin: Called dummy plugin's disable function, it should not have.");
    } else {
        ok(true, "kvm_engine_unload_plugin: Correctly did not call dummy plugin's disable function.");
    }
    if(getenv("DUMMY_FREE_STATE_CALLED")) {
        ok(true, "kvm_engine_unload_plugin: Correctly called dummy plugin's free_state function.");
    }else {
        ok(false, "kvm_engine_unload_plugin: Did not call dummy plugin's free_state function.");
    }
    if(getenv("DUMMY2_DISABLE_CALLED")) {
        ok(false, "kvm_engine_unload_plugin: Called dummy2 plugin's disable function, it should not have.");
    } else {
        ok(true, "kvm_engine_unload_plugin: Correctly did not call dummy2 plugin's disable function.");
    }
    if(getenv("DUMMY2_FREE_STATE_CALLED")) {
        ok(false, "kvm_engine_unload_plugin: Incorrectly called dummy2 plugin's free_state function.");
    }else {
        ok(true, "kvm_engine_unload_plugin:  Correctly did not call dummy2 plugin's free_state function.");
    }
    if(e->plugin_count == 1) {
        ok(true, "kvm_engine_unload_plugin: Correct plugin count.");
    } else {
        ok(false, "kvm_engine_unload_plugin: Incorrect plugin count.");
    }
    destruct_kvm_engine_helper(e);

    e = construct_kvm_engine_helper(serialized_vm_path);
    kvm_engine_load_plugin(e, "./libdummy_plugin.so", false);
    u64 p2_id = (u64)kvm_engine_load_plugin(e, "./libdummy2_plugin.so", false);
    // given two loaded plugins, test unloading of second plugin, not enabled at load time
    kvm_engine_unload_plugin(e, p2_id);

    if(getenv("DUMMY2_DISABLE_CALLED")) {
        ok(false, "kvm_engine_unload_plugin: Called dummy2 plugin's disable function, it should not have.");
    } else {
        ok(true, "kvm_engine_unload_plugin: Correctly did not call dummy2 plugin's disable function.");
    }
    if(getenv("DUMMY2_FREE_STATE_CALLED")) {
        ok(true, "kvm_engine_unload_plugin: Correctly called dummy2 plugin's free_state function.");
    }else {
        ok(false, "kvm_engine_unload_plugin: Did not call dummy2 plugin's free_state function.");
    }
    if(getenv("DUMMY_DISABLE_CALLED")) {
        ok(false, "kvm_engine_unload_plugin: Called dummy plugin's disable function, it should not have.");
    } else {
        ok(true, "kvm_engine_unload_plugin: Correctly did not call dummy plugin's disable function.");
    }
    if(getenv("DUMMY_FREE_STATE_CALLED")) {
        ok(false, "kvm_engine_unload_plugin: Incorrectly called dummy plugin's free_state function.");
    }else {
        ok(true, "kvm_engine_unload_plugin:  Correctly did not call dummy plugin's free_state function.");
    }
    if(e->plugin_count == 1) {
        ok(true, "kvm_engine_unload_plugin: Correct plugin count.");
    } else {
        ok(false, "kvm_engine_unload_plugin: Incorrect plugin count.");
    }

    destruct_kvm_engine_helper(e);

    e = construct_kvm_engine_helper(serialized_vm_path);
    p1_id = (u64)kvm_engine_load_plugin(e, "./libdummy_plugin.so", true);
    kvm_engine_load_plugin(e, "./libdummy2_plugin.so", true);
    // given two loaded plugins, test unloading of first plugin, enabled at load time
    kvm_engine_unload_plugin(e, p1_id);

    if(getenv("DUMMY_DISABLE_CALLED")) {
        ok(true, "kvm_engine_unload_plugin: Called dummy plugin's disable function.");
    } else {
        ok(false, "kvm_engine_unload_plugin: Did not call dummy plugin's disable function.");
    }
    if(getenv("DUMMY_FREE_STATE_CALLED")) {
        ok(true, "kvm_engine_unload_plugin: Correctly called dummy plugin's free_state function.");
    }else {
        ok(false, "kvm_engine_unload_plugin: Did not call dummy plugin's free_state function.");
    }
    if(getenv("DUMMY2_DISABLE_CALLED")) {
        ok(false, "kvm_engine_unload_plugin: Called dummy2 plugin's disable function, it should not have.");
    } else {
        ok(true, "kvm_engine_unload_plugin: Correctly did not call dummy2 plugin's disable function.");
    }
    if(getenv("DUMMY2_FREE_STATE_CALLED")) {
        ok(false, "kvm_engine_unload_plugin: Incorrectly called dummy2 plugin's free_state function.");
    }else {
        ok(true, "kvm_engine_unload_plugin:  Correctly did not call dummy2 plugin's free_state function.");
    }
    if(e->plugin_count == 1) {
        ok(true, "kvm_engine_unload_plugin: Correct plugin count.");
    } else {
        ok(false, "kvm_engine_unload_plugin: Incorrect plugin count.");
    }
    destruct_kvm_engine_helper(e);

    e = construct_kvm_engine_helper(serialized_vm_path);
    kvm_engine_load_plugin(e, "./libdummy_plugin.so", true);
    p2_id = (u64)kvm_engine_load_plugin(e, "./libdummy2_plugin.so", true);

    // given two loaded plugins, test unloading of second plugin, enabled at load time
    kvm_engine_unload_plugin(e, p2_id);

    if(getenv("DUMMY2_DISABLE_CALLED")) {
        ok(true, "kvm_engine_unload_plugin: Called dummy2 plugin's disable function.");
    } else {
        ok(false, "kvm_engine_unload_plugin: Did not call dummy2 plugin's disable function.");
    }
    if(getenv("DUMMY2_FREE_STATE_CALLED")) {
        ok(true, "kvm_engine_unload_plugin: Correctly called dummy2 plugin's free_state function.");
    }else {
        ok(false, "kvm_engine_unload_plugin: Did not call dummy2 plugin's free_state function.");
    }
    if(getenv("DUMMY_DISABLE_CALLED")) {
        ok(false, "kvm_engine_unload_plugin: Called dummy plugin's disable function, it should not have.");
    } else {
        ok(true, "kvm_engine_unload_plugin: Correctly did not call dummy plugin's disable function.");
    }
    if(getenv("DUMMY_FREE_STATE_CALLED")) {
        ok(false, "kvm_engine_unload_plugin: Incorrectly called dummy plugin's free_state function.");
    }else {
        ok(true, "kvm_engine_unload_plugin:  Correctly did not call dummy plugin's free_state function.");
    }
    if(e->plugin_count == 1) {
        ok(true, "kvm_engine_unload_plugin: Correct plugin count.");
    } else {
        ok(false, "kvm_engine_unload_plugin: Incorrect plugin count.");
    }
    destruct_kvm_engine_helper(e);

    e = construct_kvm_engine_helper(serialized_vm_path);
    p1_id = (u64)kvm_engine_load_plugin(e, "./libdummy_plugin.so", true);
    p2_id = (u64)kvm_engine_load_plugin(e, "./libdummy2_plugin.so", true);
    // given two loaded plugins, test unloading of both plugins, enabled at load time
    kvm_engine_unload_plugin(e, p1_id);
    kvm_engine_unload_plugin(e, p2_id);

    if(getenv("DUMMY_DISABLE_CALLED")) {
        ok(true, "kvm_engine_unload_plugin: Called dummy plugin's disable function.");
    } else {
        ok(false, "kvm_engine_unload_plugin: Did not call dummy plugin's disable function.");
    }
    if(getenv("DUMMY_FREE_STATE_CALLED")) {
        ok(true, "kvm_engine_unload_plugin: Correctly called dummy plugin's free_state function.");
    }else {
        ok(false, "kvm_engine_unload_plugin: Did not call dummy plugin's free_state function.");
    }
    if(getenv("DUMMY2_DISABLE_CALLED")) {
        ok(true, "kvm_engine_unload_plugin: Called dummy2 plugin's disable function.");
    } else {
        ok(false, "kvm_engine_unload_plugin: Did not call dummy2 plugin's disable function.");
    }
    if(getenv("DUMMY2_FREE_STATE_CALLED")) {
        ok(true, "kvm_engine_unload_plugin: Called dummy2 plugin's free_state function.");
    }else {
        ok(false, "kvm_engine_unload_plugin: Did not call dummy2 plugin's free_state function.");
    }
    if(e->plugin_count == 0) {
        ok(true, "kvm_engine_unload_plugin: Correct plugin count.");
    } else {
        ok(false, "kvm_engine_unload_plugin: Incorrect plugin count.");
    }
    destruct_kvm_engine_helper(e);

    e = construct_kvm_engine_helper(serialized_vm_path);
    p1_id = (u64)kvm_engine_load_plugin(e, "./libdummy_plugin.so", false);
    kvm_engine_load_plugin(e, "./libdummy2_plugin.so", false);
    // given two loaded plugins, test double-unloading of first plugin
    kvm_engine_unload_plugin(e, p1_id);
    if(kvm_engine_unload_plugin(e, p1_id)) {
        ok(false, "kvm_engine_unload_plugin: Double unload.");
    } else {
        ok(true, "kvm_engine_unload_plugin: Correctly did not unload any plugins.");
    }
    if(e->plugin_count == 1) {
        ok(true, "kvm_engine_unload_plugin: Correct plugin count.");
    } else {
        ok(false, "kvm_engine_unload_plugin: Incorrect plugin count.");
    }
    destruct_kvm_engine_helper(e);
}

static void
test_kvm_engine_get_plugin_id_by_name_dummy_single(const char * serialized_vm_path)
{
    kvm_engine *e = construct_kvm_engine_helper(serialized_vm_path);
    s64 p1_id = kvm_engine_load_plugin(e, "./libdummy_plugin.so", true);
    // test get plugin name by id of single plugin
    s64 id = kvm_engine_get_plugin_id_by_name(e, "Test plugin");
    if(p1_id >= 0 && id >= 0 && id == p1_id){
        ok(true, "kvm_engine_get_plugin_id_by_name: Successfully got correct plugin id.");
    }else {
        ok(false, "kvm_engine_get_plugin_id_by_name: Faild to return the correct id.");
    }

    destruct_kvm_engine_helper(e);
}

static void
test_kvm_engine_get_plugin_id_by_name_dummy_multi(const char * serialized_vm_path)
{
    kvm_engine *e = construct_kvm_engine_helper(serialized_vm_path);
    kvm_engine_load_plugin(e, "./libdummy_plugin.so", true);
    kvm_engine_load_plugin(e, "./libdummy2_plugin.so", true);

    // test get plugin id by name with two plugins loaded
    s64 id = kvm_engine_get_plugin_id_by_name(e, "Test plugin");
    if(id == 0){
        ok(true, "kvm_engine_get_plugin_id_by_name: Successfully got correct plugin id.");
    }else {
        ok(false, "kvm_engine_get_plugin_id_by_name: Faild to return the correct id.");
    }
    id = kvm_engine_get_plugin_id_by_name(e, "Test plugin two");
    if(id == 1){
        ok(true, "kvm_engine_get_plugin_id_by_name: Successfully got correct plugin id.");
    }else {
        ok(false, "kvm_engine_get_plugin_id_by_name: Faild to return the correct id.");
    }

    destruct_kvm_engine_helper(e);
}

static void
test_kvm_engine_enable_plugin_dummy_single(const char * serialized_vm_path)
{
    kvm_engine *e = construct_kvm_engine_helper(serialized_vm_path);
    u64 p1_id = (u64)kvm_engine_load_plugin(e, "./libdummy_plugin.so", false);
    reset_dummy_env();
    // test enable plugin of a single plugin
    kvm_engine_enable_plugin(e, p1_id);

    if(getenv("DUMMY_ENABLE_CALLED")){
        ok(true, "kvm_engine_enable_plugin: successfully called dummy plugin's enable function.");
    } else {
        ok(false, "kvm_engine_enable_plugin: Failed to call dummy plugin's enable function.");
    }
    reset_dummy_env();
    // test for double enable
    kvm_engine_enable_plugin(e, p1_id);

    if(getenv("DUMMY_ENABLE_CALLED")){
        ok(false, "kvm_engine_enable_plugin: plugin was enabled, even though it was already enabled.");
    } else {
        ok(true, "kvm_engine_enable_plugin: Plugin was correctly not double-enabled.");
    }

    destruct_kvm_engine_helper(e);
}

static void
test_kvm_engine_enable_plugin_dummy_multi(const char * serialized_vm_path)
{
    kvm_engine *e = construct_kvm_engine_helper(serialized_vm_path);
    u64 p1_id = (u64)kvm_engine_load_plugin(e, "./libdummy_plugin.so", false);
    u64 p2_id = (u64)kvm_engine_load_plugin(e, "./libdummy2_plugin.so", false);
    reset_dummy_env();
    reset_dummy2_env();
    // given two loaded plugins, test for enable of first plugin
    kvm_engine_enable_plugin(e, p1_id);

    if(getenv("DUMMY_ENABLE_CALLED")){
        ok(true, "kvm_engine_enable_plugin: successfully called dummy plugin's enable function.");
    } else {
        ok(false, "kvm_engine_enable_plugin: Failed to call dummy plugin's enable function.");
    }
    reset_dummy_env();
    reset_dummy2_env();
    // given two loaded plugins, test for double-enable of first plugin
    kvm_engine_enable_plugin(e, p1_id);

    if(getenv("DUMMY_ENABLE_CALLED")){
        ok(false, "kvm_engine_enable_plugin: plugin was enabled, even though it was already enabled.");
    } else {
        ok(true, "kvm_engine_enable_plugin: Plugin was correctly not double-enabled.");
    }
    if(getenv("DUMMY2_ENABLE_CALLED")){
        ok(false, "kvm_engine_enable_plugin: Dummy2 plugin was enabled.");
    } else {
        ok(true, "kvm_engine_enable_plugin: Dummy2 plugin was not enabled.");
    }

    reset_dummy_env();
    reset_dummy2_env();
    // given two loaded plugins, test for enable of second plugin
    kvm_engine_enable_plugin(e, p2_id);

    if(getenv("DUMMY_ENABLE_CALLED")){
        ok(false, "kvm_engine_enable_plugin: plugin was enabled, even though it was already enabled.");
    } else {
        ok(true, "kvm_engine_enable_plugin: Plugin was correctly not double-enabled.");
    }

    if(getenv("DUMMY2_ENABLE_CALLED")){
        ok(true, "kvm_engine_enable_plugin: successfully called dummy2 plugin's enable function.");
    } else {
        ok(false, "kvm_engine_enable_plugin: Failed to call dummy2 plugin's enable function.");
    }
    reset_dummy_env();
    reset_dummy2_env();
    // given two loaded plugins, test for double-enable of second plugin
    kvm_engine_enable_plugin(e, p2_id);

    if(getenv("DUMMY2_ENABLE_CALLED")){
        ok(false, "kvm_engine_enable_plugin: dummy2 plugin was enabled, even though it was already enabled.");
    } else {
        ok(true, "kvm_engine_enable_plugin: Dummy2 plugin was correctly not double-enabled.");
    }

    destruct_kvm_engine_helper(e);
}

static void
test_kvm_engine_disable_plugin_dummy_single(const char * serialized_vm_path)
{
    kvm_engine *e = construct_kvm_engine_helper(serialized_vm_path);
    u64 p1_id = (u64)kvm_engine_load_plugin(e, "./libdummy_plugin.so", false);
    kvm_engine_enable_plugin(e, p1_id);
    reset_dummy_env();
    // test disable of a single plugin
    kvm_engine_disable_plugin(e, p1_id);

    if(getenv("DUMMY_DISABLE_CALLED")) {
        ok(true, "kvm_engine_disable_plugin: Correctly called dummy plugin's disable function.");
    } else {
        ok(false, "kvm_engine_disable_plugin: Did not call dummy plugin's disable function.");
    }
    reset_dummy_env();
    // test for double-disable of a single plugin
    kvm_engine_disable_plugin(e, p1_id);

    if(getenv("DUMMY_DISABLE_CALLED")) {
        ok(false, "kvm_engine_disable_plugin: Plugin was double-disabled.");
    } else {
        ok(true, "kvm_engine_disable_plugin: Plugin was not double-disabled.");
    }

    destruct_kvm_engine_helper(e);
}

static void
test_kvm_engine_disable_plugin_dummy_multi(const char * serialized_vm_path)
{
    kvm_engine *e = construct_kvm_engine_helper(serialized_vm_path);
    u64 p1_id = (u64)kvm_engine_load_plugin(e, "./libdummy_plugin.so", true);
    u64 p2_id = (u64)kvm_engine_load_plugin(e, "./libdummy2_plugin.so", true);
    reset_dummy_env();
    reset_dummy2_env();
    // given two loaded plugins, test disable of first plugin.
    kvm_engine_disable_plugin(e, p1_id);

    if(getenv("DUMMY_DISABLE_CALLED")) {
        ok(true, "kvm_engine_disable_plugin: Correctly called dummy plugin's disable function.");
    } else {
        ok(false, "kvm_engine_disable_plugin: Did not call dummy plugin's disable function.");
    }
    if(getenv("DUMMY2_DISABLE_CALLED")) {
        ok(false, "kvm_engine_disable_plugin: dummy2 plugin was disabled.");
    } else {
        ok(true, "kvm_engine_disable_plugin: dummy2 plugin was not disabled.");
    }

    reset_dummy_env();
    reset_dummy2_env();
    // given two loaded plugins, test double-disable of first plugin.
    kvm_engine_disable_plugin(e, p1_id);

    if(getenv("DUMMY_DISABLE_CALLED")) {
        ok(false, "kvm_engine_disable_plugin: Plugin was double-disabled.");
    } else {
        ok(true, "kvm_engine_disable_plugin: Plugin was not double-disabled.");
    }
    if(getenv("DUMMY2_DISABLE_CALLED")) {
        ok(false, "kvm_engine_disable_plugin: dummy2 plugin was disabled.");
    } else {
        ok(true, "kvm_engine_disable_plugin: dummy2 plugin was not disabled.");
    }
    reset_dummy_env();
    reset_dummy2_env();
    // given two loaded plugins, test disable of second plugin.
    kvm_engine_disable_plugin(e, p2_id);

    if(getenv("DUMMY2_DISABLE_CALLED")) {
        ok(true, "kvm_engine_disable_plugin: Correctly called dummy2 plugin's disable function.");
    } else {
        ok(false, "kvm_engine_disable_plugin: Did not call dummy2 plugin's disable function.");
    }
    if(getenv("DUMMY_DISABLE_CALLED")) {
        ok(false, "kvm_engine_disable_plugin: dummy plugin was disabled.");
    } else {
        ok(true, "kvm_engine_disable_plugin: dummy plugin was not disabled.");
    }

    destruct_kvm_engine_helper(e);
}

static void
test_kvm_engine_configure_plugin_dummy_single(const char * serialized_vm_path)
{
    kvm_engine *e = construct_kvm_engine_helper(serialized_vm_path);
    u64 p1_id = (u64)kvm_engine_load_plugin(e, "./libdummy_plugin.so", true);
    reset_dummy_env();
    void * config = (void *) 0xDEADBEEFCAFEBABE;
    // test configure of a single plugin
    kvm_engine_configure_plugin(
        e,
        p1_id,
        config
    );

    if(getenv("DUMMY_CONFIGURE_CALLED")) {
        ok(true,"kvm_engine_configure_plugin: Correctly called plugin configure.");
    } else {
        ok(false, "kvm_engine_configure_plugin: Failed to call plugin configure.");
    }
    if(getenv("DUMMY_CONFIG_PASSED_CORRECTLY")) {
        ok(true,"kvm_engine_configure_plugin: Correctly passed plugin config.");
    } else {
        ok(false, "kvm_engine_configure_plugin: Failed to pass plugin config.");
    }
    destruct_kvm_engine_helper(e);
}

static void
test_kvm_engine_configure_plugin_dummy_multi(const char * serialized_vm_path)
{
    kvm_engine *e = construct_kvm_engine_helper(serialized_vm_path);
    u64 p1_id = (u64)kvm_engine_load_plugin(e, "./libdummy_plugin.so", true);
    u64 p2_id = (u64)kvm_engine_load_plugin(e, "./libdummy2_plugin.so", true);
    reset_dummy_env();
    reset_dummy2_env();
    void * config = (void *) 0xDEADBEEFCAFEBABE;
    kvm_engine_configure_plugin(
        e,
        p1_id,
        config
    );

    if(getenv("DUMMY_CONFIGURE_CALLED")) {
        ok(true,"kvm_engine_configure_plugin: Correctly called plugin configure.");
    } else {
        ok(false, "kvm_engine_configure_plugin: Failed to call plugin configure.");
    }
    if(getenv("DUMMY_CONFIG_PASSED_CORRECTLY")) {
        ok(true,"kvm_engine_configure_plugin: Correctly passed plugin config.");
    } else {
        ok(false, "kvm_engine_configure_plugin: Failed to pass plugin config.");
    }
    if(getenv("DUMMY2_CONFIGURE_CALLED")) {
        ok(false,"kvm_engine_configure_plugin: Called dummy2 plugin configure.");
    } else {
        ok(true, "kvm_engine_configure_plugin: Did not call dummy2 plugin configure.");
    }

    reset_dummy_env();
    reset_dummy2_env();

    kvm_engine_configure_plugin(
        e,
        p2_id,
        config
    );

    if(getenv("DUMMY2_CONFIGURE_CALLED")) {
        ok(true,"kvm_engine_configure_plugin: Correctly called dummy2 plugin configure.");
    } else {
        ok(false, "kvm_engine_configure_plugin: Failed to call dummy2 plugin configure.");
    }
    if(getenv("DUMMY2_CONFIG_PASSED_CORRECTLY")) {
        ok(true,"kvm_engine_configure_plugin: Correctly passed dummy2 plugin config.");
    } else {
        ok(false, "kvm_engine_configure_plugin: Failed to pass dummy2 plugin config.");
    }
    if(getenv("DUMMY_CONFIGURE_CALLED")) {
        ok(false,"kvm_engine_configure_plugin: Called dummy plugin configure.");
    } else {
        ok(true, "kvm_engine_configure_plugin: Did not call dummy plugin configure.");
    }
    destruct_kvm_engine_helper(e);
}

static void
test_kvm_engine_reset_plugin_dummy_single(const char * serialized_vm_path)
{
	kvm_engine *e = construct_kvm_engine_helper(serialized_vm_path);
    u64 p1_id = (u64)kvm_engine_load_plugin(e, "./libdummy_plugin.so", true);
	reset_dummy_env();

	kvm_engine_reset_plugin(e, p1_id);
    if(getenv("DUMMY_RESET_CALLED")) {
        ok(true,"kvm_engine_reset_plugin: Correctly called plugin reset.");
    } else {
        ok(false, "kvm_engine_reset_plugin: Failed to call plugin reset.");
    }
    if(getenv("DUMMY_RESET_STATE_PASSED")) {
        ok(true,"kvm_engine_reset_plugin: state was passed to plugin reset function.");
    } else {
        ok(false, "kvm_engine_reset_plugin: state was NOT passed to plugin reset function.");
    }

	destruct_kvm_engine_helper(e);
}

static void
test_kvm_engine_reset_plugin_dummy_multi(const char * serialized_vm_path)
{
    kvm_engine *e = construct_kvm_engine_helper(serialized_vm_path);
    u64 p1_id = (u64)kvm_engine_load_plugin(e, "./libdummy_plugin.so", true);
    u64 p2_id = (u64)kvm_engine_load_plugin(e, "./libdummy2_plugin.so", true);
    reset_dummy_env();
    reset_dummy2_env();
    // test reset of first plugin
    kvm_engine_reset_plugin(e, p1_id);
    if(getenv("DUMMY_RESET_CALLED")) {
        ok(true,"kvm_engine_reset_plugin: Correctly called plugin reset.");
    } else {
        ok(false, "kvm_engine_reset_plugin: Failed to call plugin reset.");
    }
    if(getenv("DUMMY_RESET_STATE_PASSED")) {
        ok(true,"kvm_engine_reset_plugin: state was passed to plugin reset function.");
    } else {
        ok(false, "kvm_engine_reset_plugin: state was NOT passed to plugin reset function.");
    }
    if(getenv("DUMMY2_RESET_CALLED")) {
        ok(false,"kvm_engine_reset_plugin: Called dummy2 plugin reset.");
    } else {
        ok(true, "kvm_engine_reset_plugin: Did not call dummy2 plugin reset.");
    }

    reset_dummy_env();
    reset_dummy2_env();
    // test reset of second plugin
    kvm_engine_reset_plugin(e, p2_id);

    if(getenv("DUMMY2_RESET_CALLED")) {
        ok(true,"kvm_engine_reset_plugin: Correctly called dummy2 plugin reset.");
    } else {
        ok(false, "kvm_engine_reset_plugin: Failed to call dummy2 plugin reset.");
    }
    if(getenv("DUMMY2_RESET_STATE_PASSED")) {
        ok(true,"kvm_engine_reset_plugin: state was passed to dummy2 plugin reset function.");
    } else {
        ok(false, "kvm_engine_reset_plugin: state was NOT passed to dummy2 plugin reset function.");
    }
    if(getenv("DUMMY_RESET_CALLED")) {
        ok(false,"kvm_engine_reset_plugin: Called dummy plugin reset.");
    } else {
        ok(true, "kvm_engine_reset_plugin: Did not call dummy plugin reset.");
    }

    destruct_kvm_engine_helper(e);
}

static void
test_kvm_engine_extract_plugin_data_dummy_single(const char * serialized_vm_path)
{
    kvm_engine *e = construct_kvm_engine_helper(serialized_vm_path);
    void * out = NULL;
    char expected_out[0x40];
    memset(expected_out, 0x41, 0x40);

    u64 p1_id = (u64)kvm_engine_load_plugin(e, "./libdummy_plugin.so", true);

    reset_dummy_env();
    size_t out_size = kvm_engine_extract_plugin_data(e, p1_id, &out);
    if(getenv("DUMMY_EXTRACT_CALLED")) {
        ok(true, "kvm_engine_extract_plugin_data: Correctly called plugin extract data function");
    } else {
        ok(false, "kvm_engine_extract_plugin_data: Failed to call plugin extract data function");
    }
    if(getenv("DUMMY_EXTRACT_STATE_PASSED_CORRECTLY")){
        ok(true, "kvm_engine_extract_plugin_data: Correctly passed plugin state.");
    } else {
        ok(false, "kvm_engine_extract_plugin_data: Failed to pass plugin state");
    }
    if(!memcmp(expected_out, out, 0x40)) {
        ok(true, "kvm_engine_extract_plugin_data: Output matched expected value.");
    } else {
        ok(false, "kvm_engine_extract_plugin_data: Output did not match expected value.");
    }
    if(out_size == (size_t)0x40) {
        ok(true, "kvm_engine_extract_plugin_data: Output size matched expected value.");
    } else {
        ok(false, "kvm_engine_extract_plugin_data: Output size did not match expected value.");
    }

    free(out);

    destruct_kvm_engine_helper(e);
}

static void
test_kvm_engine_extract_plugin_data_dummy_multi(const char * serialized_vm_path)
{
    kvm_engine *e = construct_kvm_engine_helper(serialized_vm_path);
    void * out = NULL;
    size_t out_size = 0;
    char expected_out[0x40];
    memset(expected_out, 0x42, 0x40);

    kvm_engine_load_plugin(e, "./libdummy_plugin.so", true);
    u64 p2_id = (u64)kvm_engine_load_plugin(e, "./libdummy2_plugin.so", true);

    reset_dummy_env();
    reset_dummy2_env();

    out_size = kvm_engine_extract_plugin_data(e, p2_id, &out);
    if(getenv("DUMMY2_EXTRACT_CALLED")) {
        ok(true, "kvm_engine_extract_plugin_data: Correctly called dummy2 plugin extract data function");
    } else {
        ok(false, "kvm_engine_extract_plugin_data: Failed to call dummy2 plugin extract data function");
    }
    if(getenv("DUMMY2_EXTRACT_STATE_PASSED_CORRECTLY")){
        ok(true, "kvm_engine_extract_plugin_data: Correctly passed dummy2 plugin state.");
    } else {
        ok(false, "kvm_engine_extract_plugin_data: Failed to pass dummy2 plugin state");
    }
    if(!memcmp(expected_out, out, 0x40)) {
        ok(true, "kvm_engine_extract_plugin_data: Output matched expected value.");
    } else {
        ok(false, "kvm_engine_extract_plugin_data: Output did not match expected value.");
    }
    if(out_size == 0x40) {
        ok(true, "kvm_engine_extract_plugin_data: Output size matched expected value.");
    } else {
        ok(false, "kvm_engine_extract_plugin_data: Output size did not match expected value.");
    }

    free(out);

    destruct_kvm_engine_helper(e);
}

static void
test_kvm_engine_get_plugin_description_dummy_single(const char * serialized_vm_path)
{
	kvm_engine *e = construct_kvm_engine_helper(serialized_vm_path);
    u64 p1_id = (u64)kvm_engine_load_plugin(e, "./libdummy_plugin.so", true);
	reset_dummy_env();

	const char * expected_desc = "This is a test plugin for conducting unit tests on kvm_engine. It is compiled directly into the unit tests for Nocturne.";
	const char * desc = kvm_engine_get_plugin_description(e, p1_id);

	if(desc && !strcmp(expected_desc, desc)){
	    ok(true, "kvm_engine_get_plugin_description: Returned expected result.");
    } else {
	    ok(false, "kvm_engine_get_plugin_description: Did not return the expected result.");
	}

	destruct_kvm_engine_helper(e);
}

static void
test_kvm_engine_get_plugin_description_dummy_multi(const char * serialized_vm_path)
{
    kvm_engine *e = construct_kvm_engine_helper(serialized_vm_path);
    u64 p1_id = (u64)kvm_engine_load_plugin(e, "./libdummy_plugin.so", true);
    u64 p2_id = (u64)kvm_engine_load_plugin(e, "./libdummy2_plugin.so", true);

    const char * expected_desc = "This is a test plugin for conducting unit tests on kvm_engine. It is compiled directly into the unit tests for Nocturne.";
    const char * desc = kvm_engine_get_plugin_description(e, p1_id);

    if(desc && !strcmp(expected_desc, desc)){
        ok(true, "kvm_engine_get_plugin_description: Returned expected result.");
    } else {
        ok(false, "kvm_engine_get_plugin_description: Did not return the expected result.");
    }
    desc = kvm_engine_get_plugin_description(e, p2_id);
    if(desc && !strcmp(expected_desc, desc)){
        ok(true, "kvm_engine_get_plugin_description: Returned expected result.");
    } else {
        ok(false, "kvm_engine_get_plugin_description: Did not return the expected result.");
    }

    destruct_kvm_engine_helper(e);
}

static void
test_kvm_engine_launch_hooks_dummy_single(const char * serialized_vm_path)
{
    kvm_engine *e = construct_kvm_engine_helper(serialized_vm_path);
    kvm_engine_load_plugin(e, "./libdummy_plugin.so", true);
    reset_dummy_env();

    kvm_engine_launch_vm(e);

    if(getenv("DUMMY_VM_PRE_LAUNCH_HOOK_CALLED")) {
        ok(true, "kvm_engine_launch_vm: VM pre launch hook was correctly invoked.");
    } else {
        ok(false, "kvm_engine_launch_vm: VM pre launch hook was not invoked.");
    }
    if(getenv("DUMMY_VM_POST_LAUNCH_HOOK_CALLED")) {
        ok(true, "kvm_engine_launch_vm: VM post launch hook was correctly invoked.");
    } else {
        ok(false, "kvm_engine_launch_vm: VM post launch hook was not invoked.");
    }
    if(getenv("DUMMY_VCPU_PRE_LAUNCH_HOOK_CALLED")) {
        ok(true, "kvm_engine_launch_vm: VCPU pre launch hook was correctly invoked.");
    } else {
        ok(false, "kvm_engine_launch_vm: VCPU pre launch hook was not invoked.");
    }
    if(getenv("DUMMY_VCPU_POST_LAUNCH_HOOK_CALLED")) {
        ok(true, "kvm_engine_launch_vm: VCPU post launch hook was correctly invoked.");
    } else {
        ok(false, "kvm_engine_launch_vm: VCPU post launch hook was not invoked.");
    }

    destruct_kvm_engine_helper(e);
}

static void
test_kvm_engine_launch_hooks_dummy_multi(const char * serialized_vm_path)
{
    kvm_engine *e = construct_kvm_engine_helper(serialized_vm_path);
    kvm_engine_load_plugin(e, "./libdummy_plugin.so", true);
    kvm_engine_load_plugin(e, "./libdummy2_plugin.so", true);
    reset_dummy_env();
    reset_dummy2_env();
    kvm_engine_launch_vm(e);

    if(getenv("DUMMY_VM_PRE_LAUNCH_HOOK_CALLED")) {
        ok(true, "kvm_engine_launch_vm: dummy plugin VM pre launch hook was correctly invoked.");
    } else {
        ok(false, "kvm_engine_launch_vm: dummy plugin VM pre launch hook was not invoked.");
    }
    if(getenv("DUMMY_VM_POST_LAUNCH_HOOK_CALLED")) {
        ok(true, "kvm_engine_launch_vm: dummy plugin VM post launch hook was correctly invoked.");
    } else {
        ok(false, "kvm_engine_launch_vm: dummy plugin VM post launch hook was not invoked.");
    }
    if(getenv("DUMMY_VCPU_PRE_LAUNCH_HOOK_CALLED")) {
        ok(true, "kvm_engine_launch_vm: dummy plugin VCPU pre launch hook was correctly invoked.");
    } else {
        ok(false, "kvm_engine_launch_vm: dummy plugin VCPU pre launch hook was not invoked.");
    }
    if(getenv("DUMMY_VCPU_POST_LAUNCH_HOOK_CALLED")) {
        ok(true, "kvm_engine_launch_vm: dummy plugin VCPU post launch hook was correctly invoked.");
    } else {
        ok(false, "kvm_engine_launch_vm: dummy plugin VCPU post launch hook was not invoked.");
    }
    if(getenv("DUMMY2_VM_PRE_LAUNCH_HOOK_CALLED")) {
        ok(true, "kvm_engine_launch_vm: dummy2 plugin VM pre launch hook was correctly invoked.");
    } else {
        ok(false, "kvm_engine_launch_vm: dummy2 plugin VM pre launch hook was not invoked.");
    }
    if(getenv("DUMMY2_VM_POST_LAUNCH_HOOK_CALLED")) {
        ok(true, "kvm_engine_launch_vm: dummy2 plugin VM post launch hook was correctly invoked.");
    } else {
        ok(false, "kvm_engine_launch_vm: dummy2 plugin VM post launch hook was not invoked.");
    }
    if(getenv("DUMMY2_VCPU_PRE_LAUNCH_HOOK_CALLED")) {
        ok(true, "kvm_engine_launch_vm: dummy2 plugin VCPU pre launch hook was correctly invoked.");
    } else {
        ok(false, "kvm_engine_launch_vm: dummy2 plugin VCPU pre launch hook was not invoked.");
    }
    if(getenv("DUMMY2_VCPU_POST_LAUNCH_HOOK_CALLED")) {
        ok(true, "kvm_engine_launch_vm: dummy2 plugin VCPU post launch hook was correctly invoked.");
    } else {
        ok(false, "kvm_engine_launch_vm: dummy2 plugin VCPU post launch hook was not invoked.");
    }

    destruct_kvm_engine_helper(e);
}

static void
test_kvm_engine_get_plugin_name_list(const char *serialized_vm_path)
{
    kvm_engine *e = construct_kvm_engine_helper(serialized_vm_path);
    kvm_engine_load_plugin(e, "./libdummy_plugin.so", false);
    kvm_engine_load_plugin(e, "./libdummy2_plugin.so", false);

    const char * dummy1_name = "Test plugin";
    const char * dummy2_name = "Test plugin two";
    const char ** name_list = kvm_engine_get_plugin_name_list(e, false);

    if(name_list[0] && !strcmp(dummy1_name, name_list[0])) {
        ok(true, "kvm_engine_get_plugin_name_list: First name in list matches expected result.");
    } else {
        ok(false, "kvm_engine_get_plugin_name_list: First name in list does not match the expected result.");
    }

    if(name_list[1] && !strcmp(dummy2_name, name_list[1])) {
        ok(true, "kvm_engine_get_plugin_name_list: Second name in list matches expected result.");
    } else {
        ok(false, "kvm_engine_get_plugin_name_list: Second name in list does not match the expected result.");
    }

    int count = 0;
    while(name_list[count]) {
        count++;
    }

    if(count == 2) {
        ok(true, "kvm_engine_get_plugin_name_list: Correct number of entries");
    } else {
        ok(true, "kvm_engine_get_plugin_name_list: Incorrect number of entries");
    }

    destruct_kvm_engine_helper(e);
    free(name_list);
}

// Runs all of the unit tests.
void
test_kvm_engine(const char * serialized_vm_path)
{
    diagnostics("Testing kvm_engine API.");
    test_kvm_engine_wrap_vm();
    test_kvm_engine_unwrap_vm();

    if(serialized_vm_path) {
        // Tests plugin API functions using a single dummy plugin
        diagnostics("Testing kvm_engine Plugin API with a single plugin.");
        test_kvm_engine_load_plugin_dummy_single(serialized_vm_path);
        test_kvm_vm_unload_plugin_dummy_single(serialized_vm_path);
        test_kvm_engine_get_plugin_id_by_name_dummy_single(serialized_vm_path);
        test_kvm_engine_enable_plugin_dummy_single(serialized_vm_path);
        test_kvm_engine_disable_plugin_dummy_single(serialized_vm_path);
        test_kvm_engine_unwrap_vm_dummy_single(serialized_vm_path);
        test_kvm_engine_configure_plugin_dummy_single(serialized_vm_path);
        test_kvm_engine_reset_plugin_dummy_single(serialized_vm_path);
        test_kvm_engine_extract_plugin_data_dummy_single(serialized_vm_path);
        test_kvm_engine_get_plugin_description_dummy_single(serialized_vm_path);
        test_kvm_engine_launch_hooks_dummy_single(serialized_vm_path);
        diagnostics("Single plugin kvm_engine API tests complete.");

        // Tests every plugin API function using two dummy plugins.
        diagnostics("Testing kvm_engine Plugin API with two plugins");
        test_kvm_engine_load_plugin_dummy_multi(serialized_vm_path);
        test_kvm_vm_unload_plugin_dummy_multi(serialized_vm_path);
        test_kvm_engine_get_plugin_id_by_name_dummy_multi(serialized_vm_path);
        test_kvm_engine_enable_plugin_dummy_multi(serialized_vm_path);
        test_kvm_engine_disable_plugin_dummy_multi(serialized_vm_path);
        test_kvm_engine_unwrap_vm_dummy_multi(serialized_vm_path);
        test_kvm_engine_configure_plugin_dummy_multi(serialized_vm_path);
        test_kvm_engine_reset_plugin_dummy_multi(serialized_vm_path);
        test_kvm_engine_extract_plugin_data_dummy_multi(serialized_vm_path);
        test_kvm_engine_get_plugin_description_dummy_multi(serialized_vm_path);
        test_kvm_engine_launch_hooks_dummy_multi(serialized_vm_path);
        test_kvm_engine_get_plugin_name_list(serialized_vm_path);
        diagnostics("kvm_engine Plugin API tests complete.");
    }

    diagnostics("kvm_engine API tests complete.");
}
