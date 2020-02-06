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

#include "intel_pt_tap.h"
#include <plugin.h>

// Unit tests for the intel_pt Nocturne plugin.

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

// helper function to validate whether or not the intel_pt internal state is tracking all VCPU's
static void
check_pt_state(kvm_engine *e, pt_state *s)
{
    kvm_vm *vm = e->vm;
    SIMPLE_TAP_TEST(vm->vcpu_count == s->vcpu_pt_count, "check_pt_state: vcpu count and vcpu_pt count comparison.")

    kvm_vcpu * vcpu_itr;
    RECORD_LIST_FOREACH(vcpu_itr, vm->kvm_vcpu_head) {
        bool found = false;
        kvm_vcpu_pt *vcpu_pt_itr;
        // check to see if we're already tracking this vcpu.
        RECORD_LIST_FOREACH(vcpu_pt_itr, s->vcpu_pt_list_head)
        {
            if(vcpu_pt_itr->vcpu == vcpu_itr) {
                found = true;
                break;
            }
        }
        SIMPLE_TAP_TEST(found, "check_pt_state: vcpu_pt object found for corresponding kvm_vcpu object.")
    }
    kvm_vcpu_pt *vcpu_pt_itr;
    RECORD_LIST_FOREACH(vcpu_pt_itr, s->vcpu_pt_list_head)
    {
        test_kvm_vcpu_pt_create(vcpu_pt_itr);
        test_kvm_vcpu_pt_default_config(vcpu_pt_itr);
    }
}

// test intel_pt populate function
static void
test_intel_pt_plugin_populate(const char * serialized_vm_path, const char * plugin_path)
{
    kvm_engine *e = construct_kvm_engine_helper(serialized_vm_path);
    u64 p_id = (u64)kvm_engine_load_plugin(e, plugin_path, false);
    kvmcore_plugin_record *p_r = get_plugin_helper(e, p_id);
    kvmcore_plugin *p = &p_r->plugin;
    kvmcore_plugin_state *s = &p_r->state;

    bool fn_ptrs_set_correctly = true;
    if(
        !p->enable ||
        !p->disable ||
        !p->free_state ||
        !p->configure ||
        !p->extract_data ||
        !p->vcpu_pre_launch_hook ||
        !p->vcpu_post_launch_hook
        )
    {
        fn_ptrs_set_correctly = false;
    }
    ok(fn_ptrs_set_correctly, "test_intel_pt_plugin_populate: Function pointer values.");

    SIMPLE_TAP_TEST(!s->flags.reset_on_snapshot_restore, "test_intel_pt_plugin_populate: reset_on_snapshot_restore value.")
    SIMPLE_TAP_TEST(s->internal_state, "test_intel_pt_plugin_populate: Internal state object.")

    check_pt_state(e, (pt_state *)s->internal_state);

    destruct_kvm_engine_helper(e);
}
// test plugin enable
static void
test_intel_pt_plugin_enable(const char * serialized_vm_path, const char * plugin_path)
{
    kvm_engine *e = construct_kvm_engine_helper(serialized_vm_path);
    u64 p_id = (u64)kvm_engine_load_plugin(e, plugin_path, false);

    // enable plugin
    kvm_engine_enable_plugin(e, p_id);

    kvmcore_plugin_record *p_r = get_plugin_helper(e, p_id);
    kvmcore_plugin_state *s = &p_r->state;
    pt_state * pt_state = s->internal_state;
    kvm_vcpu_pt *vcpu_pt_itr;

    // check each vcpu to ensure that they are marked as 'should enable'
    RECORD_LIST_FOREACH(vcpu_pt_itr, pt_state->vcpu_pt_list_head){
        test_kvm_vcpu_pt_mark_should_enable(vcpu_pt_itr);
    }

    destruct_kvm_engine_helper(e);
}

// test plugin disable
static void
test_intel_pt_plugin_disable(const char * serialized_vm_path, const char * plugin_path)
{
    kvm_engine *e = construct_kvm_engine_helper(serialized_vm_path);
    u64 p_id = (u64)kvm_engine_load_plugin(e, plugin_path, false);

    kvm_engine_enable_plugin(e, p_id);
    kvm_engine_disable_plugin(e, p_id);

    kvmcore_plugin_record *p_r = get_plugin_helper(e, p_id);
    kvmcore_plugin_state *s = &p_r->state;
    pt_state * pt_state = s->internal_state;
    kvm_vcpu_pt *vcpu_pt_itr;

    // check each vcpu to ensure that they are not marked as 'should enable'
    RECORD_LIST_FOREACH(vcpu_pt_itr, pt_state->vcpu_pt_list_head){
        test_kvm_vcpu_pt_mark_should_not_enable(vcpu_pt_itr);
    }

    destruct_kvm_engine_helper(e);
}

// test intel pt configuration function
static void
test_intel_pt_plugin_configure(const char * serialized_vm_path, const char * plugin_path)
{
    kvm_engine *e = construct_kvm_engine_helper(serialized_vm_path);
    u64 p_id = (u64)kvm_engine_load_plugin(e, plugin_path, false);

    // objects we will need later
    kvmcore_plugin_record *p_r = get_plugin_helper(e, p_id);
    kvmcore_plugin_state *s = &p_r->state;
    pt_state * pt_state = s->internal_state;

    // Instantiate a vm-wide configuration object
    intel_pt_configuration pt_config;
    pt_config.config_count = 1;
    pt_config.vcpu_configuration = calloc(pt_config.config_count, sizeof(kvm_vcpu_pt_configuration *));

    // Instantiate and configure a vcpu configuration
    kvm_vcpu_pt_configuration * vcpu0_config = calloc(1, sizeof(kvm_vcpu_pt_configuration));

    vcpu0_config->vcpu_id = 0;
    vcpu0_config->vcpu_enable = true;
    // enable ring 3 tracing and addr range tracing, disable kernel tracing
    vcpu0_config->ring_3.enable = true;
    vcpu0_config->ring_0.enable = false;
    vcpu0_config->addr_range[0].start_addr = 0x41414141;
    vcpu0_config->addr_range[0].start_addr = 0x42424242;

    // place vcpu configuration in master configuration object
    pt_config.vcpu_configuration[0] = vcpu0_config;

    kvm_engine_configure_plugin(e, p_id, &pt_config);

    // test vcpu configurations to make sure that they are set correctly
    kvm_vcpu_pt *vcpu_pt_itr;
    RECORD_LIST_FOREACH(vcpu_pt_itr, pt_state->vcpu_pt_list_head){
        // if vcpu id matches vcpu 0 id
        if(vcpu_pt_itr->vcpu->id == vcpu0_config->vcpu_id) {
            // test that the vcpu is marked as 'to_be_enabled'
            SIMPLE_TAP_TEST(vcpu_pt_itr->status.configured_to_be_enabled, "test_intel_pt_plugin_configure: vcpu_pt configured_to_be_enabled status field check")
            // test that ring 3 tracing is enabled,and addr range tracing is enabled, and ring 0 tracing is disabled.
            SIMPLE_TAP_TEST(
                vcpu_pt_itr->selectors.ring_3.enabled &&
                !vcpu_pt_itr->selectors.ring_0.enabled &&
                vcpu_pt_itr->selectors.addr_range[0].enabled,
                "test_intel_pt_plugin_configure: vcpu_pt selectors check.")
        }
    }

    free(vcpu0_config);
    free(pt_config.vcpu_configuration);
    destruct_kvm_engine_helper(e);
}

// Callback function used by libipt during instruction decoding.
// Provides libipt with a function to read raw instruction bytes at a given IP address.
static int
instruction_provider(u8 * buf, size_t size, const struct pt_asid *asid, u64 ip, void * context)
{
    kvm_vm *vm = (kvm_vm *) context;
    kvm_vcpu *vcpu = RECORD_LIST_FIRST(vm->kvm_vcpu_head);
    // iterate over all vcpus, find the one that libipt is interested in.
    while(vcpu)
    {
        struct kvm_sregs sregs;
        memset(&sregs, 0, sizeof(struct kvm_sregs));
        IOCTL1(vcpu->fd, KVM_GET_SREGS, &sregs)
        // if cr3 matches, assume this is the vcpu that libipt is interested in.
        if(sregs.cr3 == asid->cr3) {
            break;
        }
        vcpu = RECORD_LIST_NEXT(vcpu);
    }
    // if we found a vcpu, use it to read the requested number of bytes from the specified IP.
    if(vcpu) {
        u8 * read_results = kvm_vm_read_vaddr(vm, ip, size, vcpu->id);
        if (!read_results) {
            return -1;
        }
        // copy bytes to buf.
        memcpy(buf, read_results, size);
        free(read_results);
        return (int)size;
    }

    return -1;
}
// splits up 'decoded_data', looking for lines of disassembly.
// Then tests that the discovered line of disassembly correlates to the provided instruction.
static bool
test_inst_decode(u8 * decoded_data, u64 inst_count, char * inst[], u64 inst_addr[])
{
    u64 itr = 0;
    char *decoded_data_line_itr     = (char *)decoded_data;
    char *inst_addr_str = NULL;
    bool decoded_correctly = false;
    for(; itr < inst_count; itr++) {
		asprintf(&inst_addr_str, "%016lx", inst_addr[itr]);
		// search each line of the decoded data for the line containing the start IP address.
		while (decoded_data_line_itr) {
			char *curr = strsep(&decoded_data_line_itr, "\n");
			// if we found the string containing the target address, test the disassembly.
			if (strstr(curr, inst_addr_str)) {
                if(strstr(curr, inst[itr])) {
                    decoded_correctly = true;
                } else {
                    decoded_correctly = false;
                }
                break;
			}
		}
        free(inst_addr_str);
	}
    return decoded_correctly;
}
// compares an expected packet decode output with one obtained during testing.
static bool
test_packet_decode(const char * expected_packet_decode_path, u8 *decoded_packets)
{
    FILE *expected_output_file = fopen(expected_packet_decode_path, "r");
    // get expected output file size
    fseek(expected_output_file, 0, SEEK_END);
    size_t expected_output_size = (size_t) ftell(expected_output_file);
    fseek(expected_output_file, 0L, SEEK_SET);

    // read expected output file into memory
    char * expected_output = calloc(1, expected_output_size);
    fread(expected_output, expected_output_size, 1, expected_output_file);

    fclose(expected_output_file);

    char * next_line = (char *)decoded_packets;
    char * exp_next_line = expected_output;

    bool pt_packet_match = true;
    // go line by line, ignore vmcs, cbr, and pad packets.
    while(next_line)
    {
        char *curr_line = strsep(&next_line, "\n");
        // if we found the string containing the target address, test the disassembly.
        if(!strstr(curr_line, "vmcs") || !strstr(curr_line, "cbr")) {
            continue;
        }
		if (!strstr(curr_line, "pad")) {

			char * exp_curr_line = strsep(&exp_next_line, "\n");
            if(strcmp(curr_line, exp_curr_line) != 0) {
                // expected packet did not match the current packet.
                pt_packet_match = false;
                break;
            }
		}
	}
    free(expected_output);
    return pt_packet_match;
}

/*
 * The inst decode function writes to stdout, but we need it to write to a buffer.
 * We create a pipe and dup2 over the stdout file descriptor, so that we can obtain the
 * decoded data. We then restore the stdout file descriptor.
 */
static u8 *
intel_pt_inst_decode_helper(u8 * data_in, size_t data_in_size, kvm_vm *vm)
{
    int decode_pipe[2];
    pipe(decode_pipe);

    // pt_inst_decode writes to stdout, lets dup2 over stdout with our pipe.
    int saved_stdout = dup(1);
    dup2(decode_pipe[1], 1);


    // do decoding, prints to stdout
    pt_inst_decode(data_in, data_in_size, &instruction_provider, vm);

    // copy decoded instructions.
    u8 * decoded_data = calloc(1, 0x1000);
    read(decode_pipe[0], decoded_data, 0x1000);

    // fix stdout file descriptor
    dup2(saved_stdout, 1);
    // close no longer needed fds
    close(decode_pipe[0]);
    close(decode_pipe[1]);
    close(saved_stdout);

    return decoded_data;
}

/*
 * The packet decode function writes to stdout, but we need it to write to a buffer.
 * We create a pipe and dup2 over the stdout file descriptor, so that we can obtain the
 * decoded data. We then restore the stdout file descriptor.
 */
static u8 *
intel_pt_packet_decode_helper(u8 *data_in, size_t data_in_size)
{
    int decode_pipe[2];
    pipe(decode_pipe);

    // pt_inst_decode writes to stdout, lets dup2 over stdout with our pipe.
    int saved_stdout = dup(1);
    dup2(decode_pipe[1], 1);

    // do decoding, prints to stdout
    pt_packet_decode(data_in, data_in_size);

    // copy decoded instructions from stdout into a buffer.
    u8 * decoded_data = calloc(1, 0x1000);
    read(decode_pipe[0], decoded_data, 0x1000);

    // fix stdout file descriptor
    dup2(saved_stdout, 1);
    // close no longer needed fds
    close(decode_pipe[0]);
    close(decode_pipe[1]);
    close(saved_stdout);

    return decoded_data;
}

// wrapper function to free an intel_pt_trace_data object using the utility function provided by intel_pt.
static void
intel_pt_trace_data_free_helper(const char * plugin_path, intel_pt_trace_data *trace_data)
{
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpedantic"
    void * plugin_lib_handle = dlopen(plugin_path, RTLD_LAZY);
    void (*trace_data_free)(intel_pt_trace_data *) = dlsym(plugin_lib_handle, "intel_pt_trace_data_free");
    trace_data_free(trace_data);
    dlclose(plugin_lib_handle);
#pragma clang diagnostic pop
}

// test the tracing of a single instruction of execution
static void
test_intel_pt_plugin_execution_one(const char * serialized_vm_path, const char * plugin_path)
{
    kvm_engine *e = construct_kvm_engine_helper(serialized_vm_path);
    u64 p_id = (u64)kvm_engine_load_plugin(e, plugin_path, true);

    kvmcore_plugin_record *p_r = get_plugin_helper(e, p_id);
    kvmcore_plugin_state *s = &p_r->state;
    pt_state * pt_state = s->internal_state;

    kvm_vm *  vm       = e->vm;
    kvm_vcpu *vcpu = RECORD_LIST_FIRST(vm->kvm_vcpu_head);

    struct kvm_regs regs;
    memset(&regs, 0 ,sizeof(struct kvm_regs));

    IOCTL1(vcpu->fd, KVM_GET_REGS, &regs)

    u64 start_ip = regs.rip;

    u8 nop[1];
    u64 end_ip = start_ip + 1;
    memcpy(&nop, X86_NOP, 1);
    // put instruction into memory, add stop point.
    kvm_engine_patch_vaddr(e, start_ip, nop, 1, vcpu->id);
    kvm_engine_add_vaddr_stop_point(e, end_ip, 0);
    // run vm.
    kvm_engine_launch_vm(e);

    // unit test to check that there is data to extract
    kvm_vcpu_pt * vcpu_pt_itr;
    bool data_to_extract = false;
    RECORD_LIST_FOREACH(vcpu_pt_itr, pt_state->vcpu_pt_list_head) {
        if(vcpu_pt_itr->trace_data_size) {
            data_to_extract = true;
            break;
        }
    }

    SIMPLE_TAP_TEST(data_to_extract, "test_intel_pt_plugin_execution_one: Intel PT data ready for extraction.")
    // extract data
    intel_pt_trace_data *trace_data = NULL;
    kvm_engine_extract_plugin_data(e, p_id, (void **) &trace_data);

    SIMPLE_TAP_TEST(trace_data, "test_intel_pt_plugin_execution_one: kvm_engine_extract_plugin_data return value.")
    SIMPLE_TAP_TEST(trace_data->entry_count, "test_intel_pt_plugin_execution_one: trace_data->entry_count")
    SIMPLE_TAP_TEST(trace_data->vcpu_entry[0], "test_intel_pt_plugin_execution_one: trace_data->vcpu_entry[0]")

    // pt_inst_decode frees the provided data buffer...
    u8 * vcpu_0_data = calloc(1, trace_data->vcpu_entry[0]->data_size);
    memcpy(vcpu_0_data, trace_data->vcpu_entry[0]->data, trace_data->vcpu_entry[0]->data_size);
    // decode pt packets into disassembly.
    u8 * decoded_data = intel_pt_inst_decode_helper(vcpu_0_data, trace_data->vcpu_entry[0]->data_size, e->vm);

    char * expected_inst[1] = {"nop"};
    u64 expected_inst_addr[1] = {start_ip};
    // test that instructions were decoded correctly.
    bool decoded_correctly = test_inst_decode(decoded_data, 1, expected_inst, expected_inst_addr);
    SIMPLE_TAP_TEST(decoded_correctly, "test_intel_pt_plugin_execution_one: Expected decoding of trace data.")
    free(decoded_data);

    // decode packets into a human-readable format
    u8 * decoded_packets = intel_pt_packet_decode_helper(trace_data->vcpu_entry[0]->data, trace_data->vcpu_entry[0]->data_size);
    // test decoded packets with a expected output.
    bool pt_packet_match = test_packet_decode("./intel_pt_execution_one_expected_packet_decode.txt", decoded_packets);
    SIMPLE_TAP_TEST(pt_packet_match, "test_intel_pt_plugin_execution_one: PT Packet match.")
    free(decoded_packets);

    intel_pt_trace_data_free_helper(plugin_path, trace_data);
    destruct_kvm_engine_helper(e);
}

static void
test_intel_pt_plugin_execution_multi(const char * serialized_vm_path, const char * plugin_path)
{
    kvm_engine *e = construct_kvm_engine_helper(serialized_vm_path);
    u64 p_id = (u64)kvm_engine_load_plugin(e, plugin_path, true);

    kvmcore_plugin_record *p_r = get_plugin_helper(e, p_id);
    kvmcore_plugin_state *s = &p_r->state;
    pt_state * pt_state = s->internal_state;

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

    // put instructions into memory, add stop point.
    kvm_engine_patch_vaddr(e, start_ip, nop, 1, vcpu->id);
    kvm_engine_patch_vaddr(e, start_ip+1, xor, 2, vcpu->id);
    kvm_engine_add_vaddr_stop_point(e, end_ip, 0);
    // run vm.
    kvm_engine_launch_vm(e);

    // unit test to check that there is data to extract
    kvm_vcpu_pt * vcpu_pt_itr;
    bool data_to_extract = false;
    RECORD_LIST_FOREACH(vcpu_pt_itr, pt_state->vcpu_pt_list_head) {
        if(vcpu_pt_itr->trace_data_size) {
            data_to_extract = true;
            break;
        }
    }

    SIMPLE_TAP_TEST(data_to_extract, "test_intel_pt_plugin_execution_multi: Intel PT data ready for extraction.")
    // extract data
    intel_pt_trace_data *trace_data = NULL;
    kvm_engine_extract_plugin_data(e, p_id, (void **) &trace_data);

    SIMPLE_TAP_TEST(trace_data, "test_intel_pt_plugin_execution_multi: kvm_engine_extract_plugin_data return value.")
    SIMPLE_TAP_TEST(trace_data->entry_count, "test_intel_pt_plugin_execution_multi: trace_data->entry_count")
    SIMPLE_TAP_TEST(trace_data->vcpu_entry[0], "test_intel_pt_plugin_execution_multi: trace_data->vcpu_entry[0]")

    // pt_inst_decode frees the provided data buffer...
    u8 * vcpu_0_data = calloc(1, trace_data->vcpu_entry[0]->data_size);
    memcpy(vcpu_0_data, trace_data->vcpu_entry[0]->data, trace_data->vcpu_entry[0]->data_size);
    // decode pt packets into disassembly.
    u8 * decoded_data = intel_pt_inst_decode_helper(vcpu_0_data, trace_data->vcpu_entry[0]->data_size, e->vm);

    char * expected_inst[2] = {"nop", "xor eax, eax"};
    u64 expected_inst_addr[2] = {start_ip, start_ip+1};
    // test that instructions were decoded correctly.
    bool decoded_correctly = test_inst_decode(decoded_data, 2, expected_inst, expected_inst_addr);
    SIMPLE_TAP_TEST(decoded_correctly, "test_intel_pt_plugin_execution_multi: Expected decoding of trace data.")
    free(decoded_data);

    // decode packets into a human-readable format
    u8 * decoded_packets = intel_pt_packet_decode_helper(trace_data->vcpu_entry[0]->data, trace_data->vcpu_entry[0]->data_size);
    // test decoded packets with a expected output.
    bool pt_packet_match = test_packet_decode("./intel_pt_execution_multi_expected_packet_decode.txt", decoded_packets);
    SIMPLE_TAP_TEST(pt_packet_match, "test_intel_pt_plugin_execution_multi: PT Packet match.")
    free(decoded_packets);

    intel_pt_trace_data_free_helper(plugin_path, trace_data);
    destruct_kvm_engine_helper(e);
}

void
test_intel_pt_plugin(const char * serialized_vm_path, const char *plugin_path)
{
    diagnostics("Testing intel_pt plugin.");
    test_intel_pt_plugin_populate(serialized_vm_path, plugin_path);
    test_intel_pt_plugin_enable(serialized_vm_path, plugin_path);
    test_intel_pt_plugin_disable(serialized_vm_path, plugin_path);
    test_intel_pt_plugin_configure(serialized_vm_path, plugin_path);
    test_intel_pt_plugin_execution_one(serialized_vm_path, plugin_path);
    test_intel_pt_plugin_execution_multi(serialized_vm_path, plugin_path);
    diagnostics("intel_pt plugin unit tests complete.");
}
