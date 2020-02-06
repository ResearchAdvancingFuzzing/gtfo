#include "build_test_vm.h"

/* 32-bit page directory entry bits */
#define PDE32_PRESENT 1
#define PDE32_RW (1U << 1)
#define PDE32_USER (1U << 2)
#define PDE32_PS (1U << 7)
#define PDE32_ACCESSED (1U << 5)

#define CR4_PSE (1U << 4)

/* CR0 bits */
#define CR0_PE 1u
#define CR0_MP (1U << 1)
#define CR0_ET (1U << 4)
#define CR0_NE (1U << 5)
#define CR0_WP (1U << 16)
#define CR0_AM (1U << 18)
#define CR0_PG (1U << 31)


static const u8 test_code[] = {
    0xb8, 0xef, 0xbe, 0xad, 0xde, /* mov eax, 0xdeadbeef */
   0xbb, 0xbe, 0xba, 0xfe, 0xca, /* mov ebx, 0xcafebabe */
    0xf4 /* hlt */
};

/* Builds a small vm for testing purposes.
 * The vm is set up to run in protected mode with paging.
 * Returns the path to serialized snapshot of the vm.
 */
char *
build_paged_protected_mode_x86_test_vm() {

    // create a new vm
    kvm_vm *vm = kvm_vm_create();

    // add a vcpu
    kvm_vcpu *vcpu_0 = kvm_vcpu_create(vm->kvm_fd, vm->vm_fd, 0);
    kvm_vm_insert_vcpu(vm, vcpu_0);

    // set TSS section address, not used but required to be set.
    u32 tss_addr = 0xfffbd000;
    IOCTL1(vm->vm_fd, KVM_SET_TSS_ADDR, tss_addr)
    kvm_vm_record_guest_tss_addr(&vm->record, tss_addr);

    // map some memory
    u64 mem_size = 0x4000;
    void * mem_addr = mmap(NULL, mem_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);

    if(mem_addr == MAP_FAILED) {
        exit(1);
    }
    madvise(mem_addr, mem_size, MADV_MERGEABLE);
    // write our test code to memory.
    memcpy(mem_addr, test_code, sizeof(test_code));

    // create a new memory region
    struct kvm_userspace_memory_region mem;
    memset(&mem, 0, sizeof(struct kvm_userspace_memory_region));

    mem.slot = 0;
    mem.flags = 0;
    mem.guest_phys_addr = 0;
    mem.memory_size = mem_size;
    mem.userspace_addr = (u64)mem_addr;

    // add new memory region to the vm.
    kvm_vm_insert_userspace_memory_region(vm, &mem, true);

    // configure special registers and enable protected mode
    struct kvm_sregs sregs;
    IOCTL1(vcpu_0->fd, KVM_GET_SREGS, &sregs)

    // Begin setup for protected mode
    struct kvm_segment seg;
    memset(&seg, 0 , sizeof(struct kvm_segment));
    seg.base = 0;
    seg.limit = 0xffffffff;
    seg.selector = 1 << 3;
    seg.present = 1;
    seg.type = 11; // Code: execute, read, access
    seg.dpl = 0; // privilege level, root
    seg.db = 1; // operand size, if set, 32 bit.
    seg.s = 1; // code/data
    seg.l = 0; // long mode
    seg.g = 1; // 4kb page granularity

    memcpy(&sregs.cs, &seg, sizeof(struct kvm_segment));

    seg.type = 3; // Data segments, read/write, access
    seg.selector = 2 << 3;

    memcpy(&sregs.ds, &seg, sizeof(struct kvm_segment));
    memcpy(&sregs.es, &seg, sizeof(struct kvm_segment));
    memcpy(&sregs.fs, &seg, sizeof(struct kvm_segment));
    memcpy(&sregs.gs, &seg, sizeof(struct kvm_segment));
    memcpy(&sregs.ss, &seg, sizeof(struct kvm_segment));
    // End setup for protected mode

    // Begin setup for paging,
    // we place a pde at phys addr 0x1000
    u32 pde_addr = 0x1000;
    u32 *pde = (void *)((u64)mem_addr + pde_addr);

    // A single 4MB page to cover the memory region , ie. vaddr == paddr.
    // Other PDEs are left zeroed, meaning not present.
    pde[0] = PDE32_PRESENT | PDE32_RW | PDE32_USER | PDE32_PS | PDE32_ACCESSED;

    sregs.cr3 = pde_addr;
    // enable 4MB page size
    sregs.cr4 = CR4_PSE;
    // set control flags
    sregs.cr0 = CR0_PE | CR0_MP | CR0_ET | CR0_NE | CR0_WP | CR0_AM | CR0_PG;
    // clear efer MSR.
    sregs.efer = 0;

    IOCTL1(vcpu_0->fd, KVM_SET_SREGS, &sregs)

    struct kvm_regs regs;
    memset(&regs, 0 ,sizeof(struct kvm_regs));

    // bit 1 of rflags is unused but according to the intel spec, it must be set.
    regs.rflags = 2;
    regs.rip = 0;
    IOCTL1(vcpu_0->fd, KVM_SET_REGS, &regs)

    u64 snapshot_id = kvm_vm_take_snapshot(vm);

    // test execution to check that vm is configured correctly.
    s64 ret = 0;
    IOCTL1_R(vcpu_0->fd, KVM_RUN, NULL ,ret, s64)

    if(ret < 0) {
        log_warn("build_paged_protected_mode_x86_test_vm: KVM RUN ERROR");
        exit(1);
    }
    // We expect the exit reason to be KVM_EXIT_HLT.
    if(vcpu_0->kvm_run->exit_reason != KVM_EXIT_HLT)
    {
        log_warn("build_paged_protected_mode_x86_test_vm: Unknown exit reason.");
    }
    // Check registers for expected value.
    IOCTL1(vcpu_0->fd, KVM_GET_REGS, &regs)
    if (
        regs.rax != 0xdeadbeef ||
        regs.rbx != 0xcafebabe ||
        regs.rip != 0xb
        ) {
        log_warn("build_paged_protected_mode_x86_test_vm: Test execution of vm did not behave as expected.");
    }

    char * path = kvm_vm_snapshot_serialize(vm, snapshot_id, true);
    kvm_vm_free(vm);
    return path;

}
