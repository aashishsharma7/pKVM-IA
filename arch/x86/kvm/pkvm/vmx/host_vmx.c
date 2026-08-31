// SPDX-License-Identifier: GPL-2.0
#include <linux/kvm_types.h>
#include <linux/memblock.h>
#include <kvm_emulate.h>
#include <vmx/x86_ops.h>
#include <asm/io.h>
#include "debug.h"
#include "ept.h"
#include "host_vmx.h"
#include "pkvm/init.h"
#include "pkvm/lapic.h"
#include "pkvm/trace.h"
#include "pkvm.h"
#include "pkvm_iommu.h"

#define CR4			4
#define MOV_TO_CR		0

struct vmcs_config host_vmcs_config;

static int vmx_hyp_mmu_finalize(struct pkvm_pgtable *pgt)
{
	if (!pgt)
		return -EINVAL;

	vmcs_writel(HOST_CR3, pgt->root_pa);

	return 0;
}

static struct pkvm_init_ops vmx_init_ops = {
	.hyp_mmu_finalize = vmx_hyp_mmu_finalize,
	.host_mmu_init = pkvm_host_ept_init,
	.host_mmu_finalize = pkvm_host_ept_finalize,
	.hyp_global_init = pkvm_vmx_init,
	.reprivilege_cpu = pkvm_vmx_reprivilege_cpu,
	.hyp_iommu_init = pkvm_intel_iommu_init,
};

struct pkvm_init_ops *pkvm_vmx_init_ops = &vmx_init_ops;

static void skip_emulated_instruction(void)
{
	unsigned long rip;

	rip = vmcs_readl(GUEST_RIP);
	rip += vmcs_read32(VM_EXIT_INSTRUCTION_LEN);
	vmcs_writel(GUEST_RIP, rip);
}

static void handle_irq_window(struct kvm_vcpu *vcpu)
{
	u32 cpu_based_exec_ctrl = exec_controls_get(to_vmx(vcpu));

	exec_controls_set(to_vmx(vcpu), cpu_based_exec_ctrl &
					~CPU_BASED_INTR_WINDOW_EXITING);

	kvm_make_request(KVM_REQ_EVENT, vcpu);
}

static void handle_cpuid(struct kvm_vcpu *vcpu)
{
	u32 eax, ebx, ecx, edx;

	eax = vcpu->arch.regs[VCPU_REGS_RAX];
	ecx = vcpu->arch.regs[VCPU_REGS_RCX];
	native_cpuid(&eax, &ebx, &ecx, &edx);
	vcpu->arch.regs[VCPU_REGS_RAX] = eax;
	vcpu->arch.regs[VCPU_REGS_RBX] = ebx;
	vcpu->arch.regs[VCPU_REGS_RCX] = ecx;
	vcpu->arch.regs[VCPU_REGS_RDX] = edx;
}

static void handle_vmcall(struct kvm_vcpu *vcpu)
{
	pkvm_handle_host_hypercall(vcpu);
}

static void handle_cr(struct kvm_vcpu *vcpu)
{
	struct vcpu_vt *vt = to_vt(vcpu);
	unsigned long exit_qual, val;
	int cr, type, reg;

	exit_qual = vt->exit_qualification;
	cr = exit_qual & 15;
	type = (exit_qual >> 4)	& 3;
	reg = (exit_qual >> 8) & 15;

	switch (type) {
	case MOV_TO_CR:
		switch (cr) {
		case CR4:
			/*
			 * VMXE bit is owned by pkvm, others are owned by host
			 * So only when guest is trying to modify VMXE bit it
			 * can cause vmexit and get here.
			 */
			val = vcpu->arch.regs[reg];
			vmcs_writel(CR4_READ_SHADOW, val);
			break;
		default:
			break;
		}
		break;
	default:
		break;
	}
}

static bool is_msr_in_bitmap_range(unsigned long msr)
{
	return msr <= 0x1FFF || (msr >= 0xC0000000 && msr <= 0xC0001FFF);
}

static int handle_read_msr(struct kvm_vcpu *vcpu)
{
	unsigned long msr = vcpu->arch.regs[VCPU_REGS_RCX];
	u32 low, high;

	/*
	 * The MSR reading bitmap doesn't intercept any MSR. If the vmexit is
	 * caused by such MSR in the range of the bitmap, it should be a code
	 * bug.
	 */
	BUG_ON(is_msr_in_bitmap_range(msr));

	if (rdmsr_safe(msr, &low, &high)) {
		kvm_inject_gp(vcpu, 0);
		return X86EMUL_UNHANDLEABLE;
	}

	vcpu->arch.regs[VCPU_REGS_RAX] = low;
	vcpu->arch.regs[VCPU_REGS_RDX] = high;

	return X86EMUL_CONTINUE;
}

static int handle_write_msr(struct kvm_vcpu *vcpu)
{
	unsigned long msr = vcpu->arch.regs[VCPU_REGS_RCX];
	int ret = X86EMUL_CONTINUE;
	u32 low, high;
	u64 val;

	low = vcpu->arch.regs[VCPU_REGS_RAX];
	high = vcpu->arch.regs[VCPU_REGS_RDX];
	val = low | ((u64)high << 32);

	switch (msr) {
	case MSR_CORE_PERF_GLOBAL_CTRL: {
		struct kvm_pmu *pmu = vcpu_to_pmu(vcpu);
		struct vcpu_vmx *vmx = to_vmx(vcpu);

		if (!kvm_pmu_has_perf_global_ctrl(pmu)) {
			ret = X86EMUL_UNHANDLEABLE;
			break;
		}

		if (pmu->global_ctrl == val)
			break;

		/*
		 * PMU is owned by the host. But the host must be prevented
		 * from profiling pKVM or pVM so the global ctrl MSR is kept
		 * as ZERO (disabled) outside of the host context.
		 *
		 * Capture the value written by host. If it's non-zero then
		 * update the VMCS guest field and rely on VM entry/exit
		 * control to switch the MSR value. The VMCS host field is
		 * fixed to ZERO.
		 */
		pmu->global_ctrl = val;
		if (val) {
			vmcs_write64(GUEST_IA32_PERF_GLOBAL_CTRL, val);
			vm_entry_controls_setbit(vmx,
					VM_ENTRY_LOAD_IA32_PERF_GLOBAL_CTRL);
			vm_exit_controls_setbit(vmx,
					VM_EXIT_LOAD_IA32_PERF_GLOBAL_CTRL);
		} else {
			vm_entry_controls_clearbit(vmx,
					VM_ENTRY_LOAD_IA32_PERF_GLOBAL_CTRL);
			vm_exit_controls_clearbit(vmx,
					VM_EXIT_LOAD_IA32_PERF_GLOBAL_CTRL);
		}
		break;
	}
	case MSR_IA32_APICBASE:
	case APIC_BASE_MSR ... APIC_BASE_MSR + 0xff:
		if (pkvm_lapic_msr_write(msr, val))
			ret = X86EMUL_UNHANDLEABLE;
		break;
	default:
		/*
		 * The MSRs intercepted by the writing bitmap should be
		 * emulated by the switch cases. Otherwise it should be a code
		 * bug.
		 */
		BUG_ON(is_msr_in_bitmap_range(msr));

		if (wrmsr_safe(msr, low, high))
			ret = X86EMUL_UNHANDLEABLE;

		break;
	}

	if (ret == X86EMUL_UNHANDLEABLE)
		kvm_inject_gp(vcpu, 0);

	return ret;
}

static void handle_preemption_timer(struct kvm_vcpu *vcpu)
{
	pin_controls_clearbit(to_vmx(vcpu), PIN_BASED_VMX_PREEMPTION_TIMER);
}

static int handle_xsetbv(struct kvm_vcpu *vcpu)
{
	u32 eax = (u32)(vcpu->arch.regs[VCPU_REGS_RAX] & -1u);
	u32 edx = (u32)(vcpu->arch.regs[VCPU_REGS_RDX] & -1u);
	u32 ecx = (u32)(vcpu->arch.regs[VCPU_REGS_RCX] & -1u);

	asm goto("1: xsetbv\n\t"
		 _ASM_EXTABLE(1b, %l[fault])
		 : : "a" (eax), "d" (edx), "c" (ecx) : : fault);

	return X86EMUL_CONTINUE;

fault:
	/*
	 * Although the SDM doesn't describe the priority of #UD and
	 * interception for xsetbv, the experiment shows that #UD due to
	 * CR4.OSXSAVE[bit 18] == 0 and the LOCK prefix has priority
	 * over the interception.
	 *
	 * So the pKVM hypervisor itself won't generate #UD when
	 * executes the xsetbv instruction, only #GP can be generated
	 * due to invalid configurations. Always inject #GP if xsetbv
	 * is failed.
	 *
	 * TODO: CPUID.01H:ECX.XSAVE[bit 26] == 0 will also result in
	 * #UD but all modern Intel CPUs have XSAVE. If the pKVM runs
	 * on such CPU without XSAVE, verify if this #UD also has
	 * priority over the interception.
	 */
	kvm_inject_gp(vcpu, 0);
	return X86EMUL_UNHANDLEABLE;
}

static void inject_pending_nmi(struct kvm_vcpu *vcpu)
{
	if (!vcpu->arch.nmi_pending)
		return;

	/*
	 * Check for the NMI blocking and inject the NMI only when it is not
	 * blocked.
	 * The vmx code vmx_nmi_blocked() and vmx_inject_nmi() are not used at
	 * here as their implementation is related with the global parameter
	 * enable_vnmi which can determine how the guest VMs handle the NMI. The
	 * host VM has physical NMI passthrough which is not exactly fitting to
	 * the usage of enable_vnmi.
	 */
	if (!(vmcs_read32(GUEST_INTERRUPTIBILITY_INFO) &
	      (GUEST_INTR_STATE_MOV_SS | GUEST_INTR_STATE_STI |
	       GUEST_INTR_STATE_NMI))) {
		--vcpu->arch.nmi_pending;
		vmcs_write32(VM_ENTRY_INTR_INFO_FIELD,
			     INTR_TYPE_NMI_INTR | INTR_INFO_VALID_MASK | NMI_VECTOR);
		vmx_clear_hlt(vcpu);
	}

	/*
	 * If there are more pending NMI, open the irq window to inject the
	 * pending ones when the NMI is unblocked. Using irq window rather than
	 * the NMI window since this is for the physical NMI, while NMI window
	 * is for virtual-NMI when virtual-NMI execution control is enabled,
	 * which is not used for the host VM.
	 */
	if (vcpu->arch.nmi_pending)
		vmx_enable_irq_window(vcpu);
}

static void handle_pending_events(struct kvm_vcpu *vcpu, bool *req_immediate_exit)
{
	if (kvm_check_request(KVM_REQ_NMI, vcpu)) {
		vcpu->arch.nmi_pending += atomic_xchg(&vcpu->arch.nmi_queued, 0);
		kvm_make_request(KVM_REQ_EVENT, vcpu);
	}

	if (kvm_check_request(KVM_REQ_EVENT, vcpu)) {
		if (vcpu->arch.exception.pending) {
			vmx_inject_exception(vcpu);
			vcpu->arch.exception.pending = false;
			vcpu->arch.exception.injected = true;
		}

		if (vcpu->arch.nmi_pending) {
			/*
			 * Inject pending NMI if no exception is already injected.
			 * Otherwise request an immediate exit to inject NMI in the
			 * next vmexit.
			 */
			if (!vcpu->arch.exception.injected)
				inject_pending_nmi(vcpu);
			else
				*req_immediate_exit = true;
		}
	}

	if (kvm_check_request(KVM_REQ_TLB_FLUSH_CURRENT, vcpu))
		pkvm_flush_host_ept();
}

static void fixup_host_vmx(struct vcpu_vmx *vmx)
{
	if (boot_cpu_has(X86_FEATURE_INTEL_PT)) {
		/*
		 * The VM_ENTRY_LOAD_IA32_RTIT_CTL bit may be cleared due to the
		 * MSR_IA32_RTIT_CTL TRACEEN bit is set before deprivileging. See
		 * comments in init_vmentry_control in pkvm_init.c.
		 *
		 * Ensure this bit is set after the host exits to the root mode.
		 * This can be done safely as VM_EXIT_CLEAR_IA32_RTIT_CTL is
		 * guaranteed to be set which causes the MSR_IA32_RTIT_CTL is 0.
		 */
		if (!(vm_entry_controls_get(vmx) & VM_ENTRY_LOAD_IA32_RTIT_CTL))
			vm_entry_controls_setbit(vmx, VM_ENTRY_LOAD_IA32_RTIT_CTL);
	}

	this_cpu_write(host_vcpu_fixup, false);
}

static void handle_host_io(struct kvm_vcpu *vcpu)
{
	struct vcpu_vt *vt = to_vt(vcpu);
	unsigned long exit_qual = vt->exit_qualification;
	unsigned port = exit_qual >> 16;
	int in = (exit_qual & 8) != 0;
	int size = exit_qual & 7; /* 0: 1-byte, 1: 2-byte, 3: 4-byte */

	if (port == 0xCF8) {
		if (!in) {
			if (size == 0)
				outb((u8)vcpu->arch.regs[VCPU_REGS_RAX], 0xCF8);
			else if (size == 1)
				outw((u16)vcpu->arch.regs[VCPU_REGS_RAX], 0xCF8);
			else
				outl((u32)vcpu->arch.regs[VCPU_REGS_RAX], 0xCF8);
		} else {
			if (size == 0)
				vcpu->arch.regs[VCPU_REGS_RAX] = (vcpu->arch.regs[VCPU_REGS_RAX] & ~0xFFULL) | inb(0xCF8);
			else if (size == 1)
				vcpu->arch.regs[VCPU_REGS_RAX] = (vcpu->arch.regs[VCPU_REGS_RAX] & ~0xFFFFULL) | inw(0xCF8);
			else
				vcpu->arch.regs[VCPU_REGS_RAX] = (u64)(u32)inl(0xCF8);
		}
	} else if (port >= 0xCFC && port <= 0xCFF) {
		u32 addr = inl(0xCF8);
		u8 bus = (addr >> 16) & 0xFF;
		u8 dev = (addr >> 11) & 0x1F;
		u8 func = (addr >> 8) & 0x7;
		u8 offset = (addr & 0xFC) + (port - 0xCFC);

		/* Check if targeting an actively assigned device */
		if (is_pci_bdf_assigned(bus, dev, func)) {
			u32 val = (u32)vcpu->arch.regs[VCPU_REGS_RAX];
			int sz = (size == 0 ? 1 : (size == 1 ? 2 : 4));

			if (!in) {
				/* Host WRITE to Assigned Device */
				switch (offset) {
				case 0x00 ... 0x03:
					pkvm_info("pKVM: Blocked Host WRITE to RO Vendor/Device ID (offset 0x%x, val 0x%x, sz %d)\n",
					          offset, val, sz);
					return;
				case 0x04 ... 0x05:
					pkvm_info("pKVM: Filtered Host WRITE to Command Register (offset 0x%x, val 0x%x, sz %d)\n",
					          offset, val, sz);
					break;
				case 0x06 ... 0x07:
					pkvm_info("pKVM: Allowed Host WRITE to Status Register W1C (offset 0x%x, val 0x%x, sz %d)\n",
					          offset, val, sz);
					break;
				case 0x08 ... 0x0F:
					pkvm_info("pKVM: Blocked Host WRITE to RO RevID/Class/CLS/BIST (offset 0x%x, val 0x%x, sz %d)\n",
					          offset, val, sz);
					return;
				case 0x10 ... 0x27:
					pkvm_info("pKVM: Blocked Host WRITE to BAR%d (offset 0x%x, val 0x%x, sz %d)\n",
					          (offset - 0x10) / 4, offset, val, sz);
					/* Suppress hardware write while assigned to protected VM */
					return;
				case 0x28 ... 0x2F:
					pkvm_info("pKVM: Blocked Host WRITE to CardBus/Subsystem ID (offset 0x%x, val 0x%x, sz %d)\n",
					          offset, val, sz);
					return;
				case 0x30 ... 0x33:
					pkvm_info("pKVM: Blocked Host WRITE to Expansion ROM BAR (offset 0x%x, val 0x%x, sz %d)\n",
					          offset, val, sz);
					/* Suppress hardware write */
					return;
				case 0x34 ... 0x3B:
					pkvm_info("pKVM: Blocked Host WRITE to RO CapPtr/Reserved (offset 0x%x, val 0x%x, sz %d)\n",
					          offset, val, sz);
					return;
				case 0x3C ... 0x3F:
					pkvm_info("pKVM: Blocked Host WRITE to Interrupt Line/Pin (offset 0x%x, val 0x%x, sz %d)\n",
					          offset, val, sz);
					return;
				case 0x40 ... 0x6F:
					pkvm_info("pKVM: Allowed Host WRITE to Intel Vendor Specific Cap (offset 0x%x, val 0x%x, sz %d)\n",
					          offset, val, sz);
					break;
				case 0x70 ... 0xAB:
					pkvm_info("pKVM: Allowed Host WRITE to PCIe Capability (offset 0x%x, val 0x%x, sz %d)\n",
					          offset, val, sz);
					break;
				case 0xAC ... 0xCF:
					pkvm_info("pKVM: Mediated Host WRITE to MSI Capability (offset 0x%x, val 0x%x, sz %d)\n",
					          offset, val, sz);
					break;
				case 0xD0 ... 0xDF:
					pkvm_info("pKVM: Allowed Host WRITE to Power Management PMCSR (offset 0x%x, val 0x%x, sz %d)\n",
					          offset, val, sz);
					break;
				default:
					pkvm_info("pKVM: Blocked Host WRITE to Unclassified offset 0x%x (val 0x%x, sz %d)\n",
					          offset, val, sz);
					return;
				}
			} else {
				/* Host READ from Assigned Device */
				pkvm_info("pKVM: Allowed Host READ from %02x:%02x.%d reg 0x%x (sz %d)\n",
				          bus, dev, func, offset, sz);
			}
		}

		/* Pass-through all other I/O to hardware */
		if (!in) {
			if (size == 0)
				outb((u8)vcpu->arch.regs[VCPU_REGS_RAX], port);
			else if (size == 1)
				outw((u16)vcpu->arch.regs[VCPU_REGS_RAX], port);
			else
				outl((u32)vcpu->arch.regs[VCPU_REGS_RAX], port);
		} else {
			if (size == 0)
				vcpu->arch.regs[VCPU_REGS_RAX] = (vcpu->arch.regs[VCPU_REGS_RAX] & ~0xFFULL) | inb(port);
			else if (size == 1)
				vcpu->arch.regs[VCPU_REGS_RAX] = (vcpu->arch.regs[VCPU_REGS_RAX] & ~0xFFFFULL) | inw(port);
			else
				vcpu->arch.regs[VCPU_REGS_RAX] = (u64)(u32)inl(port);
		}
	} else {
		/* Fallback for other ports if any */
		if (!in) {
			if (size == 0)
				outb((u8)vcpu->arch.regs[VCPU_REGS_RAX], port);
			else if (size == 1)
				outw((u16)vcpu->arch.regs[VCPU_REGS_RAX], port);
			else
				outl((u32)vcpu->arch.regs[VCPU_REGS_RAX], port);
		} else {
			if (size == 0)
				vcpu->arch.regs[VCPU_REGS_RAX] = (vcpu->arch.regs[VCPU_REGS_RAX] & ~0xFFULL) | inb(port);
			else if (size == 1)
				vcpu->arch.regs[VCPU_REGS_RAX] = (vcpu->arch.regs[VCPU_REGS_RAX] & ~0xFFFFULL) | inw(port);
			else
				vcpu->arch.regs[VCPU_REGS_RAX] = (u64)(u32)inl(port);
		}
	}
}

void pkvm_host_vmexit_main(struct vcpu_vmx *vmx)
{
	struct kvm_vcpu *vcpu = &vmx->vcpu;
	bool req_immediate_exit = false;
	struct vcpu_vt *vt = &vmx->vt;
	bool skip_instruction = false;

	pkvm_trace_vmexit_start(vcpu);

	pkvm_set_vcpu_outside_guest(vcpu);

	vcpu->arch.cr2 = native_read_cr2();
	vcpu->arch.exception.injected = false;

	vt->exit_reason.full = vmcs_read32(VM_EXIT_REASON);
	vt->exit_qualification = vmcs_readl(EXIT_QUALIFICATION);

	switch (vt->exit_reason.full) {
	case EXIT_REASON_INIT_SIGNAL:
		pkvm_handle_init_signal();
		break;
	case EXIT_REASON_INTERRUPT_WINDOW:
		handle_irq_window(vcpu);
		break;
	case EXIT_REASON_CPUID:
		handle_cpuid(vcpu);
		skip_instruction = true;
		break;
	case EXIT_REASON_VMCALL:
		handle_vmcall(vcpu);
		skip_instruction = true;
		break;
	case EXIT_REASON_CR_ACCESS:
		handle_cr(vcpu);
		skip_instruction = true;
		break;
	case EXIT_REASON_MSR_READ:
		if (handle_read_msr(vcpu) == X86EMUL_CONTINUE)
			skip_instruction = true;
		break;
	case EXIT_REASON_MSR_WRITE:
		if (handle_write_msr(vcpu) == X86EMUL_CONTINUE)
			skip_instruction = true;
		break;
	case EXIT_REASON_EPT_VIOLATION:
		pkvm_handle_host_ept_violation(vcpu);
		break;
	case EXIT_REASON_IO_INSTRUCTION:
		handle_host_io(vcpu);
		skip_instruction = true;
		break;
	case EXIT_REASON_PREEMPTION_TIMER:
		handle_preemption_timer(vcpu);
		break;
	case EXIT_REASON_XSETBV:
		if (handle_xsetbv(vcpu) == X86EMUL_CONTINUE)
			skip_instruction = true;
		break;
	default:
		pkvm_err_ratelimited("Unsupported vmexit reason 0x%x.\n",
				      vt->exit_reason.full);
		break;
	}

	if (skip_instruction)
		skip_emulated_instruction();

handle_events:
	handle_pending_events(vcpu, &req_immediate_exit);

	pkvm_set_vcpu_in_guest(vcpu);

	if (req_immediate_exit) {
		kvm_make_request(KVM_REQ_EVENT, vcpu);
		request_host_immediate_exit(vmx);
	} else if (READ_ONCE(vcpu->mode) == EXITING_GUEST_MODE ||
		   kvm_request_pending(vcpu)) {
		pkvm_set_vcpu_outside_guest(vcpu);
		/*
		 * Some vcpu requests may be set after handle_pending_events()
		 * but before set vcpu mode to IN_GUEST_MODE. In this case the
		 * init signal will not be send to kick the vcpu. To guarantee
		 * such vcpu requests can be handled timely, try to handle
		 * pending event again.
		 */
		goto handle_events;
	}

	if (vcpu->arch.cr2 != native_read_cr2())
		native_write_cr2(vcpu->arch.cr2);

	if (unlikely(this_cpu_read(host_vcpu_fixup)))
		fixup_host_vmx(vmx);

	pkvm_trace_vmexit_end(vcpu, vt->exit_reason.basic);
}
