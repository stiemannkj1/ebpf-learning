#include <linux/bpf.h>
#include <linux/ptrace.h>

#define PT_REGS_PARM1(x) ((x)->di)
#define PT_REGS_PARM2(x) ((x)->si)
#define PT_REGS_PARM3(x) ((x)->dx)

int bpf_prog1(struct pt_regs *ctx) {
    unsigned int fd = PT_REGS_PARM1(ctx);
    const char __user *buf = (const char __user *)PT_REGS_PARM2(ctx);
    int flags = PT_REGS_PARM3(ctx);
    bpf_trace_printk("openat called with dirfd: %d, filename: %p, flags: %d\n", fd, buf, flags); 

    // Now you can work with the parameters.
    // Note: To read the data from the `buf` pointer, you should use one of the eBPF helpers `bpf_probe_read_*()`.
    // For example, to read data from a user space pointer, you would use `bpf_probe_read_user()`.
    // Be aware that reading kernel memory directly can be unsafe and may cause your eBPF program to be rejected by the verifier.

    return 0;
}
