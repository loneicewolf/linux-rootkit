
```Makefile
obj-m += lkm.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```


```c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/ftrace.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/uio.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("LIW");
MODULE_DESCRIPTION("VFS Randomness Override (Safe Mode)");

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
static kallsyms_lookup_name_t real_kallsyms_lookup_name;

/* * The signature for the urandom read function.
 * It uses the iov_iter struct, which is how modern kernels handle read/write.
 */
static ssize_t (*orig_urandom_read_iter)(struct kiocb *iocb, struct iov_iter *iter);

/* ---------------------------------------------------------
 * The VFS Hook Logic
 * --------------------------------------------------------- */
static ssize_t hook_urandom_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
    ssize_t ret;
    size_t count = iov_iter_count(iter);

    /* 1. Let the real read happen first */
    ret = orig_urandom_read_iter(iocb, iter);

    /* 2. If the read was successful, we overwrite the data in the user's buffer.
     * Note: iov_iter_count(iter) now reflects the remaining bytes, so we use 'ret'
     */
    if (ret > 0 && ret <= 256) {
        /* We need to get the user space address from the iterator.
         * iter->ubuf is the pointer to the user's buffer in recent kernels.
         */
        void __user *user_buf = iter->ubuf;
        
        if (user_buf) {
            unsigned char fake[256];
            memset(fake, 0x01, ret);
            
            /* Use copy_to_user since we are safely in a syscall context now */
            if (copy_to_user(user_buf, fake, ret)) {
                // Fail gracefully
            }
        }
    }

    return ret;
}

/* ---------------------------------------------------------
 * Ftrace Boilerplate
 * --------------------------------------------------------- */
struct ftrace_hook {
    const char *name;
    void *hook_addr;
    void *orig_addr;
    unsigned long address;
    struct ftrace_ops ops;
};

static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
                                    struct ftrace_ops *ops, struct ftrace_regs *fregs)
{
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);
    struct pt_regs *regs = ftrace_get_regs(fregs);

    if (!within_module(parent_ip, THIS_MODULE)) {
        regs->ip = (unsigned long)hook->hook_addr;
    }
}

static struct ftrace_hook random_hook = {
    .name = "urandom_read_iter",
    .hook_addr = hook_urandom_read_iter,
    .orig_addr = &orig_urandom_read_iter
};

/* Module Init/Exit logic remains the same... */
static int resolve_kallsyms(void) {
    struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
    int ret = register_kprobe(&kp);
    if (ret < 0) return ret;
    real_kallsyms_lookup_name = (kallsyms_lookup_name_t)kp.addr;
    unregister_kprobe(&kp);
    return 0;
}

static int __init hook_init(void) {
    if (resolve_kallsyms() < 0) return -ENOENT;
    random_hook.address = real_kallsyms_lookup_name(random_hook.name);
    if (!random_hook.address) return -ENOENT;

    *((unsigned long*)random_hook.orig_addr) = random_hook.address;
    random_hook.ops.func = fh_ftrace_thunk;
    random_hook.ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION | FTRACE_OPS_FL_IPMODIFY;

    ftrace_set_filter_ip(&random_hook.ops, random_hook.address, 0, 0);
    register_ftrace_function(&random_hook.ops);

    pr_info("ROOK: VFS entropy hook engaged.\n");
    return 0;
}

static void __exit hook_exit(void) {
    unregister_ftrace_function(&random_hook.ops);
    ftrace_set_filter_ip(&random_hook.ops, random_hook.address, 1, 0);
    pr_info("ROOK: VFS entropy hook released.\n");
}

module_init(hook_init);
module_exit(hook_exit);
```
