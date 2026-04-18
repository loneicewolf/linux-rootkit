```py
# Randomness Predictor While the LKM is loaded.
import struct
import sys

def xorshift32(state):
    state ^= (state << 13) & 0xFFFFFFFF
    state ^= (state >> 17) & 0xFFFFFFFF
    state ^= (state << 5) & 0xFFFFFFFF
    return state

def predict_perfectly(hex_input, initial_seed=0xACE1BA5E):
    # Parse hexdump input into raw bytes
    input_chunks = hex_input.split()
    target_bytes = []
    for chunk in input_chunks:
        b = bytes.fromhex(chunk)
        target_bytes.append(b[1]) # hexdump swaps them
        target_bytes.append(b[0])
    
    state = initial_seed
    found = False
    
    # We search the tape
    for i in range(1000000):
        curr = state
        match = True
        for b in target_bytes:
            if (curr & 0xFF) != b:
                match = False
                break
            curr = xorshift32(curr)
        
        if match:
            # We found the sequence. 'curr' is the state AFTER the sequence.
            # But hexdump might be showing the next bytes in the SAME line.
            print(f"[!] Match found at offset {i}")
            
            # Predict the next 16 bytes exactly
            res = []
            for _ in range(16):
                res.append(curr & 0xFF)
                curr = xorshift32(curr)
            
            # Print in hexdump format
            formatted = []
            for j in range(0, len(res), 2):
                word = (res[j+1] << 8) | res[j]
                formatted.append(f"{word:04x}")
            print(f"[+] Next 16 bytes: {' '.join(formatted)}")
            found = True
            break
        state = xorshift32(state)

    if not found:
        print("[-] No match found.")

if __name__ == "__main__":
    predict_perfectly(sys.argv[1])
```

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
MODULE_DESCRIPTION("VFS Randomness Override (Predictable Mode)");

/* ---------------------------------------------------------
 * Xorshift PRNG Logic
 * --------------------------------------------------------- */
static uint32_t secret_state = 0xACE1BA5E; // Your secret seed

static uint32_t xorshift32(void)
{
    uint32_t x = secret_state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    secret_state = x;
    return x;
}

/* ---------------------------------------------------------
 * Hooking Infrastructure
 * --------------------------------------------------------- */
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
static kallsyms_lookup_name_t real_kallsyms_lookup_name;

static ssize_t (*orig_urandom_read_iter)(struct kiocb *iocb, struct iov_iter *iter);

static ssize_t hook_urandom_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
    ssize_t ret;
    ret = orig_urandom_read_iter(iocb, iter);

    if (ret > 0) { 
        void __user *user_buf = iter->ubuf;
        
        if (user_buf) {
            size_t i;
            for (i = 0; i < ret; i++) {
                // Generate a "random" byte using our formula
                uint8_t predictable_byte = (uint8_t)(xorshift32() & 0xFF);
                
                if (copy_to_user(user_buf + i, &predictable_byte, 1)) {
                    break;
                }
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

    pr_info("ROOK: VFS predictable entropy engaged.\n");
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
