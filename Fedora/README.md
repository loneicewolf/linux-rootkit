# I will clean this up later on!


## LKM Execution
- `make clean`
- `make all`
- `nano /usr/local/bin/test.sh` `# make some commands here, you will find a test script below`
- `sudo insmod lkm_exec.ko` `# todo: [+] arguments to what script to execute and maybe [+] reverse shell`


```Makefile
obj-m += lkm_exec.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

```


- `lkm_exec.c`
```c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/umh.h> // The header for user-mode helpers

MODULE_LICENSE("GPL");
MODULE_AUTHOR("The Architect");

static int __init ghost_exec_init(void) {
    // Set up the path and arguments 
    // char *argv[] = { "/tmp/test.sh", NULL };
    char *argv[] = { "/usr/local/bin/test.sh", NULL };
    static char *envp[] = {
        "HOME=/",
        "TERM=linux",
        "PATH=/sbin:/usr/sbin:/bin:/usr/bin",
        NULL
    };

    printk(KERN_INFO "GHOST: Attempting to execute /tmp/test.sh\n");

    // call_usermodehelper(path, argv, envp, wait_flag)
    return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
}

static void __exit ghost_exec_exit(void) {
    printk(KERN_INFO "GHOST: Executor unloaded.\n");
}

module_init(ghost_exec_init);
module_exit(ghost_exec_exit);
```


- `/usr/local/bin/test.sh`
```bash
#!/bin/bash
sudo /bin/bash -c 'whoami > /tmp/WHOAMI'
```
