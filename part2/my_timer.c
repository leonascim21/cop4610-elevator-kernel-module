#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("cop4610t");
MODULE_DESCRIPTION("Timer Linux Kernel Module");
MODULE_VERSION("1.0");

#define PROC_NAME "my_timer"
#define PERMS 0666
#define PARENT NULL
#define BUF_LEN 100
static struct timespec64 last_time;


static struct proc_dir_entry *proc_entry;

static ssize_t procfile_read(struct file *file, char* ubuf, size_t count, loff_t *ppos) {
    int len;
    char buffer[BUF_LEN];
    struct timespec64 current_time;
    long long elapsed_sec = 0, elapsed_nsec = 0;
    ktime_get_real_ts64(&current_time);

    if (last_time.tv_sec || last_time.tv_nsec) {
        elapsed_sec = current_time.tv_sec - last_time.tv_sec;
        elapsed_nsec = current_time.tv_nsec - last_time.tv_nsec;
        if (elapsed_nsec < 0) {
            elapsed_sec--;
            elapsed_nsec *= -1;
        }
        len = snprintf(buffer, BUF_LEN, "current time: %lld.%lld\n"
                                        "elapsed time: %lld.%lld\n",
                                        current_time.tv_sec, (long long)current_time.tv_nsec,
                                        elapsed_sec, elapsed_nsec);
    }
    else {
        len = snprintf(buffer, BUF_LEN, "current time: %lld.%lld\n",
                                        current_time.tv_sec, (long long)current_time.tv_nsec);
    }


    last_time = current_time;
    if (*ppos > 0 || count < len)
        return 0;
    if(copy_to_user(ubuf, buffer, len)) {
        return -EFAULT;
    }
    *ppos = len;
    return len;
}

static const struct proc_ops timer_fops = {
    .proc_read = procfile_read,
};

static int __init my_timer_init(void) {
    proc_entry = proc_create(PROC_NAME, PERMS, PARENT, &timer_fops);
    if (proc_entry == NULL)
        return -ENOMEM;
    return 0;
}

static void __exit my_timer_exit(void) {
    proc_remove(proc_entry);
}

module_init(my_timer_init);
module_exit(my_timer_exit);