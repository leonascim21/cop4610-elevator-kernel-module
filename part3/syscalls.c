#include <linux/linkage.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/syscalls.h>

int (*STUB_start_elevator)(void) = NULL;
int (*STUB_issue_request)(int, int, int) = NULL;
int (*STUB_stop_elevator)(void) = NULL;
EXPORT_SYMBOL(STUB_start_elevator);
EXPORT_SYMBOL(STUB_issue_request);
EXPORT_SYMBOL(STUB_stop_elevator);

SYSCALL_DEFINE0(start_elevator) {
	printk(KERN_NOTICE "Starting Elevator\n");
	if (STUB_start_elevator != NULL)
		return STUB_start_elevator();
	else
		return -ENOSYS;
}

SYSCALL_DEFINE3(issue_request, int, start_floor, int, destination_floor, int, type) {
        printk(KERN_NOTICE "Request from floor %d to %d for type %d\n", start_floor, destination_floor, type);
	if (STUB_issue_request != NULL)
                return STUB_issue_request(start_floor, destination_floor, type);
        else
                return -ENOSYS;

}

SYSCALL_DEFINE0(stop_elevator) {
        printk(KERN_NOTICE "Stopping Elevator\n");
        if (STUB_stop_elevator != NULL)
                return STUB_stop_elevator();
        else
                return -ENOSYS;

}

