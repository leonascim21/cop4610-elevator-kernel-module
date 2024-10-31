#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/syscalls.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("cop4610t");
MODULE_DESCRIPTION("Elevator Kernel Module");
MODULE_VERSION("1.0");

#define PROC_NAME "elevator"
#define BUF_LEN 10000
#define PERMS 0666
#define PARENT NULL
#define MAX_FLOOR 6
#define MAX_PASSENGERS 5
#define F_WEIGHT 100
#define O_WEIGHT 150
#define S_WEIGHT 250
#define J_WEIGHT 200
#define MAX_WEIGHT 750
#define IDLE 0
#define UP 1
#define DOWN 2
#define LOADING 3
#define OFFLINE 4

static ssize_t procfile_read(struct file *file, char *buf, size_t count, loff_t *ppos);
static bool load_passengers(void);
static bool unload_passengers(void);
static void move_elevator(void);
static int elevator_thread_fn(void *data);
static int start_elevator(void);
static int issue_request(int start_floor, int dest_floor, int type);
static int stop_elevator(void);

extern int (*STUB_start_elevator)(void);
extern int (*STUB_issue_request)(int, int, int);
extern int (*STUB_stop_elevator)(void);


struct passenger {
    struct list_head list;
    int start_floor;
    int dest_floor;
    //type: 0 - Freshman, 1 - Sophomore, 2 - junior, 3 - senior
    int type;
    int weight;
};

struct floor {
    struct list_head waiting_list;
    int waiting_count;
};

struct elevator {
    int state;
    int current_floor;
    int num_passengers;
    int current_weight;
    int passengers_serviced;
    struct list_head inside_elevator_list;
    struct floor floors[MAX_FLOOR];
    struct mutex elevator_lock;
    struct task_struct *elevator_thread;
};

static bool is_stopping = false;
static struct elevator elev;
static struct proc_dir_entry *proc_entry;

static const struct proc_ops elevator_fops = {
    .proc_read = procfile_read
};

static char get_passenger_type(int type) {
    return (type == 0) ? 'F' : (type == 1) ? 'O' : (type == 2) ? 'J' : 'S';
}

static ssize_t procfile_read(struct file *file, char *buf, size_t count, loff_t *ppos) {
    char buffer[BUF_LEN];
    int len = 0;

    if (mutex_lock_interruptible(&elev.elevator_lock)) {
        return 1;
    }

    int state = elev.state;
    len += snprintf(buffer + len, sizeof(buffer) - len, "Elevator state: %s\n",
                    (state == OFFLINE) ? "OFFLINE" : (state == IDLE) ? "IDLE" :
                    (state == UP) ? "UP" : (state == DOWN) ? "DOWN" : "LOADING");
    len += snprintf(buffer + len, sizeof(buffer) - len, "Current floor: %d\n", elev.current_floor);
    len += snprintf(buffer + len, sizeof(buffer) - len,
                    "Current load: %d lbs\n", elev.current_weight);
    len += snprintf(buffer + len, sizeof(buffer) - len, "Elevator status:");

    struct passenger *p;
    list_for_each_entry(p, &elev.inside_elevator_list, list) {
        len += snprintf(buffer + len, sizeof(buffer) - len, " %c%d",
                       get_passenger_type(p->type), p->dest_floor);
    }
    len += snprintf(buffer + len, sizeof(buffer) - len, "\n\n");

    for (int i = MAX_FLOOR; i > 0; i--) {
        if (i == elev.current_floor) {
            len += snprintf(buffer + len, sizeof(buffer) - len, "[*] Floor %d: %d waiting",
                            i, elev.floors[i - 1].waiting_count);
        } else {
            len += snprintf(buffer + len, sizeof(buffer) - len, "[ ] Floor %d: %d waiting",
                            i, elev.floors[i - 1].waiting_count);
        }

        list_for_each_entry(p, &elev.floors[i - 1].waiting_list, list) {
            len += snprintf(buffer + len, sizeof(buffer) - len, " %c%d",
                            get_passenger_type(p->type), p->dest_floor);
        }
        len += snprintf(buffer + len, sizeof(buffer) - len, "\n");
    }

    len += snprintf(buffer + len, sizeof(buffer) - len,
                    "\nNumber of passengers: %d\n", elev.num_passengers);
    int waiting = 0;
    for (int i = 0; i < MAX_FLOOR; i++) {
        waiting += elev.floors[i].waiting_count;
    }
    len += snprintf(buffer + len, sizeof(buffer) - len,
                    "Number of passengers waiting: %d\n", waiting);
    len += snprintf(buffer + len, sizeof(buffer) - len,
                    "Number of passengers serviced: %d\n", elev.passengers_serviced);

    mutex_unlock(&elev.elevator_lock);

    return simple_read_from_buffer(buf, count, ppos, buffer, len);
}

static bool load_passengers(void) {
    //dont load passenger if elevator is stopping
    if (is_stopping) {
        return false;
    }

    struct passenger *p, *dummy;
    struct floor *current_floor = &elev.floors[elev.current_floor - 1];
    bool loaded = false;

    list_for_each_entry_safe(p, dummy, &current_floor->waiting_list, list) {
        if (elev.num_passengers < MAX_PASSENGERS && elev.current_weight + p->weight <= MAX_WEIGHT){
            list_del(&p->list);
            list_add_tail(&p->list, &elev.inside_elevator_list);
            current_floor->waiting_count--;
            elev.num_passengers++;
            elev.current_weight += p->weight;
            elev.state = LOADING;
            loaded = true;
        } else {
            break;
        }
    }
    if (loaded) {
        return true;
    }
    return false;
}

static bool unload_passengers(void) {
    struct passenger *p, *dummy;
    bool unloaded = false;

    list_for_each_entry_safe(p, dummy, &elev.inside_elevator_list, list) {
        if (p->dest_floor == elev.current_floor) {
            list_del(&p->list);
            elev.current_weight -= p->weight;
            elev.passengers_serviced++;
            kfree(p);
            elev.num_passengers--;
            elev.state = LOADING;
            unloaded = true;
        }
    }
    if (unloaded) {
        return true;
    }
    return false;
}

static void move_elevator(void) {
    //elevator goes up until it reaches max floor
    if (elev.state == UP) {
        elev.current_floor++;
        if (elev.current_floor >= MAX_FLOOR) {
            elev.current_floor = MAX_FLOOR;
            elev.state = DOWN;
        }
    //elevator goes down until it reaches first floor
    } else if (elev.state == DOWN) {
        elev.current_floor--;
        if (elev.current_floor <= 1) {
            elev.current_floor = 1;
            elev.state = UP;
        }
    }
}

static int elevator_thread_fn(void *data) {
    while (!kthread_should_stop()) {
        if(elev.state == OFFLINE) {
            ssleep(1);
            continue;
        }

        if (mutex_lock_interruptible(&elev.elevator_lock)) {
            continue;
        }

        int prev_state = elev.state;
        bool loaded = load_passengers();
        bool unloaded = unload_passengers();
        //sleep for 1 sec if passengers are loaded or unloaded
        if (loaded || unloaded) {
            mutex_unlock(&elev.elevator_lock);
            ssleep(1);
            if(mutex_lock_interruptible(&elev.elevator_lock)) {
                continue;
            }
        }

        //check if anyone is waiting on any floor to start elevator if idling
        bool is_waiting = false;
        for (int i = 0; i < MAX_FLOOR; i++) {
            if (elev.floors[i].waiting_count > 0) {
                is_waiting = true;
                break;
            }
        }

        if (elev.num_passengers > 0 || is_waiting) {
            if (elev.state == IDLE || elev.state == LOADING) {
                if (prev_state == UP || prev_state == DOWN) {
                    elev.state = prev_state;
                } else {
                    //default elevator to go up if it was idle or offline
                    elev.state = UP;
                }
            }
            move_elevator();
        } else {
            elev.state = IDLE;
        }

        mutex_unlock(&elev.elevator_lock);
        //sleep 2 seconds after every move
        ssleep(2);
        if (is_stopping) {
            stop_elevator();
        }
    }
    return 0;
}

static int start_elevator(void) {
    if (elev.state != OFFLINE) {
        return 1;
    }

    is_stopping = false;
    elev.state = IDLE;
    return 0;
}

static int issue_request(int start_floor, int dest_floor, int type) {
    if (start_floor < 1 || start_floor > MAX_FLOOR || dest_floor < 1 || dest_floor > MAX_FLOOR
        || type < 0 || type > 3 || start_floor == dest_floor) {
        return 1;
    }

    struct passenger *new_passenger = kmalloc(sizeof(struct passenger), GFP_KERNEL);
    if (!new_passenger) {
        return -ENOMEM;
    }

    new_passenger->start_floor = start_floor;
    new_passenger->dest_floor = dest_floor;
    new_passenger->type = type;
    new_passenger->weight = (type == 0) ? F_WEIGHT : (type == 1) ? O_WEIGHT :
                            (type == 2) ? J_WEIGHT : S_WEIGHT;

    struct floor *floor = &elev.floors[start_floor - 1];

    if (mutex_lock_interruptible(&elev.elevator_lock)) {
        kfree(new_passenger);
        return 2;
    }

    list_add_tail(&new_passenger->list, &floor->waiting_list);
    floor->waiting_count++;

    mutex_unlock(&elev.elevator_lock);
    return 0;
}

static int stop_elevator(void) {
    if (elev.state == OFFLINE) {
        return 1;
    }
    if (elev.num_passengers != 0) {
        is_stopping = true;
    } else {
        elev.state = OFFLINE;
    }
    return 0;
}

static int __init elevator_init(void) {
    proc_entry = proc_create(PROC_NAME, PERMS, PARENT, &elevator_fops);
    if (!proc_entry) {
        return -ENOMEM;
    }

    mutex_init(&elev.elevator_lock);
    elev.state = OFFLINE;
    elev.current_floor = 1;
    elev.num_passengers = 0;
    elev.current_weight = 0;
    elev.passengers_serviced = 0;
    INIT_LIST_HEAD(&elev.inside_elevator_list);

    for (int i = 0; i < MAX_FLOOR; i++) {
        INIT_LIST_HEAD(&elev.floors[i].waiting_list);
        elev.floors[i].waiting_count = 0;
    }

    STUB_start_elevator = start_elevator;
    STUB_issue_request = issue_request;
    STUB_stop_elevator = stop_elevator;

    elev.elevator_thread = kthread_run(elevator_thread_fn, NULL, "elevator_thread");

    return 0;
}

static void __exit elevator_exit(void) {
    if (elev.elevator_thread) {
        kthread_stop(elev.elevator_thread);
    }

    struct passenger *p, *dummy;

    list_for_each_entry_safe(p, dummy, &elev.inside_elevator_list, list) {
        list_del(&p->list);
        kfree(p);
    }

    for (int i = 0; i < MAX_FLOOR; i++) {
        list_for_each_entry_safe(p, dummy, &elev.floors[i].waiting_list, list) {
            list_del(&p->list);
            kfree(p);
        }
    }

    mutex_destroy(&elev.elevator_lock);
    proc_remove(proc_entry);

    STUB_start_elevator = NULL;
    STUB_issue_request = NULL;
    STUB_stop_elevator = NULL;
}

module_init(elevator_init);
module_exit(elevator_exit);