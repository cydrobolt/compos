#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

MODULE_LICENSE("MIT");
MODULE_AUTHOR("cydrobolt");
MODULE_DESCRIPTION("compos self-control module");

static int __init compos_init(void) {
    printk(KERN_INFO "Loading compos\n");
    return 0;
}

static void __exit compos_cleanup(void) {
    printk(KERN_ALERT "Cleaning up compos.\n");
}

module_init(compos_init);
module_exit(compos_cleanup);
