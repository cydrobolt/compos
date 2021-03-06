#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/list.h>
#include <asm/uaccess.h>

// Import proc_fs and netfilter
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/tcp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/skbuff.h>

// Import JSON libraries to interface with compos_ctl
#include "lib/jsmn.h"

// Define constants
#define PROCFS_NAME         "compos"
#define PROCFS_MAX_SIZE     1024

MODULE_LICENSE("MIT");
MODULE_AUTHOR("cydrobolt");
MODULE_DESCRIPTION("compos self-control module");

static struct nf_hook_ops nfho;
static struct proc_dir_entry *proc_entry;

static char procfs_buffer[PROCFS_MAX_SIZE];
static int procfs_buffer_size = 0;

/* proc file functions */
static int cp_proc_write(struct file *file, char *buffer, size_t count, loff_t *offset) {
    procfs_buffer_size = count;
    if (procfs_buffer_size > PROCFS_MAX_SIZE) {
        procfs_buffer_size = PROCFS_MAX_SIZE;
    }

    printk(KERN_INFO "received something in write!");
    if (!copy_from_user(procfs_buffer, buffer, procfs_buffer_size)) {
        printk(KERN_INFO "received information in procfile");
        printk(KERN_INFO "%s", procfs_buffer);
        return -EFAULT;
    }

    return procfs_buffer_size;
}

static int cp_proc_show(struct seq_file *m, void *v) {
    seq_printf(m, "hello world!\n");
    return 0;
}

static int cp_proc_open(struct inode *inode, struct file *file) {
    return single_open(file, cp_proc_show, NULL);
}

static const struct file_operations cp_fops = {
    owner: THIS_MODULE,
    open: cp_proc_open,
    read: seq_read,
    llseek: seq_lseek,
    release: single_release,
    write: cp_proc_write
};

/* netfilter hooks */
unsigned int hook_func_out (void *priv,
                            struct sk_buff *skb,
                            const struct nf_hook_state *state) {

    // Intercept outbound packets
    struct iphdr *ip_header = (struct iphdr *) skb_network_header(skb);
    // unsigned int src_ip = (unsigned int)ip_header->saddr;
    unsigned int dest_ip = (unsigned int) ip_header->daddr;

    printk("packet with dest %pI4", &dest_ip);
    if (false) {
        return NF_DROP;
    }

    return NF_ACCEPT;
}

/* initialize & cleanup compos */
static int __init compos_init(void) {
    printk(KERN_INFO "Loading compos\n");

    nfho.hook = hook_func_out;
    nfho.hooknum = NF_INET_LOCAL_OUT;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;
    // Register hook
    nf_register_hook(&nfho);

    // Initialize proc file
    proc_entry = proc_create(PROCFS_NAME, 0, NULL, &cp_fops);

    if (proc_entry == NULL) {
        remove_proc_entry(PROCFS_NAME, NULL);
        printk(KERN_ALERT "Could not initialize /proc/%s\n", PROCFS_NAME);
        return -ENOMEM;
    }

    printk(KERN_INFO "compos proc file created");

    return 0;
}

static void __exit compos_cleanup(void) {
    printk(KERN_ALERT "Cleaning up compos.\n");
    nf_unregister_hook(&nfho);
    remove_proc_entry(PROCFS_NAME, NULL);
}

module_init(compos_init);
module_exit(compos_cleanup);
