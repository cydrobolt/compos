#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/list.h>
#include <asm/uaccess.h>

// Import proc_fs and netfilter
#include <linux/proc_fs.h>
#include <linux/tcp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/skbuff.h>

// Import JSON libraries to interface with compos_ctl
#include "lib/jsmn.h"


MODULE_LICENSE("MIT");
MODULE_AUTHOR("cydrobolt");
MODULE_DESCRIPTION("compos self-control module");

static struct nf_hook_ops nfho;

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

static int __init compos_init(void) {
    printk(KERN_INFO "Loading compos\n");

    nfho.hook = hook_func_out;
    nfho.hooknum = NF_INET_LOCAL_OUT;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;
    // Register hook
    nf_register_hook(&nfho);

    return 0;
}

static void __exit compos_cleanup(void) {
    printk(KERN_ALERT "Cleaning up compos.\n");
    nf_unregister_hook(&nfho);
}

module_init(compos_init);
module_exit(compos_cleanup);
