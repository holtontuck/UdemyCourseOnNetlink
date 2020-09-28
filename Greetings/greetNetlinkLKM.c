#include <linux/module.h>
#include <linux/netlink.h>
#include <net/sock.h>
#include <linux/string.h>


#define NETLINK_TEST_PROTOCOL	31

static struct sock* nl_sk = NULL;

static void netlink_recv_msg_fn(struct sk_buff *skb_in) {


}


static struct netlink_kernel_cfg cfg = {

	.input = netlink_recv_mesg_fn, 
};


static int __init NetlinkGreetings_init(void) {
	printk(KERN_INFO "Hello Kernel, I am kernel Module NetlinkGreetingsLKM.ko\n");
	
	//Create a netlink socket
	nl_sk = netlink_kernel_create(&init_net, NETLINK_TEST_PROTOCOL, &cfg);
	if (nl_sk == NULL) {
		printk(KERN_INFO "Kernel Netlink Socket for Netlink protocl %u failed.\n"
			, NETLINK_TEST_PROTOCOL);
			return -ENOMUM;
	}
	printk("Netlink Socket Created Successfully");
	return 0;
}


static void __exit NetlinkGreetings_exit(void) {
	printk(KERN_INFO "Goodbye Kernel, I am kernel Module NetlinkGreetingsLKM.ko\n");
	nl_kernel_release(nl_sk);
	nl_sk = NULL;
}


static void nlmsg_dump(struct nlmsghdr *nlh) {

	if (nlh == NULL) {
		printk(KERN_INFO "Invalid Netlink Message Header");
		return -1;
	}

	printk("NETLINK MESSAGE HEADER FIELD VALUES:\n");
	printk("LENGTH: %d\n", nlh->nlmsg_len);
	printk("TYPE: %hd\n", nlh->nlmsg_type);
	printk("FLAGS: %hd\n", nlh->nlmsg_flags);
	printk("SEQUENCE: %d\n", nlh->nlmsg_seq);
	printk("PID: %d\n", nlh->nlmsg_pid);
}

module_init(NetlinkGreetings_init);
module_exit(NetlinkGreetings_exit);

MODULE_LICENSE("GPL")

