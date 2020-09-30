#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <linux/netlink.h>
/*For kernel space, all errors are define in
 usr/include/asm-generic/errno.h*/
#include <errno.h>
#include <unistd.h>
#include <memory.h>
#include <stdint.h>
#include <pthread.h>
#include "netLinkKernelUtils.h"

#define NETLINK_USER	31


struct thread_arg_t {
	int sock_fd;
};


int
send_netlink_msg_to_kernel(int sock_fd, char* msg, 
	uint32_t msg_size, int nlmsg_type, uint16_t flags);


int
create_netlink_socket(int proto_num) {
	return socket(AF_NETLINK, SOCK_DGRAM, proto_num);
}

static void
greet_kernel(int sock_fd, char* user_msg, uint32_t msg_len) {
	send_netlink_msg_to_kernel (sock_fd,
			user_msg, msg_len, NLMSG_GREET, NLM_F_ACK);
}


/*Return the number of bytes sent to kernel*/ 
int
send_netlink_msg_to_kernel(int sock_fd,
							char* msg,
							uint32_t msg_size,
							int nlmsg_type,
							uint16_t flags){

	struct sockaddr_nl dest_addr;
	int ret_val = 0;

	memset(&dest_addr, 0, sizeof(dest_addr));
	dest_addr.nl_family = AF_NETLINK;
	dest_addr.nl_pid	= 0;//Because it's the kernel, there's no PID
	
	struct nlmsghdr* nlh = (struct nlmsghdr*)calloc(1,
			NLMSG_HDRLEN + NLMSG_SPACE(msg_size));
		
	nlh->nlmsg_len 		= 	NLMSG_HDRLEN + NLMSG_SPACE(msg_size);
	nlh->nlmsg_pid 		= 	getpid();
	nlh->nlmsg_flags 	=  	flags;
	nlh->nlmsg_type		= 	nlmsg_type;
	nlh->nlmsg_seq 		= 	0;

	strncpy(NLMSG_DATA(nlh), msg, msg_size);

	//Wrap message inside iovector data structure
	struct iovec iov;
	iov.iov_base = (void*)nlh;
	iov.iov_len = nlh->nlmsg_len;

	//Now, wrap the data in a msghdr struct
	static struct msghdr outermsghdr;

	memset(&outermsghdr, 0, sizeof(outermsghdr));
	outermsghdr.msg_name 		= (void*)&dest_addr;
	outermsghdr.msg_namelen		= sizeof(dest_addr);
	outermsghdr.msg_iov 		= &iov;
	outermsghdr.msg_iovlen		= 1;//Number of units in this vector
	
	//reset errno
	errno = 0;
	ret_val = sendmsg(sock_fd, &outermsghdr, 0);
	if (ret_val < 0) {
		fprintf(stderr, "Msg Sending Failed; error number = %d\n", errno);
	}
	return ret_val;
}


static void*
_start_kernel_data_receiver_thread(void* arg) {
	
	int ret_val = 0;
	struct iovec iov;
	struct nlmsghdr* nlh_recv = NULL;
	static struct msghdr outermsghdr;
	int sock_fd = 0;

	struct thread_arg_t* thread_arg = (struct thread_arg_t*)arg;
	sock_fd = thread_arg->sock_fd;

	nlh_recv = (struct nlmsghdr*)calloc(1, 
			NLMSG_HDRLEN + NLMSG_SPACE(MAX_PAYLOAD));

	do {/* Becase Userspace application is receiving the msg from KS
			leave all fields of nlmsghdr empty. Kernel will fill the fields
			when it delivers the msg to userspace */
		memset(nlh_recv, 0, NLMSG_HDRLEN + NLMSG_SPACE(MAX_PAYLOAD));

		iov.iov_base = (void*) nlh_recv;
		iov.iov_len = NLMSG_HDRLEN + NLMSG_SPACE(MAX_PAYLOAD);

		memset(&outermsghdr, 0, sizeof(struct msghdr));

		outermsghdr.msg_iov		= &iov;
		outermsghdr.msg_name	= NULL;
		outermsghdr.msg_iovlen	= 1;
		outermsghdr.msg_namelen = 0;

		/* Read message from kernel. It's a blocking system call
		 * Application execution is suspended at this point
		 * and would not resume until it receives linux kernel
		 * msg. We can configure recvmsg() not to block,
		 * but we'll use it in blocking mode, for now. */

		ret_val = recvmsg(sock_fd, &outermsghdr, 0);
		
		/* We have sucessfully received msg from linux kernel*/
		/* print the msg from kernel. kernel msg shall be stored
		 * in outermsghdr.msg_iv->iov_base
		 * in same format : nl_hdr followed by data*/
		
		nlh_recv = outermsghdr.msg_iov->iov_base;
		char *payload = NLMSG_DATA(nlh_recv);

	printf("Received Netlink msg from kernel, bytes recvd = %d\n", ret_val);
	printf("msg recvd from kernel = %s\n", payload);
	} while(1);
	
}

void
start_kernel_data_receiver_thread(struct thread_arg_t* thread_arg) {
	
	pthread_attr_t attr;
	pthread_t recv_pkt_thread;

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	pthread_create(&recv_pkt_thread, &attr,
			_start_kernel_data_receiver_thread,
			(void*)thread_arg);
}


int
main(int argc, char** argv) {

	int choice = 0;
	int sock_fd = 0;
	
	errno = 0;
	sock_fd = create_netlink_socket(NETLINK_USER);

	if (sock_fd < 0) {
		fprintf(stderr, "Error: Netlink socket creation failed: error = %d\n", errno);
		exit(EXIT_FAILURE);
	}				

	struct sockaddr_nl src_addr;

	struct nlmsghdr* nlh = NULL;

	memset(&src_addr, 0, sizeof(src_addr));

	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_pid = getpid();

	if (bind(sock_fd, (struct sockaddr*)&src_addr, sizeof(src_addr)) == -1) {
		fprintf(stderr, "Error: Bind has failed\n");
		exit(1);
	}

	struct thread_arg_t thread_arg;
	thread_arg.sock_fd = sock_fd;

	start_kernel_data_receiver_thread(&thread_arg);

	while(1) {
	/*Main - Menu*/
		printf("Main-Menu\n");
		printf("\t1. Greet Kernel\n");
		printf("\t2. Exit\n");
		printf(">>");
		scanf("%d\n", &choice);
		switch(choice) {
			case 1:
				{
					char user_msg[MAX_PAYLOAD];
					memset (user_msg, 0, MAX_PAYLOAD);
					if ((fgets(user_msg, MAX_PAYLOAD, stdin) == NULL)){
						fprintf(stderr, "Error reading from stdin\n");
						exit(1);
					}
					greet_kernel(sock_fd, user_msg, strnlen(user_msg, MAX_PAYLOAD));
					break;
				}

			case 2:
				{
					close(sock_fd);
					return 0;
					break;
				}
			default:
				;
		}
	}
	return 0;
}
