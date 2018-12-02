#include <linux/slab.h>
#include <linux/kthread.h>

#include <linux/errno.h>
#include <linux/types.h>

#include <linux/netdevice.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/delay.h>
#include <linux/un.h>
#include <linux/unistd.h>
#include <linux/wait.h>
#include <linux/ctype.h>
#include <asm/unistd.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <net/inet_connection_sock.h>
#include <net/request_sock.h>
#include <linux/skbuff.h>
#include <linux/workqueue.h>
#include <linux/inet.h>
#include "bio.h"

#define SERVER_PORT 55555
#define SERVER_ADDR "192.168.10.3"



int connect_bio_server(bio_node_t *cnode)
{
	int error;
	struct socket *socket;
	struct sockaddr_in sin;
	char one = 1;

	if(cnode->bio_conn.connected == 1  && cnode->bio_conn.reconfig != 1) {
		printk("already connected\n");
		return 0;
	}
	if (cnode->bio_conn.client_socket != NULL) {
		printk("[%s]release the client_socket\n", __func__);
		sock_release(cnode->bio_conn.client_socket);
		cnode->bio_conn.client_socket = NULL;
	} 

	error = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &cnode->bio_conn.client_socket);
	if (error < 0) {
		printk(KERN_ERR "CREATE SOCKET ERROR");
		return -1;
	}

	socket = cnode->bio_conn.client_socket;
	cnode->bio_conn.client_socket->sk->sk_reuse = 1;
	socket->ops->setsockopt(socket, SOL_TCP, TCP_NODELAY, &one, sizeof(one));

	if(cnode->bio_conn.serverip[0] != '\0') {
		sin.sin_addr.s_addr = in_aton(cnode->bio_conn.serverip);
		//sin.sin_addr.s_addr = in_aton(cnode->bio_conn.serverip);
		sin.sin_family = AF_INET;
		if(cnode->bio_conn.port)
			sin.sin_port = htons((unsigned short int) cnode->bio_conn.port);
		else
			sin.sin_port = htons((unsigned short int) SERVER_PORT);
	} else {
		sin.sin_addr.s_addr = in_aton(SERVER_ADDR);
		sin.sin_family = AF_INET;
		sin.sin_port = htons(SERVER_PORT);
	}
	error = socket->ops->connect(socket, (struct sockaddr *)&sin, sizeof(sin), 0);
	if (error < 0) {
		cnode->bio_conn.connected = 0;
		printk(KERN_ERR "connect failed");
		return -1;
	} else {
		printk("tcp io connected\n");
		cnode->bio_conn.connected = 1;
	}
	return 0;
}

int bio_send_msg(bio_node_t *cnode, tcpio_msg_t *tmsg) 
{
	int ret = 0;
	struct msghdr msg = {0};
	struct socket *sock = cnode->bio_conn.client_socket;
	if(cnode->role == BIO_CLIENT_NODE) {
		sock = cnode->bio_conn.client_socket;

		if(cnode->bio_conn.connected == 0) {
			printk("connected=0, calling connect_bio_server\n");
			connect_bio_server(cnode);
		}
		if(cnode->bio_conn.connected == 1) {
			struct kvec iv = {tmsg, tmsg->bhdr.totallen};
			sock = cnode->bio_conn.client_socket;
			if (sock == NULL) {
				printk("sock is NULL\n");
				return -1;
			}
			//printk("connected=1, calling kernel_sendmsg\n");
			ret = kernel_sendmsg(sock, &msg, &iv, 1, tmsg->bhdr.totallen);
			if (ret < 0) {
				printk("kernel_sendmsg returned %d\n", ret);
				cnode->bio_conn.connected = 0;
			}
			//printk("kernel_sendmsg returned %d\n", ret);
			

		}
	}
	return 0;
}

int bio_recv_msg(bio_node_t *cnode, tcpio_msg_t *tmsg) 
{
	struct socket *sock = cnode->bio_conn.client_socket;
	struct msghdr msg = {
                .msg_flags      = MSG_WAITALL,
        };
	struct kvec iov;
	int size=0;

	if(sock==NULL) {
		printk("sock = NULL\n");
		return -1;
	}
	if(sock->sk==NULL) {
		printk("sock->sk is NULL\n");
		return -1;
	}

	iov.iov_base=tmsg;
	iov.iov_len=tmsg->bhdr.totallen;
	size = kernel_recvmsg(sock, &msg, &iov, 1, iov.iov_len, msg.msg_flags);
	//printk("sock_recvmsg returned %d\n", size);
	return size;
}

int tcpio_sendcmd(bio_node_t *cnode, tcpio_msg_t *tmsg)
{
	return bio_send_msg(cnode, tmsg);
}

int tcpio_test(bio_node_t *cnode)
{
	int size;
	tcpio_msg_t *tmsg,*reply;
	tmsg = alloc_tcpio_mem(256);
	if(tmsg) {
		reply = alloc_tcpio_mem(256);
	} else {
		printk("unable to allocate tmsg\n");
		return -1;
	}
	if(reply == NULL) {
		printk("unable to allocate reply\n");
		goto err1;
	}

	tmsg->bhdr.msgtype = 10;
	tmsg->bhdr.msgid = 5;
	snprintf(tmsg->buffer, 256, "hello from client\n");
	bio_send_msg(cnode, tmsg);
	printk("calling bio_recv_msg\n");
	size = bio_recv_msg(cnode, reply);
	if(size > 0) {
		printk("client recved:%s\n", reply->buffer);
	}
	
	free_tcpio_mem(reply);
err1:
	free_tcpio_mem(tmsg);
	return 0;
}

void cleanup_tcpio_client(bio_node_t *cnode)
{
        if (cnode->bio_conn.client_socket != NULL) {
                printk("release the client_socket\n");
                sock_release(cnode->bio_conn.client_socket);
		cnode->bio_conn.connected = 0;
                cnode->bio_conn.client_socket = NULL;
        }

}

