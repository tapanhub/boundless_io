#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
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
#include <linux/socket.h>
#include <linux/ctype.h>
#include <asm/unistd.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <net/inet_connection_sock.h>
#include <net/request_sock.h>
#include <linux/inet.h>
#include "bio.h"

#define SERVER_PORT 55555

#define dprint(fmt, args...) printk(KERN_INFO"[%s:%d]" #fmt, __func__, __LINE__, ##args)
#ifndef SERVERSOCK_THREADNAME
#define SERVERSOCK_THREADNAME "bio_server"
#define SERVERSOCK_THREADNAMEACCEPT "bio_server_accept"
#endif

int tcpio_serv_accept_worker(void *data);
int tcpio_serv_start_listen(void *data);
int tcpio_serv_start(void);

static atomic_t revc_count;
static atomic_t send_count;



int tcpio_serv_recv(bio_node_t *snode, tcpio_msg_t *tmsg) 
{
	struct msghdr msg = {
                .msg_flags      = MSG_WAITALL,
        };
	struct kvec iov;
	int size=0;
	struct socket *sock = snode->bio_conn.accpted_sock;

	if(sock==NULL) {
		pr_info("sock = NULL\n");
		return -1;
	}
	if(sock->sk==NULL) {
		pr_info("sock->sk is NULL\n");
		return -1;
	}

	iov.iov_base=tmsg;
	iov.iov_len=tmsg->bhdr.totallen;

	//pr_info("calling kernel_recvmsg with iov_len = %d\n", tmsg->bhdr.totallen);
	size = kernel_recvmsg(sock, &msg, &iov, 1, iov.iov_len, msg.msg_flags);
	if(size > 0) {
		atomic_inc(&revc_count);
	}
	pr_info("sock_recvmsg returned %d\n", size);
	return size;
}
  
int tcpio_serv_send(bio_node_t *snode, tcpio_msg_t *tmsg) 
{
	struct msghdr msg = {
                .msg_flags      = MSG_WAITALL,
        };
	struct kvec iov;
	int size=0;
	struct socket *sock = snode->bio_conn.accpted_sock;
	

	if(sock==NULL)
	{
		pr_info("sock is NULL\n");
		return -1;
	}

	iov.iov_base=tmsg;
	iov.iov_len=tmsg->bhdr.totallen;


	size = kernel_sendmsg(sock, &msg, &iov, 1, iov.iov_len);
	atomic_inc(&send_count);
	//pr_info("message size(%d) is sent!", size);
	return size;
}

int tcpio_serv_accept_worker(void *data)
{
	int error,ret=0;
	struct socket *socket;
	struct socket *cscok;
	tcpio_msg_t	*tmsg;
	bio_node_t *snode = (bio_node_t *)data;

	struct inet_connection_sock *isock;

	DECLARE_WAITQUEUE(wait,current);

	
	socket = snode->bio_conn.listen_socket;

	error = sock_create(PF_INET,SOCK_STREAM,IPPROTO_TCP, &snode->bio_conn.accpted_sock);

	cscok=(struct socket *) snode->bio_conn.accpted_sock;

	if(error<0) {
		pr_info(KERN_ERR "create csocket error\n");
		return error;
	}

	spin_lock(&snode->bio_conn.tcpio_serv_lock);
	snode->bio_conn.running = 1;
	spin_unlock(&snode->bio_conn.tcpio_serv_lock);

	isock = inet_csk(socket->sk);

	while (snode->bio_conn.running == 1 && !kthread_should_stop() ) {
		if(reqsk_queue_empty(&isock->icsk_accept_queue)){
			add_wait_queue(&socket->sk->sk_wq->wait, &wait);
			__set_current_state(TASK_INTERRUPTIBLE);
			schedule_timeout(HZ/100);
			__set_current_state(TASK_RUNNING);
			remove_wait_queue(&socket->sk->sk_wq->wait, &wait);
			continue;
		}
		pr_info("do accept\n");
		ret = socket->ops->accept(socket,cscok,O_NONBLOCK);
		if(ret<0){
			pr_err("accept error,release the socket\n");
			sock_release(cscok);
			return ret;
		}

		/*receive*/
		tmsg = alloc_tcpio_mem(sizeof(bio_cmdinfo_t));
		if(!tmsg) {
			printk("unable to allocate tmsg with 256 bytes\n");
			free_tcpio_mem(tmsg);
			return -1;
		}
		pr_info("do receive the package\n");
tcpiorecvmsg:
		if(snode->bio_conn.running != 1 || kthread_should_stop()) {
			free_tcpio_mem(tmsg);
			return -1;
		}
		tcpio_mem_init(tmsg, sizeof(bio_cmdinfo_t));
		error=tcpio_serv_recv(snode,tmsg);
		if (error < 0) {
                	if (error != -EAGAIN && error != -EINTR && error != -ERESTARTSYS) {
				printk("tcpio_serv_recv returned %d\n", error);	
                	}
			
        	}
		if(error == 0) {
			free_tcpio_mem(tmsg);
			continue;
		}

		if(error > 0) {
			bio_process_scmds(snode, tmsg);
			goto tcpiorecvmsg;
		}
	}
	free_tcpio_mem(tmsg);

	return ret;
}

int tcpio_serv_start_listen(void *data)
{
	int error;
	struct socket *socket;
	struct sockaddr_in sin;
	bio_node_t *snode = (bio_node_t  *)data;


	spin_lock(&snode->bio_conn.tcpio_serv_lock);
	snode->bio_conn.running = 1;
	spin_unlock(&snode->bio_conn.tcpio_serv_lock);

	error = sock_create(PF_INET,SOCK_STREAM,IPPROTO_TCP,&snode->bio_conn.listen_socket);

	if(error<0) {
		pr_info(KERN_ERR "sock_create returned %d\n", error);
		return -1;
	}

	socket = snode->bio_conn.listen_socket;
	snode->bio_conn.listen_socket->sk->sk_reuse=1;


	sin.sin_addr.s_addr=htonl(INADDR_ANY);
	sin.sin_family=AF_INET;

	if(biosconfig.sport)
		sin.sin_port=htons(biosconfig.sport);
	else
		sin.sin_port=htons(SERVER_PORT);

	error = socket->ops->bind(socket,(struct sockaddr*)&sin,sizeof(sin));
	if(error<0) {
		pr_info("error: bind address");
		return -1;
	}

	error = socket->ops->listen(socket,5);
	if(error<0) {
		pr_info("error: listen");
		return -1;
	}

	tcpio_serv_accept_worker(snode);
	do_exit(0);
	return 0;
}

int start_bio_server(bio_node_t *snode)
{
	snode->bio_conn.running = 1;
	snode->bio_conn.tcpio_serv_lock = __SPIN_LOCK_UNLOCKED(snode->bio_conn.tcpio_serv_lock);
	snode->bio_conn.thread = kthread_run((void *)tcpio_serv_start_listen, snode, SERVERSOCK_THREADNAME);
	return 0;
}



int stop_tcpio_server(bio_node_t * snode)
{
	int err = 0;

	pr_info("module cleanup\n");
	if (snode->bio_conn.listen_socket!= NULL) 
	{
		if (snode->bio_conn.running == 1) {
			snode->bio_conn.running = 0;
			if( snode->bio_conn.accpted_sock->ops != NULL) {
				synchronize_rcu();
                		kernel_sock_shutdown(snode->bio_conn.accpted_sock, SHUT_RDWR);
                		sock_release(snode->bio_conn.accpted_sock);

			}
		}

		pr_info("stopping listen thead\n");
		err=kthread_stop(snode->bio_conn.thread);

		
	}


	/* free allocated resources before exit */
	if (snode->bio_conn.listen_socket!= NULL) 
	{
		pr_info("release the listen_socket\n");
		synchronize_rcu();
               	kernel_sock_shutdown(snode->bio_conn.listen_socket, SHUT_RDWR);
               	sock_release(snode->bio_conn.listen_socket);
	}

	pr_info(KERN_INFO SERVERSOCK_THREADNAME": module unloaded\n");
	return err;
}

int restart_bio_server(bio_node_t *snode)
{
	stop_tcpio_server(snode);
	start_bio_server(snode);
	return 0;
}
