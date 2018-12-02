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
#define SERVER_ADDR "192.168.1.2"


void *alloc_tcpio_mem(int size)
{
	tcpio_msg_t *tmsg;
	int	totallen = sizeof(tcpio_msg_t) + size;
	tmsg = kmalloc(totallen, GFP_KERNEL);
	memset(tmsg, 0, totallen);
	if(tmsg) {
		tmsg->bhdr.msglen=size;
		tmsg->bhdr.len=size;
		tmsg->bhdr.totallen=totallen;
	} else {
		printk("Unable to allocate %d bytes with flag GFP_KERNEL\n", size);
	}
	return tmsg;
}

tcpio_msg_t * tcpio_mem_init(tcpio_msg_t *tmsg, int size)
{
	int	totallen = sizeof(tcpio_msg_t) + size;

	memset(tmsg, 0, totallen);
	tmsg->bhdr.msglen=size;
	tmsg->bhdr.len=size;
	tmsg->bhdr.totallen=totallen;
	return tmsg;
}

void free_tcpio_mem(void *buf)
{
	kfree(buf);
}



