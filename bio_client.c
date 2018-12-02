#include <linux/slab.h>
#include <linux/kthread.h>

#include <linux/errno.h>
#include <linux/types.h>
#include "bio.h"

#define BIO_CLIENT_THREAD_NAME	"bio_client"

int bio_register_device(void);
static int __init bio_client_init(void);
static void  __exit bio_client_exit(void);

static bio_node_t client_node;

bio_node_t *get_cnode(void)
{
	return &client_node;
}


int bio_register_device()
{
	bio_device_t *biodev = kzalloc(sizeof(bio_device_t), GFP_KERNEL);
    	if (!biodev) {
		printk("unable to allocate dynamic memory\n");
        	return -ENOMEM;
	}

	biodev->bio_device_lock = __SPIN_LOCK_UNLOCKED(biodev->bio_device_lock);
	INIT_LIST_HEAD(&biodev->list);
	return 0;
}

int bio_conn_init(void)
{
	snprintf(client_node.bio_conn.serverip, sizeof(client_node.bio_conn.serverip), "%s", bioconfig.serverip);
	client_node.bio_conn.port = bioconfig.dport;
	return 0;
}


static int __init bio_client_init(void)
{
	extern int tcpio_test(bio_node_t *);
	memset(&client_node, 0, sizeof(client_node));
	client_node.bio_node_lock = __SPIN_LOCK_UNLOCKED(client_node.bio_node_lock);
	client_node.role = BIO_CLIENT_NODE;
	INIT_LIST_HEAD(&client_node.devlist);
	init_bioctl();
	bio_conn_init();
	
	/*TODO start debugfs */
	connect_bio_server(&client_node);
	register_bio_cfile(&client_node, "/tmp/myfile");
	register_bio_cfile(&client_node, "/tmp/myfile1");
    	return 0;
}

static void  __exit bio_client_exit(void)
{

	/* stop, cleanup , free other resources */
	exit_bioctl();
	deregister_bio_cfile_all(&client_node);
	cleanup_tcpio_client(&client_node);

}

module_init(bio_client_init);
module_exit(bio_client_exit);
MODULE_LICENSE("GPL");
