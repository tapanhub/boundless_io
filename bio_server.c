#include <linux/slab.h>
#include <linux/kthread.h>

#include <linux/errno.h>
#include <linux/types.h>
#include "bio.h"

#define BIO_SERVER_THREAD_NAME	"bio_server"

int bio_register_device(void);
int bio_server_worker(void *unused);
void bio_server_exit(void);
int start_bio_server(bio_node_t *snode);

static bio_node_t server_node;

bio_node_t *get_snode()
{
	return &server_node;
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
	/* Register device */
	return 0;
}

int bio_server_worker(void *unused)
{
	/* int error,ret=0; */
	start_bio_server(&server_node);
	while (!kthread_should_stop())
	{
		/*TODO process each device's pending task */
		set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(HZ);
	}
	printk(KERN_INFO "Thread Stopping\n");
	do_exit(0);
	return 0;
}

int bio_server_init(void)
{
	memset(&server_node, 0, sizeof(server_node));
	server_node.bio_node_lock = __SPIN_LOCK_UNLOCKED(server_node.bio_node_lock);
	server_node.role = BIO_SERVER_NODE;
	INIT_LIST_HEAD(&server_node.devlist);
	
	pr_info("creating debugfs entries\n");
	init_bioctl();
	pr_info("starting bio server\n");
	start_bio_server(get_snode());
    	return 0;
}

void bio_server_exit()
{

	/* stop, cleanup , free other resources */
	exit_bioctl();
	stop_tcpio_server(&server_node);

	deregister_bio_sfile_all(&server_node);
}

module_init(bio_server_init);
module_exit(bio_server_exit);
MODULE_LICENSE("GPL");
