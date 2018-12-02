#include <asm/uaccess.h>
#include <linux/inet.h>
#include "bio.h"

#define  COMMAND_MAX_LEN 128

struct bio_sconfig biosconfig = {
	.sport=55555,
};
struct dentry *bio_ctl=NULL; 
int fv;
struct dentry *basedir; 



static int bioctl_show(struct seq_file *s, void *unused)
{
	seq_printf(s, "serverip port:%d\n", biosconfig.sport);
        return 0;
}

static int bioctl_open(struct inode *inode, struct file *file)
{
        return single_open(file, bioctl_show, NULL);
}

static ssize_t bio_ctl_write(struct file *fp, const char __user *user_buffer, 
                                size_t count, loff_t *position) 
{ 
	char *s;
	long kint;
	char command_buf[COMMAND_MAX_LEN];
	int i=0;
	
	memset(command_buf, '\0', sizeof(command_buf));

        if(count > COMMAND_MAX_LEN ) 
                return -EINVAL; 
	if(*position > COMMAND_MAX_LEN) {
		return 0;
	}
	if(*position + count > COMMAND_MAX_LEN) {
		count = COMMAND_MAX_LEN - *position;
	}
	if(copy_from_user(command_buf, user_buffer, count)) {
		return -EFAULT;
	}
	
	if(strstr(command_buf, "help")) {
		pr_info("echo '<server ipaddr>:<server port>' > bio_ctl\n");
	}
  
	s=command_buf;
	{
		char sport[20] = {0};
		i = 0;
		s += 1; 	/* skip ':' char */
		while(*s && (s - command_buf) < COMMAND_MAX_LEN && (i < sizeof(sport)-2)) {
			if(*s == ' ' || *s == ',') {
				break;
			}
			sport[i++] = *s++;
		}
		sport[i] = '\0';

		if(kstrtol(sport, 0, &kint)) {
			printk("invalid sport in \"%s\"\n", command_buf);
			return -EINVAL;
		}
		if(kint > 0 && kint < 65535) {
			if(biosconfig.sport != kint) {
				biosconfig.sport = kint;
				biosconfig.reconfig = 1;
			}
		} else {
			printk("invalid sport in \"%s\"\n", command_buf);
			return -EINVAL;
		}
		
	} 
	if(biosconfig.reconfig == 1) {
		printk("new config installed: server port=%d \n", biosconfig.sport);
		bio_node_t *snode = get_snode();		
		restart_bio_server(snode);
		biosconfig.reconfig = 0;
	}
	return count;
} 
static const struct file_operations bio_ctl_fops = { 
	.open           = bioctl_open,
        .read           = seq_read,
        .llseek         = seq_lseek,
        .release        = single_release,
        .write 		= bio_ctl_write, 
}; 

int  init_debugfs(void)
{
	basedir = debugfs_create_dir("bio_ctl", NULL);
	return (0);
}

void exit_debugfs(void) 
{ 
	if(basedir)
		debugfs_remove_recursive(basedir); 
}

int init_bioctl(void)
{
	init_debugfs();
	if(basedir)
		bio_ctl = debugfs_create_file("bio_ctl", 0644, basedir, &fv, &bio_ctl_fops);
	return 0;
}

int exit_bioctl(void)
{
	if (!bio_ctl) { 
		debugfs_remove(bio_ctl);
	}
	exit_debugfs();
	return 0;
}

 
