#ifndef RPC_H
#define RPC_H

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/kallsyms.h>
#include <linux/debugfs.h> 
#include <linux/fs.h>   
#include <linux/time.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/uaccess.h>
#include <net/sock.h>
#include <linux/stat.h>
#include <linux/fs.h>



#define BIO_MAX_FUNCS		16
#define BIO_MAX_FUNC_NAME_LEN	64
#define BIO_MAX_FUNC_ARGS	8
#define BIO_DEFAULT_RW_BUFFER_SIZE 1024


/* BIO error codes */

#define EBIO_SUCCESS		0	/* operation successfully executed */
#define EBIO_FILENOTFOUND	110	/* file not found */
#define EBIO_NOMEMORY		ENOMEM	/* kmalloc failed */
#define EBIO_UNABLETOOPEN	111	/* unable to open file */
#define EBIO_ENTRYEXISTS	112	/* entry already exists */


#define DEFINE_BIODEVICE_STRUCT(name, array)							\
	static bio_device_t __b_io_ ## name = { 						\
		.bio_device_lock = __SPIN_LOCK_UNLOCKED(__b_io ## name.bio_device_lock), 	\
		.function_cnt = sizeof(array),							\
		.funcs = array;									\
	}

typedef enum bio_cmd {
	BIO_CMD_REGISTER = 1000,
	BIO_CMD_LLSEEK, 
	BIO_CMD_READ, 
	BIO_CMD_WRITE, 
	BIO_CMD_AIO_READ,
	BIO_CMD_AIO_WRITE,
	BIO_CMD_READ_ITER,
	BIO_CMD_WRITE_ITER,
	BIO_CMD_ITERATE,
	BIO_CMD_POLL,
	BIO_CMD_UNLOCKED_IOCTL,
	BIO_CMD_COMPAT_IOCTL,
	BIO_CMD_MMAP,
	BIO_CMD_MREMAP,
	BIO_CMD_OPEN,
	BIO_CMD_FLUSH,
	BIO_CMD_RELEASE,
	BIO_CMD_FSYNC,
	BIO_CMD_AIO_FSYNC,
	BIO_CMD_FASYNC,
	BIO_CMD_LOCK,
	BIO_CMD_SENDPAGE,
	BIO_CMD_GET_UNMAPPED_AREA,
	BIO_CMD_CHECK_FLAGS,
	BIO_CMD_FLOCK,
	BIO_CMD_SPLICE_WRITE,
	BIO_CMD_SPLICE_READ,
	BIO_CMD_SETLEASE,
	BIO_CMD_FALLOCATE,
	BIO_CMD_SHOW_FDINFO,
	BIO_CMD_GETATTR,
	BIO_CMD_DEREGISTER,
	BIO_CMD_DEREGISTER_ALL,
	BIO_CMD_INVALID,
} bio_cmd_t;

/* struct for BIO_CMD_REGISTER */
typedef int (*inode_getattr_t) (struct vfsmount *mnt, struct dentry *, struct kstat *);
typedef struct bio_fileinfo {
	char	filename[256];
	int	fileid;
	int	srvrefid;
	unsigned int f_flags;
        fmode_t	f_mode;
	loff_t offset;
	unsigned long count;
	int	wrbuf_size;
	int	ret;
} bio_fileinfo_t;

typedef struct bio_ioctlinfo {
	int	fileid;
	int	srvrefid;
	int	wrbuf_size;
	unsigned int  cmd;
	unsigned int  dir;
	unsigned int  size;
	int	ret;
} bio_ioctlinfo_t;

typedef union bio_cmdinfo {
	bio_fileinfo_t finfo;
	bio_ioctlinfo_t iinfo;
} bio_cmdinfo_t;

struct bio_node;
typedef struct bio_device {
	struct 	list_head list;
	struct 	list_head reflist;
	char	filename[256];
	struct inode_operations  bio_iop;
	struct inode_operations  *org_iop;
	struct file_operations *org_i_fop; /* client uses it to store original fop pointer */
	struct file_operations bio_fop; 
	struct inode	*cinode; /* client holds reference */
	void 	*org_i_private; /* stores original inode->i_private pointer */
	int	fileid;		/* server will allocate & client will use */
	int	refcnt;		/* server will incr with each reference */
	struct bio_node *node;		/* server will allocate & client will use */
	spinlock_t bio_device_lock;
} bio_device_t;

typedef struct connection_details {
	int		reconfig;
	int		connected;
	int 		running;
	char		serverip[20];
	int		port;
	struct socket 	*listen_socket;
	struct task_struct *thread;
	struct task_struct *accept_worker;
	struct socket *accpted_sock;
	spinlock_t tcpio_serv_lock;
	struct	socket *client_socket;

} bio_conn_t;

typedef struct bio_funcarg {
	int	len;
	char	value[];
} bio_funcarg_t;

typedef struct bio_function {
	char	funname[BIO_MAX_FUNC_NAME_LEN];
	int	numargs;
	bio_funcarg_t *args[BIO_MAX_FUNC_ARGS];
} bio_function_t;

typedef enum	role {
	BIO_CLIENT_NODE,
	BIO_SERVER_NODE,
} bio_role_t;

typedef	struct devref {
	struct 	list_head list;
	bio_device_t	*bdev;
	struct	file	*filp;
	struct bio_node *node;		
	int	srvrefid;
} bio_devref_t;

	

typedef struct  bio_node {
	struct 	list_head devlist;
	int		count;
	bio_role_t	role;	/* client = BIO_CLIENT_NODE, server = BIO_SERVER_NODE */
	bio_conn_t	bio_conn;
	struct	task_struct *bio_worker;
	spinlock_t 	bio_node_lock;
} bio_node_t;

typedef struct bio_msg_hdr {
	unsigned int msgtype;
	unsigned int msgid;
	unsigned int totallen;
	unsigned int msglen;
	unsigned int len;
} bio_msg_hdr_t;

typedef struct {
	bio_msg_hdr_t	bhdr;
	char		buffer[];
} tcpio_msg_t;

typedef enum bio_fops {
	BIO_LLSEEK, 
	BIO_READ, 
	BIO_WRITE, 
	BIO_AIO_READ,
	BIO_AIO_WRITE,
	BIO_READ_ITER,
	BIO_WRITE_ITER,
	BIO_ITERATE,
	BIO_POLL,
	BIO_UNLOCKED_IOCTL,
	BIO_COMPAT_IOCTL,
	BIO_MMAP,
	BIO_MREMAP,
	BIO_OPEN,
	BIO_FLUSH,
	BIO_RELEASE,
	BIO_FSYNC,
	BIO_AIO_FSYNC,
	BIO_FASYNC,
	BIO_LOCK,
	BIO_SENDPAGE,
	BIO_GET_UNMAPPED_AREA,
	BIO_CHECK_FLAGS,
	BIO_FLOCK,
	BIO_SPLICE_WRITE,
	BIO_SPLICE_READ,
	BIO_SETLEASE,
	BIO_FALLOCATE,
	BIO_SHOW_FDINFO,
} bio_fops_t;

struct bio_cconfig {
	int dport;
	char serverip[20];
	int reconfig;
};

struct bio_sconfig {
	int sport;
	int reconfig;
};

extern struct bio_sconfig biosconfig;

extern int connect_bio_server(bio_node_t *cnode);
extern int stop_tcpio_server(bio_node_t * snode);
void free_tcpio_mem(void *buf);
void *alloc_tcpio_mem(int size);
void cleanup_tcpio_client(bio_node_t *cnode);
int register_bio_cfile(bio_node_t *snode, char *filename);
int register_bio_sfile(bio_node_t *snode, tcpio_msg_t *tmsg);
int deregister_bio_sfile(bio_node_t *snode,char *filename);
int tcpio_sendcmd(bio_node_t *cnode, tcpio_msg_t *tmsg);
int bio_recv_msg(bio_node_t *cnode, tcpio_msg_t *tmsg);
int deregister_bio_cfile(bio_node_t *cnode,char *filename);
int deregister_bio_sfile_all(bio_node_t *snode);
int deregister_bio_cfile_all(bio_node_t *cnode);
tcpio_msg_t * bio_process_scmds(bio_node_t *snode, tcpio_msg_t *tmsg);
tcpio_msg_t * tcpio_mem_init(tcpio_msg_t *tmsg, int size);
int open_bio_sfile(bio_node_t *snode, bio_fileinfo_t *finfo);
int release_bio_sfile(bio_node_t *snode, bio_fileinfo_t *finfo);
int tcpio_serv_send(bio_node_t *snode, tcpio_msg_t *tmsg);
int read_bio_sfile(bio_node_t *snode, tcpio_msg_t *rw_tmsg);
int tcpio_serv_recv(bio_node_t *snode, tcpio_msg_t *tmsg);
int bio_send_msg(bio_node_t *cnode, tcpio_msg_t *tmsg);
int  init_debugfs(void);
void exit_debugfs(void);
bio_node_t *get_snode(void);
bio_node_t *get_cnode(void);
int bio_conn_init(void);
int restart_bio_server(bio_node_t *snode);
extern struct bio_cconfig bioconfig;
int init_bioctl(void);
int exit_bioctl(void);
#endif
