#include <linux/fs.h>
#include <asm/segment.h>
#include <asm/uaccess.h>
#include <linux/buffer_head.h>
#include <linux/fs.h>
#include <asm/ioctl.h>
#include "bio.h"

loff_t bio_cllseek (struct file *, loff_t, int);
ssize_t bio_cread (struct file *, char __user *, size_t, loff_t *);
ssize_t bio_cwrite (struct file *, const char __user *, size_t, loff_t *);
ssize_t bio_caio_read (struct kiocb *, const struct iovec *, unsigned long, loff_t);
ssize_t bio_caio_write (struct kiocb *, const struct iovec *, unsigned long, loff_t);
ssize_t bio_cread_iter (struct kiocb *, struct iov_iter *);
ssize_t bio_cwrite_iter (struct kiocb *, struct iov_iter *);
int bio_citerate (struct file *, struct dir_context *);
unsigned int bio_cpoll (struct file *, struct poll_table_struct *);
long bio_cunlocked_ioctl (struct file *, unsigned int, unsigned long);
long bio_ccompat_ioctl (struct file *, unsigned int, unsigned long);
int bio_cmmap (struct file *, struct vm_area_struct *);
int bio_cmremap(struct file *, struct vm_area_struct *);
int bio_copen (struct inode *, struct file *);
int bio_cflush (struct file *, fl_owner_t id);
int bio_crelease (struct inode *, struct file *);
int bio_cfsync (struct file *, loff_t, loff_t, int datasync);
int bio_caio_fsync (struct kiocb *, int datasync);
int bio_cfasync (int, struct file *, int);
int bio_clock (struct file *, int, struct file_lock *);
ssize_t bio_csendpage (struct file *, struct page *, int, size_t, loff_t *, int);
unsigned long bio_cget_unmapped_area(struct file *, unsigned long, unsigned long, unsigned long, unsigned long);
int bio_ccheck_flags(int);
int bio_cflock (struct file *, int, struct file_lock *);
ssize_t bio_csplice_write(struct pipe_inode_info *, struct file *, loff_t *, size_t, unsigned int);
ssize_t bio_csplice_read(struct file *, loff_t *, struct pipe_inode_info *, size_t, unsigned int);
int bio_csetlease(struct file *, long, struct file_lock **, void **);
long bio_cfallocate(struct file *file, int mode, loff_t offset, loff_t len);
void bio_cshow_fdinfo(struct seq_file *m, struct file *f);
int bio_cgetattr(struct vfsmount *mnt, struct dentry *, struct kstat *);




loff_t bio_cllseek (struct file *f, loff_t s, int l)
{
	printk("%s called\n", __func__);
	return 0;
}
	
ssize_t bio_cread (struct file *f, char __user *ubuf, size_t s, loff_t *offset)
{
	int size;
	tcpio_msg_t *tmsg, *rw_tmsg;
	bio_fileinfo_t *finfo;
	int 	ret = 0;
	int bufsize;

	bio_device_t *biodev = (bio_device_t *) f->f_inode->i_private;
	bio_devref_t *ref = (bio_devref_t *) f->private_data;

	if(!ref) {
		pr_err("f->private_data	is NULL. registration unsuccessful ?\n");
		return -1;
	}
	//pr_debug("%s called f=%#x ubuf=%#x, size=%ld, offset=%ld\n", __func__, (unsigned int)f, (unsigned int) ubuf, s, *offset);

	tmsg = alloc_tcpio_mem(sizeof(bio_cmdinfo_t));
	if(!tmsg) {
		return -EBIO_NOMEMORY;
	}

	tmsg->bhdr.msgtype = BIO_CMD_READ;
	finfo = (bio_fileinfo_t *)tmsg->buffer;

	finfo->ret = -1;	/*set default as failed */
	finfo->fileid = biodev->fileid;
	finfo->srvrefid = ref->srvrefid;
	finfo->offset = *offset;
	finfo->count = s;

	tcpio_sendcmd(biodev->node, tmsg);

	/* server should send updated finfo */
	size = bio_recv_msg(biodev->node, tmsg);
	finfo = (bio_fileinfo_t *)tmsg->buffer;
	bufsize = finfo->wrbuf_size;

	if(finfo->ret != 0) {
		ret = -1;
		goto err;
	}
	//pr_info("%s size=%d, bufsize = %d, ret = %d\n", __func__, size, bufsize, finfo->ret);

	if(bufsize < 0 || bufsize >= 4096 ) {
		pr_err("%s unsupported bufsize  %d is used in server\n", __func__, bufsize);
		goto err;
	}
	rw_tmsg = alloc_tcpio_mem(bufsize);
	if(!rw_tmsg) {
		ret = -EBIO_NOMEMORY;
		goto err;
	}

	ret = 0;
	while(1) { 	/* server returned success */
		bio_recv_msg(biodev->node, rw_tmsg);
		//pr_info("%s msglen=%d, bufsize = %d, len = %d\n", __func__, 
					//rw_tmsg->bhdr.msglen, bufsize, rw_tmsg->bhdr.len);
		if(rw_tmsg->bhdr.msglen == bufsize && rw_tmsg->bhdr.len <= bufsize) {
			copy_to_user(ubuf + ret, rw_tmsg->buffer, rw_tmsg->bhdr.len);
			ret += rw_tmsg->bhdr.len;
			if(rw_tmsg->bhdr.len < bufsize) {
				free_tcpio_mem(rw_tmsg);
				break;
			}
		} else {
			pr_err("wrong size %d buffer recved\n", rw_tmsg->bhdr.msglen);
			free_tcpio_mem(rw_tmsg);
			break;
		}
		if(ret >= s) 
			break;
	} 
	*offset += ret; 
	

err:
	free_tcpio_mem(tmsg);

	printk("%s returning\n", __func__);
	return ret;
}
ssize_t bio_cwrite (struct file *f, const char __user *ubuf, size_t size, loff_t *offset)
{
	tcpio_msg_t *tmsg, *rw_tmsg;
	bio_fileinfo_t *finfo;
	int 	ret = 0;
	int 	sent = 0;
	int bufsize;
	int	readsize = 0;
	size_t	remaining = size;

	bio_device_t *biodev = (bio_device_t *) f->f_inode->i_private;
	bio_devref_t *ref = (bio_devref_t *) f->private_data;

	if(!ref) {
		pr_err("f->private_data	is NULL. registration unsuccessful ?\n");
		return -1;
	}
	//pr_info("%s called f=%#x ubuf=%#x, size=%ld, offset=%ld\n", __func__, (unsigned int)f, (unsigned int) ubuf, size, *offset);

	tmsg = alloc_tcpio_mem(sizeof(bio_cmdinfo_t));
	if(!tmsg) {
		return -EBIO_NOMEMORY;
	}

	tmsg->bhdr.msgtype = BIO_CMD_WRITE;
	finfo = (bio_fileinfo_t *)tmsg->buffer;

	finfo->ret = -1;	/*set default as failed */
	finfo->fileid = biodev->fileid;
	finfo->srvrefid = ref->srvrefid;
	finfo->offset = *offset;
	finfo->count = size;
	finfo->wrbuf_size = BIO_DEFAULT_RW_BUFFER_SIZE;

	tcpio_sendcmd(biodev->node, tmsg);

	bufsize = finfo->wrbuf_size;

	//pr_info("%s size=%d, bufsize = %d, ret = %d\n", __func__, size, bufsize, finfo->ret);

	if(bufsize < 0 || bufsize >= 4096 ) {
		pr_err("%s unsupported bufsize  %d is used in server\n", __func__, bufsize);
		goto err;
	}

	rw_tmsg = alloc_tcpio_mem(bufsize);
	if(!rw_tmsg) {
		ret = -EBIO_NOMEMORY;
		goto err;
	}

	ret = 0;
	while(remaining > 0 ) { 	/* server returned success */
		if(remaining < BIO_DEFAULT_RW_BUFFER_SIZE) {
			readsize =  remaining;
		} else {
			readsize = BIO_DEFAULT_RW_BUFFER_SIZE;
		}

		copy_from_user(rw_tmsg->buffer, ubuf + sent, readsize);
		rw_tmsg->bhdr.len = readsize;
		tcpio_sendcmd(biodev->node, rw_tmsg);
		sent += readsize;
		remaining -= readsize;
	}
	ret = sent;
	*offset += ret; 
	free_tcpio_mem(rw_tmsg);
err:
	free_tcpio_mem(tmsg);
	//printk("%s returning\n", __func__);
	return ret;
}
ssize_t bio_caio_read (struct kiocb *k, const struct iovec * iov, unsigned long a, loff_t offset)
{
	printk("%s called\n", __func__);
	return 0;
}
ssize_t bio_caio_write (struct kiocb *k, const struct iovec *iov, unsigned long i, loff_t offset)
{
	printk("%s called\n", __func__);
	return 0;
}
ssize_t bio_cread_iter (struct kiocb *k, struct iov_iter * iov)
{
	printk("%s called\n", __func__);
	return 0;
}
ssize_t bio_cwrite_iter (struct kiocb *k, struct iov_iter * iov)
{
	printk("%s called\n", __func__);
	return 0;
}
int bio_citerate (struct file *f, struct dir_context * iov)
{
	printk("%s called\n", __func__);
	return 0;
}
unsigned int bio_cpoll (struct file *f, struct poll_table_struct *p)
{
	printk("%s called\n", __func__);
	return 0;
}

long bio_process_ioctl (struct file *f, unsigned int cmd, unsigned long arg, bio_cmd_t type)
{
	unsigned int  dir = _IOC_DIR(cmd); /* _IOC_NONE ,_IOC_READ,_IOC_WRITE */
	unsigned int  size = _IOC_SIZE(cmd);
	tcpio_msg_t *tmsg;
	tcpio_msg_t *rw_tmsg;
	bio_ioctlinfo_t *iinfo;
	int  len = 0;

	bio_devref_t *devref = (bio_devref_t *) f->private_data;
	bio_device_t *biodev =  devref->bdev;


	tmsg = alloc_tcpio_mem(sizeof(bio_cmdinfo_t));
	if(!tmsg) {
		return -EBIO_NOMEMORY;
	}
	
	tmsg->bhdr.msgtype = type;
	iinfo = (bio_ioctlinfo_t *)tmsg->buffer;
	
	iinfo->ret = -1;	/*set default as failed */
	iinfo->fileid = biodev->fileid;
	iinfo->srvrefid = devref->srvrefid;
	iinfo->cmd	= cmd;
	iinfo->dir = dir;
	iinfo->size = size;
	
	tcpio_sendcmd(biodev->node, tmsg);
	if( size > 0) {	/* server returned success */
		rw_tmsg = alloc_tcpio_mem(size);
		copy_from_user(rw_tmsg->buffer, (void *)arg, size);
		bio_send_msg(biodev->node, rw_tmsg);
		bio_recv_msg(biodev->node, rw_tmsg);
		copy_to_user((void *)arg, rw_tmsg->buffer, rw_tmsg->bhdr.len);
	}
	len = bio_recv_msg(biodev->node, tmsg);
	iinfo = (bio_ioctlinfo_t *)tmsg->buffer;
	return iinfo->ret;
}
long bio_cunlocked_ioctl (struct file *f, unsigned int cmd, unsigned long arg)
{
	printk("%s called\n", __func__);
	return bio_process_ioctl(f, cmd, arg, BIO_CMD_UNLOCKED_IOCTL);
}
long bio_ccompat_ioctl (struct file *f, unsigned int cmd, unsigned long arg)
{

	printk("%s called\n", __func__);
	return bio_process_ioctl(f, cmd, arg, BIO_CMD_COMPAT_IOCTL);
}
int bio_cmmap (struct file *f, struct vm_area_struct * vm)
{
	printk("%s called\n", __func__);
	return 0;
}
int bio_cmremap(struct file *f, struct vm_area_struct *vm)
{
	printk("%s called\n", __func__);
	return 0;
}
int bio_copen (struct inode *i, struct file *f)
{
	int size;
	tcpio_msg_t *tmsg;
	bio_fileinfo_t *finfo;

	bio_device_t *biodev = (bio_device_t *) i->i_private;
	bio_devref_t *devref = NULL;

	/*TODO call rpc to open remote file */
	tmsg = alloc_tcpio_mem(sizeof(bio_cmdinfo_t));
	if(!tmsg) {
		return -EBIO_NOMEMORY;
	}
	
	tmsg->bhdr.msgtype = BIO_CMD_OPEN;
	finfo = (bio_fileinfo_t *)tmsg->buffer;
	
	snprintf(finfo->filename, sizeof(finfo->filename), "%s", biodev->filename);
	finfo->ret = -1;	/*set default as failed */
	finfo->fileid = biodev->fileid;
	finfo->f_flags = f->f_flags;
	finfo->f_mode = f->f_mode;

	
	tcpio_sendcmd(biodev->node, tmsg);

	/* server should send updated finfo */
	size = bio_recv_msg(biodev->node, tmsg);
	finfo = (bio_fileinfo_t *)tmsg->buffer;

	
	if(finfo->ret == 0) 	/* server returned success */
	{
		devref = kmalloc(sizeof(bio_devref_t), GFP_KERNEL);
		if(!devref) {
			pr_err("%s unable to allocate memory\n", __func__);			
			free_tcpio_mem(tmsg);
			return -1;
		}
		memset(devref, 0, sizeof(bio_devref_t));
		INIT_LIST_HEAD(&devref->list);
		devref->bdev=biodev;
		devref->filp=f;
		devref->node=biodev->node;
		devref->srvrefid=finfo->srvrefid;
		f->private_data = (void *)devref;

		spin_lock(&biodev->bio_device_lock);
		list_add(&devref->list, &biodev->reflist);
		spin_unlock(&biodev->bio_device_lock);

	} else {
		pr_err("%s unable to remotely open filename=%s\n", __func__, biodev->filename);
	}
	free_tcpio_mem(tmsg);
	return 0;
}
int bio_cflush (struct file *f, fl_owner_t id)
{
	printk("%s called\n", __func__);
	return 0;
}
int bio_crelease (struct inode *i, struct file *f)
{

	int size;
	tcpio_msg_t *tmsg;
	bio_fileinfo_t *finfo;
	int 	ret = 0;

	bio_device_t *biodev = (bio_device_t *) i->i_private;
	bio_devref_t *ref = (bio_devref_t *) f->private_data;

	if(!ref) {
		pr_err("f->private_data	is NULL. registration unsuccessful ?\n");
		return -1;
	}

	tmsg = alloc_tcpio_mem(sizeof(bio_cmdinfo_t));
	if(!tmsg) {
		return -EBIO_NOMEMORY;
	}

	tmsg->bhdr.msgtype = BIO_CMD_RELEASE;
	finfo = (bio_fileinfo_t *)tmsg->buffer;

	snprintf(finfo->filename, sizeof(finfo->filename), "%s", biodev->filename);
	finfo->ret = -1;	/*set default as failed */
	finfo->fileid = biodev->fileid;
	finfo->srvrefid = ref->srvrefid;

	tcpio_sendcmd(biodev->node, tmsg);

	/* server should send updated finfo */
	size = bio_recv_msg(biodev->node, tmsg);
	finfo = (bio_fileinfo_t *)tmsg->buffer;
	ret = finfo->ret;

	if(finfo->ret == 0) { 	/* server returned success */
		spin_lock(&biodev->bio_device_lock);
		list_del(&ref->list);
		spin_unlock(&biodev->bio_device_lock);
	} else {
		pr_err("%s serv returned %d\n", __func__, finfo->ret);
	}

	kfree(ref);
	free_tcpio_mem(tmsg);

	printk("%s called\n", __func__);
	return ret;
}

int bio_cgetattr(struct vfsmount *mnt, struct dentry *d, struct kstat *stat)
{
	int size;
	tcpio_msg_t *tmsg, *rw_tmsg;
	bio_fileinfo_t *finfo;
	int 	ret = 0;

	bio_device_t *biodev = (bio_device_t *) d->d_inode->i_private;
	if(!biodev) {
		
	}

	tmsg = alloc_tcpio_mem(sizeof(bio_cmdinfo_t));
	if(!tmsg) {
		return -EBIO_NOMEMORY;
	}

	tmsg->bhdr.msgtype = BIO_CMD_GETATTR;
	finfo = (bio_fileinfo_t *)tmsg->buffer;

	finfo->ret = -1;	/*set default as failed */
	finfo->fileid = biodev->fileid;

	tcpio_sendcmd(biodev->node, tmsg);

	/* server should send updated finfo */
	size = bio_recv_msg(biodev->node, tmsg);
	finfo = (bio_fileinfo_t *)tmsg->buffer;
	ret = finfo->ret;

	if(finfo->ret == 0) { 	/* server returned success */
		rw_tmsg = alloc_tcpio_mem(sizeof(struct kstat));
		if(!rw_tmsg) {
			pr_err("%s unable to allocate %ld\n", __func__, sizeof(struct kstat));
			ret = -EBIO_NOMEMORY;
			goto err;
		}

		size = bio_recv_msg(biodev->node, rw_tmsg);
		memcpy(stat, rw_tmsg->buffer, sizeof(struct kstat));
		free_tcpio_mem(rw_tmsg);
	} else {
		pr_err("%s serv returned %d\n", __func__, finfo->ret);
	}
err:
	free_tcpio_mem(tmsg);
	return ret;
}

int bio_cfsync (struct file *f, loff_t offset, loff_t ofset, int datasync)
{
	printk("%s called\n", __func__);
	return 0;
}
int bio_caio_fsync (struct kiocb *k, int datasync)
{
	printk("%s called\n", __func__);
	return 0;
}
int bio_cfasync (int i, struct file *f, int j)
{
	printk("%s called\n", __func__);
	return 0;
}
int bio_clock (struct file *f, int i, struct file_lock *fl)
{
	printk("%s called\n", __func__);
	return 0;
}
ssize_t bio_csendpage (struct file *f, struct page *p, int i, size_t s, loff_t *offset, int j)
{
	printk("%s called\n", __func__);
	return 0;
}
unsigned long bio_cget_unmapped_area(struct file *f, unsigned long a, unsigned long b , unsigned long c, unsigned long d)
{
	printk("%s called\n", __func__);
	return 0;
}
int bio_ccheck_flags(int i)
{
	printk("%s called\n", __func__);
	return 0;
}
int bio_cflock (struct file *f, int a , struct file_lock *fl)
{
	printk("%s called\n", __func__);
	return 0;
}
ssize_t bio_csplice_write(struct pipe_inode_info *fi, struct file *f, loff_t *a, size_t b, unsigned int c)
{
	printk("%s called\n", __func__);
	return 0;
}
ssize_t bio_csplice_read(struct file *f, loff_t *o, struct pipe_inode_info *p, size_t s, unsigned int i)
{
	printk("%s called\n", __func__);
	return 0;
}
int bio_csetlease(struct file *f, long la, struct file_lock **a, void **b)
{
	printk("%s called\n", __func__);
	return 0;
}
long bio_cfallocate(struct file *file, int mode, loff_t offset, loff_t len)
{
	printk("%s called\n", __func__);
	return 0;
}
void bio_cshow_fdinfo(struct seq_file *m, struct file *f)
{
	printk("%s called\n", __func__);
}
#define MYFILE "/tmp/myfile"


struct file_operations	bio_fop  = {
	.llseek = bio_cllseek, 
	.read = bio_cread, 
	.write = bio_cwrite, 
	.aio_read = bio_caio_read, 
	.aio_write = bio_caio_write, 
	.read_iter = bio_cread_iter, 
	.write_iter = bio_cwrite_iter, 
	.iterate = bio_citerate, 
	.poll = bio_cpoll, 
	.unlocked_ioctl = bio_cunlocked_ioctl, 
	.compat_ioctl = bio_ccompat_ioctl, 
	.mmap = bio_cmmap, 
	.mremap= bio_cmremap,
	.open = bio_copen, 
	.flush = bio_cflush, 
	.release = bio_crelease, 
	.fsync = bio_cfsync, 
	.aio_fsync = bio_caio_fsync, 
	.fasync = bio_cfasync, 
	.lock = bio_clock, 
	.sendpage = bio_csendpage, 
	.get_unmapped_area= bio_cget_unmapped_area,
	.check_flags= bio_ccheck_flags,
	.flock = bio_cflock, 
	.splice_write= bio_csplice_write,
	.splice_read= bio_csplice_read,
	.setlease= bio_csetlease,
	.fallocate= bio_cfallocate,
	.show_fdinfo= bio_cshow_fdinfo
};

 
int bio_enable_cfops(struct file_operations *dst, struct file_operations *src)
{
	memset(dst, 0, sizeof(struct file_operations));

	if(src->llseek) {
		dst->llseek = bio_fop.llseek; 
	}
	if(src->read) {
		dst->read = bio_fop.read; 
	}
	if(src->write) {
		dst->write = bio_fop.write; 
	}
	if(src->aio_read) {
		dst->aio_read = bio_fop.aio_read; 
	}
	if(src->aio_write) {
		dst->aio_write = bio_fop.aio_write; 
	}
	if(src->read_iter) {
		dst->read_iter = bio_fop.read_iter; 
	}
	if(src->write_iter) {
		dst->write_iter = bio_fop.write_iter; 
	}
	if(src->iterate) {
		dst->iterate = bio_fop.iterate; 
	}
	if(src->poll) {
		dst->poll = bio_fop.poll; 
	}
	if(src->unlocked_ioctl) {
		dst->unlocked_ioctl = bio_fop.unlocked_ioctl; 
	}
	if(src->compat_ioctl) {
		dst->compat_ioctl = bio_fop.compat_ioctl; 
	}
	if(src->mmap) {
		dst->mmap = bio_fop.mmap; 
	}
	if(src->mremap) {
		dst->mremap = bio_fop.mremap; 
	}
	if(src->open) {
		dst->open = bio_fop.open; 
	}
	if(src->flush) {
		dst->flush = bio_fop.flush; 
	}
	if(src->release) {
		dst->release = bio_fop.release; 
	}
	if(src->fsync) {
		dst->fsync = bio_fop.fsync; 
	}
	if(src->aio_fsync) {
		dst->aio_fsync = bio_fop.aio_fsync; 
	}
	if(src->fasync) {
		dst->fasync = bio_fop.fasync; 
	}
	if(src->lock) {
		dst->lock = bio_fop.lock; 
	}
	if(src->sendpage) {
		dst->sendpage = bio_fop.sendpage; 
	}
	if(src->get_unmapped_area) {
		dst->get_unmapped_area = bio_fop.get_unmapped_area; 
	}
	if(src->check_flags) {
		dst->check_flags = bio_fop.check_flags; 
	}
	if(src->flock) {
		dst->flock = bio_fop.flock; 
	}
	if(src->splice_write) {
		dst->splice_write = bio_fop.splice_write; 
	}
	if(src->splice_read) {
		dst->splice_read = bio_fop.splice_read; 
	}
	if(src->setlease) {
		dst->setlease = bio_fop.setlease; 
	}
	if(src->fallocate) {
		dst->fallocate = bio_fop.fallocate; 
	}
	if(src->show_fdinfo) {
		dst->show_fdinfo = bio_fop.show_fdinfo; 
	}
	return 0;
}
int register_bio_cfile(bio_node_t *cnode, char *filename) 
{ 
	struct file *filp;
	int size;
	tcpio_msg_t *tmsg, *rw_tmsg;
	bio_fileinfo_t *finfo;
	int	ret = -1;
	
	bio_device_t *biodev = NULL;
	bio_device_t *dev;
	list_for_each_entry(dev, &cnode->devlist, list) {
		if(!strcmp(dev->filename, filename)) {
			pr_err("%s is already registred\n", filename);
			return -EBIO_ENTRYEXISTS;
		}
	}
	filp = filp_open(filename, O_RDONLY, 0);
	if (IS_ERR(filp)) {
                pr_err("%s(): ERROR opening file(%s) with errno = %ld!\n",
                       __func__, filename, -PTR_ERR(filp));
                return PTR_ERR(filp);
        }

	tmsg = alloc_tcpio_mem(sizeof(bio_cmdinfo_t));
	if(!tmsg) {
		return -EBIO_NOMEMORY;
	}
	
	tmsg->bhdr.msgtype = BIO_CMD_REGISTER;
	finfo = (bio_fileinfo_t *)tmsg->buffer;
	
	snprintf(finfo->filename, sizeof(finfo->filename), "%s", filename);
	finfo->ret = -1;	/*set default as failed */
	
	tcpio_sendcmd(cnode, tmsg);
	/* server should send updated finfo */
	size = bio_recv_msg(cnode, tmsg);
	finfo = (bio_fileinfo_t *)tmsg->buffer;

	
	if(finfo->ret == 0) 	/* server returned success */
	{
		rw_tmsg = alloc_tcpio_mem(sizeof(struct file_operations));
		if(!rw_tmsg) {
			ret = -EBIO_NOMEMORY;
			goto err;
		}
		bio_recv_msg(cnode, rw_tmsg);

		biodev = kmalloc(sizeof(bio_device_t), GFP_KERNEL);

		if(!biodev) {
			printk("unable to allocate biodev\n");
			free_tcpio_mem(tmsg);
			return -EBIO_NOMEMORY;
		}

		biodev->bio_device_lock = __SPIN_LOCK_UNLOCKED(biodev->bio_device_lock);
		INIT_LIST_HEAD(&biodev->list);
		INIT_LIST_HEAD(&biodev->reflist);
		snprintf(biodev->filename, sizeof(biodev->filename), "%s", filename);
		biodev->fileid = finfo->fileid;
		biodev->cinode = file_inode(filp);
		ihold(biodev->cinode);
		biodev->org_i_fop = (struct file_operations *)biodev->cinode->i_fop;
		biodev->org_i_private = (struct file_operations *)biodev->cinode->i_private;

		memcpy(&biodev->bio_iop, biodev->cinode->i_op, sizeof(struct inode_operations));
		biodev->bio_iop.getattr = bio_cgetattr;
		biodev->org_iop =  biodev->cinode->i_op;

		biodev->node = cnode;
		bio_enable_cfops(&biodev->bio_fop, (struct file_operations *) rw_tmsg->buffer);
		*((struct file_operations **) &biodev->cinode->i_fop) = &biodev->bio_fop;
		*((struct inode_operations **) &biodev->cinode->i_op) = &biodev->bio_iop;
		biodev->cinode->i_private = biodev; 

		filp_close(filp, NULL);

		spin_lock(&cnode->bio_node_lock);
		list_add(&biodev->list, &cnode->devlist);
		spin_unlock(&cnode->bio_node_lock);

		free_tcpio_mem(tmsg);
		return 0;
	}
err:

	free_tcpio_mem(tmsg);
	return -EBIO_UNABLETOOPEN;
}


int deregister_bio_cfile(bio_node_t *cnode,char *filename)
{
	bio_device_t *dev, *tmpdev;
	list_for_each_entry_safe(dev, tmpdev, &cnode->devlist, list) {
		if(!strcmp(dev->filename, filename)) {
			spin_lock(&cnode->bio_node_lock);
    			list_del(&dev->list);
			spin_unlock(&cnode->bio_node_lock);
			printk("%s is removed\n", filename);
			if(dev->cinode) {
				*((struct file_operations **) &dev->cinode->i_fop) = dev->org_i_fop;
				dev->cinode->i_private = dev->org_i_private;
				*((struct inode_operations **) &dev->cinode->i_op) = dev->org_iop;
				iput(dev->cinode);
			}
			kfree(dev);
			return 0;
		}
	}
	return EBIO_FILENOTFOUND;
}

int deregister_bio_cfile_all(bio_node_t *cnode)
{
	bio_device_t *dev, *tmpdev;
	list_for_each_entry_safe(dev, tmpdev, &cnode->devlist, list) {
			spin_lock(&cnode->bio_node_lock);
    			list_del(&dev->list);
			spin_unlock(&cnode->bio_node_lock);
			printk("%s is removed\n", dev->filename);
			if(dev->cinode) {
				*((struct file_operations **) &dev->cinode->i_fop) = dev->org_i_fop;
				iput(dev->cinode);
			}

			kfree(dev);
	}
	return 0;
}
