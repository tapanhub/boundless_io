#include <linux/fs.h>
#include <asm/segment.h>
#include <asm/uaccess.h>
#include <linux/buffer_head.h>
#include <linux/fs.h>
#include "bio.h"

int open_bio_sfile(bio_node_t *snode, bio_fileinfo_t *finfo)
{
	struct file *filp;
	bio_device_t *biodev = NULL;
	bio_device_t *dev;
	bio_devref_t *devref = NULL;

	list_for_each_entry(dev, &snode->devlist, list) {
		if(dev->fileid == finfo->fileid) {
			biodev = dev;
			break;
		}
	}
	if(biodev == NULL) {
		pr_err("%s entry not found\n", __func__);
		finfo->ret = -1;
		return -1;
	}

	filp = filp_open(biodev->filename, finfo->f_flags, finfo->f_mode);

	if (IS_ERR(filp)) {
                pr_err("%s(): ERROR opening file(%s) with errno = %ld!\n",
                       __func__, finfo->filename, -PTR_ERR(filp));
		finfo->ret = -PTR_ERR(filp);
                return -PTR_ERR(filp);
        }
	
	devref = kmalloc(sizeof(bio_devref_t), GFP_KERNEL);
	if(!devref) {
		pr_err("%s unable to allocate memory\n", __func__);			
		filp_close(filp, NULL);
		return -1;
	}

	finfo->ret = 0; 	/* server returned success */
	biodev->refcnt ++;

	memset(devref, 0, sizeof(bio_devref_t));

	INIT_LIST_HEAD(&devref->list);

	devref->bdev=biodev;
	devref->filp=filp;
	devref->node=biodev->node;
	devref->srvrefid=biodev->refcnt;

	finfo->srvrefid= devref->srvrefid;

	spin_lock(&biodev->bio_device_lock);
	list_add(&devref->list, &biodev->reflist);
	spin_unlock(&biodev->bio_device_lock);
	return 0;
}

int read_bio_sfile(bio_node_t *snode, tcpio_msg_t *tmsg)
{
	struct file *filp;
	bio_fileinfo_t	*finfo = (bio_fileinfo_t *)tmsg->buffer;
	bio_device_t *biodev = NULL;
	bio_device_t *dev;
	bio_devref_t *ref, *tmpref;
	tcpio_msg_t *rw_tmsg;
	loff_t	offset = finfo->offset;
	loff_t	cpos = 0;
	unsigned long size = 0;

	list_for_each_entry(dev, &snode->devlist, list) {
		if(dev->fileid == finfo->fileid) {
			biodev = dev;
			break;
		}
	}
	if(biodev == NULL) {
		pr_err("%s entry not found\n", __func__);
		finfo->ret = -1;
		return -1;
	}

	list_for_each_entry_safe(ref, tmpref, &biodev->reflist, list) {
		if(ref->srvrefid == finfo->srvrefid) {
			filp = ref->filp;
			rw_tmsg = alloc_tcpio_mem(BIO_DEFAULT_RW_BUFFER_SIZE);
			if(rw_tmsg == NULL) {
				pr_err("%s unable to allocate buffer of size %d\n", __func__, BIO_DEFAULT_RW_BUFFER_SIZE);
				finfo->ret = -1;
				return -1;
			}

			offset = finfo->offset;
			size = finfo->count;
			finfo->wrbuf_size = BIO_DEFAULT_RW_BUFFER_SIZE;
			finfo->ret = 0;

			tcpio_serv_send(snode, tmsg);

			while (cpos < size) {
				int bytes = 0;
				int readsize = BIO_DEFAULT_RW_BUFFER_SIZE;
				int pos = 0;
				
				if(size < BIO_DEFAULT_RW_BUFFER_SIZE) {
					readsize =  size;
				}
				while (pos < readsize) {
					bytes = kernel_read(filp, offset + pos, (char *)(rw_tmsg->buffer) + pos, readsize - pos);

					if (bytes < 0) {
						break;
					}
					pos += bytes;
					
					if (bytes == 0)
						break;
				}
				rw_tmsg->bhdr.len = pos;
				//pr_info("%s bhdr.len = %ld, readsize=%d\n", __func__, pos, readsize);
				tcpio_serv_send(snode, rw_tmsg);
				if(pos < readsize) {
					break;
				}
				offset += pos;
				cpos += pos;
			}

			break;
		}
	}
	return finfo->ret;
}

int ioctl_bio_sfile(bio_node_t *snode, tcpio_msg_t *tmsg, bio_cmd_t type)
{
	struct file *filp;
	bio_ioctlinfo_t	*iinfo = (bio_ioctlinfo_t *)tmsg->buffer;
	bio_device_t *biodev = NULL;
	bio_device_t *dev;
	bio_devref_t *ref, *tmpref;
	tcpio_msg_t *rw_tmsg;
	loff_t	ret = 0;
	int	recvbufsize=0;
	mm_segment_t old_fs;

	list_for_each_entry(dev, &snode->devlist, list) {
		if(dev->fileid == iinfo->fileid) {
			biodev = dev;
			break;
		}
	}
	if(biodev == NULL) {
		pr_err("%s entry not found\n", __func__);
		iinfo->ret = -1;
		return -1;
	}

	recvbufsize = iinfo->size;

	if(recvbufsize < 0) {
		pr_err("%s unsupported recvbufsize  %d is used in server\n", __func__, recvbufsize);
		goto err;
	}

	list_for_each_entry_safe(ref, tmpref, &biodev->reflist, list) {
		if(ref->srvrefid == iinfo->srvrefid) {
			filp = ref->filp;
			if(recvbufsize>0) {
				rw_tmsg = alloc_tcpio_mem(recvbufsize);
				if(rw_tmsg == NULL) {
					pr_err("%s unable to allocate buffer of size %d\n", __func__, BIO_DEFAULT_RW_BUFFER_SIZE);
					iinfo->ret = -1;
					goto err;
				}
				tcpio_serv_recv(biodev->node, rw_tmsg);
			}
			old_fs = get_fs();
			set_fs(KERNEL_DS);
			if(type == BIO_CMD_COMPAT_IOCTL) {
				iinfo->ret = (int )filp->f_op->compat_ioctl(filp, iinfo->cmd, (long )rw_tmsg->buffer);
			} else if (type == BIO_CMD_UNLOCKED_IOCTL) {
				iinfo->ret = (int )filp->f_op->unlocked_ioctl(filp, iinfo->cmd, (long )rw_tmsg->buffer);
			}
			set_fs(old_fs);
			if(recvbufsize > 0) {
				tcpio_serv_send(biodev->node, rw_tmsg);
			}
		}
	}
	if(recvbufsize > 0) {
		free_tcpio_mem(rw_tmsg);
	}
err:
	tcpio_serv_send(snode, tmsg);
	free_tcpio_mem(tmsg);
	printk("%s returning\n", __func__);
	return ret;

}
int write_bio_sfile(bio_node_t *snode, tcpio_msg_t *tmsg)
{
	struct file *filp;
	bio_fileinfo_t	*finfo = (bio_fileinfo_t *)tmsg->buffer;
	bio_device_t *biodev = NULL;
	bio_device_t *dev;
	bio_devref_t *ref, *tmpref;
	tcpio_msg_t *rw_tmsg;
	loff_t	offset = finfo->offset;
	loff_t	ret = 0;
	unsigned long size = finfo->count;
	int	recvbufsize=0;

	list_for_each_entry(dev, &snode->devlist, list) {
		if(dev->fileid == finfo->fileid) {
			biodev = dev;
			break;
		}
	}
	if(biodev == NULL) {
		pr_err("%s entry not found\n", __func__);
		finfo->ret = -1;
		return -1;
	}

	recvbufsize = finfo->wrbuf_size;

	if(recvbufsize < 0 || recvbufsize >= 4096 ) {
		pr_err("%s unsupported recvbufsize  %d is used in server\n", __func__, recvbufsize);
		goto err;
	}

	list_for_each_entry_safe(ref, tmpref, &biodev->reflist, list) {
		if(ref->srvrefid == finfo->srvrefid) {
			filp = ref->filp;
			rw_tmsg = alloc_tcpio_mem(recvbufsize);
			if(rw_tmsg == NULL) {
				pr_err("%s unable to allocate buffer of size %d\n", __func__, BIO_DEFAULT_RW_BUFFER_SIZE);
				finfo->ret = -1;
				goto err;
			}
			while(ret < size) { 	/* server returned success */
				int bytes = 0;
				int writesize = recvbufsize;
				int pos = 0;

				tcpio_serv_recv(biodev->node, rw_tmsg);
				//pr_info("%s msglen=%d, writesize = %d, len = %d\n", __func__, 
						//	rw_tmsg->bhdr.msglen, writesize, rw_tmsg->bhdr.len);
				if(rw_tmsg->bhdr.msglen == recvbufsize && rw_tmsg->bhdr.len <= recvbufsize) {
					writesize = rw_tmsg->bhdr.len;
					while (pos < writesize) {
						bytes = kernel_write(filp,  (char *)(rw_tmsg->buffer) + pos, writesize - pos,offset + pos);

						if (bytes < 0) {
							break;
						}
						pos += bytes;
						
						if (bytes == 0)
							break;
					}
					ret += pos;
					offset += pos;
					//pr_info("%s bhdr.len = %ld, readsize=%d\n", __func__, pos, writesize);
				} else {
					pr_err("wrong size %d buffer recved\n", rw_tmsg->bhdr.msglen);
					free_tcpio_mem(rw_tmsg);
					break;
				}
			}
		}
	}
	free_tcpio_mem(rw_tmsg);
err:
	free_tcpio_mem(tmsg);
	printk("%s returning\n", __func__);
	return ret;
}

static inline bio_device_t * get_biodev(bio_node_t *snode, bio_fileinfo_t *finfo)
{
	bio_device_t *dev;
	list_for_each_entry(dev, &snode->devlist, list) {
		if(dev->fileid == finfo->fileid) {
			return dev;
		}
	}
	return NULL;
}

static inline bio_devref_t * get_devref_any(bio_node_t *snode, bio_fileinfo_t *finfo, bio_device_t *biodev)
{

	bio_devref_t *ref, *tmpref;

	list_for_each_entry_safe(ref, tmpref, &biodev->reflist, list) {
		return ref;
	}
	return NULL;
}

static inline bio_devref_t * get_devref(bio_node_t *snode, bio_fileinfo_t *finfo, bio_device_t *biodev)
{

	bio_devref_t *ref, *tmpref;

	list_for_each_entry_safe(ref, tmpref, &biodev->reflist, list) {
		if(ref->srvrefid == finfo->srvrefid) {
			return ref;
		}
	}
	return NULL;
}

int getattr_bio_sfile(bio_node_t *snode, tcpio_msg_t *tmsg)
{
	int	ret= -1;
	tcpio_msg_t *rw_tmsg;
	struct kstat *stat;
	bio_fileinfo_t	*finfo = (bio_fileinfo_t *)tmsg->buffer;
	bio_device_t *biodev = get_biodev(snode, finfo);
	struct file *filp = NULL;
	

	if(biodev == NULL) {
		pr_err("%s entry not found\n", __func__);
		finfo->ret = -1;
		return -1;
	}

	filp = filp_open(biodev->filename, O_RDONLY, 0);

	if (IS_ERR(filp)) {
               	pr_err("%s(): ERROR opening file(%s) with errno = %ld!\n",
                      	__func__, biodev->filename, -PTR_ERR(filp));
		finfo->ret = -1;
		tcpio_serv_send(snode, tmsg);
               	return PTR_ERR(filp);
       	}

	rw_tmsg = alloc_tcpio_mem(sizeof(struct kstat));
	if(!rw_tmsg) {
		pr_err("%s unable to allocate %ld\n", __func__, sizeof(struct kstat));
		ret = -EBIO_NOMEMORY;
		finfo->ret = ret;
		tcpio_serv_send(snode, tmsg);
		return ret;
	}
	stat = (struct kstat *) rw_tmsg->buffer;
	ret = vfs_getattr(&filp->f_path, stat);
	filp_close(filp, NULL);

	finfo->ret = ret;
	tcpio_serv_send(snode, tmsg);
	tcpio_serv_send(snode, rw_tmsg);
	free_tcpio_mem(rw_tmsg);
	return ret;
}
int release_bio_sfile(bio_node_t *snode, bio_fileinfo_t *finfo)
{
	struct file *filp;
	bio_device_t *biodev = NULL;
	bio_device_t *dev;
	bio_devref_t *ref, *tmpref;

	list_for_each_entry(dev, &snode->devlist, list) {
		if(dev->fileid == finfo->fileid) {
			biodev = dev;
			break;
		}
	}
	if(biodev == NULL) {
		pr_err("%s entry not found\n", __func__);
		finfo->ret = -1;
		return -1;
	}

	list_for_each_entry_safe(ref, tmpref, &biodev->reflist, list) {
		if(ref->srvrefid == finfo->srvrefid) {
			filp = ref->filp;
			filp_close(filp, NULL);
			//pr_info("%s srvrefid %d is found, deleting now\n", __func__, ref->srvrefid);
			spin_lock(&biodev->bio_device_lock);
    			list_del(&ref->list);
			spin_unlock(&biodev->bio_device_lock);
			finfo->ret = 0;
			break;
		}
	}
	return finfo->ret;
}

int bio_enable_sfops(struct file_operations *dst, const struct file_operations *src)
{
	memset(dst, 0, sizeof(struct file_operations));

	if(src->llseek) {
		dst->llseek = (void *) -1;
	}
	if(src->read) {
		dst->read = (void *) -1;
	}
	if(src->write) {
		dst->write = (void *) -1;
	}
	if(src->aio_read) {
		dst->aio_read = (void *) -1;
	}
	if(src->aio_write) {
		dst->aio_write = (void *) -1;
	}
	if(src->read_iter) {
		dst->read_iter = (void *) -1;
	}
	if(src->write_iter) {
		dst->write_iter = (void *) -1;
	}
	if(src->iterate) {
		dst->iterate = (void *) -1;
	}
	if(src->poll) {
		dst->poll = (void *) -1;
	}
	if(src->unlocked_ioctl) {
		dst->unlocked_ioctl = (void *) -1;
	}
	if(src->compat_ioctl) {
		dst->compat_ioctl = (void *) -1;
	}
	if(src->mmap) {
		dst->mmap = (void *) -1;
	}
	if(src->mremap) {
		dst->mremap = (void *) -1;
	}
	if(src->open) {
		dst->open = (void *) -1;
	}
	if(src->flush) {
		dst->flush = (void *) -1;
	}
	if(src->release) {
		dst->release = (void *) -1;
	}
	if(src->fsync) {
		dst->fsync = (void *) -1;
	}
	if(src->aio_fsync) {
		dst->aio_fsync = (void *) -1;
	}
	if(src->fasync) {
		dst->fasync = (void *) -1;
	}
	if(src->lock) {
		dst->lock = (void *) -1;
	}
	if(src->sendpage) {
		dst->sendpage = (void *) -1;
	}
	if(src->get_unmapped_area) {
		dst->get_unmapped_area = (void *) -1;
	}
	if(src->check_flags) {
		dst->check_flags = (void *) -1;
	}
	if(src->flock) {
		dst->flock = (void *) -1;
	}
	if(src->splice_write) {
		dst->splice_write = (void *) -1;
	}
	if(src->splice_read) {
		dst->splice_read = (void *) -1;
	}
	if(src->setlease) {
		dst->setlease = (void *) -1;
	}
	if(src->fallocate) {
		dst->fallocate = (void *) -1;
	}
	if(src->show_fdinfo) {
		dst->show_fdinfo = (void *) -1;
	}
	return 0;
}

int register_bio_sfile(bio_node_t *snode, tcpio_msg_t *tmsg)
{
	static int fileid = 1;
	struct file *filp; 
	bio_fileinfo_t *finfo = (bio_fileinfo_t *)tmsg->buffer;
	bio_device_t *biodev = NULL;
	bio_device_t *dev;
	tcpio_msg_t *rw_tmsg = NULL;
	int	ret = -1;
	struct inode *i;

	list_for_each_entry(dev, &snode->devlist, list) {
		if(!strcmp(dev->filename, finfo->filename)) {
			printk("%s is already registred\n", finfo->filename);
			ret = -EBIO_ENTRYEXISTS;
			goto err;
		}
	}

	rw_tmsg = alloc_tcpio_mem(sizeof (struct file_operations));
	if(!rw_tmsg) {
		printk("unable to allocate rw_tmsg\n");
		ret = -EBIO_NOMEMORY;
		goto err;
	}

	filp = filp_open(finfo->filename, O_RDONLY, 0);

	if (IS_ERR(filp)) {
                pr_err("%s(): ERROR opening file(%s) with errno = %ld!\n",
                       __func__, finfo->filename, -PTR_ERR(filp));
		ret = PTR_ERR(filp);
		goto err;
        }
	
	i=file_inode(filp);
	bio_enable_sfops(((struct file_operations *)rw_tmsg->buffer), i->i_fop);
	filp_close(filp, NULL);
	biodev = kmalloc(sizeof(bio_device_t), GFP_KERNEL);
	if(!biodev) {
		printk("unable to allocate biodev\n");
		ret = -EBIO_NOMEMORY;
		goto err;
	}
	biodev->bio_device_lock = __SPIN_LOCK_UNLOCKED(biodev->bio_device_lock);
	INIT_LIST_HEAD(&biodev->list);
	INIT_LIST_HEAD(&biodev->reflist);
	snprintf(biodev->filename, sizeof(biodev->filename), "%s", finfo->filename);
	biodev->fileid = fileid;
	biodev->node = snode;
	finfo->fileid = fileid;
	fileid++;
	spin_lock(&snode->bio_node_lock);
	list_add(&biodev->list, &snode->devlist);
	spin_unlock(&snode->bio_node_lock);
	printk("file %s is registered successfully fileid=%d\n", finfo->filename, finfo->fileid); 
	ret = 0;
err:
	finfo->ret = ret;
	tcpio_serv_send(snode, tmsg);
	if(ret == 0) {
		
		tcpio_serv_send(snode, rw_tmsg);
	}
	free_tcpio_mem(rw_tmsg);
	return ret;
}

int deregister_bio_sfile(bio_node_t *snode,char *filename)
{
	bio_device_t *dev, *tmpdev;
	list_for_each_entry_safe(dev, tmpdev, &snode->devlist, list) {
		if(!strcmp(dev->filename, filename)) {
			spin_lock(&snode->bio_node_lock);
    			list_del(&dev->list);
			spin_unlock(&snode->bio_node_lock);
			printk("%s is removed\n", filename);
			kfree(dev);
			return 0;
		}
	}
	return EBIO_FILENOTFOUND;
}

int deregister_bio_sfile_all(bio_node_t *snode)
{
	bio_device_t *dev, *tmpdev;
	list_for_each_entry_safe(dev, tmpdev, &snode->devlist, list) {
			spin_lock(&snode->bio_node_lock);
    			list_del(&dev->list);
			spin_unlock(&snode->bio_node_lock);
			printk("%s is removed\n", dev->filename);
			kfree(dev);
	}
	return 0;
}

tcpio_msg_t * bio_process_scmds(bio_node_t *snode, tcpio_msg_t *tmsg)
{
/*
	printk("msgtype=%d, msgid=%d, totallen=%d, msglen=%d\n", 
			tmsg->bhdr.msgtype, tmsg->bhdr.msgid, tmsg->bhdr.totallen, tmsg->bhdr.msglen);
*/
	bio_fileinfo_t	*finfo = (bio_fileinfo_t *)tmsg->buffer;

	switch (tmsg->bhdr.msgtype)
	{
		case BIO_CMD_REGISTER:
			{
				int	ret= -1;
				ret = register_bio_sfile(snode, tmsg);
			}
			break;
		case BIO_CMD_OPEN:
			{
				int	ret= -1;

				ret = open_bio_sfile(snode, finfo);
				finfo->ret = ret;
				tcpio_serv_send(snode, tmsg);
			}
			break;
		case BIO_CMD_READ:
			read_bio_sfile(snode, tmsg);
			break;
		case BIO_CMD_WRITE:
			write_bio_sfile(snode, tmsg);
			break;
		case BIO_CMD_COMPAT_IOCTL:
			ioctl_bio_sfile(snode, tmsg, BIO_CMD_COMPAT_IOCTL);
			break;
		case BIO_CMD_UNLOCKED_IOCTL:
			ioctl_bio_sfile(snode, tmsg, BIO_CMD_UNLOCKED_IOCTL);
			break;

		case BIO_CMD_RELEASE:
			{
				int	ret= -1;

				ret = release_bio_sfile(snode, finfo);
				finfo->ret = ret;
				tcpio_serv_send(snode, tmsg);

			}
			break;
		case BIO_CMD_GETATTR:
			getattr_bio_sfile(snode, tmsg);
			break;

		case BIO_CMD_DEREGISTER:
			break;
		case BIO_CMD_DEREGISTER_ALL:
			break;
		default:	/* invalid cmd */
			break;
	}
	return tmsg;
}
 

