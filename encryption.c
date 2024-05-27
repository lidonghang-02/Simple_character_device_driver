/*
 * @Date: 2023-11-17 17:22:51
 * @author: lidonghang-02 2426971102@qq.com
 * @LastEditTime: 2024-05-27 11:57:56
 */
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/device.h>

#include "encryption.h"

#define DEV_MAJOR 0
#define DEV_MINOR 0

static int major = DEV_MAJOR;
static int minor = DEV_MINOR;

struct encryption_char_dev
{
	struct cdev cdev;
	struct device *class_dev;

	char *key;
	char *buffer;
	int key_len;
	int length;
	int mode;
};

char S[257]; // State vector
char T[257]; // Temporary vector

struct encryption_char_dev *devp;
struct class *cls;

static int encryption_open(struct inode *inode, struct file *filep)
{
	struct encryption_char_dev *dev;
	dev = container_of(inode->i_cdev, struct encryption_char_dev, cdev); // 获取设备结构体的地址

	filep->private_data = dev; // 将设备结构地址放到文件描述符结构的私有数据中
	printk("encryption_open()\n");
	return 0;
}
static int encryption_release(struct inode *inode, struct file *filep)
{
	printk("encryption_release()\n");

	return 0;
}

static void work_data(char *data, struct encryption_char_dev *dev, int size)
{
	int i = 0, j = 0, t;
	int a = 0, b = 0;
	while (i < 256)
	{
		S[i] = i;
		T[i] = dev->key[i % dev->key_len];
		i++;
	}

	for (i = 0; i < 256; i++)
	{
		j = (j + S[i] + T[i]) % 256;
		swap(S[i], S[j]);
	}

	for (i = 0; i < size; i++)
	{

		a = (a + 1) % 256;
		b = (b + S[a]) % 256;
		swap(S[a], S[b]);

		t = (S[a] + S[b]) % 256;
		data[i] = data[i] ^ S[t];
	}
}

static ssize_t encryption_read(struct file *filep, char __user *buf, size_t size, loff_t *pos)
{
	struct encryption_char_dev *dev = filep->private_data;
	printk("encryption_read()\n");

	if (*pos >= dev->length)
	{
		printk("dev-len = %d\n", dev->length);
		return -ENOMEM;
	}

	if (size > dev->length - *pos)
		size = dev->length - *pos;

	// 加密读取数据
	if (dev->mode == DECRYPTION)
		work_data(dev->buffer + *pos, dev, (int)size);

	if (copy_to_user(buf, dev->buffer + *pos, size))
		return -EFAULT;

	*pos += size;

	return size;
}
static ssize_t encryption_write(struct file *filep, const char __user *buf, size_t size, loff_t *pos)
{
	struct encryption_char_dev *dev = filep->private_data;

	printk("encryption_write()\n");

	char *new_buffer = (char *)kmalloc(size + dev->length, GFP_KERNEL);
	if (!new_buffer)
	{
		printk(KERN_ERR "kmalloc failed\n");
		return -ENOMEM;
	}
	memcpy(new_buffer, dev->buffer, dev->length);

	if (copy_from_user(new_buffer + dev->length, buf, size))
		return -EFAULT;

	kfree(dev->buffer);
	dev->buffer = new_buffer;
	if (dev->mode == ENCRYPTION)
		work_data(dev->buffer + dev->length, dev, (int)size);

	dev->length += size;
	*pos += size;
	return size;
}

static long encryption_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
	int ret = 0;
	char tmp_key[256] = {0};
	struct encryption_char_dev *dev = filep->private_data;

	if (_IOC_TYPE(cmd) != DEV_MAJIC)
		return -ENOTTY; // 检查幻数

	if (_IOC_NR(cmd) > IO_MAXNR)
		return -ENOTTY; // 检查命令编号

	if (_IOC_DIR(cmd) & _IOC_READ)
		ret = !access_ok(VERIFY_WRITE, (void __user *)arg, _IOC_SIZE(cmd));
	else if (_IOC_DIR(cmd) & _IOC_WRITE)
		ret = !access_ok(VERIFY_READ, (void __user *)arg, _IOC_SIZE(cmd));
	if (ret)
		return -EFAULT;

	switch (cmd)
	{
	case Setkey:
		if (copy_from_user(tmp_key, (char __user *)arg, sizeof(tmp_key)))
			return -EFAULT;

		if (dev->key)
			kfree(dev->key);
		dev->key_len = strlen(tmp_key);
		dev->key = kmalloc(sizeof(char) * dev->key_len, GFP_KERNEL);
		memcpy(dev->key, tmp_key, sizeof(char) * dev->key_len);
		break;
	case SetMode:

		ret = get_user(dev->mode, (unsigned int __user *)arg);
		if (ret)
			return -EFAULT;
		break;
	case Reset:
		if (dev->buffer)
		{
			kfree(dev->buffer);
			dev->length = 0;
		}
		break;
	default:
		return -ENOTTY;
	}

	return ret;
}
struct file_operations encryption_ops = {
	.owner = THIS_MODULE,
	.open = encryption_open,
	.release = encryption_release,
	.read = encryption_read,
	.write = encryption_write,
	.unlocked_ioctl = encryption_ioctl,
};
static int __init encryption_init_module(void)
{
	int ret;
	dev_t devno;

	devno = MKDEV(major, minor);

	if (major)
		ret = register_chrdev_region(devno, 1, "encryption");
	else
	{
		ret = alloc_chrdev_region(&devno, 0, 1, "encryption");
		major = MAJOR(devno);
	}

	if (ret < 0)
		return ret;

	devp = kzalloc(sizeof(struct encryption_char_dev), GFP_KERNEL);
	if (!devp)
	{
		printk(KERN_ERR "kzalloc failed\n");
		ret = -ENOMEM;
		goto out_err_1;
	}
	devp->mode = NORMAL;

	cls = class_create(THIS_MODULE, "encryption_cls");
	if (IS_ERR(cls))
	{
		printk(KERN_ERR "class_create() failed for cls\n");
		ret = PTR_ERR(cls);
		goto out_err_1;
	}

	cdev_init(&devp->cdev, &encryption_ops);
	devp->cdev.owner = THIS_MODULE;

	ret = cdev_add(&devp->cdev, devno, 1);
	if (ret)
		goto out_err_2;

	devp->class_dev = device_create(cls, NULL, devno, NULL, "encryptiondev");
	if (IS_ERR(devp->class_dev))
	{
		ret = PTR_ERR(devp->class_dev);
		goto out_err_3;
	}

	printk("encryption_init \n");
	return 0;

out_err_3:
	cdev_del(&devp->cdev);
out_err_2:
	class_destroy(cls);
out_err_1:
	unregister_chrdev(major, "encryption");
	return ret;
}
static void __exit encryption_exit_module(void)
{
	device_destroy(cls, MKDEV(major, minor));
	cdev_del(&devp->cdev);
	class_destroy(cls);
	unregister_chrdev_region(MKDEV(major, minor), 1);
	kfree(devp);
	printk("encryption_exit \n");
}
module_init(encryption_init_module);
module_exit(encryption_exit_module);

MODULE_AUTHOR("lidonghang-02");
MODULE_LICENSE("GPL");
