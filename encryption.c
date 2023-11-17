/*
 * @Date: 2023-11-17 17:22:51
 * @author: lidonghang-02 2426971102@qq.com
 * @LastEditTime: 2023-11-17 18:29:58
 */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kdev_t.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>
#include <linux/io.h>
#include <linux/slab.h>

#include "encryption.h"

static int major = 256;
static int minor = 0;

struct encryption_char_dev
{
	struct cdev cdev;
	char *key;
	char *buffer;
	int key_len;
	int length;
	int mode, status;
};
char S[257]; // State vector
char T[257]; // Temporary vector

struct encryption_char_dev *devp;
struct class *cls;

static dev_t devno;
struct device *class_dev = NULL;

static int encryption_open(struct inode *inode, struct file *filep)
{
	struct encryption_char_dev *dev;
	printk(KERN_INFO "%s open \n", current->comm);
	dev = container_of(inode->i_cdev, struct encryption_char_dev, cdev); // 获取设备结构体的地址
	dev->length = 0;
	dev->mode = NORMAL;
	dev->status = 0;

	filep->private_data = dev; // 将设备结构地址放到文件描述符结构的私有数据中
	return 0;
}
static int encryption_release(struct inode *inode, struct file *filep)
{
	printk("encryption_release()\n");

	return 0;
}

static ssize_t encryption_read(struct file *filep, char __user *buf, size_t size, loff_t *pos)
{

	struct encryption_char_dev *dev = filep->private_data;

	if (*pos >= dev->length)
	{
		return 0;
	}
	if (size > dev->length - *pos)
	{
		size = dev->length - *pos;
	}
	// 加密读取数据
	if (dev->mode == DECRYPTION && dev->status == READ_Status)
	{
		char keystream, ch;
		char *temp = (char *)kzalloc(dev->length, GFP_KERNEL);
		if (!temp)
		{
			return -ENOMEM;
		}
		char *temp_buf = (char *)kzalloc(dev->length, GFP_KERNEL);
		if (!temp_buf)
		{
			return -ENOMEM;
		}
		int i = 0, j = 0, t;
		int a = 0, b = 0;
		memcpy(temp_buf, dev->buffer + *pos, size);

		while (i < 256)
		{
			S[i] = i;
			T[i] = dev->key[i % dev->key_len];
			i++;
		}

		for (i = 0; i < 256; i++)
		{
			j = (j + S[i] + T[i]) + 256;
			j = j % 256;
			swap(S[i], S[j]);
		}
		for (i = 0; i < size; i++)
		{

			b = (a + 1 + 256) % 256;
			b = (b + S[a] + 256) % 256;
			swap(S[a], S[b]);

			t = (S[a] + S[b] + 256) % 256;
			keystream = S[t];
			ch = (int)temp_buf[i] ^ (int)keystream;
			temp[i] = ch;
		}

		temp[size] = '\0';
		// printk(KERN_INFO "decrypted read->%s 		len->%d\n", temp, strlen(temp));

		if (copy_to_user(buf, temp, size))
		{
			return -EFAULT;
		}
		kfree(temp);
		kfree(temp_buf);
	}
	else if (dev->mode == NORMAL && dev->status == READ_Status)
	{
		// printk(KERN_INFO "normal read->%s 		len->%d\n", dev->buffer, strlen(dev->buffer));

		if (copy_to_user(buf, dev->buffer + *pos, size))
		{
			return -EFAULT;
		}
	}
	else
		return -EFAULT;

	*pos += size;
	return size;
}
static ssize_t encryption_write(struct file *filep, const char __user *buf, size_t size, loff_t *pos)
{
	struct encryption_char_dev *dev = filep->private_data;
	int error = -ENOMEM;

	if (dev->mode == ENCRYPTION && dev->status == WRITE_Status)
	{
		char keystream, ch;
		// char *new_buffer = NULL;
		char *temp = (char *)kzalloc(size + size, GFP_KERNEL);
		if (!temp)
		{
			return -ENOMEM;
		}
		char *temp_buf = (char *)kzalloc(size + size, GFP_KERNEL);
		if (!temp_buf)
		{
			return -ENOMEM;
		}
		int t;
		int a = 0, b = 0;
		int i = 0, j = 0;

		if (copy_from_user(temp_buf, buf, size))
		{
			goto error_2;
		}

		while (i < 256)
		{
			S[i] = i;
			T[i] = dev->key[i % dev->key_len];
			i++;
		}
		for (i = 0; i < 256; i++)
		{
			j = (j + S[i] + T[i]) + 256;
			j = j % 256;
			swap(S[i], S[j]);
		}
		for (i = 0; i < size; i++)
		{

			b = (a + 1 + 256) % 256;
			b = (b + S[a] + 256) % 256;
			swap(S[a], S[b]);

			t = (S[a] + S[b] + 256) % 256;
			keystream = S[t];
			ch = (int)temp_buf[i] ^ (int)keystream;
			temp[i] = ch;
		}
		temp[size] = '\0';
		size = strlen(temp);
		char *new_buffer = (char *)kzalloc(size + dev->length + 2, GFP_KERNEL);

		if (!new_buffer)
		{
			goto error_1;
		}

		memcpy(new_buffer, dev->buffer, dev->length);
		memcpy(new_buffer + dev->length, temp, size);

		kfree(dev->buffer);
		kfree(temp);
		kfree(temp_buf);
		dev->buffer = new_buffer;
		dev->length += size;
		// printk(KERN_INFO "encrypted write-> %s 		len->%d\n", dev->buffer, strlen(dev->buffer));
	}
	else if (dev->mode == NORMAL && dev->status == WRITE_Status)
	{
		char *new_buffer = (char *)kzalloc(size + dev->length, GFP_KERNEL);
		if (!new_buffer)
		{
			printk(KERN_INFO "normal write new buffer error\n");
			goto error_1;
		}
		if (copy_from_user(new_buffer + dev->length, buf, size))
		{
			error = -EFAULT;
			goto error_2;
		}
		memcpy(new_buffer, dev->buffer, dev->length);
		kfree(dev->buffer);
		dev->buffer = new_buffer;
		dev->length += size;
		// printk(KERN_INFO "normal write-> %s 		len->%d\n", dev->buffer, strlen(dev->buffer));
	}
	else if (dev->mode == KEY)
	{
		kfree(dev->key);
		dev->key = (char *)kzalloc(size, GFP_KERNEL);
		if (!dev->key)
		{
			goto error_1;
		}
		if (copy_from_user(dev->key, buf, size))
		{
			goto error_2;
		}
		dev->key_len = strlen(dev->key);
		// printk(KERN_INFO "set key-> %s 		len->%d\n", dev->key, strlen(dev->key));
	}
	else
		goto error_2;
	return size;
error_2:
	kfree(dev->buffer);
	kfree(dev->key);
error_1:
	return error;
}

long encryption_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
	long ret = 0;
	int temp_mode = 0;
	void __user *argp = (void __user *)arg;
	int __user *p = argp;
	struct encryption_char_dev *dev = filep->private_data;

	if (_IOC_TYPE(cmd) != DEV_FIFO_TYPE)
	{
		pr_err("cmd   %u,bad magic 0x%x/0x%x.\n", cmd, _IOC_TYPE(cmd), DEV_FIFO_TYPE);
		return -ENOTTY; // 检查幻数
	}
	if (_IOC_NR(cmd) > DEV_FIFO_TYPE)
		return -ENOTTY; // 检查命令编号

	if (_IOC_DIR(cmd) & _IOC_READ) // 涉及到用户空间与内核空间数据交互，判断读OK吗？
		ret = !access_ok((void __user *)arg, _IOC_SIZE(cmd));
	if (ret)
		return -EFAULT;

	switch (cmd)
	{
	case Setkey:
		dev->mode = KEY;
		break;
	case SetMode:
		ret = get_user(temp_mode, p);
		if (temp_mode == ENCRYPTION)
			dev->mode = ENCRYPTION;
		else if (temp_mode == DECRYPTION)
			dev->mode = DECRYPTION;
		else
			dev->mode = NORMAL;
		break;
	case StartWrite:
		dev->status = WRITE_Status;
		break;
	case StartRead:
		dev->status = READ_Status;
		break;
	case Reset:
		kfree(dev->buffer);
		dev->length = 0;
		break;
	default:
		return -ENOTTY;
	}

	return ret;
}
static struct file_operations encryption_ops =
	{
		.open = encryption_open,
		.release = encryption_release,
		.read = encryption_read,
		.write = encryption_write,
		.unlocked_ioctl = encryption_ioctl,
};
static int encryption_init(void)
{
	int result;

	printk("encryption_init \n");
	result = register_chrdev(major, "encryption", &encryption_ops);
	if (result < 0)
	{
		printk("register_chrdev fail \n");
		return result;
	}
	cls = class_create(THIS_MODULE, "encryption_cls");
	if (IS_ERR(cls))
	{
		printk(KERN_ERR "class_create() failed for cls\n");
		result = PTR_ERR(cls);
		goto out_err_1;
	}
	devno = MKDEV(major, minor);

	class_dev = device_create(cls, NULL, devno, NULL, "encryptiondev");
	if (IS_ERR(class_dev))
	{
		result = PTR_ERR(class_dev);
		goto out_err_2;
	}

	devp = kzalloc(sizeof(struct encryption_char_dev) * minor, GFP_KERNEL); // 给字符设备分配空间，这里hello_nr_devs为2
	if (!devp)
	{
		return -ENOMEM;
	}
	return 0;

out_err_2:
	class_destroy(cls);
out_err_1:
	unregister_chrdev(major, "encryption");
	return result;
}
static void encryption_exit(void)
{
	printk("encryption_exit \n");
	device_destroy(cls, devno);
	class_destroy(cls);
	unregister_chrdev(major, "encryption");
	kfree(devp);
	return;
}
module_init(encryption_init);
module_exit(encryption_exit);
MODULE_LICENSE("GPL");
