#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <string.h>
#include "encryption.h"

void write_data(int fd, char *buf, int mode)
{
	if (mode != ENCRYPTION && mode != NORMAL)
	{
		printf("write_data mode failed\n");
		return;
	}
	int len;
	ioctl(fd, SetMode, &mode);
	// 开始写入数据
	len = write(fd, buf, strlen(buf));
	if (len < 0)
	{
		perror("write");
		return;
	}
	printf("write:%s  len = %d\n", buf, len);
}

void read_data(int fd, char *buf, int mode, int length)
{
	if (mode != DECRYPTION && mode != NORMAL)
	{
		printf("read_data mode failed\n");
		return;
	}
	int len;
	ioctl(fd, SetMode, &mode);
	len = read(fd, buf, length);
	if (len < 0)
	{
		perror("read");
		return;
	}
	buf[len] = '\0';
	printf("Read encrypted data: %s  len = %d\n", buf, len);
}

int main(void)
{
	int fd, len, mode;

	char result[1025] = {0};
	char key[256] = "asdasd";
	char small_data[5] = "qwer";

	char *big_data = malloc(sizeof(char) * (1024 * 1024));
	char *res_big_data = malloc(sizeof(char) * 2 * 1024 * 1024);

	char *populate_the_data = "abc";

	int i,
		j;
	fd = open("/dev/encryptiondev", O_RDWR);
	if (fd < 0)
	{
		perror("open fail");
		return 0;
	}
	// 设置密钥
	ioctl(fd, Setkey, key);

	printf("===============================\n");

	write_data(fd, small_data, ENCRYPTION);

	read_data(fd, result, NORMAL, 64);

	write_data(fd, small_data, ENCRYPTION);

	read_data(fd, result, DECRYPTION, 64);

	ioctl(fd, Reset);

	// 开始写入大数据测试
	printf("============大数据测试============\n");
	mode = ENCRYPTION;
	ioctl(fd, SetMode, &mode);

	int pos = 0;
	len = strlen(populate_the_data);
	for (i = 0; i < 1024; i++)
	{
		for (j = 0; j < 1024; j++)
		{
			big_data[pos] = populate_the_data[pos % len];
			pos++;
		}
	}

	printf("big_data len = %d\n", pos);
	big_data[pos] = '\0';

	int ret = write(fd, big_data, sizeof(big_data));
	if (ret < 0)
	{
		printf("ret = %d\n", ret);
		perror("write");
		return 0;
	}

	mode = DECRYPTION;
	ioctl(fd, SetMode, &mode);

	FILE *fp = fopen("out.txt", "w");

	for (i = 0; i < 1024; i++)
	{
		for (j = 0; j < 1024 / 64; j++)
		{
			len = read(fd, result, 64);
			result[len] = '\0';
			fprintf(fp, "%s", result);
		}
	}

	printf("write out.txt success");
	printf("\n===============================\n");
	ioctl(fd, Reset);
	close(fd);
	return 0;
}
