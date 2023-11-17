#include <stdio.h>
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
        ioctl(fd, StartWrite);
        len = write(fd, buf, strlen(buf));
        if (len < 0)
        {
                perror("write");
                exit(1);
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
        ioctl(fd, StartRead);
        len = read(fd, buf, length);
        if (len < 0)
        {
                perror("read");
                exit(1);
        }
        buf[len] = '\0';
        printf("Read encrypted data: %s  len = %d\n", buf, len);
}

int main(void)
{
        int fd, len, mode, size = 1024 * 1024;
        char big_data[1025] = "abc";
        char result[1025] = {0};
        char key[64] = "asdasd";
        char encryotion_data[5] = "qwer";
        fd = open("/dev/encryptiondev", O_RDWR);
        if (fd < 0)
        {
                perror("open fail \n");
                return 0;
        }
        // 设置密钥
        ioctl(fd, Setkey);
        write(fd, key, strlen(key));
        printf("===============================\n");

        write_data(fd, encryotion_data, ENCRYPTION);

        read_data(fd, result, NORMAL, 64);

        write_data(fd, encryotion_data, ENCRYPTION);

        read_data(fd, result, DECRYPTION, 64);

        // return 0;
        // ioctl(fd, Reset);

        // 开始写入大数据测试
        printf("============大数据测试============\n");
        mode = ENCRYPTION;
        ioctl(fd, SetMode, &mode);
        ioctl(fd, StartWrite);
        for (int i = 0; i < 1025; i++)
        {
                for (int j = 0; j < 1024 / strlen(big_data); j++)
                        write(fd, big_data, strlen(big_data));
        }
        mode = DECRYPTION;
        ioctl(fd, SetMode, &mode);
        ioctl(fd, StartRead);

        FILE *fp = fopen("out.txt", "w");

        for (int i = 0; i < 1024; i++)
        {
                for (int j = 0; j < 1024 / strlen(big_data); j++)
                {
                        len = read(fd, result, strlen(big_data));
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
