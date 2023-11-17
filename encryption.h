#ifndef __ENCRYPTION_H_
#define __ENCRYPTION_H_

#define KEY 1
#define ENCRYPTION 2
#define DECRYPTION 3
#define NORMAL 4
#define WRITE_Status 5
#define READ_Status 6

#define DEV_FIFO_TYPE 'k'

#define Setkey _IO(DEV_FIFO_TYPE, 0)
#define SetMode _IOW(DEV_FIFO_TYPE, 1, int)
#define StartWrite _IO(DEV_FIFO_TYPE, 2)
#define StartRead _IO(DEV_FIFO_TYPE, 3)
#define Reset _IO(DEV_FIFO_TYPE, 4)

#endif
