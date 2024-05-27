#ifndef __ENCRYPTION_H_
#define __ENCRYPTION_H_

#define ENCRYPTION 1
#define DECRYPTION 2
#define NORMAL 0

#define DEV_MAJIC 'k'

#define Setkey _IOW(DEV_MAJIC, 0, char[256])
#define SetMode _IOW(DEV_MAJIC, 1, int)
#define Reset _IO(DEV_MAJIC, 2)

#define IO_MAXNR 2

#endif
