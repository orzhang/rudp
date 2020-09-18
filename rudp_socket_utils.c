#include "rudp_socket_utils.h"

#include <stdio.h>
#ifndef WIN32
#include <sys/socket.h>
#else
#include <winsock.h>
#endif

int rudp_set_socket_buffer(int sock)
{
    if (sock <= 0)
        return -1;
    int err = -1;
    int snd_size = 8 * 1024 * 1024; /* 发送缓冲区大小 */
    int rcv_size = 8 * 1024 * 1024; /* 接收缓冲区大小 */
    int optlen;                     /* 选项值长度 */
    optlen = sizeof(snd_size);
    err = setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &snd_size, optlen);
    if (err < 0)
    {
        //printf("setsockopt SO_SNDBUF error\n");
        return -2;
    }
    optlen = sizeof(rcv_size);
    err = setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (char *)&rcv_size, optlen);
    if (err < 0)
    {
        //printf("setsockopt SO_RCVBUF error\n");
        return -3;
    }

    err = -1;
    snd_size = 0;
    rcv_size = 0;
    optlen = sizeof(snd_size);
    err = getsockopt(sock, SOL_SOCKET, SO_SNDBUF, &snd_size, &optlen);
    if (err < 0)
    {
        //printf("getsockopt SO_SNDBUF error\n");
        return -4;
    }
    optlen = sizeof(rcv_size);
    err = getsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rcv_size, &optlen);
    if (err < 0)
    {
        //printf("getsockopt SO_RCVBUF error\n");
        return -5;
    }
    //printf("getsockopt SO_SNDBUF=%d,SO_RCVBUF=%d\n",snd_size,rcv_size);
    return 0;
}