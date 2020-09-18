#include "rudp.h"
#include "rudp_connect.h"
#include "rudp_socket_utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef BUILD_APP
#include <unistd.h>
#include <net/if.h>
#endif

//Mac OS sockets
#if __APPLE__
#ifndef SOCK_NONBLOCK
#include <fcntl.h>
#define SOCK_NONBLOCK O_NONBLOCK
#endif

#define MSG_NOSIGNAL 0x2000 /* don't raise SIGPIPE */
#endif	// __APPLE__

RudpRetCode rudp_client_open(rudp_client_open_param_t *param, void **rudp_connect_out)
{
    if (!param || !param->ev_base || !rudp_connect_out)
        return RudpRet_ERROR_Param;

#ifndef WIN32
    int sock = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
    if (sock == -1)
    {
        //printf("udp socket create fail.\n");
        return RudpRet_INTERNAL_ERROR;
    }
#else
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET)
    {
        return RudpRet_INTERNAL_ERROR;
    }
    u_long nonblock = 1;
    ioctlsocket(sock, FIONBIO, &nonblock);
#endif

#ifndef BUILD_APP
    /*
    if (strlen(param->interfaces) > 0)
    {
        //bind interface
        struct ifreq ifr;
        memset(&ifr, 0x00, sizeof(ifr));
        strncpy(ifr.ifr_ifrn.ifrn_name, param->interfaces, sizeof(ifr.ifr_ifrn.ifrn_name));
        int ret = setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, (char *)&ifr, sizeof(ifr));
        if (ret == -1)
        {
            //CXP_LOG(ERR, "Failed to bind socket [sock:%d] to device [%s].",fd, interface);
            close(sock);
            return RudpRet_INTERFACE_ERROR;
        }
    }
    */
#endif
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(param->server_ip);
    serv_addr.sin_port = htons(param->server_port);

    rudp_set_socket_buffer(sock);
    connect(sock, (struct sockaddr *)&serv_addr, sizeof(struct sockaddr_in));

    rudp_connect_t *rudp_connect = (rudp_connect_t *)rudp_malloc(sizeof(rudp_connect_t));
    if (!rudp_connect)
    {
        //printf("malloc rudp_connect_t fail.\n");
        close(sock);
        return RudpRet_MALLOC_ERROR;
    }
    memset(rudp_connect, 0, sizeof(rudp_connect_t));
    rudp_connect->isClient = 1;
    rudp_connect->status = RudpConnectStatus_Handshake;
    rudp_connect->sock = sock;
    memcpy(&rudp_connect->dst_addr, &serv_addr, sizeof(struct sockaddr_in));
    rudp_connect->ev_base = param->ev_base;
    rudp_connect->user_data = param->user_data;
    rudp_connect->on_connect = param->on_connect;
    rudp_connect->on_send = param->on_send;
    rudp_connect->on_recv = param->on_recv;
    iqueue_init(&rudp_connect->pacing_data_queue);

    if (param->req_data && param->req_data_len > 0)
    {
        rudp_connect->req_data_len = param->req_data_len;
        rudp_connect->req_data = (char *)rudp_malloc(param->req_data_len);
        if (!rudp_connect->req_data)
        {
            //printf("malloc first buffer fail.\n");
            close(sock);
            rudp_free(rudp_connect);
            return RudpRet_MALLOC_ERROR;
        }
        memcpy(rudp_connect->req_data, param->req_data, param->req_data_len);
    }

    RudpRetCode ret = rudp_connect_start(rudp_connect);
    if (ret != RudpRet_NO_ERROR)
    {
        rudp_connect_close(rudp_connect);
    }
    *rudp_connect_out = rudp_connect;
    return ret;
}
