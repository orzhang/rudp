#include "rudp.h"
#include "rudp_connect.h"
#include "rudp_socket_utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef WIN32
#include <unistd.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#endif

#include <event2/event.h>

//Mac OS sockets
#if __APPLE__
#ifndef SOCK_NONBLOCK
#include <fcntl.h>
#define SOCK_NONBLOCK O_NONBLOCK
#endif

#define MSG_NOSIGNAL 0x2000 /* don't raise SIGPIPE */
#endif	// __APPLE__
typedef struct
{
    int sock;
    struct sockaddr_in serv_addr;

    struct event_base *ev_base;
    struct event *ev_reader;
    void *user_data;

    on_accept_t on_accept;

#if !(defined(WIN32) || defined(__APPLE__) || defined(__MACOS__))
    struct mmsghdr udp_msgs[RUDP_UDP_VLEN];
    struct iovec udp_iovecs[RUDP_UDP_VLEN];
    char udp_bufs[RUDP_UDP_VLEN][RUDP_UDP_BUFSIZE];
    struct sockaddr_in udp_clientaddr[RUDP_UDP_VLEN];
    char udp_msg_control[RUDP_UDP_VLEN][CMSG_SPACE(sizeof(struct sockaddr_in))];
#endif
} rudp_server_t;

void process_server_recv_data(rudp_server_t *rudp_server, struct sockaddr_in *serv_addr, struct sockaddr_in *clnt_addr, const char *data, unsigned int data_len)
{
    if (!rudp_server || !serv_addr || !clnt_addr || !data || data_len <= 4)
        return;

    if (data_len >= 24)
    {
        char head[23] = {0};
        if (memcmp(head, data + 1, 23) == 0)
            return;
    }

    /*
    char sip[256] = {0};
    char cip[256] = {0};

    struct sockaddr_in *sin = (struct sockaddr_in *)serv_addr;
    inet_ntop(sin->sin_family, (void *)&(sin->sin_addr), sip, sizeof(sip));
    int sport = ntohs(sin->sin_port);

    sin = (struct sockaddr_in *)clnt_addr;
    inet_ntop(sin->sin_family, (void *)&(sin->sin_addr), cip, sizeof(cip));
    int cport = ntohs(sin->sin_port);

    printf(">>>>client[%s:%d],server[%s:%d],data_len[%d]<<<<\n",cip,cport,sip,sport,data_len);
    */

#ifndef WIN32
    int sock = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
    if (sock < 0)
    {
        //printf("udp socket create fail.\n");
        return;
    }
#else
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET)
    {
        return;
    }
    u_long nonblock = 1;
    ioctlsocket(sock, FIONBIO, &nonblock);
#endif

    rudp_set_socket_buffer(sock);

    evutil_make_listen_socket_reuseable(sock);

    if (bind(sock, (struct sockaddr *)serv_addr, sizeof(struct sockaddr_in)) == -1)
    {
        //printf("rebind udp port fail.\n");
        close(sock);
        return;
    }

    connect(sock, (struct sockaddr *)clnt_addr, sizeof(struct sockaddr_in));

    rudp_connect_t *rudp_connect = (rudp_connect_t *)rudp_malloc(sizeof(rudp_connect_t));
    if (!rudp_connect)
    {
        //printf("malloc rudp_connect_t fail.\n");
        close(sock);
        return;
    }
    memset(rudp_connect, 0, sizeof(rudp_connect_t));
    rudp_connect->isClient = 0;
    rudp_connect->status = RudpConnectStatus_Handshake;
    rudp_connect->sock = sock;
    memcpy(&rudp_connect->dst_addr, clnt_addr, sizeof(struct sockaddr_in));
    iqueue_init(&rudp_connect->pacing_data_queue);
    rudp_connect->req_data_len = data_len;
    rudp_connect->req_data = (char *)rudp_malloc(data_len);
    if (!rudp_connect->req_data)
    {
        //printf("malloc first buffer fail.\n");
        close(sock);
        rudp_free(rudp_connect);
        return;
    }
    memcpy(rudp_connect->req_data, data, data_len);

    const char *init_data = NULL;
    unsigned int init_data_len = 0;
    int head_len = RUDP_PROTOCOL_HEAD_LEN + sizeof(rudp_msg_head_t) + sizeof(rudp_msg_body_handshake_request_t);
    if (data_len > head_len)
    {
        init_data = data + head_len;
        init_data_len = data_len - head_len;
    }

    if (rudp_server->on_accept)
        rudp_server->on_accept(rudp_connect, rudp_server->user_data, init_data, init_data_len); //todo

    //todo add wait list
}

void on_server_recv(evutil_socket_t fd, short events, void *arg)
{
    if (!arg)
        return;
    rudp_server_t *rudp_server = (rudp_server_t *)arg;
    struct sockaddr_in *serv_addr = &rudp_server->serv_addr;

    while (1)
    {
#if !(defined(WIN32) || defined(__APPLE__) || defined(__MACOS__))
        int retval = recvmmsg(fd, rudp_server->udp_msgs, RUDP_UDP_VLEN, 0, NULL);
        if (retval <= 0)
        {
            //perror("recvmmsg()");
            return;
        }

        int i = 0;
        for (i = 0; i < retval; i++)
        {
            char *buffer = rudp_server->udp_bufs[i];
            int len = rudp_server->udp_msgs[i].msg_len;
            rudp_server->udp_msgs[i].msg_len = 0;

            struct msghdr *hdr = &rudp_server->udp_msgs[i].msg_hdr;
            struct cmsghdr *cmsg = NULL;
            struct sockaddr_in server_addr;
            if (hdr->msg_controllen > 0)
            {
                memset(&server_addr, 0, sizeof(server_addr));
                for (cmsg = CMSG_FIRSTHDR(hdr); cmsg != NULL; cmsg = CMSG_NXTHDR(hdr, cmsg))
                {
                    if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_RECVORIGDSTADDR)
                    {
                        memcpy(&server_addr, CMSG_DATA(cmsg), sizeof(struct sockaddr_in));
                        server_addr.sin_family = AF_INET;
                        serv_addr = &server_addr;
                        break;
                    }
                }
            }

            process_server_recv_data(rudp_server, serv_addr, &rudp_server->udp_clientaddr[i], buffer, len);
        }
#else
        char buffer[2048] = {0};
        struct sockaddr_in clnt_addr;
        socklen_t clnt_adr_sz = sizeof(clnt_addr);

        memset(&clnt_addr, 0, sizeof(clnt_addr));
        int len = recvfrom(fd, buffer, sizeof(buffer), 0, (struct sockaddr *)&clnt_addr, &clnt_adr_sz);
        if (len <= 0)
        {
            //perror("recv()");
            return;
        }
        process_server_recv_data(rudp_server, serv_addr, &clnt_addr, buffer, len);
#endif
    }
}

void *rudp_server_open(rudp_server_open_param_t *param)
{
    if (!param || !param->ev_base)
        return NULL;

#ifndef WIN32
    int sock = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
    if (sock <= 0)
    {
        //printf("udp socket create fail.\n");
        return NULL;
    }

    int opt = 1;
    //setsockopt(sock, SOL_IP, IP_RECVORIGDSTADDR, &opt, sizeof(opt));
    setsockopt(sock, IPPROTO_IP, IP_PKTINFO, &opt, sizeof(opt));
#else
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET)
    {
        return NULL;
    }
    u_long nonblock = 1;
    ioctlsocket(sock, FIONBIO, &nonblock);
#endif

    evutil_make_listen_socket_reuseable(sock);

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(param->server_ip);
    serv_addr.sin_port = htons(param->server_port);

    rudp_server_t *rudp_server = (rudp_server_t *)rudp_malloc(sizeof(rudp_server_t));
    if (!rudp_server)
    {
        //printf("malloc rudp_server_t fail.\n");
        return NULL;
    }
    memset(rudp_server, 0, sizeof(rudp_server_t));
    rudp_server->ev_base = param->ev_base;
    rudp_server->user_data = param->user_data;
    rudp_server->on_accept = param->on_accept;
    rudp_server->sock = sock;
    memcpy(&rudp_server->serv_addr, &serv_addr, sizeof(struct sockaddr_in));

    rudp_set_socket_buffer(sock);

    if (bind(sock, (struct sockaddr *)&serv_addr, sizeof(struct sockaddr_in)) == -1)
    {
        //printf("bind udp port fail.listen_addr=%s:%d\n",param->server_ip,param->server_port);
        return NULL;
    }

    struct event *ev_reader = event_new(param->ev_base, sock, EV_READ | EV_PERSIST, on_server_recv, rudp_server);
    if (!ev_reader)
    {
        rudp_free(rudp_server);
        //printf("event_new event fail.\n");
        return NULL;
    }

    event_priority_set(ev_reader, 0);
    event_add(ev_reader, NULL);

    rudp_server->ev_reader = ev_reader;

#if !(defined(WIN32) || defined(__APPLE__) || defined(__MACOS__))
    //init struct mmsghdr
    int i = 0;
    memset(rudp_server->udp_msgs, 0, sizeof(rudp_server->udp_msgs));
    for (i = 0; i < RUDP_UDP_VLEN; i++)
    {
        rudp_server->udp_iovecs[i].iov_base = rudp_server->udp_bufs[i];
        rudp_server->udp_iovecs[i].iov_len = RUDP_UDP_BUFSIZE;
        rudp_server->udp_msgs[i].msg_hdr.msg_iov = &rudp_server->udp_iovecs[i];
        rudp_server->udp_msgs[i].msg_hdr.msg_iovlen = 1;
        rudp_server->udp_msgs[i].msg_hdr.msg_name = &rudp_server->udp_clientaddr[i];
        rudp_server->udp_msgs[i].msg_hdr.msg_namelen = sizeof(rudp_server->udp_clientaddr[i]);
        rudp_server->udp_msgs[i].msg_hdr.msg_control = rudp_server->udp_msg_control[i];
        rudp_server->udp_msgs[i].msg_hdr.msg_controllen = sizeof(rudp_server->udp_msg_control[i]);
    }
#endif

    return rudp_server;
}

void rudp_server_close(void *rudp_server_i)
{
    if (!rudp_server_i)
        return;
    rudp_server_t *rudp_server = (rudp_server_t *)rudp_server_i;
    if (rudp_server->ev_reader)
        event_free(rudp_server->ev_reader);
    close(rudp_server->sock);
    rudp_free(rudp_server);
}

void rudp_server_accept(rudp_server_accept_param_t *param, void *rudp_connect_i)
{
    if (!rudp_connect_i)
        return;
    rudp_connect_t *rudp_connect = (rudp_connect_t *)rudp_connect_i;
    if (!param)
    {
        //abort connect
        rudp_connect_close(rudp_connect);
        return;
    }

    rudp_connect->ev_base = param->ev_base;
    rudp_connect->user_data = param->user_data;
    rudp_connect->on_connect = param->on_connect;
    rudp_connect->on_send = param->on_send;
    rudp_connect->on_recv = param->on_recv;

    if (param->resp_data && param->resp_data_len > 0)
    {
        rudp_connect->resp_data_len = param->resp_data_len;
        rudp_connect->resp_data = (char *)rudp_malloc(param->resp_data_len);
        if (!rudp_connect->resp_data)
        {
            //printf("malloc first buffer fail.\n");
            rudp_connect_close(rudp_connect);
            return;
        }
        memcpy(rudp_connect->resp_data, param->resp_data, param->resp_data_len);
    }

    RudpRetCode ret = rudp_connect_start(rudp_connect);
    if (ret != RudpRet_NO_ERROR)
    {
        //rudp_free(rudp_connect);
        rudp_connect_close(rudp_connect);
    }
}
