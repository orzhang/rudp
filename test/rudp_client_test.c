#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include <event2/event.h>
#include "rudp.h"

struct event_base *ev_base = NULL;
struct event *ev_send_timer = NULL;
void *rudp_connect_g = NULL;

int scale_mode = 0;
long total_byte_send = 0;
long total_byte_send_last = 0;
long total_byte_recv = 0;
long total_byte_recv_last = 0;

int seq = 0;
char send_buffer[1024 * 60];

void send_timer(evutil_socket_t fd, short events, void *arg)
{
    if (!arg)
        return;

    snprintf(send_buffer, sizeof(send_buffer), "%d", seq);

    RudpRetCode ret = rudp_connect_send(arg, send_buffer, sizeof(send_buffer), RudpDataType_Tcp, 1);
    if (ret == RudpRet_NO_ERROR)
        total_byte_send += sizeof(send_buffer);

    seq++;
}

void on_connect(void *rudp_connect, void *user_data, RudpConnectFlag flag, const char *resp_data, unsigned int resp_data_len)
{
    printf("on_connect,rudp_connect=%p,user_data=%p,flag=%d,resp_data_len=%d,resp_data=%s.\n", rudp_connect, user_data, flag, resp_data_len, (resp_data ? resp_data : "NULL"));

    if (flag != RudpConnectFlag_Ok)
    {
        printf("connect peer fail.\n");
        exit(0);
    }
    rudp_connect_g = rudp_connect;

    if (scale_mode == 0)
    {
        struct timeval tv = {1, 100 * 1000};
        ev_send_timer = event_new(ev_base, -1, EV_TIMEOUT | EV_PERSIST, send_timer, rudp_connect);
        if (!ev_send_timer || event_add(ev_send_timer, &tv) < 0)
        {
            fprintf(stderr, "Could not create/add a timer event!\n");
            return;
        }
    }
}

void on_send(void *rudp_connect, void *user_data)
{
    if (scale_mode == 0)
    {
        printf("on_send,rudp_connect=%p,user_data=%p.\n", rudp_connect, user_data);
    }
    else
    {
        while (1)
        {
            snprintf(send_buffer, sizeof(send_buffer), "%d", seq);

            RudpRetCode ret = rudp_connect_send(rudp_connect, send_buffer, sizeof(send_buffer), RudpDataType_Tcp, 1);
            if (ret == RudpRet_NO_ERROR)
                total_byte_send += sizeof(send_buffer);
            else if (ret == RudpRet_ERROR_Eagain)
                return;
            else
            {
                printf("rudp_connect_send error...\n");
                return;
            }

            seq++;
        }
    }
}

void on_recv(void *rudp_connect, void *user_data, const char *data, unsigned int data_len)
{
    //printf("on_recv,rudp_connect=%x,user_data=%x,data_len=%d,data=0x%x.rtt=%d\n",rudp_connect,user_data,data_len,data,rudp_connect_get_rtt(rudp_connect));
}

void printf_status(int last)
{
    if (last || total_byte_send_last != total_byte_send || total_byte_recv_last != total_byte_recv)
    {
        char status[4096] = {0};
        rudp_connect_get_status(rudp_connect_g, status, 4096);
        printf("all_send=%ld,diff_send=%ld,all_recv=%ld,diff_recv=%ld,status=%s\n",
               total_byte_send, total_byte_send - total_byte_send_last, total_byte_recv, total_byte_recv - total_byte_recv_last, status);
    }
    total_byte_send_last = total_byte_send;
    total_byte_recv_last = total_byte_recv;
}

void timeout_cb(evutil_socket_t fd, short events, void *arg)
{
    printf_status(0);
}

void signal_cb(evutil_socket_t sig, short events, void *user_data)
{
    printf("Caught an interrupt signal; exiting cleanly in two seconds.\n");
    struct timeval delay = {1, 0};
    event_base_loopexit(ev_base, &delay);
}

int main(int argc, char **argv)
{
    printf("---------------client_process Begin-----------------\n");

    char *server_ip = "127.0.0.1";
    unsigned int server_port = 55555;
    if (argc >= 3)
    {
        server_ip = argv[1];
        server_port = atoi(argv[2]);
    }

    memset(send_buffer, 'H', sizeof(send_buffer));
    ev_base = event_base_new();
    if (!ev_base)
    {
        fprintf(stderr, "Could not initialize libevent!\n");
        return 1;
    }

    struct event *signal_event = evsignal_new(ev_base, SIGINT, signal_cb, (void *)ev_base);
    if (!signal_event || event_add(signal_event, NULL) < 0)
    {
        fprintf(stderr, "Could not create/add a signal event!\n");
        return 1;
    }

    struct timeval tv = {1, 0};
    struct event *timer_event = event_new(ev_base, -1, EV_TIMEOUT | EV_PERSIST, timeout_cb, NULL);
    if (!timer_event || event_add(timer_event, &tv) < 0)
    {
        fprintf(stderr, "Could not create/add a timer event!\n");
        return 1;
    }

    char *hello = "I'm client ,hello server!";

    rudp_client_open_param_t param;
    memset(&param, 0, sizeof(param));
    memcpy(param.server_ip, server_ip, sizeof(param.server_ip));
    //memcpy(param.interface,"ens33",sizeof(param.interface));
    param.server_port = server_port;
    param.ev_base = ev_base;
    param.on_connect = on_connect;
    param.on_send = on_send;
    param.on_recv = on_recv;
    param.req_data = hello;
    param.req_data_len = strlen(hello);

    void *rudp_connect_out = NULL;
    RudpRetCode ret = rudp_client_open(&param,&rudp_connect_out);
    if (ret != RudpRet_NO_ERROR)
    {
        fprintf(stderr, "rudp_client_open fail!\n");
        return 1;
    }

    event_base_dispatch(ev_base);

    if (signal_event)
        event_free(signal_event);
    if (ev_base)
        event_base_free(ev_base);
    printf("---------------client_process End-----------------\n");
    printf_status(1);
    return 0;
}
