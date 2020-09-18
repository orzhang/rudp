#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include <event2/event.h>
#include "rudp.h"

struct event_base *ev_base = NULL;
void *rudp_connect_g = NULL;

long total_byte_send = 0;
long total_byte_send_last = 0;
long total_byte_recv = 0;
long total_byte_recv_last = 0;

void on_connect(void *rudp_connect, void *user_data, RudpConnectFlag flag, const char *resp_data, unsigned int resp_data_len)
{
    printf("on_connect,rudp_connect=%p,user_data=%p,flag=%d,resp_data_len=%d,resp_data=%s.\n", rudp_connect, user_data, flag, resp_data_len, (resp_data ? resp_data : "NULL"));

    if (flag != RudpConnectFlag_Ok)
        rudp_connect_close(rudp_connect);
    else
        rudp_connect_g = rudp_connect;
}

void on_send(void *rudp_connect, void *user_data)
{
    printf("on_send,rudp_connect=%p,user_data=%p.\n", rudp_connect, user_data);
}

void on_recv(void *rudp_connect, void *user_data, const char *data, unsigned int data_len)
{
    //printf("on_recv,rudp_connect=%x,user_data=%x,data_len=%d,data=0x%x,rtt=%d\n",rudp_connect,user_data,data_len,data,rudp_connect_get_rtt(rudp_connect));
    total_byte_recv += data_len;
    //RudpRetCode ret = rudp_connect_send(rudp_connect,data,data_len,RudpDataType_Tcp,1);
}

void on_accept(void *rudp_connect, void *user_data, const char *init_data, unsigned int init_data_len)
{
    printf("on_accept,rudp_connect=%p,user_data=%p,init_data_len=%d,init_data=%.*s.\n", rudp_connect, user_data, init_data_len, init_data_len, init_data);

    char *resp = "I'm server ,hello client!";

    rudp_server_accept_param_t param;
    memset(&param, 0, sizeof(param));
    param.ev_base = ev_base;
    param.on_connect = on_connect;
    param.on_send = on_send;
    param.on_recv = on_recv;
    param.resp_data = resp;
    param.resp_data_len = strlen(resp);

    rudp_server_accept(&param, rudp_connect);
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
    printf("---------------server_process Begin-----------------\n");

    char *server_ip = "0.0.0.0";
    unsigned int server_port = 55555;
    if (argc >= 3)
    {
        server_ip = argv[1];
        server_port = atoi(argv[2]);
    }

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

    rudp_server_open_param_t param;
    memset(&param, 0, sizeof(param));
    memcpy(param.server_ip, server_ip, sizeof(param.server_ip));
    param.server_port = server_port;
    param.ev_base = ev_base;
    param.on_accept = on_accept;

    void *rudp_server = rudp_server_open(&param);
    if (!rudp_server)
    {
        fprintf(stderr, "rudp_server_open fail!\n");
        return 1;
    }

    event_base_dispatch(ev_base);

    if (signal_event)
        event_free(signal_event);
    if (ev_base)
        event_base_free(ev_base);
    printf("---------------server_process End-----------------\n");
    return 0;
}