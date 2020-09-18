#ifndef __RUDP_STREAM_H__
#define __RUDP_STREAM_H__

#include "ikcp.h"
#include "rudp.h"
#include <event2/event.h>

typedef void (*on_can_send_t)(void *rudp_stream, int can_send, void *user_data);

typedef struct
{
    int stream_id;
    int can_send;
    struct event *ev_timer_update;
    long first_ts;
    ikcpcb *kcp;

    on_can_send_t on_can_send;
    void *user_data;
} rudp_stream_t;

rudp_stream_t *rudp_stream_create(unsigned int stream_id, struct event_base *ev_base);

void rudp_stream_destory(rudp_stream_t *rudp_stream);

//-----向流里面塞数据，准备向网络发出数据
int rudp_stream_send(rudp_stream_t *rudp_stream, const char *data, int len);

//-----从网络里面接受数据，准备塞给流处理
int rudp_stream_input(rudp_stream_t *rudp_stream, const char *data, int len);

//-----上层获取 把流处理完来至网络的数据
int rudp_stream_recv(rudp_stream_t *rudp_stream, char *buffer, int len);

int rudp_stream_peeksize(rudp_stream_t *rudp_stream);

void rudp_stream_update_snd_wnd(rudp_stream_t *rudp_stream, unsigned int snd_wnd);

void rudp_stream_set_resend_limited(rudp_stream_t *rudp_stream, unsigned int resend_limited);

void rudp_stream_set_recv_out_of_order(rudp_stream_t *rudp_stream, unsigned int recv_out_of_order);

#endif