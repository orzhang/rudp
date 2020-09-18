#include "rudp_stream.h"
#include "ikcp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef WIN32
#include <time.h>
#include <unistd.h>
#endif

int get_stream_ts(rudp_stream_t *rudp_stream)
{
    if (!rudp_stream)
        return 0;
    long timestamp = 0;
#ifdef WIN32
    timestamp = GetTickCount();
#else
    struct timespec tv;
    clock_gettime(CLOCK_MONOTONIC, &tv);
    timestamp = ((int64_t)tv.tv_sec) * 1000 + (int64_t)tv.tv_nsec / 1000000;
#endif

    if (rudp_stream->first_ts == 0)
        rudp_stream->first_ts = timestamp;
    return timestamp - rudp_stream->first_ts;
}

void rudp_stream_is_block(rudp_stream_t *rudp_stream)
{
    if (!rudp_stream || !rudp_stream->kcp)
        return;

    int is_block = 0;

    //printf("nsnd_que=%d,nsnd_buf=%d\n",rudp_stream->kcp->nsnd_que,rudp_stream->kcp->nsnd_buf,rudp_stream->kcp->snd_wnd);
    if (rudp_stream->kcp->nsnd_buf + rudp_stream->kcp->nsnd_que > rudp_stream->kcp->snd_wnd)
        is_block = 1;

    if (rudp_stream->can_send == 0 && is_block == 0)
    {
        //can send
        //printf("rudp_stream->can_send = 1\n");
        rudp_stream->can_send = 1;
        if (rudp_stream->on_can_send)
            rudp_stream->on_can_send(rudp_stream, 1, rudp_stream->user_data);
    }
    else if (rudp_stream->can_send == 1 && is_block == 1)
    {
        //can not send
        //printf("rudp_stream->can_send = 0\n");
        rudp_stream->can_send = 0;
        if (rudp_stream->on_can_send)
            rudp_stream->on_can_send(rudp_stream, 0, rudp_stream->user_data);
    }
}

void on_update_timer(evutil_socket_t fd, short events, void *arg)
{
    if (!arg)
        return;
    rudp_stream_t *rudp_stream = (rudp_stream_t *)arg;
    if (!rudp_stream->kcp)
        return;

    int current = get_stream_ts(rudp_stream);
    ikcp_update(rudp_stream->kcp, current);

    rudp_stream_is_block(rudp_stream);
}

void rudp_stream_update_snd_wnd(rudp_stream_t *rudp_stream, unsigned int snd_wnd)
{
    if (!rudp_stream)
        return;

    unsigned int stream_id = rudp_stream->stream_id;
    unsigned int snd_wnd_set = snd_wnd;

    if (stream_id == 1 || stream_id == 2 || stream_id == 5)
    {
        if (snd_wnd_set < 64)
            snd_wnd_set = 64;
        if (snd_wnd_set > 1024)
            snd_wnd_set = 1024;
        ikcp_wndsize(rudp_stream->kcp, snd_wnd_set, 1024); //set
        //ikcp_wndsize(rudp_stream->kcp, 128, 1024);//min
        //ikcp_wndsize(rudp_stream->kcp, 1024, 1024);//max
    }
    else if (stream_id == 3 || stream_id == 4) //data tcp udp
    {
        if (snd_wnd_set < 64)
            snd_wnd_set = 64;
        if (snd_wnd_set > 4096)
            snd_wnd_set = 4096;
        ikcp_wndsize(rudp_stream->kcp, snd_wnd_set, 4096); //set
        //ikcp_wndsize(rudp_stream->kcp, 512, 4096);//min
        //ikcp_wndsize(rudp_stream->kcp, 4096, 4096);//max
        rudp_stream->kcp->fastresend = snd_wnd_set / 100;
    }

    rudp_stream_is_block(rudp_stream);
}

void rudp_stream_set_resend_limited(rudp_stream_t *rudp_stream, unsigned int resend_limited)
{
    if (!rudp_stream)
        return;

    unsigned int stream_id = rudp_stream->stream_id;
    if (stream_id == 4 || stream_id == 5 || stream_id == 7) //udp and icmp
        ikcp_resend_limited(rudp_stream->kcp, resend_limited);
}

void rudp_stream_set_recv_out_of_order(rudp_stream_t *rudp_stream, unsigned int recv_out_of_order)
{
    if (!rudp_stream)
        return;

    unsigned int stream_id = rudp_stream->stream_id;
    if (stream_id == 2 || stream_id == 3 || stream_id == 4 || stream_id == 5 || stream_id == 6 || stream_id == 7) //tcp udp  icmp
        ikcp_recv_out_of_order(rudp_stream->kcp, recv_out_of_order);
}

rudp_stream_t *rudp_stream_create(unsigned int stream_id, struct event_base *ev_base)
{
    if (!ev_base || !stream_id)
        return NULL;
    rudp_stream_t *rudp_stream = (rudp_stream_t *)rudp_malloc(sizeof(rudp_stream_t));
    if (!rudp_stream)
        return NULL;
    memset(rudp_stream, 0, sizeof(rudp_stream_t));
    rudp_stream->stream_id = stream_id;
    rudp_stream->can_send = 1;
    rudp_stream->first_ts = 0;

    rudp_stream->kcp = ikcp_create(stream_id, NULL);
    if (!rudp_stream->kcp)
    {
        rudp_free(rudp_stream);
        return NULL;
    }

    rudp_stream->ev_timer_update = event_new(ev_base, -1, EV_TIMEOUT | EV_PERSIST, on_update_timer, rudp_stream);
    if (!rudp_stream->ev_timer_update)
    {
        ikcp_release(rudp_stream->kcp);
        rudp_free(rudp_stream);
        return NULL;
    }

    int interval = 0;
    if (stream_id == 1) //data cmd
    {
        interval = 10;
        ikcp_nodelay(rudp_stream->kcp, 1, 10, 2, 1);
        ikcp_wndsize(rudp_stream->kcp, 256, 1024); //init
        //ikcp_wndsize(rudp_stream->kcp, 128, 1024);//min
        //ikcp_wndsize(rudp_stream->kcp, 1024, 1024);//max
    }
    else if (stream_id == 2) //data nodely
    {
        interval = 15;
        ikcp_nodelay(rudp_stream->kcp, 1, 15, 3, 1);
        ikcp_wndsize(rudp_stream->kcp, 256, 1024); //init
        //ikcp_wndsize(rudp_stream->kcp, 128, 1024);//min
        //ikcp_wndsize(rudp_stream->kcp, 1024, 1024);//max
    }
    else if (stream_id == 3) //data tcp Reattime or Interactive
    {
        interval = 20;
        ikcp_nodelay(rudp_stream->kcp, 0, 20, 40, 1);
        ikcp_wndsize(rudp_stream->kcp, 1024, 4096); //init
        //ikcp_wndsize(rudp_stream->kcp, 512, 4096);//min
        //ikcp_wndsize(rudp_stream->kcp, 4096, 4096);//max

        //ikcp_recv_out_of_order(rudp_stream->kcp, 1);
    }
    else if (stream_id == 4) //data udp Reattime or Interactive
    {
        interval = 20;
        ikcp_nodelay(rudp_stream->kcp, 1, 20, 40, 1);
        ikcp_wndsize(rudp_stream->kcp, 1024, 4096); //init
        ///ikcp_wndsize(rudp_stream->kcp, 512, 4096);//min
        //ikcp_wndsize(rudp_stream->kcp, 4096, 4096);//max

        //ikcp_resend_limited(rudp_stream->kcp,1);
        //ikcp_recv_out_of_order(rudp_stream->kcp, 1);
    }
    else if (stream_id == 5) //data icmp ping
    {
        interval = 10;
        ikcp_nodelay(rudp_stream->kcp, 1, 10, 2, 1);
        ikcp_wndsize(rudp_stream->kcp, 256, 1024); //init
        //ikcp_wndsize(rudp_stream->kcp, 128, 1024);//min
        //ikcp_wndsize(rudp_stream->kcp, 1024, 1024);//max

        //ikcp_resend_limited(rudp_stream->kcp,1);
        //ikcp_recv_out_of_order(rudp_stream->kcp, 1);
    }
    else if (stream_id == 6) //data tcp Bandwidth or Other
    {
        interval = 20;
        ikcp_nodelay(rudp_stream->kcp, 0, interval, 0, 1);
        ikcp_wndsize(rudp_stream->kcp, 4096, 4096);
    }
    else if (stream_id == 7) //data udp Bandwidth or Other
    {
        interval = 20;
        ikcp_nodelay(rudp_stream->kcp, 0, interval, 0, 1);
        ikcp_wndsize(rudp_stream->kcp, 4096, 4096);
    }

    if (interval > 0)
    {
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = interval * 1000;
        event_add(rudp_stream->ev_timer_update, &tv);
    }

    return rudp_stream;
}

void rudp_stream_destory(rudp_stream_t *rudp_stream)
{
    if (!rudp_stream)
        return;

    if (rudp_stream->ev_timer_update)
    {
        event_free(rudp_stream->ev_timer_update);
        rudp_stream->ev_timer_update = NULL;
    }
    if (rudp_stream->kcp)
    {
        ikcp_flush(rudp_stream->kcp);
        ikcp_release(rudp_stream->kcp);
        rudp_stream->kcp = NULL;
    }
    rudp_free(rudp_stream);
    rudp_stream = NULL;
}

/*****-----向流里面塞数据，准备向网络发出数据********/
int rudp_stream_send(rudp_stream_t *rudp_stream, const char *data, int len)
{
    if (!rudp_stream || !rudp_stream->kcp || !data || len <= 0)
        return -3;
    rudp_stream_is_block(rudp_stream);

    int current = get_stream_ts(rudp_stream);
    ikcp_update(rudp_stream->kcp, current);

    int ret = ikcp_send(rudp_stream->kcp, data, len);
    ikcp_flush(rudp_stream->kcp);
    return ret;
}

/********-----从网络里面接受数据，准备塞给流处理*******/
int rudp_stream_input(rudp_stream_t *rudp_stream, const char *data, int len)
{
    if (!rudp_stream || !rudp_stream->kcp || !data || len <= 0)
        return -3;

    int current = get_stream_ts(rudp_stream);
    unsigned int stream_id = rudp_stream->stream_id;
    int ackNoDelay = 0;

    if (stream_id == 1 || stream_id == 2 || stream_id == 5)
    {
        //ikcp_flush(rudp_stream->kcp);
        ackNoDelay = 1;
    }

    return ikcp_input(rudp_stream->kcp, data, len, current, ackNoDelay);
}

//-----上层获取 把流处理完来至网络的数据
int rudp_stream_recv(rudp_stream_t *rudp_stream, char *buffer, int len)
{
    if (!rudp_stream || !rudp_stream->kcp || !buffer || len <= 0)
        return -4;
    return ikcp_recv(rudp_stream->kcp, buffer, len);
}

int rudp_stream_peeksize(rudp_stream_t *rudp_stream)
{
    if (!rudp_stream || !rudp_stream->kcp)
        return -4;
    return ikcp_peeksize(rudp_stream->kcp);
}
