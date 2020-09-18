#include "rudp.h"
#include "rudp_connect.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifndef WIN32
#include <unistd.h>
//#include <endian.h>
#endif

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

/*
**数据发送的协议：协议头(1Byte)+FEC头(如果开启FEC)+RUDP头(如果不是RAW UDP)+数据内容
**其中1Byte协议头，第一位代表是否是Cmd，1代表cmd，0代表data；第二位代表是否是RAW UDP，1代表是，0代表否；第三位代表是否开启FEC，1代表开启，0代表关闭；
*/

int rudp_fec_output(rudp_connect_t *rudp_connect, const char *data, int len);
void rudp_set_snd_wnd_multi_stream(rudp_connect_t *rudp_connect, unsigned int snd_wnd);
void rudp_set_mtu_multi_stream(rudp_connect_t *rudp_connect);
int rudp_send_handshake_req(rudp_connect_t *rudp_connect);

int get_conn_ts(rudp_connect_t *rudp_connect)
{
    if (!rudp_connect)
        return 0;
    long timestamp = 0;
#ifdef WIN32
    timestamp = GetTickCount();
#else
    struct timespec tv;
    clock_gettime(CLOCK_MONOTONIC, &tv);
    timestamp = ((int64_t)tv.tv_sec) * 1000 + (int64_t)tv.tv_nsec / 1000000;
#endif

    if (rudp_connect->first_ts == 0)
        rudp_connect->first_ts = timestamp;
    return timestamp - rudp_connect->first_ts;
}

int udp_output_cmd(rudp_connect_t *rudp_connect, const char *buf, int len)
{
    if (!rudp_connect || !buf || len <= 0)
        return -1;

#ifdef WIN32
    if (len > 2000)
        return -2;
    char buffer[2048] = {0};
    buffer[0] |= 0x80;
    int head_len = 1;
    memcpy(buffer + head_len, buf, len);
    send(rudp_connect->sock, buffer, head_len + len, 0);
#else
    unsigned char head[RUDP_PROTOCOL_HEAD_LEN] = {0};
    head[0] |= 0x80;

    struct msghdr msg;
    struct iovec io[2];

    memset(&msg, 0, sizeof(struct msghdr));
    io[0].iov_base = head;
    io[0].iov_len = sizeof(head);
    io[1].iov_base = (void *)buf;
    io[1].iov_len = len;
    msg.msg_iov = io;
    msg.msg_iovlen = 2;

    sendmsg(rudp_connect->sock, &msg, 0);
#endif

    rudp_connect->send_bytes_local += len;
    rudp_connect->send_packages_local++;
    rudp_connect->pacing_send_bytes += len;

    return 0;
}

int udp_output_data(rudp_connect_t *rudp_connect, const char *buf, int len, int is_fec, int is_unreliable)
{
    if (!rudp_connect || !buf || len <= 0)
        return -1;

#ifdef WIN32
    if (len > 2000)
        return -2;
    char buffer[2048] = {0};
    if (is_unreliable)
        buffer[0] |= 0x40;
    if (is_fec)
        buffer[0] |= 0x20;
    int head_len = 1;
    memcpy(buffer + head_len, buf, len);
    send(rudp_connect->sock, buffer, head_len + len, 0);
#else
    unsigned char head[RUDP_PROTOCOL_HEAD_LEN] = {0};
    if (is_unreliable)
        head[0] |= 0x40;
    if (is_fec)
        head[0] |= 0x20;

    struct msghdr msg;
    struct iovec io[2];

    memset(&msg, 0, sizeof(struct msghdr));
    io[0].iov_base = head;
    io[0].iov_len = sizeof(head);
    io[1].iov_base = (void *)buf;
    io[1].iov_len = len;
    msg.msg_iov = io;
    msg.msg_iovlen = 2;

    sendmsg(rudp_connect->sock, &msg, 0);
#endif
    rudp_connect->send_bytes_local += len;
    rudp_connect->send_packages_local++;
    rudp_connect->pacing_send_bytes += len;

    return 0;
}

int udp_output_nodely_i(const char *buf, int len, ikcpcb *kcp, void *user)
{
    if (!kcp || !user || !buf || len <= 0)
        return -1;
    rudp_connect_t *rudp_connect = (rudp_connect_t *)user;

    int ret = -5;

    rudp_connect->fec_in_use = 1;
    if (!rudp_connect->fec_on || kcp->conv == 3 || kcp->conv == 6 || kcp->conv == 7)
        rudp_connect->fec_in_use = 0;

    if (rudp_connect->fec_in_use)
        ret = rudp_fec_output(rudp_connect, buf, len);
    if (rudp_connect->fec_in_use && ret < 0)
        rudp_connect->fec_in_use = 0;
    if (ret < 0)
        ret = udp_output_data(rudp_connect, buf, len, 0, 0);
    return ret;
}

int udp_output_nodely(const char *buf, int len, ikcpcb *kcp, void *user)
{
    if (!kcp || !user || !buf || len <= 0)
        return -1;

    int ret = 0;
    ret = udp_output_nodely_i(buf, len, kcp, user);
    if (ret < 0)
        return ret;

    rudp_connect_t *rudp_connect = (rudp_connect_t *)user;
    int multiple = 1;
    if (kcp->conv == 5 && rudp_connect->send_package_multiple > 0)
    { //icmp double send
        multiple = 2;
    }
    if (rudp_connect->send_package_multiple > 1)
    { //all data double send
        multiple = rudp_connect->send_package_multiple;
    }

    if (multiple > 1)
    {
        //printf("----udp_output_nodely---kcp=%d,send_package_multiple=%d\n",kcp->conv,rudp_connect->send_package_multiple);
        int i = 1;
        for (i = 1; i < multiple; i++)
        {
            ret = udp_output_nodely_i(buf, len, kcp, user);
            if (ret < 0)
                return ret;
        }
    }
    return ret;
}

int is_over_rate(rudp_connect_t *rudp_connect)
{
    if (!rudp_connect)
        return 0;
    if (rudp_connect->pacing_on && rudp_connect->pacing_rate)
    {
        long current_ts = get_conn_ts(rudp_connect);

        if (rudp_connect->last_pacing_ts > 0 && rudp_connect->pacing_send_bytes && current_ts > rudp_connect->last_pacing_ts)
        {
            long diff = current_ts - rudp_connect->last_pacing_ts;
            unsigned long cur_pacing_rate = rudp_connect->pacing_send_bytes * 8 * 1000 / diff;

            if (cur_pacing_rate > rudp_connect->pacing_rate)
            {
                rudp_connect->last_over_rate_ts = current_ts;
                //pause send
                //todo freeze a bit of time
                //printf("debug ---diff=%ld--cur_pacing_rate=%ld--rudp_connect->pacing_set_rate=%ld-\n",diff,cur_pacing_rate,rudp_connect->pacing_set_rate);
                return 1;
            }
        }
    }
    return 0;
}

void udp_output_multi(rudp_connect_t *rudp_connect)
{
    if (!rudp_connect)
        return;
    pacing_data *seg = NULL;
    int is_over = 0;
    while (!iqueue_is_empty(&rudp_connect->pacing_data_queue))
    {
        seg = iqueue_entry(rudp_connect->pacing_data_queue.next, pacing_data, node);
        if (!seg)
            continue;

        int ret = -5;

        rudp_connect->fec_in_use = 1;
        if (!rudp_connect->fec_on || seg->stream_id == 3)
            rudp_connect->fec_in_use = 0;

        if (rudp_connect->fec_in_use)
            ret = rudp_fec_output(rudp_connect, seg->data, seg->len);
        if (rudp_connect->fec_in_use && ret < 0)
            rudp_connect->fec_in_use = 0;
        if (ret < 0)
            ret = udp_output_data(rudp_connect, seg->data, seg->len, 0, 0);

        iqueue_del(&seg->node);
        rudp_free(seg->data);
        rudp_free(seg);

        is_over = is_over_rate(rudp_connect);
        if (is_over)
            return;
    }
}

void rudp_kcp_input(rudp_connect_t *rudp_connect, const char *data, unsigned int len); //---------申明

void rudp_fec_input(rudp_connect_t *rudp_connect, char *data, int len) //raw udp -> fec -> kcp
{
    if (!rudp_connect || !data || len < fecHeaderSizeTotal)
        return;

    fec_packet_t *fec_pkg = fec_decode(data, len);
    if (!fec_pkg)
        return;

    if (fec_pkg->type == typeData)
        rudp_kcp_input(rudp_connect, fec_pkg->data + fecHeaderSizeShift, fec_pkg->len - fecHeaderSizeShift);

    int new_fec = 0;
    if (!rudp_connect->fec_recv)
    {
        new_fec = 1;
    }
    else
    {
        int dataShards = 0;
        int parityShards = 0;
        int ret = fec_getShards(rudp_connect->fec_recv, &dataShards, &parityShards);
        if (ret < 0 || dataShards <= 0 || parityShards <= 0)
        {
            fec_packet_delete(fec_pkg);
            return;
        }
        if (dataShards != fec_pkg->dataShards || parityShards != fec_pkg->parityShards)
            new_fec = 1;
    }

    if (new_fec)
    {
        if (rudp_connect->fec_recv)
        {
            fec_delete(rudp_connect->fec_recv);
            rudp_connect->fec_recv = NULL;
        }

        long current_ts = get_conn_ts(rudp_connect);

        if (rudp_connect->last_fec_recv_ts > 0 && current_ts < rudp_connect->last_fec_recv_ts + 10 * 1000)
        {
            fec_packet_delete(fec_pkg);
            return;
        }
        rudp_connect->last_fec_recv_ts = current_ts;

        fec_param_t param;
        param.dataShards = fec_pkg->dataShards;
        param.parityShards = fec_pkg->parityShards;
        param.fecExpire = 1000;
        param.rxLimit = 100;
        rudp_connect->fec_recv = fec_new(&param);
    }

    if (!rudp_connect->fec_recv)
    {
        fec_packet_delete(fec_pkg);
        return;
    }

    if (fec_pkg->type == typeData || fec_pkg->type == typeFEC)
    {
        unsigned char *fec_tmp_buffers[RUDP_FEC_TOTAL_BUF];
        unsigned char marks[RUDP_FEC_TOTAL_BUF];
        int dataShards = 0;
        int parityShards = 0;
        int totalShards = 0;
        int ret = fec_getShards(rudp_connect->fec_recv, &dataShards, &parityShards);
        if (ret < 0 || dataShards <= 0 || parityShards <= 0)
        {
            fec_packet_delete(fec_pkg);
            return;
        }
        totalShards = dataShards + parityShards;

        int i = 0;
        for (i = 0; i < totalShards; i++)
        {
            fec_tmp_buffers[i] = rudp_connect->fec_recv_buffers[i];
            marks[i] = 1;
        }

        ret = fec_reconstruct(rudp_connect->fec_recv, fec_pkg, fec_tmp_buffers, marks, totalShards);

        if (ret > 0)
        {
            //printf("---DEBUG rudp_fec_input---:ret=%d.\n",ret);
            int i = 0;
            for (i = 0; i < dataShards; i++)
            {
                if (marks[i])
                {
                    unsigned short sz = 0;
                    fec_decode16u(fec_tmp_buffers[i], &sz);

                    /*
                    unsigned int stream_id = *(int *)(fec_tmp_buffers[i] + 2);
                    #if IWORDS_BIG_ENDIAN
                        stream_id = ntohl(stream_id);
                    #endif

                    printf("---DEBUG rudp_fec_input---:i=%d,sz=%d,stream_id=%d.\n",i,sz,stream_id);
                    */
                    if (sz >= fecHeaderSizeShift && sz < RUDP_UDP_BUFSIZE)
                        rudp_kcp_input(rudp_connect, fec_tmp_buffers[i] + fecHeaderSizeShift, sz - fecHeaderSizeShift);
                }
            }
        }
        else
        {
            if (ret == -1 || ret == -2 || ret == -3 || ret == -4)
                fec_packet_delete(fec_pkg);
        }
    }
    return;
}

int rudp_fec_output(rudp_connect_t *rudp_connect, const char *data, int len) //kcp -> fec -> raw udp
{
    if (!rudp_connect || !data || len <= 0)
        return -1;

    long current_ts = get_conn_ts(rudp_connect);

    int new_fec = 0;
    if (!rudp_connect->fec_send)
    {
        new_fec = 1;
    }
    else
    {
        int dataShards = 0;
        int parityShards = 0;
        int ret = fec_getShards(rudp_connect->fec_send, &dataShards, &parityShards);
        if (ret < 0 || dataShards <= 0 || parityShards <= 0)
        {
            new_fec = 1;
        }
        else
        {
            int redundancy = parityShards * 100 / (dataShards + parityShards);
            if (rudp_connect->lost_local > redundancy || rudp_connect->lost_local < redundancy * 4 / 5)
                new_fec = 1;
            if (new_fec && rudp_connect->last_fec_send_ts > 0 && current_ts < rudp_connect->last_fec_send_ts + 10 * 1000)
                new_fec = 0;
        }
    }

    if (rudp_connect->lost_local < 3)
    {
        return -2;
    }

    if (rudp_connect->rtt < 50)
    {
        return -2;
    }

    if (new_fec)
    {
        if (rudp_connect->fec_send)
        {
            fec_delete(rudp_connect->fec_send);
            rudp_connect->fec_send = NULL;
        }

        int dataShards = 8;
        int parityShards = 1;
        if (rudp_connect->lost_local > 50)
            dataShards = 1;
        else if (rudp_connect->lost_local < 10)
            dataShards = 9;
        else
            dataShards = 100 / rudp_connect->lost_local - 1;

        fec_param_t param;
        param.dataShards = dataShards;
        param.parityShards = parityShards;
        param.fecExpire = 1000;
        param.rxLimit = 100;
        rudp_connect->fec_send = fec_new(&param);

        rudp_connect->last_fec_send_ts = current_ts;
        rudp_connect->fec_buf_index = 0;
        rudp_connect->fec_buf_max_len = 0;
    }

    if (!rudp_connect->fec_send)
        return -3;

    int dataShards = 0;
    int parityShards = 0;
    int totalShards = 0;

    int ret = fec_getShards(rudp_connect->fec_send, &dataShards, &parityShards);
    if (ret < 0 || dataShards <= 0 || parityShards <= 0)
        return -4;
    totalShards = dataShards + parityShards;

    char *fec_buf = rudp_connect->fec_send_buffers[rudp_connect->fec_buf_index];
    memset(fec_buf, 0, RUDP_UDP_BUFSIZE);
    memcpy(fec_buf + fecHeaderSizeTotal, data, len);
    fec_markData(rudp_connect->fec_send, fec_buf, len);
    udp_output_data(rudp_connect, fec_buf, len + fecHeaderSizeTotal, 1, 0);

    if (rudp_connect->fec_buf_max_len < len + 2)
        rudp_connect->fec_buf_max_len = len + 2;

    rudp_connect->fec_buf_index++;

    if (rudp_connect->fec_buf_index == dataShards)
    {
        int i = 0;
        unsigned char *fec_tmp_buffers[RUDP_FEC_TOTAL_BUF] = {0};
        for (i = 0; i < totalShards; i++)
            fec_tmp_buffers[i] = rudp_connect->fec_send_buffers[i] + fecHeaderSize;

        fec_encode(rudp_connect->fec_send, fec_tmp_buffers, totalShards, rudp_connect->fec_buf_max_len);

        for (i = dataShards; i < totalShards; i++)
        {
            char *tmp_buf = rudp_connect->fec_send_buffers[i];
            int tmp_len = rudp_connect->fec_buf_max_len + fecHeaderSize;
            fec_markFEC(rudp_connect->fec_send, tmp_buf);
            udp_output_data(rudp_connect, tmp_buf, tmp_len, 1, 0);
        }

        rudp_connect->fec_buf_max_len = 0;
        rudp_connect->fec_buf_index = 0;
    }
    return 0;
}

int udp_output_pacing_i(const char *buf, int len, ikcpcb *kcp, void *user)
{
    if (!kcp || !user || !buf || len <= 0)
        return -1;

    rudp_connect_t *rudp_connect = (rudp_connect_t *)user;

    if (rudp_connect->pacing_on && rudp_connect->pacing_rate)
    {
        int is_over = is_over_rate(rudp_connect);
        int is_empty = iqueue_is_empty(&rudp_connect->pacing_data_queue);
        if (is_over || !is_empty)
        {
            pacing_data *seg = (pacing_data *)rudp_malloc(sizeof(pacing_data));
            if (!seg)
            {
                //printf("udp_output malloc len=%d,errno=%d.--------\n",len,errno);
                return -3;
            }
            memset(seg, 0, sizeof(pacing_data));
            seg->stream_id = kcp->conv;
            seg->len = len;
            seg->data = (char *)rudp_malloc(len);
            if (!seg->data)
            {
                //printf("udp_output malloc data len=%d,errno=%d.--------\n",len,errno);
                return -4;
            }

            memcpy(seg->data, buf, len);

            iqueue_init(&seg->node);
            iqueue_add_tail(&seg->node, &rudp_connect->pacing_data_queue);

            if (!is_over)
                udp_output_multi(rudp_connect);
            return 0;
        }
    }

    int ret = -5;

    rudp_connect->fec_in_use = 1;
    if (!rudp_connect->fec_on || kcp->conv == 3 || kcp->conv == 6 || kcp->conv == 7)
        rudp_connect->fec_in_use = 0;

    if (rudp_connect->fec_in_use)
        ret = rudp_fec_output(rudp_connect, buf, len);
    if (rudp_connect->fec_in_use && ret < 0)
        rudp_connect->fec_in_use = 0;
    if (ret < 0)
        ret = udp_output_data(rudp_connect, buf, len, 0, 0);
    return ret;
}

int udp_output_pacing(const char *buf, int len, ikcpcb *kcp, void *user)
{
    if (!kcp || !user || !buf || len <= 0)
        return -1;

    int ret = 0;
    ret = udp_output_pacing_i(buf, len, kcp, user);
    if (ret < 0)
        return ret;

    rudp_connect_t *rudp_connect = (rudp_connect_t *)user;
    int multiple = 1;
    if (kcp->conv == 5 && rudp_connect->send_package_multiple > 0)
    { //icmp double send
        multiple = 2;
    }
    if (rudp_connect->send_package_multiple > 1)
    { //all data double send
        multiple = rudp_connect->send_package_multiple;
    }

    if (multiple > 1)
    {
        //printf("----udp_output_pacing---kcp=%d,send_package_multiple=%d,send_package_multiple_all=%d\n",kcp->conv,rudp_connect->send_package_multiple,rudp_connect->send_package_multiple_all);
        int i = 1;
        for (i = 1; i < multiple; i++)
        {
            ret = udp_output_pacing_i(buf, len, kcp, user);
            if (ret < 0)
                return ret;
        }
    }
    return ret;
}

//pacing send
void pacing_send_process(rudp_connect_t *rudp_connect)
{
    if (!rudp_connect)
        return;
    //pacing
    if (rudp_connect && rudp_connect->pacing_on && rudp_connect->pacing_rate)
    {
        int is_over = is_over_rate(rudp_connect);
        int is_empty = iqueue_is_empty(&rudp_connect->pacing_data_queue);
        if (!is_over && !is_empty)
            udp_output_multi(rudp_connect);

        rudp_connect->pacing_send_bytes = 0;
        rudp_connect->last_pacing_ts = get_conn_ts(rudp_connect);
        ;
    }
}

RudpRetCode rudp_connect_send(void *rudp_connect_i, const char *data, unsigned int data_len, RudpDataType data_type, bool is_urgent)
{
    if (!rudp_connect_i || !data || !data_len)
        return RudpRet_ERROR_Param;
    unsigned int stream_id = 0;
    int is_unreliable = 0;
    if (data_type == RudpDataType_Cmd)
        stream_id = 1;
    else if (data_type == RudpDataType_NoDelay)
        stream_id = 2;
    else if (data_type == RudpDataType_Tcp)
        stream_id = 3;
    else if (data_type == RudpDataType_Udp)
        stream_id = 4;
    else if (data_type == RudpDataType_Icmp)
        stream_id = 5;
    else if (data_type == RudpDataType_TCP_BD)
        stream_id = 6;
    else if (data_type == RudpDataType_UDP_BD)
        stream_id = 7;
    else if (data_type == RudpDataType_Unreliable)
        is_unreliable = 1;
    else
    {
        return RudpRet_ERROR_DataType;
    }

    rudp_connect_t *rudp_connect = (rudp_connect_t *)rudp_connect_i;

    if (rudp_connect->status != RudpConnectStatus_OK)
    {
        return RudpRet_ERROR_Closed;
    }

    if (is_unreliable)
    {
        if ((int)data_len > rudp_connect->mtu)
            return RudpRet_ERROR_MoreMTU;
        udp_output_data(rudp_connect, data, data_len, 0, 1);
        return RudpRet_NO_ERROR;
    }

    if (!is_urgent)
    {
        if (rudp_connect->blocked)
            return RudpRet_ERROR_Eagain;

        int can_send = rudp_connect->stream[stream_id]->can_send;
        if (can_send == 0)
            return RudpRet_ERROR_Eagain;
    }

    rudp_connect->last_send_data_ts = get_conn_ts(rudp_connect);

    int ret = rudp_stream_send(rudp_connect->stream[stream_id], data, data_len);
    //int ret = udp_output(data,data_len,NULL,rudp_connect);
    if (ret != 0)
    {
        //printf("rudp_stream_send data fail.\n");
        return RudpRet_SEND_ERROR;
    }
    rudp_connect->send_bytes_app += data_len;
    return RudpRet_NO_ERROR;
}

void on_can_send(void *rudp_stream, int can_send, void *user_data)
{
    if (!rudp_stream || !user_data)
        return;
    rudp_connect_t *rudp_connect = (rudp_connect_t *)user_data;

    int blocked = 0;
    unsigned int i = 1;
    for (i = 1; i < RUDP_STREAM_COUNT; i++)
    {
        int can_send = rudp_connect->stream[i]->can_send;
        if (can_send == 0)
        {
            blocked = 1;
            break;
        }
    }
    if (rudp_connect->blocked == 1 && blocked == 0)
    {
        rudp_connect->blocked = 0;
        if (rudp_connect->on_send && rudp_connect->status == RudpConnectStatus_OK)
            rudp_connect->on_send(rudp_connect, rudp_connect->user_data);
    }
    else if (rudp_connect->blocked == 0 && blocked == 1)
    {
        rudp_connect->blocked = 1;
    }
}

void mtu_probe_recv(rudp_connect_t *rudp_connect, int length)
{
    if (!rudp_connect)
        return;
    long current_ts = get_conn_ts(rudp_connect);
    rudp_connect->last_mtu_probe_ts = current_ts;
    if (length <= rudp_connect->mtu)
        return;
    //printf("mtu_probe_recv length=%d,mtu=%d\n",length,rudp_connect->mtu);
    rudp_connect->mtu = length;
    return;
}

void mtu_probe_send(rudp_connect_t *rudp_connect, int length, int is_request)
{
    if (!rudp_connect || length <= RUDP_PROTOCOL_HEAD_LEN || length > 2048)
        return;
    char send_buffer[2048] = {0};
    int send_len = length;
    rudp_msg_head_t *head_send = (rudp_msg_head_t *)(send_buffer);

    if (is_request)
        head_send->type = htons(RudpMsgType_mtu_request);
    else
        head_send->type = htons(RudpMsgType_mtu_response);
    head_send->len = htons(send_len);

#ifdef WIN32
    socklen_t optlen = sizeof(int);
    int val_old = 0;
    int val_new = 1;
    getsockopt(rudp_connect->sock, IPPROTO_IP, IP_DONTFRAGMENT, &val_old, &optlen);
    setsockopt(rudp_connect->sock, IPPROTO_IP, IP_DONTFRAGMENT, &val_new, sizeof(val_new));
    udp_output_cmd(rudp_connect, send_buffer, send_len);
    setsockopt(rudp_connect->sock, IPPROTO_IP, IP_DONTFRAGMENT, &val_old, sizeof(val_old));

#else
    socklen_t optlen = sizeof(int);
    int val_old = 0;
    int val_new = IP_PMTUDISC_DO;
    IP_HDRINCL
    getsockopt(rudp_connect->sock, IPPROTO_IP, IP_MTU_DISCOVER, &val_old, &optlen);
    setsockopt(rudp_connect->sock, IPPROTO_IP, IP_MTU_DISCOVER, &val_new, sizeof(val_new));
    udp_output_cmd(rudp_connect, send_buffer, send_len);
    setsockopt(rudp_connect->sock, IPPROTO_IP, IP_MTU_DISCOVER, &val_old, sizeof(val_old));
#endif
}

void mtu_probe_send_multi(rudp_connect_t *rudp_connect, int mtu_begin, int mtu_end, int mtu_step)
{
    if (!rudp_connect || mtu_step <= 0 || mtu_step > 10 || mtu_begin <= 0 || mtu_end <= 0 || mtu_begin >= mtu_end)
        return;
    int mtu = 0;
    int flag = 0;
    for (mtu = mtu_end; mtu >= mtu_begin; mtu -= mtu_step)
    {
        mtu_probe_send(rudp_connect, mtu - RUDP_PROTOCOL_HEAD_LEN, 1);
        if (mtu == mtu_begin)
            flag = 1;
    }
    if (flag == 0)
        mtu_probe_send(rudp_connect, mtu_begin - RUDP_PROTOCOL_HEAD_LEN, 1);
}

void mtu_probe_process(rudp_connect_t *rudp_connect)
{
    if (!rudp_connect)
        return;
    if (!rudp_connect->mtu_probe_on)
        return;

    long current_ts = get_conn_ts(rudp_connect);

    if (rudp_connect->last_mtu_probe_ts <= 0)
        rudp_connect->last_mtu_probe_ts = current_ts;
    if (current_ts < rudp_connect->last_mtu_probe_ts + 2000)
        return;
    rudp_connect->last_mtu_probe_ts = current_ts;

    int mtu_begin = rudp_connect->mtu;
    int mtu_step = 0;
    int mtu_end = 0;

    if (rudp_connect->mtu_step >= 15)
    {
        //printf("mtu_probe_process mtu_step=%d,mtu=%d\n",rudp_connect->mtu_step,rudp_connect->mtu);
        rudp_connect->mtu_step = 1;
        mtu_step = 10;
        mtu_end = mtu_begin + mtu_step * 15;
        mtu_probe_send_multi(rudp_connect, mtu_begin, mtu_end, mtu_step);
    }
    else if (rudp_connect->mtu_step == 1)
    {
        //printf("mtu_probe_process mtu_step=%d,mtu=%d\n",rudp_connect->mtu_step,rudp_connect->mtu);
        rudp_connect->mtu_step = 0;
        mtu_step = 1;
        mtu_end = mtu_begin + mtu_step * 10;
        mtu_probe_send_multi(rudp_connect, mtu_begin, mtu_end, mtu_step);
    }
    else if (rudp_connect->mtu_step == 0)
    {
        //printf("mtu_probe_process mtu_step=%d,mtu=%d\n",rudp_connect->mtu_step,rudp_connect->mtu);
        rudp_connect->mtu_step = -1;
        mtu_step = 1;
        mtu_end = mtu_begin + mtu_step * 10;
        mtu_probe_send_multi(rudp_connect, mtu_begin, mtu_end, mtu_step);
    }
    else
    {
        //printf("mtu_probe_process mtu_step=%d,mtu=%d\n",rudp_connect->mtu_step,rudp_connect->mtu);
        rudp_connect->mtu_probe_on = 0;
        rudp_set_mtu_multi_stream(rudp_connect);
    }
}

void statistics_bandwidth_process(rudp_connect_t *rudp_connect)
{
    if (!rudp_connect)
        return;

    long current_ts = get_conn_ts(rudp_connect);

    if (rudp_connect->last_statistics_ts <= 0)
        rudp_connect->last_statistics_ts = current_ts;
    if (current_ts < rudp_connect->last_statistics_ts + 1000)
        return;

    /**************lost**********************************/

    rudp_connect->packages_array_index = rudp_connect->packages_array_index % 10;
    rudp_connect->send_packages_local_array[rudp_connect->packages_array_index] = 0;
    rudp_connect->recv_packages_local_array[rudp_connect->packages_array_index] = 0;
    rudp_connect->send_packages_remote_array[rudp_connect->packages_array_index] = 0;
    rudp_connect->recv_packages_remote_array[rudp_connect->packages_array_index] = 0;

    if (rudp_connect->send_packages_local > rudp_connect->send_packages_local_last)
        rudp_connect->send_packages_local_array[rudp_connect->packages_array_index] = rudp_connect->send_packages_local - rudp_connect->send_packages_local_last;
    if (rudp_connect->recv_packages_local > rudp_connect->recv_packages_local_last)
        rudp_connect->recv_packages_local_array[rudp_connect->packages_array_index] = rudp_connect->recv_packages_local - rudp_connect->recv_packages_local_last;
    if (rudp_connect->send_packages_remote > rudp_connect->send_packages_remote_last)
        rudp_connect->send_packages_remote_array[rudp_connect->packages_array_index] = rudp_connect->send_packages_remote - rudp_connect->send_packages_remote_last;
    if (rudp_connect->recv_packages_remote > rudp_connect->recv_packages_remote_last)
        rudp_connect->recv_packages_remote_array[rudp_connect->packages_array_index] = rudp_connect->recv_packages_remote - rudp_connect->recv_packages_remote_last;

    rudp_connect->packages_array_index++;
    rudp_connect->send_packages_local_last = rudp_connect->send_packages_local;
    rudp_connect->recv_packages_local_last = rudp_connect->recv_packages_local;
    rudp_connect->send_packages_remote_last = rudp_connect->send_packages_remote;
    rudp_connect->recv_packages_remote_last = rudp_connect->recv_packages_remote;

    int i = 0;
    unsigned long send_packages_local_count = 0;
    unsigned long recv_packages_local_count = 0;
    unsigned long send_packages_remote_count = 0;
    unsigned long recv_packages_remote_count = 0;
    for (i = 0; i < 10; i++)
    {
        send_packages_local_count += rudp_connect->send_packages_local_array[i];
        recv_packages_local_count += rudp_connect->recv_packages_local_array[i];
        send_packages_remote_count += rudp_connect->send_packages_remote_array[i];
        recv_packages_remote_count += rudp_connect->recv_packages_remote_array[i];
    }

    int lost_local = 0;
    int lost_remote = 0;
    if (send_packages_local_count > recv_packages_remote_count)
        lost_local = 100 * (send_packages_local_count - recv_packages_remote_count) / send_packages_local_count;
    if (send_packages_remote_count > recv_packages_local_count)
        lost_remote = 100 * (send_packages_remote_count - recv_packages_local_count) / send_packages_remote_count;

    rudp_connect->lost_local = lost_local;
    rudp_connect->lost_remote = lost_remote;
    if (rudp_connect->lost_local >= 100)
        rudp_connect->lost_local = 99;
    if (rudp_connect->lost_remote >= 100)
        rudp_connect->lost_remote = 99;

    if (rudp_connect->send_bandwidth_local <= 2 * 1024 * 1024)
        rudp_connect->lost_network_local = (rudp_connect->lost_network_local + rudp_connect->lost_local * 3) / 4;
    if (rudp_connect->lost_network_local > rudp_connect->lost_local)
        rudp_connect->lost_network_local = rudp_connect->lost_local;

    if (rudp_connect->send_bandwidth_remote <= 2 * 1024 * 1024)
        rudp_connect->lost_network_remote = (rudp_connect->lost_network_remote + rudp_connect->lost_remote * 3) / 4;
    if (rudp_connect->lost_network_remote > rudp_connect->lost_remote)
        rudp_connect->lost_network_remote = rudp_connect->lost_remote;

    /**************lost**********************************/

    unsigned long send_bandwidth_local_last = rudp_connect->send_bandwidth_local;

    int diff = current_ts - rudp_connect->last_statistics_ts; //ms
    if (current_ts <= rudp_connect->last_statistics_ts)
    {
        rudp_connect->last_statistics_ts = get_conn_ts(rudp_connect);
        return;
    }

    rudp_connect->send_bandwidth_app = 0;
    rudp_connect->recv_bandwidth_app = 0;
    rudp_connect->send_bandwidth_local = 0;
    rudp_connect->recv_bandwidth_local = 0;
    rudp_connect->send_bandwidth_remote = 0;
    rudp_connect->recv_bandwidth_remote = 0;
    if (rudp_connect->send_bytes_app > rudp_connect->send_bytes_app_last)
        rudp_connect->send_bandwidth_app = (rudp_connect->send_bytes_app - rudp_connect->send_bytes_app_last) / diff * (1000 * 8); //bps
    if (rudp_connect->recv_bytes_app > rudp_connect->recv_bytes_app_last)
        rudp_connect->recv_bandwidth_app = (rudp_connect->recv_bytes_app - rudp_connect->recv_bytes_app_last) / diff * (1000 * 8); //bps
    if (rudp_connect->send_bytes_local > rudp_connect->send_bytes_local_last)
        rudp_connect->send_bandwidth_local = (rudp_connect->send_bytes_local - rudp_connect->send_bytes_local_last) / diff * (1000 * 8); //bps
    if (rudp_connect->recv_bytes_local > rudp_connect->recv_bytes_local_last)
        rudp_connect->recv_bandwidth_local = (rudp_connect->recv_bytes_local - rudp_connect->recv_bytes_local_last) / diff * (1000 * 8); //bps
    if (rudp_connect->send_bytes_remote > rudp_connect->send_bytes_remote_last)
        rudp_connect->send_bandwidth_remote = (rudp_connect->send_bytes_remote - rudp_connect->send_bytes_remote_last) / diff * (1000 * 8); //bps
    if (rudp_connect->recv_bytes_remote > rudp_connect->recv_bytes_remote_last)
        rudp_connect->recv_bandwidth_remote = (rudp_connect->recv_bytes_remote - rudp_connect->recv_bytes_remote_last) / diff * (1000 * 8); //bps

    rudp_connect->send_bytes_app_last = rudp_connect->send_bytes_app;
    rudp_connect->recv_bytes_app_last = rudp_connect->recv_bytes_app;
    rudp_connect->send_bytes_local_last = rudp_connect->send_bytes_local;
    rudp_connect->recv_bytes_local_last = rudp_connect->recv_bytes_local;
    rudp_connect->send_bytes_remote_last = rudp_connect->send_bytes_remote;
    rudp_connect->recv_bytes_remote_last = rudp_connect->recv_bytes_remote;

    rudp_connect->last_statistics_ts = current_ts;

    if (rudp_connect->recv_bandwidth_remote > rudp_connect->recv_bandwidth_remote_max || current_ts > rudp_connect->recv_bandwidth_remote_max_ts + 10000)
    {
        rudp_connect->recv_bandwidth_remote_max = rudp_connect->recv_bandwidth_remote;
        rudp_connect->recv_bandwidth_remote_max_ts = current_ts;
    }

#if 0
    if(rudp_connect->pacing_on && rudp_connect->pacing_rate && rudp_connect->recv_bandwidth_remote && rudp_connect->send_bandwidth_local)
    {
        float ratio = 1.0*rudp_connect->send_bandwidth_local/rudp_connect->recv_bandwidth_remote;
        if(ratio > 1.2*100/(100-rudp_connect->lost_network_local))
        {
            rudp_connect->decrease_count++;
            if(rudp_connect->decrease_count > 5)
            {
                rudp_connect->pacing_rate /= ratio;
                rudp_connect->decrease_count = 0;
            }
        }
        else
        {
            rudp_connect->decrease_count = 0;
            //rudp_connect->pacing_rate *= 2;

            if(rudp_connect->send_bandwidth_local > send_bandwidth_local_last && current_ts < rudp_connect->last_over_rate_ts + 3000)
            {
                rudp_connect->pacing_rate *= 2;
                if(rudp_connect->pacing_rate > rudp_connect->recv_bandwidth_remote*2)
                    rudp_connect->pacing_rate = rudp_connect->recv_bandwidth_remote * 2;
            }
        }

        if(rudp_connect->pacing_rate < rudp_connect->recv_bandwidth_remote)
            rudp_connect->pacing_rate = rudp_connect->recv_bandwidth_remote;

        if(rudp_connect->pacing_rate < RUDP_PACING_RATE_MIN)
            rudp_connect->pacing_rate = RUDP_PACING_RATE_MIN;
        //if(rudp_connect->pacing_rate > RUDP_PACING_RATE_MAX)
        //    rudp_connect->pacing_rate = RUDP_PACING_RATE_MAX;
    }
#else
    if (rudp_connect->pacing_on && rudp_connect->recv_bandwidth_remote)
    {
        rudp_connect->pacing_rate = 2 * rudp_connect->recv_bandwidth_remote;
        //rudp_connect->pacing_rate = rudp_connect->recv_bandwidth_remote_max;

        if (rudp_connect->pacing_rate < RUDP_PACING_RATE_MIN)
            rudp_connect->pacing_rate = RUDP_PACING_RATE_MIN;
    }
#endif

    if (rudp_connect->recv_bandwidth_remote_max && rudp_connect->mtu && rudp_connect->rtt >= 0 && rudp_connect->rtt_min >= 0)
    {
        if (rudp_connect->rtt <= 50)
        {
            int cur_rtt = rudp_connect->rtt;
            if (rudp_connect->rtt <= 25)
                cur_rtt += 25;
            else if (rudp_connect->rtt <= 50)
                cur_rtt += 15;
            else
                cur_rtt += 5;

            rudp_connect->send_wnd = (rudp_connect->recv_bandwidth_remote_max * (cur_rtt)) / 1000 / 8 / rudp_connect->mtu;

            if ((rudp_connect->lost_network_local > 0 && rudp_connect->lost_local / rudp_connect->lost_network_local >= 3) || (rudp_connect->lost_network_local == 0 && rudp_connect->lost_local >= 3))
                rudp_connect->send_wnd *= 1;
            else
                rudp_connect->send_wnd *= 2;
        }
        else
        {
            rudp_connect->send_wnd = (rudp_connect->recv_bandwidth_remote_max * (rudp_connect->rtt_min)) / 1000 / 8 / rudp_connect->mtu;

            if ((rudp_connect->lost_network_local > 0 && rudp_connect->lost_local / rudp_connect->lost_network_local >= 3) || (rudp_connect->lost_network_local == 0 && rudp_connect->lost_local >= 5))
                rudp_connect->send_cycle = 0;

            if (rudp_connect->send_cycle >= 5)
            {
                rudp_connect->send_wnd *= 2;
                rudp_connect->send_cycle = 0;
            }
            rudp_connect->send_cycle++;
        }

        rudp_set_snd_wnd_multi_stream(rudp_connect, rudp_connect->send_wnd);
    }
}

void send_ping_process(rudp_connect_t *rudp_connect)
{
    if (!rudp_connect)
        return;

    long current_ts = get_conn_ts(rudp_connect);

    if (rudp_connect->is_lte_path)
    {
        rudp_connect->ping_interval = 2000;
        if (rudp_connect->last_send_data_ts > 0 && current_ts <= rudp_connect->last_send_data_ts + 2000)
            rudp_connect->ping_interval = 600;
    }
    else
    {
        rudp_connect->ping_interval = 1000;
        if (rudp_connect->last_send_data_ts > 0 && current_ts <= rudp_connect->last_send_data_ts + 2000)
            rudp_connect->ping_interval = 300;
    }

    if (rudp_connect->last_ping_ts <= 0)
        rudp_connect->last_ping_ts = current_ts;
    if (current_ts >= rudp_connect->last_ping_ts + rudp_connect->ping_interval)
    {
        int cur_ts = get_conn_ts(rudp_connect);

        char send_buffer[1024] = {0};
        int send_len = sizeof(rudp_msg_head_t) + sizeof(rudp_msg_body_ping_t);
        rudp_msg_head_t *head_send = (rudp_msg_head_t *)(send_buffer);
        rudp_msg_body_ping_t *body_send = (rudp_msg_body_ping_t *)head_send->data;
        head_send->type = htons(RudpMsgType_ping);
        head_send->len = htons(send_len);
        body_send->ts = htonl(cur_ts);
        body_send->send_bytes_h = htonl(rudp_connect->send_bytes_local / MAX_UINT32);
        body_send->send_bytes_l = htonl(rudp_connect->send_bytes_local % MAX_UINT32);
        body_send->recv_bytes_h = htonl(rudp_connect->recv_bytes_local / MAX_UINT32);
        body_send->recv_bytes_l = htonl(rudp_connect->recv_bytes_local % MAX_UINT32);
        body_send->send_packages_h = htonl(rudp_connect->send_packages_local / MAX_UINT32);
        body_send->send_packages_l = htonl(rudp_connect->send_packages_local % MAX_UINT32);
        body_send->recv_packages_h = htonl(rudp_connect->recv_packages_local / MAX_UINT32);
        body_send->recv_packages_l = htonl(rudp_connect->recv_packages_local % MAX_UINT32);
        udp_output_cmd(rudp_connect, send_buffer, send_len);
        rudp_connect->last_ping_ts = current_ts;
    }
}

void on_timer(evutil_socket_t fd, short events, void *arg)
{
    if (!arg)
        return;
    rudp_connect_t *rudp_connect = (rudp_connect_t *)arg;

    long current_ts = get_conn_ts(rudp_connect);

    if (rudp_connect->status == RudpConnectStatus_Handshake)
    {
        long diff1 = current_ts - rudp_connect->handshake_ts;
        long diff2 = current_ts - rudp_connect->handshake_first_ts;
        if (rudp_connect->handshake_first_ts >= 0 && diff2 > 3 * 1000)
        {
            rudp_connect->handshake_first_ts = current_ts;
            if (rudp_connect->on_connect)
            {
                rudp_connect->on_connect(rudp_connect, rudp_connect->user_data, RudpConnectFlag_Timeout, NULL, 0);
                return;
            }
        }
        if (rudp_connect->isClient && rudp_connect->handshake_ts >= 0 && diff1 > 200)
        {
            rudp_send_handshake_req(rudp_connect);
            rudp_connect->handshake_ts = current_ts;
        }
    }
    else if (rudp_connect->status == RudpConnectStatus_OK)
    {
        //pacing send
        pacing_send_process(rudp_connect);

        //mtu probe
        mtu_probe_process(rudp_connect);

        //statistics bandwidth and lost
        statistics_bandwidth_process(rudp_connect);

        //ping send
        send_ping_process(rudp_connect);
    }
    else
    {
    }

    if (rudp_connect->status == RudpConnectStatus_OK || rudp_connect->status == RudpConnectStatus_Closing)
    {
        //close timeout
        long diff = current_ts - rudp_connect->last_recv_ts;
        if (rudp_connect->last_recv_ts <= 0 || diff < 0)
        {
            rudp_connect->last_recv_ts = current_ts;
            diff = 0;
        }

        if (diff > 3 * 1000)
        {
            //printf("long time [%fs] not recv data from peer and connect is in close...\n",diff/1000.0);

            /****-----需要在靠后的位置，避免rudp_connect释放之后，再次使用********/
            RudpConnectFlag flag = RudpConnectFlag_TimeoutClose;
            if (rudp_connect->status == RudpConnectStatus_Closing)
                flag = RudpConnectFlag_OnClose;
            if (rudp_connect->on_connect)
            {
                rudp_connect->on_connect(rudp_connect, rudp_connect->user_data, flag, NULL, 0);
                return;
            }

            //rudp_connect_close(rudp_connect);
        }
    }
}

int rudp_send_handshake_req(rudp_connect_t *rudp_connect)
{
    if (!rudp_connect)
        return -1;

    char send_buffer[2048] = {0};
    int send_len = sizeof(rudp_msg_head_t) + sizeof(rudp_msg_body_handshake_request_t);
    rudp_msg_head_t *head_send = (rudp_msg_head_t *)(send_buffer);
    rudp_msg_body_handshake_request_t *body_send = (rudp_msg_body_handshake_request_t *)head_send->data;
    head_send->type = htons(RudpMsgType_handshake_request);

    if (rudp_connect->req_data && rudp_connect->req_data_len > 0)
    {
        send_len += rudp_connect->req_data_len;
        memcpy(body_send->data, rudp_connect->req_data, rudp_connect->req_data_len);
    }
    head_send->len = htons(send_len);
    body_send->version = htonl(rudp_connect->version);

    int ret = udp_output_cmd(rudp_connect, send_buffer, send_len);
    if (ret != 0)
    {
        //printf("rudp_stream_send handshake fail.\n");
        return ret;
    }
    return 0;
}

int rudp_send_handshake_resp(rudp_connect_t *rudp_connect, int response)
{
    if (!rudp_connect)
        return -1;

    char send_buffer[2048] = {0};
    int send_len = sizeof(rudp_msg_head_t) + sizeof(rudp_msg_body_handshake_response_t);
    rudp_msg_head_t *head_send = (rudp_msg_head_t *)(send_buffer);
    rudp_msg_body_handshake_response_t *body_send = (rudp_msg_body_handshake_response_t *)head_send->data;
    head_send->type = htons(RudpMsgType_handshake_response);

    if (rudp_connect->resp_data && rudp_connect->resp_data_len > 0)
    {
        send_len += rudp_connect->resp_data_len;
        memcpy(body_send->data, rudp_connect->resp_data, rudp_connect->resp_data_len);
    }
    head_send->len = htons(send_len);
    body_send->response = htonl(response);

    int ret = udp_output_cmd(rudp_connect, send_buffer, send_len);
    if (ret != 0)
    {
        //printf("rudp_stream_send handshake fail.\n");
        return ret;
    }
    return 0;
}

void process_cmd_inter(rudp_connect_t *rudp_connect, const char *data, unsigned int len)
{
    if (!rudp_connect || !data || len < sizeof(rudp_msg_head_t))
        return;

    rudp_msg_head_t *head = (rudp_msg_head_t *)data;
    int msg_type = ntohs(head->type);
    int msg_len = ntohs(head->len);
    if (msg_type == RudpMsgType_None || msg_len <= 0)
    {
        return;
    }
    if (msg_type == RudpMsgType_handshake_request)
    {
        if (msg_len > len)
            return;
        rudp_msg_body_handshake_request_t *body = (rudp_msg_body_handshake_request_t *)head->data;

        if (rudp_connect->status != RudpConnectStatus_Handshake)
            return;

        unsigned int version = ntohl(body->version);
        int response = 0;
        if (version > rudp_connect->version)
            response = 1;

        rudp_send_handshake_resp(rudp_connect, response);
    }
    else if (msg_type == RudpMsgType_handshake_response)
    {
        if (msg_len > len)
            return;
        rudp_msg_body_handshake_response_t *body = (rudp_msg_body_handshake_response_t *)head->data;

        if (rudp_connect->status != RudpConnectStatus_Handshake)
            return;

        int response = ntohl(body->response);
        if (response == 0)
        {
            rudp_connect->status = RudpConnectStatus_OK;

            rudp_send_handshake_resp(rudp_connect, 0);

            char *resp_data = body->data;
            int resp_data_len = msg_len - sizeof(rudp_msg_head_t) - sizeof(rudp_msg_body_handshake_response_t);
            if (resp_data_len <= 0)
            {
                resp_data = NULL;
                resp_data_len = 0;
            }

            if (rudp_connect->on_connect)
                rudp_connect->on_connect(rudp_connect, rudp_connect->user_data, RudpConnectFlag_Ok, resp_data, resp_data_len);

            rudp_connect->blocked = 0;
            if (rudp_connect->on_send)
                rudp_connect->on_send(rudp_connect, rudp_connect->user_data);
        }
        else if (response == 1) //unsupport version
        {
            if (rudp_connect->on_connect)
            {
                rudp_connect->on_connect(rudp_connect, rudp_connect->user_data, RudpConnectFlag_ErrorVersion, NULL, 0);
                return;
            }
        }
        else if (response == 2) // need reconnect
        {
            if (rudp_connect->on_connect)
            {
                rudp_connect->on_connect(rudp_connect, rudp_connect->user_data, RudpConnectFlag_NeedReConnect, NULL, 0);
                return;
            }
        }
        else
        {
            if (rudp_connect->on_connect)
            {
                rudp_connect->on_connect(rudp_connect, rudp_connect->user_data, RudpConnectFlag_Error, NULL, 0);
                return;
            }
        }
    }
    else if (msg_type == RudpMsgType_close)
    {
        if (msg_len > len)
            return;
        rudp_msg_body_close_t *body = (rudp_msg_body_close_t *)head->data;

        if (rudp_connect->status != RudpConnectStatus_OK && rudp_connect->status != RudpConnectStatus_Closing)
            return;

        int mode = ntohl(body->mode);
        if (mode == 1) //force close
        {
            rudp_connect->status = RudpConnectStatus_Closed;
            if (rudp_connect->on_connect)
            {
                rudp_connect->on_connect(rudp_connect, rudp_connect->user_data, RudpConnectFlag_OnClose, NULL, 0);
                return;
            }
        }
        else
        {
            rudp_connect->status = RudpConnectStatus_Closing;
        }
    }
    else if (msg_type == RudpMsgType_ping)
    {
        if (msg_len > len)
            return;
        rudp_msg_body_ping_t *body = (rudp_msg_body_ping_t *)head->data;

        rudp_connect->send_bytes_remote = ntohl(body->send_bytes_h) * MAX_UINT32 + ntohl(body->send_bytes_l);
        rudp_connect->recv_bytes_remote = ntohl(body->recv_bytes_h) * MAX_UINT32 + ntohl(body->recv_bytes_l);
        rudp_connect->send_packages_remote = ntohl(body->send_packages_h) * MAX_UINT32 + ntohl(body->send_packages_l);
        rudp_connect->recv_packages_remote = ntohl(body->recv_packages_h) * MAX_UINT32 + ntohl(body->recv_packages_l);

        int current_ts = get_conn_ts(rudp_connect);
        int current_ping_ts = ntohl(body->ts);
        if (rudp_connect->last_recv_ping_ts > 0 && current_ping_ts > rudp_connect->last_recv_ping_ts && rudp_connect->recv_bytes_remote > rudp_connect->recv_bytes_remote_ping_last)
        {
            unsigned int diff_time = current_ping_ts - rudp_connect->last_recv_ping_ts;
            unsigned long diff_Bytes = rudp_connect->recv_bytes_remote - rudp_connect->recv_bytes_remote_ping_last;
            unsigned long current_bandwidth = diff_Bytes / diff_time * (1000 * 8); //bps

            if (current_bandwidth > rudp_connect->recv_bandwidth_remote_max || current_ts > rudp_connect->recv_bandwidth_remote_max_ts + 10000)
            {
                rudp_connect->recv_bandwidth_remote_max = current_bandwidth;
                rudp_connect->recv_bandwidth_remote_max_ts = current_ts;
            }
        }
        rudp_connect->last_recv_ping_ts = current_ping_ts;
        rudp_connect->recv_bytes_remote_ping_last = rudp_connect->recv_bytes_remote;

        //send pong
        char send_buffer[1024] = {0};
        int send_len = sizeof(rudp_msg_head_t) + sizeof(rudp_msg_body_pong_t);
        rudp_msg_head_t *head_send = (rudp_msg_head_t *)(send_buffer);
        rudp_msg_body_pong_t *body_send = (rudp_msg_body_pong_t *)head_send->data;
        head_send->type = htons(RudpMsgType_pong);
        head_send->len = htons(send_len);
        body_send->ts = body->ts;
        body_send->send_bytes_h = htonl(rudp_connect->send_bytes_local / MAX_UINT32);
        body_send->send_bytes_l = htonl(rudp_connect->send_bytes_local % MAX_UINT32);
        body_send->recv_bytes_h = htonl(rudp_connect->recv_bytes_local / MAX_UINT32);
        body_send->recv_bytes_l = htonl(rudp_connect->recv_bytes_local % MAX_UINT32);
        body_send->send_packages_h = htonl(rudp_connect->send_packages_local / MAX_UINT32);
        body_send->send_packages_l = htonl(rudp_connect->send_packages_local % MAX_UINT32);
        body_send->recv_packages_h = htonl(rudp_connect->recv_packages_local / MAX_UINT32);
        body_send->recv_packages_l = htonl(rudp_connect->recv_packages_local % MAX_UINT32);
        udp_output_cmd(rudp_connect, send_buffer, send_len);
    }
    else if (msg_type == RudpMsgType_pong)
    {
        if (msg_len > len)
            return;
        rudp_msg_body_pong_t *body = (rudp_msg_body_pong_t *)head->data;

        rudp_connect->send_bytes_remote = ntohl(body->send_bytes_h) * MAX_UINT32 + ntohl(body->send_bytes_l);
        rudp_connect->recv_bytes_remote = ntohl(body->recv_bytes_h) * MAX_UINT32 + ntohl(body->recv_bytes_l);
        rudp_connect->send_packages_remote = ntohl(body->send_packages_h) * MAX_UINT32 + ntohl(body->send_packages_l);
        rudp_connect->recv_packages_remote = ntohl(body->recv_packages_h) * MAX_UINT32 + ntohl(body->recv_packages_l);

        int current_ts = get_conn_ts(rudp_connect);
        int current_pong_ts = ntohl(body->ts);
        if (rudp_connect->last_recv_pong_ts > 0 && current_pong_ts > rudp_connect->last_recv_pong_ts && rudp_connect->recv_bytes_remote > rudp_connect->recv_bytes_remote_pong_last)
        {
            unsigned int diff_time = current_pong_ts - rudp_connect->last_recv_pong_ts;
            unsigned long diff_Bytes = rudp_connect->recv_bytes_remote - rudp_connect->recv_bytes_remote_pong_last;
            unsigned long current_bandwidth = diff_Bytes / diff_time * (1000 * 8); //bps

            if (current_bandwidth > rudp_connect->recv_bandwidth_remote_max || current_ts > rudp_connect->recv_bandwidth_remote_max_ts + 10000)
            {
                rudp_connect->recv_bandwidth_remote_max = current_bandwidth;
                rudp_connect->recv_bandwidth_remote_max_ts = current_ts;
            }
        }
        rudp_connect->last_recv_pong_ts = current_pong_ts;
        rudp_connect->recv_bytes_remote_pong_last = rudp_connect->recv_bytes_remote;

        //rtt
        int pong_ts = ntohl(body->ts);
        int rtt = current_ts - pong_ts;
        if (pong_ts <= 0 || rtt <= 0)
            return;
        if (rudp_connect->rtt > 0)
        {
            rudp_connect->rtt = (7 * rudp_connect->rtt + rtt) / 8;
            if (rudp_connect->rtt > rtt)
                rudp_connect->jitter = rudp_connect->rtt - rtt;
            else
                rudp_connect->jitter = rtt - rudp_connect->rtt;
        }
        else
        {
            rudp_connect->rtt = rtt;
            rudp_connect->jitter = 0;
        }

        if (rudp_connect->rtt_min <= 0 || rtt < rudp_connect->rtt_min || current_ts > rudp_connect->rtt_min_ts + 10000)
        {
            rudp_connect->rtt_min = rtt;
            rudp_connect->rtt_min_ts = current_ts;
        }

        //printf("rtt=%d,rudp_connect->rtt=%d\n",rtt,rudp_connect->rtt);
    }
    else if (msg_type == RudpMsgType_mtu_request)
    {
        if (msg_len > len)
            return;
        int length = msg_len;
        mtu_probe_send(rudp_connect, length, 0);
    }
    else if (msg_type == RudpMsgType_mtu_response)
    {
        if (msg_len > len)
            return;
        int length = msg_len;
        mtu_probe_recv(rudp_connect, length);
    }
    else if (msg_type == RudpMsgType_notify)
    {
        if (msg_len > len)
            return;

        char *resp_data = head->data;
        int resp_data_len = msg_len - sizeof(rudp_msg_head_t);
        if (resp_data_len > 0 && rudp_connect->on_recv && rudp_connect->status == RudpConnectStatus_OK)
            rudp_connect->on_recv(rudp_connect, rudp_connect->user_data, resp_data, resp_data_len);
        else if (resp_data_len > 0 && rudp_connect->on_connect && rudp_connect->status != RudpConnectStatus_OK)
            rudp_connect->on_connect(rudp_connect, rudp_connect->user_data, RudpConnectFlag_TWSSuspend, NULL, 0);
    }
    else
    {
    }
}

void process_recv_data(rudp_connect_t *rudp_connect, unsigned int stream_id, const char *data, unsigned int len)
{
    if (!rudp_connect || !data || len <= 0)
        return;

    if (rudp_connect->status != RudpConnectStatus_OK)
        return;

    rudp_connect->recv_bytes_app += len;
    if (rudp_connect->on_recv)
        rudp_connect->on_recv(rudp_connect, rudp_connect->user_data, data, len);
}

void rudp_kcp_input(rudp_connect_t *rudp_connect, const char *data, unsigned int len)
{
    if (!rudp_connect || !data || len < 24)
        return;

    unsigned int stream_id = *(int *)(data);
#if IWORDS_BIG_ENDIAN
    stream_id = ntohl(stream_id);
#endif

    if (stream_id >= RUDP_STREAM_COUNT)
        return;
    rudp_stream_input(rudp_connect->stream[stream_id], data, len);

    while (1)
    {
        int recv_size = rudp_stream_peeksize(rudp_connect->stream[stream_id]);
        if (recv_size <= 0)
            break;
        char *recv_buffer = (char *)rudp_malloc(recv_size);
        if (!recv_buffer)
            break;

        int recv_len = rudp_stream_recv(rudp_connect->stream[stream_id], recv_buffer, recv_size);

        //if(len != 32 && len != 24)
        //    printf("udp_recv len=%d,recv_len=%d\n",len,recv_len);

        if (recv_len <= 0)
        {
            rudp_free(recv_buffer);
            break;
        }

        process_recv_data(rudp_connect, stream_id, recv_buffer, recv_len);

        rudp_free(recv_buffer);
    }
}

void on_connect_recv(evutil_socket_t fd, short events, void *arg)
{
    if (!arg)
        return;
    rudp_connect_t *rudp_connect = (rudp_connect_t *)arg;

    int retval = -1;
    int i = 0;
    while (1)
    {
        if (rudp_connect->delete_flag == 2)
        {
            rudp_connect->delete_flag = 0;
            rudp_connect_close(rudp_connect);
            return;
        }
        rudp_connect->delete_flag = 0;

#if !(defined(WIN32) || defined(__APPLE__) || defined(__MACOS__))
        retval = recvmmsg(fd, rudp_connect->udp_msgs, RUDP_UDP_VLEN, 0, NULL);
        if (retval <= 0)
        {
            //perror("recvmmsg()");
            return;
        }

        rudp_connect->delete_flag = 1;

        for (i = 0; i < retval; i++)
        {
            char *buffer = rudp_connect->udp_bufs[i];
            int len = rudp_connect->udp_msgs[i].msg_len;
            rudp_connect->udp_msgs[i].msg_len = 0;

            rudp_connect->recv_bytes_local += len;
            rudp_connect->recv_packages_local++;
            rudp_connect->last_recv_ts = get_conn_ts(rudp_connect);

            if (len <= RUDP_PROTOCOL_HEAD_LEN)
                continue;
            int is_cmd = (buffer[0] >> 7) & 0x01;
            int is_unreliable = (buffer[0] >> 6) & 0x01;
            int is_fec_on = (buffer[0] >> 5) & 0x01;

            buffer += RUDP_PROTOCOL_HEAD_LEN;
            len -= RUDP_PROTOCOL_HEAD_LEN;
            if (is_cmd)
            {
                process_cmd_inter(rudp_connect, buffer, len);
                continue;
            }
            if (is_unreliable)
            {
                char *recv_buffer = (char *)rudp_malloc(len);
                if (!recv_buffer)
                    continue;
                memcpy(recv_buffer, buffer, len);
                process_recv_data(rudp_connect, 0, recv_buffer, len);
                rudp_free(recv_buffer);
                continue;
            }
            if (is_fec_on)
            {
                rudp_fec_input(rudp_connect, buffer, len); //raw udp -> fec -> kcp
                continue;
            }

            rudp_kcp_input(rudp_connect, buffer, len);
        }
#else
        char buffer[2048] = {0};
        int len = recv(fd, buffer, sizeof(buffer), 0);
        if (len <= 0)
        {
            //perror("recv()");
            return;
        }

        rudp_connect->delete_flag = 1;

        rudp_connect->recv_bytes_local += len;
        rudp_connect->recv_packages_local++;
        rudp_connect->last_recv_ts = get_conn_ts(rudp_connect);

        if (len <= RUDP_PROTOCOL_HEAD_LEN)
            continue;
        int is_cmd = (buffer[0] >> 7) & 0x01;
        int is_unreliable = (buffer[0] >> 6) & 0x01;
        int is_fec_on = (buffer[0] >> 5) & 0x01;

        //buffer = buffer + RUDP_PROTOCOL_HEAD_LEN;
        len -= RUDP_PROTOCOL_HEAD_LEN;
        if (is_cmd)
        {
            process_cmd_inter(rudp_connect, buffer + RUDP_PROTOCOL_HEAD_LEN, len);
            continue;
        }
        if (is_unreliable)
        {
            process_recv_data(rudp_connect, 0, buffer + RUDP_PROTOCOL_HEAD_LEN, len);
            continue;
        }
        if (is_fec_on)
        {
            rudp_fec_input(rudp_connect, buffer + RUDP_PROTOCOL_HEAD_LEN, len); //raw udp -> fec -> kcp
            continue;
        }

        rudp_kcp_input(rudp_connect, buffer + RUDP_PROTOCOL_HEAD_LEN, len);
#endif
    }
}

int rudp_send_close(rudp_connect_t *rudp_connect)
{
    if (!rudp_connect)
        return -1;

    char send_buffer[1024] = {0};
    int send_len = sizeof(rudp_msg_head_t) + sizeof(rudp_msg_body_close_t);
    rudp_msg_head_t *head_send = (rudp_msg_head_t *)(send_buffer);
    rudp_msg_body_close_t *body_send = (rudp_msg_body_close_t *)head_send->data;
    head_send->type = htons(RudpMsgType_close);
    head_send->len = htons(send_len);
    body_send->mode = 0;

    int ret = udp_output_cmd(rudp_connect, send_buffer, send_len);
    if (ret != 0)
    {
        //printf("rudp_stream_send close fail.\n");
        return ret;
    }
    return 0;
}

void rudp_set_mtu_multi_stream(rudp_connect_t *rudp_connect)
{
    if (!rudp_connect)
        return;

    unsigned int i = 1;
    int mtu = rudp_connect->mtu;
    if (rudp_connect->fec_on)
        mtu -= fecHeaderSizeTotal;
    for (i = 1; i < RUDP_STREAM_COUNT; i++)
    {
        ikcp_setmtu(rudp_connect->stream[i]->kcp, mtu);
    }
}

void rudp_set_snd_wnd_multi_stream(rudp_connect_t *rudp_connect, unsigned int snd_wnd)
{
    if (!rudp_connect)
        return;

    unsigned int i = 1;
    for (i = 1; i < RUDP_STREAM_COUNT; i++)
    {
        int multiple = 1;
        if (i == 5 && rudp_connect->send_package_multiple > 0)
        { //icmp double send
            multiple = 2;
        }
        if (rudp_connect->send_package_multiple > 1)
        { //all data double send
            multiple = rudp_connect->send_package_multiple;
        }

        if (multiple > 1)
            snd_wnd = snd_wnd / multiple;
        if (rudp_connect->fec_on && i != 3 && i != 6 && i != 7)
        {
            int dataShards = 0;
            int parityShards = 0;
            fec_getShards(rudp_connect->fec_recv, &dataShards, &parityShards);
            if (dataShards > 0 && parityShards > 0)
                snd_wnd = snd_wnd * dataShards / (dataShards + parityShards);
        }

        rudp_stream_update_snd_wnd(rudp_connect->stream[i], snd_wnd);
    }
}

void rudp_destory_multi_stream(rudp_connect_t *rudp_connect)
{
    if (!rudp_connect)
        return;

    unsigned int i = 1;
    for (i = 1; i < RUDP_STREAM_COUNT; i++)
    {
        rudp_stream_destory(rudp_connect->stream[i]);
        rudp_connect->stream[i] = NULL;
    }
}

int rudp_create_multi_stream(rudp_connect_t *rudp_connect)
{
    if (!rudp_connect)
        return -1;

    unsigned int i = 1;
    for (i = 1; i < RUDP_STREAM_COUNT; i++)
    {
        rudp_connect->stream[i] = rudp_stream_create(i, rudp_connect->ev_base);
        if (!rudp_connect->stream[i])
            break;

        rudp_connect->stream[i]->kcp->user = rudp_connect;
        rudp_connect->stream[i]->kcp->output = udp_output_pacing;
        rudp_connect->stream[i]->on_can_send = on_can_send;
        rudp_connect->stream[i]->user_data = rudp_connect;
        if (i == 1 || i == 2 || i == 5)
            rudp_connect->stream[i]->kcp->output = udp_output_nodely;
    }
    if (i != RUDP_STREAM_COUNT)
    { //fail
        rudp_destory_multi_stream(rudp_connect);
        return -2;
    }
    return 0;
}

RudpRetCode rudp_connect_start(rudp_connect_t *rudp_connect)
{
    if (!rudp_connect)
        return RudpRet_ERROR_Param;

    rudp_connect->delete_flag = 0;
    rudp_connect->version = 3;
    rudp_connect->blocked = 1;
    rudp_connect->first_ts = 0;
    rudp_connect->handshake_ts = get_conn_ts(rudp_connect);
    rudp_connect->handshake_first_ts = rudp_connect->handshake_ts;
    rudp_connect->last_ping_ts = -1;
    rudp_connect->last_statistics_ts = -1;
    rudp_connect->last_recv_ping_ts = -1;
    rudp_connect->last_recv_pong_ts = -1;
    rudp_connect->last_recv_ts = -1;
    rudp_connect->rtt_min = -1;

    rudp_connect->pacing_on = 1;
    rudp_connect->pacing_rate = RUDP_PACING_RATE_INIT; //100*1024*1024;//bps
    rudp_connect->pacing_send_bytes = 0;
    rudp_connect->last_pacing_ts = -1;
    rudp_connect->last_over_rate_ts = -1;
    rudp_connect->decrease_count = 0;
    //iqueue_init(&rudp_connect->pacing_data_queue);

    rudp_connect->mtu_probe_on = 1;
    rudp_connect->last_mtu_probe_ts = -1;
    rudp_connect->mtu = 1350;
    rudp_connect->mtu_step = 15;

    rudp_connect->is_lte_path = 0;
    rudp_connect->send_package_multiple = 1;
    rudp_connect->last_send_data_ts = -1;
    rudp_connect->ping_interval = 1000;

    rudp_connect->fec_on = 0;
    rudp_connect->fec_in_use = 0;
    rudp_connect->last_fec_send_ts = -1;
    rudp_connect->last_fec_recv_ts = -1;
    memset(rudp_connect->fec_send_buffers, 0, RUDP_UDP_BUFSIZE * RUDP_FEC_TOTAL_BUF);
    memset(rudp_connect->fec_recv_buffers, 0, RUDP_UDP_BUFSIZE * RUDP_FEC_TOTAL_BUF);

#if !(defined(WIN32) || defined(__APPLE__) || defined(__MACOS__))
    //init struct mmsghdr
    int i = 0;
    memset(rudp_connect->udp_msgs, 0, sizeof(rudp_connect->udp_msgs));
    for (i = 0; i < RUDP_UDP_VLEN; i++)
    {
        rudp_connect->udp_iovecs[i].iov_base = rudp_connect->udp_bufs[i];
        rudp_connect->udp_iovecs[i].iov_len = RUDP_UDP_BUFSIZE;
        rudp_connect->udp_msgs[i].msg_hdr.msg_iov = &rudp_connect->udp_iovecs[i];
        rudp_connect->udp_msgs[i].msg_hdr.msg_iovlen = 1;
        rudp_connect->udp_msgs[i].msg_hdr.msg_name = &rudp_connect->udp_clientaddr[i];
        rudp_connect->udp_msgs[i].msg_hdr.msg_namelen = sizeof(rudp_connect->udp_clientaddr[i]);
        rudp_connect->udp_msgs[i].msg_hdr.msg_control = rudp_connect->udp_msg_control[i];
        rudp_connect->udp_msgs[i].msg_hdr.msg_controllen = sizeof(rudp_connect->udp_msg_control[i]);
    }
#endif

    unsigned int j = 1;
    for (j = 0; j < RUDP_STREAM_COUNT; j++)
        rudp_connect->stream[j] = NULL;
    int ret = rudp_create_multi_stream(rudp_connect);
    if (ret != 0)
    {
        return RudpRet_STREAM_ERROR;
    }

    struct event *ev_reader = event_new(rudp_connect->ev_base, rudp_connect->sock, EV_READ | EV_PERSIST, on_connect_recv, rudp_connect);
    struct event *ev_timer = event_new(rudp_connect->ev_base, -1, EV_TIMEOUT | EV_PERSIST, on_timer, rudp_connect);
    if (!ev_reader || !ev_timer)
    {
        //printf("event_new event fail.\n");
        if (ev_reader)
            event_free(ev_reader);
        if (ev_timer)
            event_free(ev_timer);
        return RudpRet_TIMER_ERROR;
    }
    event_add(ev_reader, NULL);

    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 10 * 1000;
    event_add(ev_timer, &tv);

    rudp_connect->ev_reader = ev_reader;
    rudp_connect->ev_timer = ev_timer;

    if (rudp_connect->isClient)
    {
        int ret = rudp_send_handshake_req(rudp_connect);
        if (ret)
        {
            //printf("rudp_send_handshake fail ret=%d.\n",ret);
            return RudpRet_SEND_ERROR;
        }
    }
    else
    {
        if (rudp_connect->req_data && rudp_connect->req_data_len)
        {
            process_cmd_inter(rudp_connect, rudp_connect->req_data, rudp_connect->req_data_len);
            rudp_free(rudp_connect->req_data);
            rudp_connect->req_data = NULL;
            rudp_connect->req_data_len = 0;
        }
    }
    return RudpRet_NO_ERROR;
}

void rudp_connect_close(void *rudp_connect_i)
{
    if (!rudp_connect_i)
        return;
    rudp_connect_t *rudp_connect = (rudp_connect_t *)rudp_connect_i;

    if (rudp_connect->delete_flag == 1)
    {
        rudp_connect->delete_flag = 2;
        return;
    }
    else if (rudp_connect->delete_flag == 2)
        return;

    rudp_send_close(rudp_connect);

    rudp_destory_multi_stream(rudp_connect);

    rudp_connect->status = RudpConnectStatus_Closed;

    if (rudp_connect->sock > 0)
    {
        close(rudp_connect->sock);
        rudp_connect->sock = 0;
    }

    if (rudp_connect->ev_reader)
    {
        event_free(rudp_connect->ev_reader);
        rudp_connect->ev_reader = NULL;
    }
    if (rudp_connect->ev_timer)
    {
        event_free(rudp_connect->ev_timer);
        rudp_connect->ev_timer = NULL;
    }

    if (rudp_connect->req_data)
    {
        rudp_free(rudp_connect->req_data);
        rudp_connect->req_data = NULL;
        rudp_connect->req_data_len = 0;
    }

    if (rudp_connect->resp_data)
    {
        rudp_free(rudp_connect->resp_data);
        rudp_connect->resp_data = NULL;
        rudp_connect->resp_data_len = 0;
    }

    pacing_data *seg = NULL;
    while (!iqueue_is_empty(&rudp_connect->pacing_data_queue))
    {
        seg = iqueue_entry(rudp_connect->pacing_data_queue.next, pacing_data, node);
        if (seg)
        {
            iqueue_del(&seg->node);
            rudp_free(seg->data);
            rudp_free(seg);
        }
    }

    if (rudp_connect->fec_recv)
    {
        fec_delete(rudp_connect->fec_recv);
        rudp_connect->fec_recv = NULL;
    }
    if (rudp_connect->fec_send)
    {
        fec_delete(rudp_connect->fec_send);
        rudp_connect->fec_send = NULL;
    }

    rudp_connect->fec_on = 0;
    rudp_connect->fec_in_use = 0;

    rudp_free(rudp_connect);
    rudp_connect = NULL;
}

void bps_to_string(unsigned long bps, char *data_out, unsigned int data_size)
{
    if (!data_out || !data_size)
        return;

    float value = bps;
    char *unit = "bps";
    if (bps >= 1024 * 1024 * 1024) //Gbps
    {
        value = 1.0 * bps / 1024 / 1024 / 1024;
        unit = "Gbps";
    }
    else if (bps >= 1024 * 1024) //Mbps
    {
        value = 1.0 * bps / 1024 / 1024;
        unit = "Mbps";
    }
    else if (bps >= 1024) //Kbps
    {
        value = 1.0 * bps / 1024;
        unit = "Kbps";
    }

    snprintf(data_out, data_size, "%.3f%s", value, unit);
    data_out[strlen(data_out)] = 0;
}

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define ip_format_i(ip) ((uint8_t *)&ip)[3], ((uint8_t *)&ip)[2], ((uint8_t *)&ip)[1], ((uint8_t *)&ip)[0]
#else
#define ip_format_i(ip) ((uint8_t *)&ip)[0], ((uint8_t *)&ip)[1], ((uint8_t *)&ip)[2], ((uint8_t *)&ip)[3]
#endif

void rudp_connect_get_fec_status(rudp_connect_t *rudp_connect, char *data_out, unsigned int data_size)
{
    if (!rudp_connect || !data_out || !data_size)
        return;

    if (rudp_connect->fec_on)
    { //fec on
        int dataShards_send = 0;
        int parityShards_send = 0;
        int dataShards_recv = 0;
        int parityShards_recv = 0;
        fec_getShards(rudp_connect->fec_send, &dataShards_send, &parityShards_send);
        fec_getShards(rudp_connect->fec_recv, &dataShards_recv, &parityShards_recv);

        snprintf(data_out, data_size, "[1,%d,(%d,%d),(%d,%d)]", rudp_connect->fec_in_use, dataShards_send, parityShards_send, dataShards_recv, parityShards_recv);
    }
    else
    { //fec off
        snprintf(data_out, data_size, "[0]");
    }
    data_out[strlen(data_out)] = 0;
}

int rudp_connect_get_status(void *rudp_connect_i, char *data_out, unsigned int data_size)
{
    if (!rudp_connect_i || !data_out || !data_size)
        return -1;

    rudp_connect_t *rudp_connect = (rudp_connect_t *)rudp_connect_i;

    struct sockaddr_in src_addr;
    struct sockaddr_in dst_addr;
    socklen_t addrlen = sizeof(struct sockaddr_in);
    memset(&src_addr, 0, sizeof(src_addr));
    memset(&dst_addr, 0, sizeof(dst_addr));
    getsockname(rudp_connect->sock, (struct sockaddr *)&src_addr, &addrlen);
    getpeername(rudp_connect->sock, (struct sockaddr *)&dst_addr, &addrlen);

    uint32_t sip = ntohl(*(uint32_t *)&src_addr.sin_addr);
    uint16_t sport = ntohs(src_addr.sin_port);
    uint32_t dip = ntohl(*(uint32_t *)&dst_addr.sin_addr);
    uint16_t dport = ntohs(dst_addr.sin_port);

    char s1[64] = {0};
    bps_to_string(rudp_connect->recv_bandwidth_app, s1, 64);
    char s2[64] = {0};
    bps_to_string(rudp_connect->send_bandwidth_app, s2, 64);
    char s3[64] = {0};
    bps_to_string(rudp_connect->recv_bandwidth_local, s3, 64);
    char s4[64] = {0};
    bps_to_string(rudp_connect->send_bandwidth_local, s4, 64);
    char s5[64] = {0};
    bps_to_string(rudp_connect->recv_bandwidth_remote, s5, 64);
    char s6[64] = {0};
    bps_to_string(rudp_connect->send_bandwidth_remote, s6, 64);
    char s7[64] = {0};
    bps_to_string(rudp_connect->pacing_rate, s7, 64);
    char s8[64] = {0};
    bps_to_string(rudp_connect->recv_bandwidth_remote_max, s8, 64);

    char fec_str[128] = {0};
    rudp_connect_get_fec_status(rudp_connect, fec_str, 128);

    float valid_recv = 0;
    if (rudp_connect->recv_bytes_local != 0)
        valid_recv = 1.0 * rudp_connect->recv_bytes_app / rudp_connect->recv_bytes_local;
    float valid_send = 0;
    if (rudp_connect->send_bytes_local != 0)
        valid_send = 1.0 * rudp_connect->send_bytes_app / rudp_connect->send_bytes_local;

    snprintf(data_out, data_size, "this[0x%p,%d,(%d@%d.%d.%d.%d:%d->%d.%d.%d.%d:%d),%d,%d],mtu[%d],rtt[%dms],jitter[%dms],fec%s,lost[%d%%,%d%%;%d%%,%d%%],app[%s,%s],bandwidth[%s,%s,%s,%s],pacing[%d,%s],valid[%.2f%%,%.2f%%],bdp[%s,%d,%u]",
             rudp_connect, rudp_connect->isClient, rudp_connect->sock, ip_format_i(sip), sport, ip_format_i(dip), dport, rudp_connect->status, rudp_connect->blocked, rudp_connect->mtu, rudp_connect->rtt, rudp_connect->jitter, fec_str,
             rudp_connect->lost_local, rudp_connect->lost_network_local, rudp_connect->lost_remote, rudp_connect->lost_network_remote, s1, s2, s3, s4, s5, s6,
             rudp_connect->pacing_on, s7, valid_recv * 100, valid_send * 100, s8, rudp_connect->rtt_min, rudp_connect->send_wnd);

    data_out[strlen(data_out)] = 0;

    return 0;
}

int rudp_connect_get_rtt(void *rudp_connect_i)
{
    if (!rudp_connect_i)
        return -1;

    rudp_connect_t *rudp_connect = (rudp_connect_t *)rudp_connect_i;
    return rudp_connect->rtt;
}

int rudp_connect_get_jitter(void *rudp_connect_i)
{
    if (!rudp_connect_i)
        return -1;

    rudp_connect_t *rudp_connect = (rudp_connect_t *)rudp_connect_i;
    return rudp_connect->jitter;
}

int rudp_connect_get_lost(void *rudp_connect_i)
{
    if (!rudp_connect_i)
        return -1;

    rudp_connect_t *rudp_connect = (rudp_connect_t *)rudp_connect_i;
    return rudp_connect->lost_local;
}

int rudp_connect_get_mtu(void *rudp_connect_i)
{
    if (!rudp_connect_i)
        return -1;

    rudp_connect_t *rudp_connect = (rudp_connect_t *)rudp_connect_i;
    return rudp_connect->mtu;
}

int rudp_connect_get_pack_info(void *rudp_connect_i, unsigned long *send_packages, unsigned long *recv_packages)
{
    if (!rudp_connect_i || !send_packages || !recv_packages)
        return -1;

    rudp_connect_t *rudp_connect = (rudp_connect_t *)rudp_connect_i;
    *send_packages = rudp_connect->send_packages_local;
    *recv_packages = rudp_connect->recv_packages_local;
    return 0;
}

void rudp_set_is_lte_path(void *rudp_connect_i, int is_lte_path) //is_lte_path is 0 or not 0
{
    if (!rudp_connect_i)
        return;

    rudp_connect_t *rudp_connect = (rudp_connect_t *)rudp_connect_i;

    if (is_lte_path)
        rudp_connect->is_lte_path = 1;
    else
        rudp_connect->is_lte_path = 0;
}

void rudp_multi_send_package(void *rudp_connect_i, int multiple_i) //multiple in 0~10,other as 1
{
    if (!rudp_connect_i)
        return;

    rudp_connect_t *rudp_connect = (rudp_connect_t *)rudp_connect_i;

    int multiple = 1;
    if (multiple_i >= 0 && multiple_i <= 10)
        multiple = multiple_i;
    rudp_connect->send_package_multiple = multiple;

    if (rudp_connect->send_package_multiple > 1)
    {
        if (rudp_connect->fec_send)
        {
            fec_delete(rudp_connect->fec_send);
            rudp_connect->fec_send = NULL;
        }
        rudp_connect->fec_on = 0;
        rudp_connect->fec_in_use = 0;
    }
}

void rudp_set_resend_limited(void *rudp_connect_i, int limited_i) //limited int 0~5,other as 0
{
    if (!rudp_connect_i)
        return;

    rudp_connect_t *rudp_connect = (rudp_connect_t *)rudp_connect_i;

    unsigned int limited = 0;
    if (limited_i >= 0 && limited_i <= 5)
        limited = limited_i;

    unsigned int i = 1;
    for (i = 1; i < RUDP_STREAM_COUNT; i++)
    {
        rudp_stream_set_resend_limited(rudp_connect->stream[i], limited);
    }
}

void rudp_set_recv_out_of_order(void *rudp_connect_i, int out_of_order_i) //out_of_order is 0 or not 0
{
    if (!rudp_connect_i)
        return;

    rudp_connect_t *rudp_connect = (rudp_connect_t *)rudp_connect_i;

    unsigned int out_of_order = 0;
    if (out_of_order_i != 0)
        out_of_order = 1;

    unsigned int i = 1;
    for (i = 1; i < RUDP_STREAM_COUNT; i++)
    {
        rudp_stream_set_recv_out_of_order(rudp_connect->stream[i], out_of_order);
    }
}

void rudp_set_fec_on(void *rudp_connect_i, int fec_on_i) //fec_on is 0 or not 0
{
    if (!rudp_connect_i)
        return;

    rudp_connect_t *rudp_connect = (rudp_connect_t *)rudp_connect_i;

    unsigned int fec_on = 0;
    if (fec_on_i != 0)
        fec_on = 1;

    rudp_connect->fec_on = fec_on;
    rudp_connect->fec_in_use = 0;

    if (rudp_connect->send_package_multiple > 1)
    {
        if (rudp_connect->fec_send)
        {
            fec_delete(rudp_connect->fec_send);
            rudp_connect->fec_send = NULL;
        }
        rudp_connect->fec_on = 0;
    }
}
