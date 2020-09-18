#ifndef __RUDP_CONNECT_H__
#define __RUDP_CONNECT_H__

#include "rudp.h"
#include "ikcp.h"
#include "fec.h"
#include "rudp_stream.h"

#ifndef BUILD_APP
#include <arpa/inet.h>
#include <sys/socket.h>
#endif
#include <event2/event.h>

#define MAX_UINT32 (0XFFFFFFFF)
#define RUDP_PACING_RATE_INIT (100 * 1024 * 1024L)
#define RUDP_PACING_RATE_MIN (10 * 1024 * 1024L)
//#define RUDP_PACING_RATE_MAX   (2*1024*1024*1024L)

#define RUDP_FEC_TOTAL_BUF 16

typedef enum
{
    RudpMsgType_None = 0,
    RudpMsgType_handshake_request = 1,
    RudpMsgType_handshake_response = 2,
    RudpMsgType_ping = 3,
    RudpMsgType_pong = 4,
    RudpMsgType_mtu_request = 5,
    RudpMsgType_mtu_response = 6,
    RudpMsgType_close = 7,
    RudpMsgType_data = 8,
    RudpMsgType_notify = 10,
} RudpMsgType;

typedef struct
{
    unsigned short type;
    unsigned short len;
    char data[0];
} rudp_msg_head_t;

typedef struct
{
    unsigned int version;
    char data[0];
} rudp_msg_body_handshake_request_t;

typedef struct
{
    int response;
    char data[0];
} rudp_msg_body_handshake_response_t;

typedef struct
{
    unsigned int ts;
    unsigned int send_bytes_h;
    unsigned int send_bytes_l;
    unsigned int recv_bytes_h;
    unsigned int recv_bytes_l;
    unsigned int send_packages_h;
    unsigned int send_packages_l;
    unsigned int recv_packages_h;
    unsigned int recv_packages_l;
} rudp_msg_body_ping_t;

typedef struct
{
    unsigned int ts;
    unsigned int send_bytes_h;
    unsigned int send_bytes_l;
    unsigned int recv_bytes_h;
    unsigned int recv_bytes_l;
    unsigned int send_packages_h;
    unsigned int send_packages_l;
    unsigned int recv_packages_h;
    unsigned int recv_packages_l;
} rudp_msg_body_pong_t;

typedef struct
{
    int mode; // 0 is safe close or 1 is force close
} rudp_msg_body_close_t;

typedef struct
{
    struct IQUEUEHEAD node;
    int stream_id;
    int len;
    char *data;
} pacing_data;

typedef enum
{
    RudpConnectStatus_Handshake,
    RudpConnectStatus_OK,
    RudpConnectStatus_Closing,
    RudpConnectStatus_Closed,
} RudpConnectStatus;

typedef struct
{
    int isClient;
    unsigned int version;
    RudpConnectStatus status;
    int delete_flag;

    int sock;
    struct sockaddr_in dst_addr;

    struct event_base *ev_base;
    struct event *ev_reader;
    struct event *ev_timer;
    void *user_data;

    on_connect_t on_connect;
    on_send_t on_send;
    on_recv_t on_recv;

    char *req_data;
    int req_data_len;
    char *resp_data;
    int resp_data_len;

    int blocked;
    int rtt;
    int jitter;
    int lost_local;
    int lost_remote;
    int lost_network_local;
    int lost_network_remote;
    rudp_stream_t *stream[RUDP_STREAM_COUNT];

#ifndef WIN32
    struct mmsghdr udp_msgs[RUDP_UDP_VLEN];
    struct iovec udp_iovecs[RUDP_UDP_VLEN];
    char udp_bufs[RUDP_UDP_VLEN][RUDP_UDP_BUFSIZE];
    struct sockaddr_in udp_clientaddr[RUDP_UDP_VLEN];
    char udp_msg_control[RUDP_UDP_VLEN][CMSG_SPACE(sizeof(struct sockaddr_in))];
#endif

    long first_ts;
    long handshake_ts;
    long handshake_first_ts;
    long last_ping_ts;
    long last_recv_ts;

    //statistics bandwidth and lost
    long last_statistics_ts;
    unsigned long send_bytes_app;
    unsigned long recv_bytes_app;
    unsigned long send_bytes_local;
    unsigned long recv_bytes_local;
    unsigned long send_bytes_remote;
    unsigned long recv_bytes_remote;
    unsigned long send_packages_local;
    unsigned long recv_packages_local;
    unsigned long send_packages_remote;
    unsigned long recv_packages_remote;

    unsigned long send_bytes_app_last;
    unsigned long recv_bytes_app_last;
    unsigned long send_bytes_local_last;
    unsigned long recv_bytes_local_last;
    unsigned long send_bytes_remote_last;
    unsigned long recv_bytes_remote_last;
    unsigned long send_packages_local_last;
    unsigned long recv_packages_local_last;
    unsigned long send_packages_remote_last;
    unsigned long recv_packages_remote_last;

    unsigned long send_bandwidth_app;
    unsigned long recv_bandwidth_app;
    unsigned long send_bandwidth_local;
    unsigned long recv_bandwidth_local;
    unsigned long send_bandwidth_remote;
    unsigned long recv_bandwidth_remote;
    unsigned int packages_array_index;
    unsigned long send_packages_local_array[10];
    unsigned long recv_packages_local_array[10];
    unsigned long send_packages_remote_array[10];
    unsigned long recv_packages_remote_array[10];

    int rtt_min;
    long rtt_min_ts;
    long last_recv_ping_ts;
    unsigned long recv_bytes_remote_ping_last;
    long last_recv_pong_ts;
    unsigned long recv_bytes_remote_pong_last;
    long recv_bandwidth_remote_max_ts;
    unsigned long recv_bandwidth_remote_max;
    unsigned int send_wnd;
    unsigned int send_cycle;

    //handle pacing
    int pacing_on;
    long last_pacing_ts;
    long last_over_rate_ts;
    unsigned int decrease_count;
    unsigned long pacing_rate; //bps
    unsigned long pacing_send_bytes;
    struct IQUEUEHEAD pacing_data_queue;

    //probe mtu
    int mtu_probe_on;
    long last_mtu_probe_ts;
    int mtu;
    int mtu_step;

    int ping_interval; //ms
    long last_send_data_ts;
    int is_lte_path;
    int send_package_multiple;

    //fec
    int fec_on;
    int fec_in_use;
    void *fec_send;
    void *fec_recv;
    long last_fec_send_ts;
    long last_fec_recv_ts;
    int fec_buf_index;
    int fec_buf_max_len;
    unsigned char fec_send_buffers[RUDP_FEC_TOTAL_BUF][RUDP_UDP_BUFSIZE];
    unsigned char fec_recv_buffers[RUDP_FEC_TOTAL_BUF][RUDP_UDP_BUFSIZE];

} rudp_connect_t;

RudpRetCode rudp_connect_start(rudp_connect_t *rudp_connect);

#endif