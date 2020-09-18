#ifndef __RUDP_H__
#define __RUDP_H__

#define _GNU_SOURCE

#include <stddef.h>
#include <stdlib.h>
#include <stdbool.h>

#ifdef WIN32
#ifndef close
#define close closesocket
#endif
#endif

#define RUDP_PROTOCOL_HEAD_LEN (1)
#define RUDP_STREAM_COUNT (8)
#define RUDP_UDP_BUFSIZE (1600)
#define RUDP_UDP_VLEN (64)

/***-----接口返回值************/
typedef enum
{
  RudpRet_NO_ERROR = 0,
  RudpRet_INTERNAL_ERROR = 1,
  RudpRet_ERROR_Param = 2,
  RudpRet_ERROR_Closed = 3,
  RudpRet_ERROR_DataType = 4,
  RudpRet_MALLOC_ERROR = 5,
  RudpRet_SEND_ERROR = 6,
  RudpRet_TIMER_ERROR = 7,
  RudpRet_SOCKET_ERROR = 8,
  RudpRet_INTERFACE_ERROR = 10,
  RudpRet_STREAM_ERROR = 11,
  RudpRet_ERROR_Eagain = 12,
  RudpRet_ERROR_MoreMTU = 13,

} RudpRetCode;

/*****-----链接状态标志********/
typedef enum
{
  RudpConnectFlag_Ok = 0,
  RudpConnectFlag_Error = 1,
  RudpConnectFlag_Timeout = 2,
  RudpConnectFlag_OnClose = 3,
  RudpConnectFlag_TimeoutClose = 4,
  RudpConnectFlag_NeedReConnect = 5,
  RudpConnectFlag_ErrorVersion = 6,
  RudpConnectFlag_TWSSuspend = 7,
} RudpConnectFlag;

/***********-----数据发送类型***********/
typedef enum
{
  RudpDataType_None = 0,    /********-----无效值*******/
  RudpDataType_Cmd = 1,     /******-----有序，可靠，低延迟，优先级高*******/
  RudpDataType_NoDelay = 2, /******-----无序，可靠，短延迟，优先级中*******/
  RudpDataType_Tcp = 3,     /******-----无序，可靠，普通延迟，优先级低*******/
  RudpDataType_Udp = 4,     /******-----无序，不可靠(有限重发)，短延迟，优先级低*******/
  RudpDataType_Icmp = 5,    /******-----无序，可靠，短延迟，优先级高，ping保障*******/
  RudpDataType_TCP_BD = 6,  /******-----无序，可靠，普通延迟，优先级低*******/
  RudpDataType_UDP_BD = 7,  /******-----无序，不可靠(有限重发)，短延迟，优先级低*******/

  RudpDataType_Unreliable = 8, /******----不可靠数据发送通道，丢包不重发，纯转发*******/
} RudpDataType;

typedef void (*on_accept_t)(void *rudp_connect, void *user_data, const char *init_data, unsigned int init_data_len);
typedef void (*on_connect_t)(void *rudp_connect, void *user_data, RudpConnectFlag flag, const char *resp_data, unsigned int resp_data_len);
typedef void (*on_send_t)(void *rudp_connect, void *user_data);
typedef void (*on_recv_t)(void *rudp_connect, void *user_data, const char *data, unsigned int data_len);

typedef struct
{
  char server_ip[16];
  int server_port;
  char interfaces[32];

  struct event_base *ev_base;
  void *user_data;

  char *req_data;
  unsigned int req_data_len;

  on_connect_t on_connect;
  on_send_t on_send;
  on_recv_t on_recv;
} rudp_client_open_param_t;

typedef struct
{
  char server_ip[16];
  int server_port;
  struct event_base *ev_base;
  void *user_data;

  on_accept_t on_accept;
} rudp_server_open_param_t;

typedef struct
{
  struct event_base *ev_base;
  void *user_data;

  char *resp_data;
  unsigned int resp_data_len;

  on_connect_t on_connect;
  on_send_t on_send;
  on_recv_t on_recv;
} rudp_server_accept_param_t;

/******void rudp_env_init();*******/
/******void rudp_env_uninit();*******/

/****** setup allocator*******/
#define rudp_malloc malloc
#define rudp_free free

RudpRetCode rudp_client_open(rudp_client_open_param_t *param, void **rudp_connect_out);

void *rudp_server_open(rudp_server_open_param_t *param);
void rudp_server_close(void *rudp_server);
void rudp_server_accept(rudp_server_accept_param_t *param, void *rudp_connect);

RudpRetCode rudp_connect_send(void *rudp_connect, const char *data, unsigned int data_len, RudpDataType data_type, bool is_urgent);
void rudp_connect_close(void *rudp_connect);

int rudp_connect_get_status(void *rudp_connect, char *data_out, unsigned int data_size);
int rudp_connect_get_rtt(void *rudp_connect);
int rudp_connect_get_jitter(void *rudp_connect);
int rudp_connect_get_lost(void *rudp_connect);
int rudp_connect_get_mtu(void *rudp_connect);
int rudp_connect_get_pack_info(void *rudp_connect, unsigned long *send_packages, unsigned long *recv_packages);

void rudp_set_is_lte_path(void *rudp_connect, int is_lte_path);        /******is_lte_path is 0 or not 0*******/
void rudp_multi_send_package(void *rudp_connect, int multiple);        /******multiple in 1~10,other as 1*******/
void rudp_set_resend_limited(void *rudp_connect, int limited);         /******limited int 0~5,other as 0*******/
void rudp_set_recv_out_of_order(void *rudp_connect, int out_of_order); /******out_of_order is 0 or not 0*******/
void rudp_set_fec_on(void *rudp_connect, int fec_on);                  /******fec_on is 0 or not 0*******/

#endif