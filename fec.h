#ifndef __FEC_H_
#define __FEC_H_

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#ifndef BUILD_APP
#include <unistd.h>
#endif

#define fec_malloc malloc
#define fec_free free

#include "rs.h"
#include "fec_utils.h"

#define FEC_MAX_DATA_LEN 1600

#define fecHeaderSize 5
#define fecHeaderSizeTotal 7
#define fecHeaderSizeShift 2
#define typeData 0x01
#define typeFEC 0x02

typedef enum
{
  FEC_LOG_LEVEL_DEBUG,
  FEC_LOG_LEVEL_INFO,
  FEC_LOG_LEVEL_NOTICE,
  FEC_LOG_LEVEL_WARN,
  FEC_LOG_LEVEL_ERR,
  FEC_LOG_LEVEL_CRIT,
  FEC_LOG_LEVEL_ALERT,
  FEC_LOG_LEVEL_EMERG,
} FEC_LOG_LEVEL_TYPE;

typedef struct _fec_packet
{
  struct IQUEUEHEAD node;

  //unsigned char type;
  //unsigned char reserve;
  int dataShards;
  int parityShards;

  unsigned char type;
  unsigned int seqid;
  unsigned long ts;

  unsigned short len;
  char data[0];
} fec_packet_t;

typedef struct _fec_param
{
  int dataShards;
  int parityShards;

  int fecExpire; /******过期时间 ms******/
  int rxLimit;   /******最大接收队列尺寸******/
} fec_param_t;

typedef struct _fec
{
  int dataShards;
  int parityShards;
  int totalShards;

  int rxLimit;
  int fecExpire;
  unsigned long lastCheckTs;
  unsigned int nextSeqid; //
  unsigned int paws;      // Protect Against Wrapped Sequence numbers

  struct IQUEUEHEAD rx_queue;
  int rx_num;

  reed_solomon *rs;

  void (*writelog)(struct _fec *fec, FEC_LOG_LEVEL_TYPE level, const char *log);
} fec_t;

//New a FEC handle
void *fec_new(fec_param_t *param);

//Delete fec handle
void fec_delete(void *fec);

//Get shard config
int fec_getShards(void *fec, int *dataShards, int *parityShards);

// Calc Parity Shards
void fec_encode(void *fec_, unsigned char **shards, int nr_shards, int block_size);

// Mark raw array as typeData, and write correct size.
void fec_markData(void *fec, char *data, unsigned short len);

// Mark raw array as typeFEC
void fec_markFEC(void *fec, char *data);

// Decode a raw array into fecPacket
fec_packet_t *fec_decode(char *data, unsigned int len);

// Input a FEC packet, and return recovered data if possible.
int fec_reconstruct(void *fec, fec_packet_t *pkt, unsigned char **shards, unsigned char *marks, int nr_shards);

void fec_decode16u(char *p, unsigned short *w);

void fec_packet_delete(fec_packet_t *pkt);

#endif