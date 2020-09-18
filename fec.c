#include "fec.h"

/* encode 8 bits unsigned int */
static inline char *encode8u(char *p, unsigned char c)
{
    *(unsigned char *)p++ = c;
    return p;
}

/* decode 8 bits unsigned int */
static inline char *decode8u(char *p, unsigned char *c)
{
    *c = *(unsigned char *)p++;
    return p;
}

/* encode 16 bits unsigned int (lsb) */
static inline char *encode16u(char *p, unsigned short w)
{
#if IWORDS_BIG_ENDIAN
    *(byte *)(p + 0) = (w & 255);
    *(byte *)(p + 1) = (w >> 8);
#else
    *(unsigned short *)(p) = w;
#endif
    p += 2;
    return p;
}

/* Decode 16 bits unsigned int (lsb) */
static inline char *decode16u(char *p, unsigned short *w)
{
#if IWORDS_BIG_ENDIAN
    *w = *(const unsigned char *)(p + 1);
    *w = *(const unsigned char *)(p + 0) + (*w << 8);
#else
    *w = *(const unsigned short *)p;
#endif
    p += 2;
    return p;
}

/* encode 32 bits unsigned int (lsb) */
static inline char *encode32u(char *p, unsigned int l)
{
#if IWORDS_BIG_ENDIAN
    *(unsigned char *)(p + 0) = (unsigned char)((l >> 0) & 0xff);
    *(unsigned char *)(p + 1) = (unsigned char)((l >> 8) & 0xff);
    *(unsigned char *)(p + 2) = (unsigned char)((l >> 16) & 0xff);
    *(unsigned char *)(p + 3) = (unsigned char)((l >> 24) & 0xff);
#else
    *(unsigned int *)p = l;
#endif
    p += 4;
    return p;
}

/* Decode 32 bits unsigned int (lsb) */
static inline char *decode32u(char *p, unsigned int *l)
{
#if IWORDS_BIG_ENDIAN
    *l = *(const unsigned char *)(p + 3);
    *l = *(const unsigned char *)(p + 2) + (*l << 8);
    *l = *(const unsigned char *)(p + 1) + (*l << 8);
    *l = *(const unsigned char *)(p + 0) + (*l << 8);
#else
    *l = *(const unsigned int *)p;
#endif
    p += 4;
    return p;
}

// write log
static void fec_log(fec_t *fec, FEC_LOG_LEVEL_TYPE level, const char *fmt, ...)
{
    if (!fec || !fec->writelog)
        return;
    char buffer[2048];
    va_list argptr;
    va_start(argptr, fmt);
    vsprintf(buffer, fmt, argptr);
    va_end(argptr);
    fec->writelog(fec, level, buffer);
}

// allocate a new fec packet
static fec_packet_t *fec_packet_new(unsigned int size)
{
    fec_packet_t *pkt = (fec_packet_t *)fec_malloc(sizeof(fec_packet_t) + size);
    if (!pkt)
        return NULL;
    memset(pkt, 0, sizeof(fec_packet_t) + size);
    return pkt;
}

// delete a packet
void fec_packet_delete(fec_packet_t *pkt)
{
    fec_free(pkt);
}

unsigned long get_timestamp()
{
    unsigned long timestamp = 0;
#if 0
    struct timeval tv;
    gettimeofday(&tv, NULL);
    timestamp = tv.tv_sec*1000 + tv.tv_usec/1000;
#else
    struct timespec tv;
    clock_gettime(CLOCK_MONOTONIC, &tv);
    timestamp = ((int64_t)tv.tv_sec) * 1000 + (int64_t)tv.tv_nsec / 1000000;
#endif

    return timestamp;
}

void *fec_new(fec_param_t *param)
{
    if (!param)
    {
        //printf("---DEBUG FEC---:ERROR NULL fec_param_t.\n");
        return NULL;
    }
    int totalShards = param->dataShards + param->parityShards;
    if (param->dataShards <= 0 || param->parityShards <= 0 || param->dataShards > 16 || param->parityShards > 4)
    {
        //printf("---DEBUG FEC---:ERROR fec_param_t,dataShards=%d,parityShards=%d.\n",param->dataShards,param->parityShards);
        return NULL;
    }
    if (param->fecExpire < 30 || param->fecExpire > 10 * 1000)
    {
        //printf("---DEBUG FEC---:ERROR fec_param_t,fecExpire=%d.\n",param->fecExpire);
        return NULL;
    }
    if (param->rxLimit < totalShards || param->rxLimit > totalShards * 100)
    {
        //printf("---DEBUG FEC---:ERROR fec_param_t,rxLimit=%d.\n",param->rxLimit);
        return NULL;
    }

    fec_init();
    reed_solomon *rs = reed_solomon_new(param->dataShards, param->parityShards);
    if (!rs)
    {
        //printf("---DEBUG FEC---:ERROR reed_solomon_new fail.\n");
        return NULL;
    }
    fec_t *fec = (fec_t *)fec_malloc(sizeof(fec_t));
    if (!fec)
    {
        //printf("---DEBUG FEC---:ERROR malloc fec fail.\n");
        reed_solomon_release(rs);
        return NULL;
    }
    memset(fec, 0, sizeof(fec_t));
    fec->dataShards = param->dataShards;
    fec->parityShards = param->parityShards;
    fec->totalShards = totalShards;
    fec->rxLimit = param->rxLimit;
    fec->fecExpire = param->fecExpire;
    fec->lastCheckTs = 0;
    fec->nextSeqid = 0;
    fec->paws = (0xffffffff / (unsigned int)(fec->totalShards) - 1) * (unsigned int)(fec->totalShards);
    fec->rs = rs;
    fec->writelog = NULL;

    iqueue_init(&fec->rx_queue);
    fec->rx_num = 0;

    //printf("---DEBUG FEC---:fec_new,fec=%p,rs=%p,dataShards=%d,parityShards=%d,rxLimit=%d,fecExpire=%d,paws=%u.\n",
    //fec,fec->rs,fec->dataShards,fec->parityShards,fec->rxLimit,fec->fecExpire,fec->paws);

    return fec;
}

void fec_delete(void *fec_)
{
    if (!fec_)
        return;
    fec_t *fec = (fec_t *)fec_;

    fec_log(NULL, FEC_LOG_LEVEL_INFO, "---FEC---:fec_delete,fec=%p.", fec);
    //printf("---DEBUG FEC---:fec_delete,fec=%p.\n",fec);

    if (fec->rs)
    {
        reed_solomon_release(fec->rs);
        fec->rs = NULL;
    }

    fec_packet_t *pkt = NULL;
    while (!iqueue_is_empty(&fec->rx_queue))
    {
        pkt = iqueue_entry(fec->rx_queue.next, fec_packet_t, node);
        iqueue_del(&pkt->node);
        fec_packet_delete(pkt);
    }
}

int fec_getShards(void *fec_, int *dataShards, int *parityShards)
{
    if (!fec_ || !dataShards || !parityShards)
        return -1;
    fec_t *fec = (fec_t *)fec_;
    *dataShards = fec->dataShards;
    *parityShards = fec->parityShards;
    return 0;
}

void fec_markData(void *fec_, char *data, unsigned short len)
{
    if (!fec_ || !data || len <= 0)
        return;
    fec_t *fec = (fec_t *)fec_;

    unsigned char type = typeData & 0x03;
    unsigned char config_dataShard = fec->dataShards & 0x0F;
    unsigned char config_parityShard = fec->parityShards & 0x03;

    data[0] = ((type << 6) | (config_dataShard << 2) | (config_parityShard));
    //data = encode8u(data,typeData);
    data++;
    data = encode32u(data, fec->nextSeqid);
    data = encode16u(data, len + fecHeaderSizeShift); // including size itself
    fec->nextSeqid++;
}

void fec_markFEC(void *fec_, char *data)
{
    if (!fec_ || !data)
        return;
    fec_t *fec = (fec_t *)fec_;

    unsigned char type = typeFEC & 0x03;
    unsigned char config_dataShard = fec->dataShards & 0x0F;
    unsigned char config_parityShard = fec->parityShards & 0x03;

    data[0] = ((type << 6) | (config_dataShard << 2) | (config_parityShard));
    //data = encode8u(data,typeFEC);
    data++;
    data = encode32u(data, fec->nextSeqid);
    fec->nextSeqid++;
    if (fec->nextSeqid >= fec->paws)
    { // paws would only occurs in MarkFEC
        fec->nextSeqid = 0;
    }
}

void fec_encode(void *fec_, unsigned char **shards, int nr_shards, int block_size)
{
    if (!fec_ || !shards || block_size <= 0)
        return;
    fec_t *fec = (fec_t *)fec_;

    if (!fec->rs)
        return;

    if (nr_shards != fec->totalShards)
    {
        fec_log(NULL, FEC_LOG_LEVEL_ERR, "---FEC---:fec_encode error nr_shards=%d,fec=%p.", nr_shards, fec);
        return;
    }
    reed_solomon_encode2(fec->rs, shards, nr_shards, block_size);
}

fec_packet_t *fec_decode(char *data, unsigned int len)
{
    if (!data || len < fecHeaderSizeTotal || len >= FEC_MAX_DATA_LEN)
        return NULL;

    fec_packet_t *pkt = fec_packet_new(FEC_MAX_DATA_LEN);
    if (!pkt)
    {
        fec_log(NULL, FEC_LOG_LEVEL_ERR, "---FEC---:fec_decode fec_packet_new error.");
        return NULL;
    }

    pkt->type = (data[0] & 0xC0) >> 6;
    pkt->dataShards = (data[0] & 0x3C) >> 2;
    pkt->parityShards = data[0] & 0x03;

    //data = decode8u(data, &pkt->type);
    data++;
    data = decode32u(data, &pkt->seqid);
    pkt->ts = get_timestamp();
    pkt->len = len - fecHeaderSize;
    memcpy(pkt->data, data, pkt->len);
    return pkt;
}

int fec_reconstruct(void *fec_, fec_packet_t *pkt_new, unsigned char **shards, unsigned char *marks, int nr_shards)
{
    if (!fec_ || !pkt_new || !shards || !marks)
        return -1;
    fec_t *fec = (fec_t *)fec_;

    if (!fec->rs)
        return -2;

    if (nr_shards < fec->totalShards)
    {
        fec_log(NULL, FEC_LOG_LEVEL_ERR, "---FEC---:fec_reconstruct error nr_shards=%d,fec=%p.", nr_shards, fec);
        return -3;
    }

    struct IQUEUEHEAD *p = NULL;
    struct IQUEUEHEAD *prev = NULL;

    //1、if or not expire
    unsigned long now = get_timestamp();
    if (now - fec->lastCheckTs >= fec->fecExpire)
    {
        for (p = fec->rx_queue.next; p != &fec->rx_queue;)
        {
            fec_packet_t *pkt = iqueue_entry(p, fec_packet_t, node);
            p = p->next;

            if (!pkt)
                continue;

            if (now - pkt->ts > fec->fecExpire)
            {
                iqueue_del(&pkt->node);
                fec_packet_delete(pkt);
                fec->rx_num--;
            }
        }
        fec->lastCheckTs = now;
    }

    //2、insert into ordered rx queue
    for (p = fec->rx_queue.prev; p != &fec->rx_queue; p = prev)
    {
        fec_packet_t *pkt = iqueue_entry(p, fec_packet_t, node);
        prev = p->prev;
        if (pkt_new->seqid == pkt->seqid)
            return -4; //repeat
        if (pkt_new->seqid > pkt->seqid)
            break;
    }

    iqueue_init(&pkt_new->node);
    iqueue_add(&pkt_new->node, p);
    fec->rx_num++;

    //3、shard range for current packet
    unsigned int shardBegin = pkt_new->seqid - pkt_new->seqid % fec->totalShards;
    unsigned int shardEnd = shardBegin + fec->totalShards - 1;
    int numShard = 0;
    int numDataShard = 0;
    int block_size = 0;

    fec_packet_t *pkt_begin = NULL;
    fec_packet_t *pkt_end = NULL;
    if (shardBegin == pkt_new->seqid)
        pkt_begin = pkt_new;
    if (shardEnd == pkt_new->seqid)
        pkt_end = pkt_new;

    numShard++;
    if (pkt_new->type == typeData)
        numDataShard++;
    marks[pkt_new->seqid % fec->totalShards] = 0;
    shards[pkt_new->seqid % fec->totalShards] = (unsigned char *)pkt_new->data;
    if (pkt_new->len > block_size)
        block_size = pkt_new->len;

    if (!pkt_end)
    {
        for (p = &pkt_new->node; p != &fec->rx_queue; p = p->next)
        {
            fec_packet_t *pkt = iqueue_entry(p, fec_packet_t, node);
            if (pkt->seqid == pkt_new->seqid)
                continue;
            if (pkt->seqid > shardEnd)
            {
                break;
            }
            else if (pkt->seqid <= shardEnd)
            {
                pkt_end = pkt;
                numShard++;
                if (pkt->type == typeData)
                    numDataShard++;
                marks[pkt->seqid % fec->totalShards] = 0;
                shards[pkt->seqid % fec->totalShards] = (unsigned char *)pkt->data;
                if (pkt->len > block_size)
                    block_size = pkt->len;
            }
        }
    }
    if (!pkt_begin)
    {
        for (p = &pkt_new->node; p != &fec->rx_queue; p = p->prev)
        {
            fec_packet_t *pkt = iqueue_entry(p, fec_packet_t, node);
            if (pkt->seqid == pkt_new->seqid)
                continue;
            if (pkt->seqid < shardBegin)
            {
                break;
            }
            else if (pkt->seqid >= shardBegin)
            {
                pkt_begin = pkt;
                numShard++;
                if (pkt->type == typeData)
                    numDataShard++;
                marks[pkt->seqid % fec->totalShards] = 0;
                shards[pkt->seqid % fec->totalShards] = (unsigned char *)pkt->data;
                if (pkt->len > block_size)
                    block_size = pkt->len;
            }
        }
    }

    if (!pkt_begin || !pkt_end)
    {
        fec_log(NULL, FEC_LOG_LEVEL_ERR, "---FEC---:unexpect error fec=%p.", fec);
        return -5;
    }

    int ret = 0;
    int delete = 0;
    if (numDataShard >= fec->dataShards) //no lost
    {
        delete = 1;
        ret = 0;
    }
    else if (numShard >= fec->dataShards) //recoverable
    {
        delete = 1;
        reed_solomon_reconstruct(fec->rs, shards, marks, nr_shards, block_size);
        ret = fec->dataShards - numDataShard;
    }
    else //not recoverable
    {
        ret = -6;
    }

    if (delete &&pkt_begin && pkt_end)
    {
        struct IQUEUEHEAD *p = &pkt_begin->node;
        struct IQUEUEHEAD *next = NULL;
        int end = 0;
        while (1)
        {
            if (p == &pkt_end->node)
                end = 1;
            next = p->next;
            fec_packet_t *pkt = iqueue_entry(p, fec_packet_t, node);
            iqueue_del(&pkt->node);
            fec_packet_delete(pkt);
            fec->rx_num--;
            if (end)
                break;
            p = next;
        }
    }

    // keep rxlimit
    if (fec->rx_num > fec->rxLimit)
    {
        fec_packet_t *pkt = iqueue_entry(fec->rx_queue.next, fec_packet_t, node);
        iqueue_del(&pkt->node);
        fec_packet_delete(pkt);
        fec->rx_num--;
    }

    return ret;
}

void fec_decode16u(char *p, unsigned short *w)
{
    decode16u(p, w);
}