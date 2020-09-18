#ifndef FEC_UTILS_H
#define FEC_UTILS_H

//=====================================================================
// QUEUE DEFINITION
//=====================================================================
#ifndef __IQUEUE_DEF__
#define __IQUEUE_DEF__

struct IQUEUEHEAD
{
	struct IQUEUEHEAD *next, *prev;
};

typedef struct IQUEUEHEAD iqueue_head;

//---------------------------------------------------------------------
// queue init
//---------------------------------------------------------------------
#define IQUEUE_HEAD_INIT(name) \
	{                          \
		&(name), &(name)       \
	}
#define IQUEUE_HEAD(name) \
	struct IQUEUEHEAD name = IQUEUE_HEAD_INIT(name)

#define IQUEUE_INIT(ptr) ( \
	(ptr)->next = (ptr), (ptr)->prev = (ptr))

#define IOFFSETOF(TYPE, MEMBER) ((size_t) & ((TYPE *)0)->MEMBER)

#define ICONTAINEROF(ptr, type, member) ( \
	(type *)(((char *)((type *)ptr)) - IOFFSETOF(type, member)))

#define IQUEUE_ENTRY(ptr, type, member) ICONTAINEROF(ptr, type, member)

//---------------------------------------------------------------------
// queue operation
//---------------------------------------------------------------------
#define IQUEUE_ADD(node, head) (                        \
	(node)->prev = (head), (node)->next = (head)->next, \
	(head)->next->prev = (node), (head)->next = (node))

#define IQUEUE_ADD_TAIL(node, head) (                   \
	(node)->prev = (head)->prev, (node)->next = (head), \
	(head)->prev->next = (node), (head)->prev = (node))

#define IQUEUE_DEL_BETWEEN(p, n) ((n)->prev = (p), (p)->next = (n))

#define IQUEUE_DEL(entry) (              \
	(entry)->next->prev = (entry)->prev, \
	(entry)->prev->next = (entry)->next, \
	(entry)->next = 0, (entry)->prev = 0)

#define IQUEUE_DEL_INIT(entry) \
	do                         \
	{                          \
		IQUEUE_DEL(entry);     \
		IQUEUE_INIT(entry);    \
	} while (0)

#define IQUEUE_IS_EMPTY(entry) ((entry) == (entry)->next)

#define iqueue_init IQUEUE_INIT
#define iqueue_entry IQUEUE_ENTRY
#define iqueue_add IQUEUE_ADD
#define iqueue_add_tail IQUEUE_ADD_TAIL
#define iqueue_del IQUEUE_DEL
#define iqueue_del_init IQUEUE_DEL_INIT
#define iqueue_is_empty IQUEUE_IS_EMPTY

#define IQUEUE_FOREACH(iterator, head, TYPE, MEMBER)            \
	for ((iterator) = iqueue_entry((head)->next, TYPE, MEMBER); \
		 &((iterator)->MEMBER) != (head);                       \
		 (iterator) = iqueue_entry((iterator)->MEMBER.next, TYPE, MEMBER))

#define iqueue_foreach(iterator, head, TYPE, MEMBER) \
	IQUEUE_FOREACH(iterator, head, TYPE, MEMBER)

#define iqueue_foreach_entry(pos, head) \
	for ((pos) = (head)->next; (pos) != (head); (pos) = (pos)->next)

#define __iqueue_splice(list, head)                              \
	do                                                           \
	{                                                            \
		iqueue_head *first = (list)->next, *last = (list)->prev; \
		iqueue_head *at = (head)->next;                          \
		(first)->prev = (head), (head)->next = (first);          \
		(last)->next = (at), (at)->prev = (last);                \
	} while (0)

#define iqueue_splice(list, head)        \
	do                                   \
	{                                    \
		if (!iqueue_is_empty(list))      \
			__iqueue_splice(list, head); \
	} while (0)

#define iqueue_splice_init(list, head) \
	do                                 \
	{                                  \
		iqueue_splice(list, head);     \
		iqueue_init(list);             \
	} while (0)

#endif

//---------------------------------------------------------------------
// WORD ORDER
//---------------------------------------------------------------------
#ifndef IWORDS_BIG_ENDIAN
#ifdef _BIG_ENDIAN_
#if _BIG_ENDIAN_
#define IWORDS_BIG_ENDIAN 1
#endif
#endif
#ifndef IWORDS_BIG_ENDIAN
#if defined(__hppa__) ||                                           \
	defined(__m68k__) || defined(mc68000) || defined(_M_M68K) ||   \
	(defined(__MIPS__) && defined(__MISPEB__)) ||                  \
	defined(__ppc__) || defined(__POWERPC__) || defined(_M_PPC) || \
	defined(__sparc__) || defined(__powerpc__) ||                  \
	defined(__mc68000__) || defined(__s390x__) || defined(__s390__)
#define IWORDS_BIG_ENDIAN 1
#endif
#endif
#ifndef IWORDS_BIG_ENDIAN
#define IWORDS_BIG_ENDIAN 0
#endif
#endif

#endif //KCP_ENCODING_H
