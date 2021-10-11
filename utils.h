#ifndef _UTILS_H
#define _UTILS_H

#define NUM_ENTRIES(x) (int)(sizeof(x) / sizeof(x[0]))

typedef __signed__ char __s8;
typedef unsigned char __u8;

typedef __signed__ short __s16;
typedef unsigned short __u16;

typedef __signed__ int __s32;
typedef unsigned int __u32;

#ifdef __GNUC__
__extension__ typedef __signed__ long long __s64;
__extension__ typedef unsigned long long __u64;
#else
typedef __signed__ long long __s64;
typedef unsigned long long __u64;
#endif

#define u8	__u8
#define u16	__u16
#define u32	__u32
#define u64	__u64

/* complex for_each that checkpatch has issues with but is correct and
 * used in multiple include files in the kernel
 */
#define for_each_dir(entry, subdir)			\
	while ((entry = readdir(subdir)) != NULL)	\
		if (strcmp(entry->d_name, ".") &&	\
		    strcmp(entry->d_name, ".."))

/* simple linked list functions */

struct linked_list {
	struct linked_list *next, *prev;
};

#define LINKED_LIST_INIT(name) { &(name), &(name) }

#define LINKED_LIST(name) \
	struct linked_list name = LINKED_LIST_INIT(name)

#define INIT_LINKED_LIST(ptr) do { \
	(ptr)->next = (ptr); (ptr)->prev = (ptr); \
} while (0)

static inline void __list_add(struct linked_list *entry,
			      struct linked_list *prev,
			      struct linked_list *next)
{
	next->prev = entry;
	entry->next = next;
	entry->prev = prev;
	prev->next = entry;
}

static inline void list_add(struct linked_list *entry, struct linked_list *list)
{
	__list_add(entry, list, list->next);
}

static inline void list_add_tail(struct linked_list *entry,
				 struct linked_list *list)
{
	__list_add(entry, list->prev, list);
}

static inline void list_del(struct linked_list *entry)
{
	entry->next->prev = entry->prev;
	entry->prev->next = entry->next;
}

static inline int list_empty(const struct linked_list *list)
{
	return list->next == list;
}

#define offset_of(type, member) ((size_t) &((type *)0)->member)

#define container_of(ptr, type, member) ({				   \
	 const typeof(((type *)0)->member) (*__mptr) = (ptr);		   \
		 (type *)((char *) __mptr - offset_of(type, member));	   \
	})

#define list_entry(entry, type, member) container_of(entry, type, member)

#define list_first_entry(ptr, type, member)				   \
	list_entry((ptr)->next, type, member)

#define list_for_each(entry, list)					   \
	for (entry = (list)->next; entry != (list); entry = entry->next)

#define list_for_each_safe(entry, tmp, list)				   \
	for (entry = (list)->next, tmp = entry->next; entry != (list);     \
	     entry = tmp, tmp = entry->next)

#define list_for_each_entry(entry, list, member)			   \
	for (entry = list_entry((list)->next, typeof(*entry), member);     \
	     &entry->member != (list);					   \
	     entry = list_entry(entry->member.next, typeof(*entry), member))

#define list_for_each_entry_safe(entry, tmp, list, member)		   \
	for (entry = list_entry((list)->next, typeof(*entry), member),     \
	     tmp = list_entry(entry->member.next, typeof(*entry), member); \
	     &entry->member != (list);					   \
	     entry = tmp,						   \
	     tmp = list_entry(tmp->member.next, typeof(*tmp), member))

#define print_debug(f, x...) \
	do { \
		if (debug) { \
			printf("%s(%d) " f "\n", __func__, __LINE__, ##x); \
			fflush(stdout); \
		} \
	} while (0)
#define print_trace()\
	do { \
		printf("%s(%d)\n", __func__, __LINE__); \
		fflush(stdout); \
	} while (0)
#define print_info(f, x...)\
	do { \
		printf(f "\n", ##x); \
		fflush(stdout); \
	} while (0)
#define print_err(f, x...)\
	do { \
		fprintf(stderr, "Error: " f "\n", ##x); \
		fflush(stderr); \
	} while (0)
#define print_errno(s, e)\
	print_err("%s - %s (%d)", s, strerror(((e) < 0) ? -(e) : (e)), e)

#define UNUSED(x) ((void) x)

#define min(x, y) ((x < y) ? x : y)

#define __round_mask(x, y) ((__typeof__(x))((y) - 1))
#define round_up(x, y) ((((x) - 1) | __round_mask(x, y)) + 1)

#endif
