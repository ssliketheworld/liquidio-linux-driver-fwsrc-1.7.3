/*! \file   cavium-list.h
    \brief  Common: A linked list implementation used to manipulate internal
                    driver lists.
*/

#ifndef _CAVIUM_LIST_H
#define _CAVIUM_LIST_H


/*
 * This variable is enabled to turn on Cavium only list routines.
 * We can use either the functions/macros in linux/list.h or our own
 * definitions. If this lib goes into the driver, it uses linux/list.h.
 * If it goes into our onboard firmware, it uses our definitions.
 *
 * The test variable forces it to go to our definitions all of the time
 * for testing.
 */
/*#define CAVIUM_LIST_TEST 1*/


#if !defined(__linux__) || defined(CAVIUM_LIST_TEST)

/*#pragma message "Using Cavium definitions for lists"*/

/*
 * If using our list definitions, we need to create a list_head entry.
 * If, however, we are using our definitions but compiling under linux,
 * our definition is a duplicate. We use their list head define with our
 * functions.
 */
#ifndef linux

/*#pragma message "Have to create our own list_head definition"*/

struct list_head {
	struct list_head *next;
	struct list_head *prev;
};
#endif

/**
 * Macro initializes a list head.
 */
#define CAVIUM_LIST_HEAD_INIT(name) { &(name) &(name) }

/**
 * Macro declares a list head entry and initializes it to point at itself.
 * Note that the init is compile time (uses constants).
 */
#define CAVIUM_LIST_HEAD(name) struct list_head = CAVIUM_LIST_HEAD_INIT()

static inline void cavium_init_list_head(struct list_head * ptr)
{
	ptr->next = ptr;
	ptr->prev = ptr;
}

/**
 * Macro initalizes list head. This is a runtime initialization.
 */
#define CAVIUM_INIT_LIST_HEAD(name) cavium_init_list_head(name)

/**
 * Macro to check if list is empty.
 */
#define CAVIUM_LIST_EMPTY(head)		((head)->next == (head))

static inline
    void cavium_list_add_head(struct list_head * node, struct list_head * head)
{
	head->next->prev = node;
	node->next = head->next;
	head->next = node;
	node->prev = head;
}

/**
 * Macro to add list entry to the head of a list.
 */
#define CAVIUM_LIST_ADD_HEAD(node, head) cavium_list_add_head(node, head)

static inline
    void cavium_list_add_tail(struct list_head * node, struct list_head * head)
{
	head->prev->next = node;
	node->prev = head->prev;
	head->prev = node;
	node->next = head;
}

/**
 * Macro to add list entry to the tail of a list.
 */
#define CAVIUM_LIST_ADD_TAIL(node, head) cavium_list_add_tail(node, head)

/* Remove the node passed as argument from its list. */
/* Remove the node passed as argument from its list. */
static inline void cavium_list_del(struct list_head * node)
{
	node->next->prev = node->prev;
	node->prev->next = node->next;
}

/*
 * Macro to delete single node.
 */
#define CAVIUM_LIST_DEL(node) cavium_list_del(node)

#define CAVIUM_LIST_FOR_EACH(tmp, head)  \
	for (tmp = (head)->next; tmp != (head); tmp = tmp->next)

#define CAVIUM_LIST_FOR_EACH_SAFE(tmp, tmp2, head)  \
	for (tmp = (head)->next, tmp2 = tmp->next; tmp != (head); tmp = tmp2, tmp2 = tmp->next)

/**
 * Move nodes from list2 to list1. list1 must be empty. list2 will be empty
 * when this call returns.
 */
static inline
    void cavium_list_move(struct list_head * list1, struct list_head * list2)
{
	if (list2->next != list2) {
		list1->next = list2->next;
		list1->next->prev = list1;
		list1->prev = list2->prev;
		list1->prev->next = list1;
	}

	list2->next = list2->prev = list2;
}

#define CAVIUM_LIST_FIRST_ENTRY(ptr, type, elem) \
	(type *)((char *)((ptr)->next) - offsetof(type, elem))

/*
 * Macro to retrieve the next entry in a list.
 */
#define CAVIUM_LIST_NEXT(ptr) (ptr)->next

#else /* linux lists */

/*#pragma message "Using Linux definitions for lists"*/

#include <linux/types.h>
#include <linux/list.h>


/**
 * Macro initializes a list head.
 */
#define CAVIUM_LIST_HEAD_INIT(name) LIST_HEAD_INIT(name)

/**
 * Macro declares a list head entry and initializes it to point at itself.
 * Note that the init is compile time (uses constants).
 */
#define CAVIUM_LIST_HEAD(name) LIST_HEAD(name)

/**
 * Macro initalizes list head. This is a runtime initialization.
 */
#define CAVIUM_INIT_LIST_HEAD(name) INIT_LIST_HEAD(name)

/**
 * Macro to check if list is empty.
 */
#define CAVIUM_LIST_EMPTY(head)		list_empty(head)

/**
 * Macro to add list entry to the head of a list.
 */
#define CAVIUM_LIST_ADD_HEAD(node, head) list_add(node, head)

/**
 * Macro to add list entry to the tail of a list.
 */
#define CAVIUM_LIST_ADD_TAIL(node, head) list_add_tail(node, head)

/* Remove the node passed as argument from its list. */
/*
 * Macro to delete single node.
 */
#define CAVIUM_LIST_DEL(node) list_del(node)

/*
 * Macro to iterate through list.
 */
#define CAVIUM_LIST_FOR_EACH(tmp, head)  list_for_each(tmp, head)

/*
 * Macro to iterate through list.
 */
#define CAVIUM_LIST_FOR_EACH_SAFE(tmp, tmp2, head)  \
	for (tmp = (head)->next, tmp2 = tmp->next; tmp != (head); tmp = tmp2, tmp2 = tmp->next)

#define CAVIUM_LIST_FIRST_ENTRY(ptr, type, elem) \
	list_first_entry(ptr, type, elem)

/*
 * Macro to retrieve the next entry in a list.
 */
#define CAVIUM_LIST_NEXT(ptr) (ptr)->next

#endif /* __linux__ */

#endif /* _CAVIUM_LIST_H */
