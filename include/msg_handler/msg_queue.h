#ifndef __MSG_HANDLER_MSG_QUEUE__
#define __MSG_HANDLER_MSG_QUEUE__

#include <pthread.h>

struct mh_msg;

typedef void (*mq_msg_handler)(struct mh_msg *);

struct mh_msg {
    int id;
    int length;
    void *data;
    mq_msg_handler handler;
    struct mh_msg *next;
};

struct mh_msg_queue;

typedef struct mh_msg * (*mq_dequeue)(struct mh_msg_queue *);
typedef struct mh_msg * (*mq_enqueue)(
        struct mh_msg_queue *,
        struct mh_msg *);
typedef struct mh_msg * (*mq_alloc)();
typedef void (*mq_release)(struct mh_msg *);
typedef void (*mq_fill)(
        struct mh_msg *,
        int,
        int,
        void *,
        mq_msg_handler);

struct mh_msg_queue_action {
    mq_dequeue dequeue;
    mq_enqueue enqueue;
    mq_alloc alloc;
    mq_release release;
    mq_fill fill;
};

struct mh_looper;

struct mh_msg_queue {
    struct mh_looper *owner;
    int expired;
    struct mh_msg_queue_action action;
    struct mh_msg *root;
    struct mh_msg *tail;
    pthread_mutex_t queue_mtx;
};

void mh_msg_queue_init(struct mh_looper *, struct mh_msg_queue *);
void mh_msg_queue_uninit(struct mh_msg_queue *);

#endif
