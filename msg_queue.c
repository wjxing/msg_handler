#include <stdlib.h>
#include <strings.h>
#include <msg_handler/utils.h>
#include <msg_handler/msg_queue.h>

static struct mh_msg *mh_msg_queue_dequeue(struct mh_msg_queue *queue) {
    struct mh_msg *msg = 0;

    pthread_mutex_lock(&queue->queue_mtx);
    if (queue->expired) {
        IF_LOGW("The message queue is expired");
        pthread_mutex_unlock(&queue->queue_mtx);
        return 0;
    }
    if (!queue->root || !queue->tail) {
        IF_LOGW("Empty msg queue");
        pthread_mutex_unlock(&queue->queue_mtx);
        return 0;
    }
    msg = queue->root;
    msg->next = 0;
    if (queue->root == queue->tail) {
        msg = queue->root;
        queue->root = queue->tail = 0;
        pthread_mutex_unlock(&queue->queue_mtx);
        return msg;
    }
    queue->root = msg->next;

    pthread_mutex_unlock(&queue->queue_mtx);
    return msg;
}

static struct mh_msg * mh_msg_queue_enqueue(
        struct mh_msg_queue *queue, struct mh_msg *msg) {
    msg->next = 0;

    pthread_mutex_lock(&queue->queue_mtx);
    if (queue->expired) {
        IF_LOGW("The message queue is expired");
        pthread_mutex_unlock(&queue->queue_mtx);
        return 0;
    }
    if (!queue->root || !queue->tail) {
        queue->root = queue->tail = msg;
        pthread_mutex_unlock(&queue->queue_mtx);
        return msg;
    }
    queue->tail->next = msg;
    queue->tail = msg;

    pthread_mutex_unlock(&queue->queue_mtx);
    return msg;
}

static struct mh_msg * mh_msg_queue_alloc() {
    struct mh_msg *msg = (struct mh_msg *)calloc(1, sizeof(struct mh_msg));
    if (!msg) {
        IF_LOGE("Maybe NO enough memory for msg");
    }
    return msg;
}

static void mh_msg_queue_release(struct mh_msg *msg) {
    if (msg->data)
        free(msg->data);
    if (msg->next)
        IF_LOGW("The msg's next NOT clear");
    free(msg);
}

static void mh_msg_queue_fill(
        struct mh_msg *msg, int id, int length, void *data, mq_msg_handler handler) {
    msg->id = id;
    msg->length = length;
    msg->data = data;
    msg->handler = handler;
}

void mh_msg_queue_init(struct mh_looper *owner, struct mh_msg_queue *queue) {
    bzero(queue, sizeof(struct mh_msg_queue));
    pthread_mutex_init(&queue->queue_mtx, 0);

    pthread_mutex_lock(&queue->queue_mtx);
    queue->owner = owner;
    queue->action.dequeue = mh_msg_queue_dequeue;
    queue->action.enqueue = mh_msg_queue_enqueue;
    queue->action.alloc = mh_msg_queue_alloc;
    queue->action.release = mh_msg_queue_release;
    queue->action.fill = mh_msg_queue_fill;
    queue->expired = 0;
    pthread_mutex_lock(&queue->queue_mtx);
}

void mh_msg_queue_uninit(struct mh_msg_queue *queue) {
    pthread_mutex_lock(&queue->queue_mtx);
    if (queue->root || queue->tail) {
        IF_LOGW("There are messages in message queue, should be release?");
        struct mh_msg *msg;
        while ((msg = queue->root)) {
            queue->action.release(msg);
            queue->root = msg->next;
        }
        queue->tail = 0;
    }
    queue->owner = 0;
    queue->expired = 1;
    pthread_mutex_unlock(&queue->queue_mtx);

    pthread_mutex_destroy(&queue->queue_mtx);
}
