#include <stdlib.h>
#include <msg_handler/utils.h>
#include <msg_handler/handler.h>

static void mh_handler_send_msg(
        struct mh_handler *handler, struct mh_msg *msg) {
    struct mh_looper *looper = handler->looper;
    looper->action.send_msg(looper, msg);
}

struct mh_msg * mh_handler_obtain_msg(struct mh_handler *handler) {
    struct mh_msg_queue *queue = &handler->looper->queue;
    return queue->action.alloc();
}

static void mh_handler_recycle_msg(
        struct mh_handler *handler, struct mh_msg *msg) {
    struct mh_msg_queue *queue = &handler->looper->queue;
    queue->action.release(msg);
}

static void mh_handler_looper_run(struct mh_handler *handler) {
    struct mh_looper *looper = handler->looper;
    looper->action.thread_run(looper);
}

static void mh_handler_register_socket(
        struct mh_handler *handler,
        int socket,
        enum SESSION_TYPE type,
        looper_msg_handler func1,
        looper_fd_release func2) {
    struct mh_looper *looper = handler->looper;
    looper->action.add_fd(looper, socket, type, func1, func2);
}

static void mh_handler_unregister_socket(
        struct mh_handler *handler,
        int socket,
        looper_msg_handler func) {
    struct mh_looper *looper = handler->looper;
    looper->action.rm_fd(looper, socket, func);
}

static void mh_handler_wait_looper(struct mh_handler *handler) {
    struct mh_looper *looper = handler->looper;
    looper->action.wait_looper(looper);
}

int mh_handler_init(struct mh_handler *handler) {
    int res = 0;
    handler->looper = (struct mh_looper *)calloc(1, sizeof(struct mh_looper));
    if (!handler->looper) {
        IF_LOGE("Maybe NO enough memory for looper");
        return -1;
    }
    handler->action.do_handler = 0;
    handler->action.handler_msg = 0;
    handler->action.connect_notify = 0;
    handler->action.connect_notify_data = 0;
    handler->action.send_msg = mh_handler_send_msg;
    handler->action.obtain_msg = mh_handler_obtain_msg;
    handler->action.recycle_msg = mh_handler_recycle_msg;
    handler->action.looper_run = mh_handler_looper_run;
    handler->action.register_socket = mh_handler_register_socket;
    handler->action.unregister_socket = mh_handler_unregister_socket;
    handler->action.wait_looper = mh_handler_wait_looper;
    res = mh_looper_init(handler, handler->looper);
    if (res) {
        IF_LOGE("Looper init fail");
    }
    return res;
}

// TODO : Thread safe?
void mh_handler_uninit(struct mh_handler *handler) {
    mh_looper_uninit(handler->looper);
    free(handler->looper);
    handler->looper = 0;
    handler->action.do_handler = 0;
    handler->action.handler_msg = 0;
}

// TODO : Thread safe? Should invoke before run.
void mh_handler_set_dh(
        struct mh_handler *handler, handler_do_handler dh) {
    handler->action.do_handler = dh;
}

// TODO : Thread safe? Should invoke before run.
void mh_handler_set_hm(
        struct mh_handler *handler, handler_handler_msg hm) {
    handler->action.handler_msg = hm;
}

// TODO : Thread safe? Should invoke before run.
void mh_handler_set_connect_notify(
        struct mh_handler *handler,
        handler_connect_notify notify,
        void *data) {
    handler->action.connect_notify = notify;
    handler->action.connect_notify_data = data;
}
