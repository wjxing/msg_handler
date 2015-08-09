#ifndef __MSG_HANDLER_HANDLER__
#define __MSG_HANDLER_HANDLER__

#include <msg_handler/looper.h>
#include <msg_handler/msg_queue.h>

struct mh_handler;

typedef void (*handler_do_handler)(struct mh_handler *);
typedef void (*handler_handler_msg)(struct mh_handler *, struct mh_msg *);
typedef void (*handler_send_msg)(struct mh_handler *, struct mh_msg *);
typedef struct mh_msg * (*handler_obtain_msg)(struct mh_handler *);
typedef void (*handler_recycle_msg)(
        struct mh_handler *,
        struct mh_msg *);
typedef void (*handler_looper_run)(struct mh_handler *);
typedef void (*handler_register_socket)(
        struct mh_handler *,
        int,
        enum SESSION_TYPE,
        looper_msg_handler,
        looper_fd_release);
typedef void (*handler_unregister_socket)(
        struct mh_handler *,
        int,
        looper_msg_handler);
typedef void (*handler_wait_looper)(struct mh_handler *);
typedef void (*handler_connect_notify)(void *, int);

struct mh_handler_action {
    handler_do_handler do_handler;
    handler_handler_msg handler_msg;
    handler_send_msg send_msg;
    handler_obtain_msg obtain_msg;
    handler_recycle_msg recycle_msg;
    handler_looper_run looper_run;
    handler_register_socket register_socket;
    handler_unregister_socket unregister_socket;
    handler_wait_looper wait_looper;
    handler_connect_notify connect_notify;
    void *connect_notify_data;
};

struct mh_handler {
    struct mh_handler_action action;
    struct mh_looper *looper;
};

int mh_handler_init(struct mh_handler *);
void mh_handler_uninit(struct mh_handler *);

void mh_handler_set_dh(struct mh_handler *, handler_do_handler);
void mh_handler_set_hm(struct mh_handler *, handler_handler_msg);
void mh_handler_set_connect_notify(
        struct mh_handler *,
        handler_connect_notify,
        void *);

#endif
