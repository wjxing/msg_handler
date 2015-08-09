#ifndef __MSG_HANDLER_LOOPER__
#define __MSG_HANDLER_LOOPER__

#include <stdbool.h>
#include <msg_handler/msg_queue.h>

#define MAX_SESSION_NUM 5
// TODO :enough?
#define MAX_DATA_SIZE   1024

struct mh_handler;
struct mh_looper;

#define looper_msg_handler mq_msg_handler

enum SESSION_TYPE {
    SESSION_TCP_SERVER      = 0,
    SESSION_TCP_CLIENT,
    SESSION_TCP_SELF_PROCESS, // self process recv data
    SESSION_UDP,
    SESSION_NONE,
};

typedef void (*looper_thread_run)(struct mh_looper *);
typedef void (*looper_wake_up)(struct mh_looper *);
typedef void (*looper_fd_handler)(int);
typedef void (*looper_fd_release)(int);
typedef int (*looper_add_fd)(
        struct mh_looper *,
        int,
        enum SESSION_TYPE,
        looper_msg_handler,
        looper_fd_release);
typedef int (*looper_add_self_process_fd)(
        struct mh_looper *,
        int,
        looper_fd_handler,
        looper_fd_release);
typedef int (*looper_rm_fd)(
        struct mh_looper *,
        int,
        looper_msg_handler);
typedef int (*looper_send_msg)(struct mh_looper *, struct mh_msg *);
typedef void (*looper_wait_looper)(struct mh_looper *);

struct mh_looper_action {
    looper_thread_run thread_run;
    looper_wake_up wake_up;
    looper_add_fd add_fd;
    looper_add_self_process_fd add_self_process_fd;
    looper_rm_fd rm_fd;
    looper_send_msg send_msg;
    looper_wait_looper wait_looper;
};

struct mh_looper_session {
    int fd;
    // Private data, do NOT modify out of file
    enum SESSION_TYPE type;
    union {
        looper_msg_handler msg_handler;
        looper_fd_handler fd_handler;
    };
    looper_fd_release fd_release;
};

struct mh_looper {
    //reverse reference
    struct mh_handler *owner;
    struct mh_msg_queue queue;
    struct mh_looper_action action;
    bool thread_alive;
    pthread_t thread;
    // TODO : delete?
    pthread_mutex_t session_mtx;
    int ctrl_pipe[2];
    // TODO : use list to fix this limit
    struct mh_looper_session fds[MAX_SESSION_NUM];
};

int mh_looper_init(struct mh_handler *, struct mh_looper *);
void mh_looper_uninit(struct mh_looper *);

#endif
