#include <stdlib.h>
#include <unistd.h>
#include <strings.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <msg_handler/utils.h>
#include <msg_handler/handler.h>
#include <msg_handler/looper.h>

enum LOOPER_CTRL_CMD {
    CTRL_EVENT  = 0,
    CTRL_ADD_FD,
    CTRL_RM_FD,
    CTRL_STOP,
};

struct ctrl_add_fd {
    char ctrl;
    struct mh_looper_session session;
};

#define ctrl_rm_fd ctrl_add_fd

#define CTRL_EVENT_SIZE     1
#define CTRL_ADD_FD_SIZE    sizeof(struct ctrl_add_fd)
#define CTRL_RM_FD_SIZE     sizeof(struct ctrl_rm_fd)

// TODO :
#define CTRL_MAX_SIZE CTRL_ADD_FD_SIZE

static void mh_looper_poll(struct mh_looper *, struct timeval *, int);

static void mh_looper_release_session(struct mh_looper_session *session) {
    if (0 <= session->fd) {
        if (session->fd_release)
            session->fd_release(session->fd);
        else
            close(session->fd);
    }
    session->fd = -1;
    if (session->type == SESSION_TCP_SERVER ||
            session->type == SESSION_TCP_CLIENT) {
        session->msg_handler = NULL;
    } else if (session->type == SESSION_TCP_SELF_PROCESS) {
        session->fd_handler = NULL;
    } else
        IF_LOGE("Release the wrong type session");
    session->fd_release = NULL;
    session->type = SESSION_NONE;
}

static void mh_looper_process_msg(struct mh_looper *looper) {
    struct mh_msg_queue *queue = &looper->queue;
    struct mh_handler *handler = looper->owner;
    struct mh_msg *msg;
    while ((msg = queue->action.dequeue(queue))) {
        if (msg->handler != NULL) {
            msg->handler(msg);
        } else if (handler->action.handler_msg != NULL) {
            handler->action.handler_msg(handler, msg);
        }
        struct timeval timeout;
        bzero(&timeout, sizeof(struct timeval));
        mh_looper_poll(looper, &timeout, 1);
        queue->action.release(msg);
    }
}

static struct mh_looper_session * mh_looper_find_unuse_session(
        struct mh_looper *looper,
        enum SESSION_TYPE type) {
    int index;
    for (index = 0; index < MAX_SESSION_NUM; index++) {
        if (looper->fds[index].fd < 0 &&
                looper->fds[index].type == SESSION_NONE) {
            struct mh_looper_session *session = &looper->fds[index];
            session->fd = -1;
            session->type = type;
            return session;
        }
    }
    return NULL;
}

static struct mh_looper_session * mh_looper_give_back_session(
        struct mh_looper *looper,
        struct mh_looper_session *session) {
    int index;
    for (index = 0; index < MAX_SESSION_NUM; index++) {
        if (looper->fds[index].fd == session->fd &&
                looper->fds[index].type == session->type) {
            struct mh_looper_session *session = &looper->fds[index];
            mh_looper_release_session(session);
            return session;
        }
    }
    return NULL;
}

static void mh_looper_process_ctrl(
        struct mh_looper *looper,
        int ignore_ctrl_event) {
    int pipe_read = looper->ctrl_pipe[0];
    char cmd[CTRL_MAX_SIZE];
    ssize_t res = read(pipe_read, cmd, CTRL_MAX_SIZE);
    if (res <= 0) {
        IF_LOGE("Process ctrl cmd errpr (%s)", strerror(errno));
        return;
    } else {
        IF_LOGI("Read ctrl size %ld", res);
    }
    switch (cmd[0]) {
      case CTRL_EVENT: {
        if (ignore_ctrl_event) {
            IF_LOGI("Ignore this ctrl event");
            break;
        }
        if (res < CTRL_EVENT_SIZE) {
            IF_LOGE("Read less ctrl event size");
            break;
        }
        IF_LOGI("Come the CTRL_EVENT");
        mh_looper_process_msg(looper);
        break;
      }
      case CTRL_ADD_FD: {
        if (res < (signed)CTRL_ADD_FD_SIZE) {
            IF_LOGE("Read less ctrl add fd size");
            break;
        }
        struct ctrl_add_fd *ctrl_msg =
            (struct ctrl_add_fd *)cmd;
        struct mh_looper_session *session =
            mh_looper_find_unuse_session(looper, SESSION_TCP_SERVER);
        if (!session) {
            IF_LOGE("TCP server NO enough sock seat");
            return;
        }
        session->fd = ctrl_msg->session.fd;
        session->type = ctrl_msg->session.type;
        if (session->type == SESSION_TCP_SERVER ||
                session->type == SESSION_TCP_CLIENT) {
            session->msg_handler = ctrl_msg->session.msg_handler;
            session->fd_release = ctrl_msg->session.fd_release;
        } else if (session->type == SESSION_TCP_SELF_PROCESS) {
            session->fd_handler = ctrl_msg->session.fd_handler;
            session->fd_release = ctrl_msg->session.fd_release;
        } else
            IF_LOGE("Wrong add fd session type");
        IF_LOGI("Come the CTRL_ADD_FD (%d) type (%d)",
            session->fd, session->type);
        break;
      }
      case CTRL_RM_FD: {
        if (res < (signed)CTRL_RM_FD_SIZE) {
            IF_LOGE("Read less ctrl rm fd size");
            break;
        }
        struct ctrl_rm_fd *ctrl_msg =
            (struct ctrl_rm_fd *)cmd;
        struct mh_looper_session *session =
            mh_looper_give_back_session(looper, &ctrl_msg->session);
        if (!session) {
            IF_LOGE("NO that TCP server sock (%d)", ctrl_msg->session.fd);
        }
        IF_LOGI("Come the CTRL_RM_FD");
        break;
      }
      case CTRL_STOP: {
        looper->thread_alive = false;
      }
    }
}

// TODO : need sync with client code
#define SAY_GOODBYE         "!@#$GoodBye$#@!"
#define SAY_GOODBYE_SIZE    sizeof(SAY_GOODBYE)
static void mh_looper_say_goodbye(int sock) {
    send(sock, SAY_GOODBYE, SAY_GOODBYE_SIZE, 0);
    close(sock);
}

static void mh_looper_process_tcp_server(
        struct mh_looper *looper,
        struct mh_looper_session *session) {
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(struct sockaddr_in);
    int sock = accept(session->fd, (struct sockaddr *)&addr, &addrlen);
    if (sock < 0) {
        IF_LOGE("TCP server get negative sock fd (%s)", strerror(errno));
        return;
    }
    if (!session->msg_handler) {
        IF_LOGE("TCP server NOT ready");
        mh_looper_say_goodbye(sock);
        return;
    }
    struct mh_looper_session *new_session =
        mh_looper_find_unuse_session(looper, SESSION_TCP_CLIENT);
    if (!new_session) {
        IF_LOGE("TCP server NO enough sock seat, say goodbye to client");
        mh_looper_say_goodbye(sock);
        return;
    }
    new_session->fd = sock;
    new_session->msg_handler = session->msg_handler;
    new_session->fd_release = session->fd_release;
    struct mh_handler *owner = looper->owner;
    if (owner->action.connect_notify) {
        owner->action.connect_notify(
                owner->action.connect_notify_data, session->fd);
    }
    IF_LOGI("TCP server get this client (%d)", sock);
}

static void mh_looper_process_tcp_client(
        struct mh_looper *looper,
        struct mh_looper_session *session) {
    char data[MAX_DATA_SIZE];
    bzero(data, MAX_DATA_SIZE);
    ssize_t size = recv(session->fd, data, MAX_DATA_SIZE, 0);
    if (size <= 0) {
        if (errno == EINTR
                /* || errno == EAGAIN || errno == EWOULDBLOCK */) {
            IF_LOGW("TCP recv returned by interrupt");
            return;
        }
        IF_LOGI("The TCP connection may be disconnect, so release it");
        mh_looper_release_session(session);
        return;
    }
    struct mh_msg *msg = looper->queue.action.alloc();
    if (!msg) {
        IF_LOGE("NO enough memory to process the client message");
        return;
    }
    char *cpdata = (char *)malloc(size);
    if (!cpdata) {
        IF_LOGE("NO enough memory to copy the client data");
        looper->queue.action.release(msg);
        return;
    }
    memcpy(cpdata, data, size);
    looper->queue.action.fill(
            msg, session->fd, size, cpdata, session->msg_handler);
    looper->queue.action.enqueue(&looper->queue, msg);
    looper->action.wake_up(looper);
}

// Maybe it is NOT fair for msg queue orders.
static void mh_looper_process_tcp_self_process(
        struct mh_looper *looper,
        struct mh_looper_session *session) {
    if (!session->fd_handler) {
        IF_LOGW("The added session (%d) NO handler", session->fd);
        return;
    }
    session->fd_handler(session->fd);
}

static void mh_looper_process_session(
        struct mh_looper *looper,
        struct mh_looper_session *session) {
    enum SESSION_TYPE type = session->type;
    switch (type) {
      case SESSION_TCP_SERVER:
        mh_looper_process_tcp_server(looper, session);
        break;
      case SESSION_TCP_CLIENT:
        mh_looper_process_tcp_client(looper, session);
        break;
      case SESSION_TCP_SELF_PROCESS:
        mh_looper_process_tcp_self_process(looper, session);
        break;
// TODO : implement
      case SESSION_UDP:
        break;
      default:
        IF_LOGI("NOT support this session type (%d)", type);
        break;
    }
}

static void mh_looper_poll(
        struct mh_looper *looper,
        struct timeval *timeout,
        int ignore_ctrl_event) {
    int index, ret;
    int max = looper->ctrl_pipe[0];
    fd_set read_fds;

    FD_ZERO(&read_fds);
    FD_SET(looper->ctrl_pipe[0], &read_fds);
    for (index = 0; index < MAX_SESSION_NUM; index++) {
        int fd = looper->fds[index].fd;
        if (fd < 0) {
            continue;
        }
        IF_LOGI("Looper fd (%d) with type (%d)",
                fd, looper->fds[index].type);
        if (max < fd) {
            max = fd;
        }
        FD_SET(fd, &read_fds);
    }
    IF_LOGI("Looper select event wait");
    // TODO : error handle
    if ((ret = select(max + 1, &read_fds, NULL, NULL, timeout)) <= 0) {
        IF_LOGE("Select fail or NO fd trigger (%s)", strerror(errno));
        return;
    }

    IF_LOGI("Looper select event come");

    if (FD_ISSET(looper->ctrl_pipe[0], &read_fds)) {
        mh_looper_process_ctrl(looper, ignore_ctrl_event);
    }
    for (index = 0; index < MAX_SESSION_NUM; index++) {
        int fd = looper->fds[index].fd;
        if (fd <= 0) {
            continue;
        }
        if (FD_ISSET(fd, &read_fds)) {
            mh_looper_process_session(looper, &looper->fds[index]);
        }
    }
}

static void * mh_looper_looper(void *data) {
    struct mh_looper *looper = (struct mh_looper *)data;
    struct mh_handler *handler = looper->owner;
    while (looper->thread_alive) {
        if (handler->action.do_handler) {
            handler->action.do_handler(handler);
        } else {
            mh_looper_poll(looper, NULL, 0);
        }
    }
    close(looper->ctrl_pipe[0]);
    close(looper->ctrl_pipe[1]);
    looper->ctrl_pipe[0] = -1;
    looper->ctrl_pipe[1] = -1;
    int index;
    for (index = 0; index < MAX_SESSION_NUM; index++) {
        mh_looper_release_session(&(looper->fds[index]));
    }
    pthread_exit(NULL);
    return 0;
}

static void mh_looper_thread_run(struct mh_looper *looper) {
    // TODO : error handle
    pipe(looper->ctrl_pipe);
    looper->thread_alive = true;
    pthread_create(&looper->thread, NULL, mh_looper_looper, looper);
}

static void mh_looper_wake_up(struct mh_looper *looper) {
    char ctrl = CTRL_EVENT;
    write(looper->ctrl_pipe[1], &ctrl, 1);
}

static void mh_looper_stop(struct mh_looper *looper) {
    char ctrl = CTRL_STOP;
    write(looper->ctrl_pipe[1], &ctrl, 1);
}

static int mh_looper_add_fd(
        struct mh_looper *looper,
        int fd,
        enum SESSION_TYPE type,
        looper_msg_handler handler,
        looper_fd_release release) {
    struct ctrl_add_fd ctrl_msg;
    ctrl_msg.ctrl = CTRL_ADD_FD;
    ctrl_msg.session.fd = fd;
    ctrl_msg.session.type = type;
    ctrl_msg.session.msg_handler = handler;
    ctrl_msg.session.fd_release = release;
    write(looper->ctrl_pipe[1], &ctrl_msg, sizeof(struct ctrl_add_fd));
    return 0;
}

static int mh_looper_add_self_process_fd(
        struct mh_looper *looper,
        int fd,
        looper_fd_handler handler,
        looper_fd_release release) {
    struct ctrl_add_fd ctrl_msg;
    ctrl_msg.ctrl = CTRL_ADD_FD;
    ctrl_msg.session.fd = fd;
    ctrl_msg.session.type = SESSION_TCP_SELF_PROCESS;
    ctrl_msg.session.fd_handler = handler;
    ctrl_msg.session.fd_release = release;
    write(looper->ctrl_pipe[1], &ctrl_msg, sizeof(struct ctrl_add_fd));
    return 0;
}

// TODO : rm client?
static int mh_looper_rm_fd(
        struct mh_looper *looper,
        int fd,
        looper_msg_handler handler) {
    struct ctrl_rm_fd ctrl_msg;
    ctrl_msg.ctrl = CTRL_RM_FD;
    ctrl_msg.session.fd = fd;
    write(looper->ctrl_pipe[1], &ctrl_msg, sizeof(struct ctrl_rm_fd));
    return 0;
}

static int mh_looper_send_msg(
        struct mh_looper *looper,
        struct mh_msg *msg) {
    struct mh_msg_queue *queue = &looper->queue;
    queue->action.enqueue(queue, msg);
    looper->action.wake_up(looper);
    return 0;
}

static void mh_looper_wait_looper(struct mh_looper *looper) {
    void *res;
    pthread_join(looper->thread, &res);
}

int mh_looper_init(
        struct mh_handler *owner, struct mh_looper *looper) {
    int index;
    pthread_mutex_init(&looper->session_mtx, 0);
    looper->owner = owner;
    looper->action.thread_run = mh_looper_thread_run;
    looper->action.wake_up = mh_looper_wake_up;
    looper->action.add_fd = mh_looper_add_fd;
    looper->action.add_self_process_fd = mh_looper_add_self_process_fd;
    looper->action.rm_fd = mh_looper_rm_fd;
    looper->action.send_msg = mh_looper_send_msg;
    looper->action.wait_looper = mh_looper_wait_looper;
    for (index = 0; index < MAX_SESSION_NUM; index++) {
        looper->fds[index].fd = -1;
        looper->fds[index].type = SESSION_NONE;
        looper->fds[index].msg_handler = NULL;
        looper->fds[index].fd_release = NULL;
        looper->fds[index].fd_release = NULL;
    }
    mh_msg_queue_init(looper, &looper->queue);
    return 0;
}

void mh_looper_uninit(struct mh_looper *looper) {
    pthread_mutex_destroy(&looper->session_mtx);
    mh_msg_queue_uninit(&looper->queue);
    mh_looper_stop(looper);
    mh_looper_wait_looper(looper);
    looper->owner = NULL;
}
