/*
 * engine.c - Supervised Multi-Container Runtime (User Space)
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "monitor_ioctl.h"

#define STACK_SIZE (1024 * 1024)
#define CONTAINER_ID_LEN 32
#define CONTROL_PATH "/tmp/mini_runtime.sock"
#define LOG_DIR "logs"
#define CONTROL_MESSAGE_LEN 256
#define CHILD_COMMAND_LEN 256
#define LOG_CHUNK_SIZE 4096
#define LOG_BUFFER_CAPACITY 16
#define DEFAULT_SOFT_LIMIT (40UL << 20)
#define DEFAULT_HARD_LIMIT (64UL << 20)

typedef enum {
    CMD_SUPERVISOR = 0,
    CMD_START,
    CMD_RUN,
    CMD_PS,
    CMD_LOGS,
    CMD_STOP
} command_kind_t;

typedef enum {
    CONTAINER_STARTING = 0,
    CONTAINER_RUNNING,
    CONTAINER_STOPPED,
    CONTAINER_KILLED,
    CONTAINER_EXITED
} container_state_t;

typedef struct container_record {
    char id[CONTAINER_ID_LEN];
    pid_t host_pid;
    time_t started_at;
    container_state_t state;
    unsigned long soft_limit_bytes;
    unsigned long hard_limit_bytes;
    int exit_code;
    int exit_signal;
    char log_path[PATH_MAX];
    int log_pipe_read_fd;   /* supervisor reads from this */
    pthread_t producer_tid;
    struct container_record *next;
} container_record_t;

typedef struct {
    char container_id[CONTAINER_ID_LEN];
    size_t length;
    char data[LOG_CHUNK_SIZE];
} log_item_t;

typedef struct {
    log_item_t items[LOG_BUFFER_CAPACITY];
    size_t head;
    size_t tail;
    size_t count;
    int shutting_down;
    pthread_mutex_t mutex;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;
} bounded_buffer_t;

typedef struct {
    command_kind_t kind;
    char container_id[CONTAINER_ID_LEN];
    char rootfs[PATH_MAX];
    char command[CHILD_COMMAND_LEN];
    unsigned long soft_limit_bytes;
    unsigned long hard_limit_bytes;
    int nice_value;
} control_request_t;

typedef struct {
    int status;
    char message[CONTROL_MESSAGE_LEN];
} control_response_t;

typedef struct {
    char id[CONTAINER_ID_LEN];
    char rootfs[PATH_MAX];
    char command[CHILD_COMMAND_LEN];
    int nice_value;
    int log_write_fd;
} child_config_t;

typedef struct {
    int server_fd;
    int monitor_fd;
    int should_stop;
    pthread_t logger_thread;
    bounded_buffer_t log_buffer;
    pthread_mutex_t metadata_lock;
    container_record_t *containers;
} supervisor_ctx_t;

/* Global supervisor context pointer — used by signal handlers */
static supervisor_ctx_t *g_ctx = NULL;

/* ───────────────────────────────────────────────────────────── */
/*  Usage / flag parsing (unchanged from boilerplate)           */
/* ───────────────────────────────────────────────────────────── */

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage:\n"
            "  %s supervisor <base-rootfs>\n"
            "  %s start <id> <container-rootfs> <command> [--soft-mib N] [--hard-mib N] [--nice N]\n"
            "  %s run <id> <container-rootfs> <command> [--soft-mib N] [--hard-mib N] [--nice N]\n"
            "  %s ps\n"
            "  %s logs <id>\n"
            "  %s stop <id>\n",
            prog, prog, prog, prog, prog, prog);
}

static int parse_mib_flag(const char *flag,
                          const char *value,
                          unsigned long *target_bytes)
{
    char *end = NULL;
    unsigned long mib;

    errno = 0;
    mib = strtoul(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0') {
        fprintf(stderr, "Invalid value for %s: %s\n", flag, value);
        return -1;
    }
    if (mib > ULONG_MAX / (1UL << 20)) {
        fprintf(stderr, "Value for %s is too large: %s\n", flag, value);
        return -1;
    }
    *target_bytes = mib * (1UL << 20);
    return 0;
}

static int parse_optional_flags(control_request_t *req,
                                int argc,
                                char *argv[],
                                int start_index)
{
    int i;
    for (i = start_index; i < argc; i += 2) {
        char *end = NULL;
        long nice_value;

        if (i + 1 >= argc) {
            fprintf(stderr, "Missing value for option: %s\n", argv[i]);
            return -1;
        }
        if (strcmp(argv[i], "--soft-mib") == 0) {
            if (parse_mib_flag("--soft-mib", argv[i + 1], &req->soft_limit_bytes) != 0)
                return -1;
            continue;
        }
        if (strcmp(argv[i], "--hard-mib") == 0) {
            if (parse_mib_flag("--hard-mib", argv[i + 1], &req->hard_limit_bytes) != 0)
                return -1;
            continue;
        }
        if (strcmp(argv[i], "--nice") == 0) {
            errno = 0;
            nice_value = strtol(argv[i + 1], &end, 10);
            if (errno != 0 || end == argv[i + 1] || *end != '\0' ||
                nice_value < -20 || nice_value > 19) {
                fprintf(stderr,
                        "Invalid value for --nice (expected -20..19): %s\n",
                        argv[i + 1]);
                return -1;
            }
            req->nice_value = (int)nice_value;
            continue;
        }
        fprintf(stderr, "Unknown option: %s\n", argv[i]);
        return -1;
    }
    if (req->soft_limit_bytes > req->hard_limit_bytes) {
        fprintf(stderr, "Invalid limits: soft limit cannot exceed hard limit\n");
        return -1;
    }
    return 0;
}

static const char *state_to_string(container_state_t state)
{
    switch (state) {
    case CONTAINER_STARTING: return "starting";
    case CONTAINER_RUNNING:  return "running";
    case CONTAINER_STOPPED:  return "stopped";
    case CONTAINER_KILLED:   return "killed";
    case CONTAINER_EXITED:   return "exited";
    default:                 return "unknown";
    }
}

/* ───────────────────────────────────────────────────────────── */
/*  Bounded buffer                                              */
/* ───────────────────────────────────────────────────────────── */

static int bounded_buffer_init(bounded_buffer_t *buffer)
{
    int rc;
    memset(buffer, 0, sizeof(*buffer));
    rc = pthread_mutex_init(&buffer->mutex, NULL);
    if (rc != 0) return rc;
    rc = pthread_cond_init(&buffer->not_empty, NULL);
    if (rc != 0) { pthread_mutex_destroy(&buffer->mutex); return rc; }
    rc = pthread_cond_init(&buffer->not_full, NULL);
    if (rc != 0) {
        pthread_cond_destroy(&buffer->not_empty);
        pthread_mutex_destroy(&buffer->mutex);
        return rc;
    }
    return 0;
}

static void bounded_buffer_destroy(bounded_buffer_t *buffer)
{
    pthread_cond_destroy(&buffer->not_full);
    pthread_cond_destroy(&buffer->not_empty);
    pthread_mutex_destroy(&buffer->mutex);
}

static void bounded_buffer_begin_shutdown(bounded_buffer_t *buffer)
{
    pthread_mutex_lock(&buffer->mutex);
    buffer->shutting_down = 1;
    pthread_cond_broadcast(&buffer->not_empty);
    pthread_cond_broadcast(&buffer->not_full);
    pthread_mutex_unlock(&buffer->mutex);
}

/*
 * bounded_buffer_push — producer side.
 * Blocks while buffer is full. Returns 0 on success, -1 if shutting down.
 *
 * Race condition without this lock: two producers could both read
 * buffer->count < CAPACITY, both decide to insert, and both write to
 * the same slot — corrupting data and losing a log chunk.
 * We use a mutex + condition variable (not a spinlock) because producers
 * may block for a long time waiting for space; spinning would waste CPU.
 */
int bounded_buffer_push(bounded_buffer_t *buffer, const log_item_t *item)
{
    pthread_mutex_lock(&buffer->mutex);

    /* Wait while full, unless shutdown has started */
    while (buffer->count == LOG_BUFFER_CAPACITY && !buffer->shutting_down)
        pthread_cond_wait(&buffer->not_full, &buffer->mutex);

    if (buffer->shutting_down) {
        pthread_mutex_unlock(&buffer->mutex);
        return -1;
    }

    buffer->items[buffer->head] = *item;
    buffer->head = (buffer->head + 1) % LOG_BUFFER_CAPACITY;
    buffer->count++;

    pthread_cond_signal(&buffer->not_empty);   /* wake one consumer */
    pthread_mutex_unlock(&buffer->mutex);
    return 0;
}

/*
 * bounded_buffer_pop — consumer side.
 * Blocks while buffer is empty. Returns 0 on success, -1 when shutdown
 * and buffer is empty (consumer should exit).
 */
int bounded_buffer_pop(bounded_buffer_t *buffer, log_item_t *item)
{
    pthread_mutex_lock(&buffer->mutex);

    /* Wait while empty — but keep draining after shutdown starts */
    while (buffer->count == 0 && !buffer->shutting_down)
        pthread_cond_wait(&buffer->not_empty, &buffer->mutex);

    if (buffer->count == 0) {
        /* Shutdown and nothing left to drain */
        pthread_mutex_unlock(&buffer->mutex);
        return -1;
    }

    *item = buffer->items[buffer->tail];
    buffer->tail = (buffer->tail + 1) % LOG_BUFFER_CAPACITY;
    buffer->count--;

    pthread_cond_signal(&buffer->not_full);    /* wake one producer */
    pthread_mutex_unlock(&buffer->mutex);
    return 0;
}

/* ───────────────────────────────────────────────────────────── */
/*  Logging consumer thread                                     */
/* ───────────────────────────────────────────────────────────── */

/*
 * logging_thread — single consumer.
 * Pops log chunks from the bounded buffer and appends them to the
 * per-container log file. Exits only after shutdown is signalled AND
 * the buffer is fully drained, so no log data is lost.
 */
void *logging_thread(void *arg)
{
    supervisor_ctx_t *ctx = (supervisor_ctx_t *)arg;
    log_item_t item;

    while (bounded_buffer_pop(&ctx->log_buffer, &item) == 0) {
        /* Find the container log path under the metadata lock */
        char log_path[PATH_MAX] = {0};

        pthread_mutex_lock(&ctx->metadata_lock);
        container_record_t *c = ctx->containers;
        while (c) {
            if (strcmp(c->id, item.container_id) == 0) {
                strncpy(log_path, c->log_path, PATH_MAX - 1);
                break;
            }
            c = c->next;
        }
        pthread_mutex_unlock(&ctx->metadata_lock);

        if (log_path[0] == '\0')
            continue;   /* container already removed — drop chunk */

        FILE *f = fopen(log_path, "a");
        if (f) {
            fwrite(item.data, 1, item.length, f);
            fclose(f);
        }
    }
    return NULL;
}

/* ───────────────────────────────────────────────────────────── */
/*  Per-container log producer thread                           */
/* ───────────────────────────────────────────────────────────── */

typedef struct {
    supervisor_ctx_t *ctx;
    char container_id[CONTAINER_ID_LEN];
    int read_fd;
} producer_arg_t;

static void *log_producer_thread(void *arg)
{
    producer_arg_t *pa = (producer_arg_t *)arg;
    log_item_t item;
    ssize_t n;

    memset(item.container_id, 0, sizeof(item.container_id));
    strncpy(item.container_id, pa->container_id, CONTAINER_ID_LEN - 1);

    while ((n = read(pa->read_fd, item.data, LOG_CHUNK_SIZE)) > 0) {
        item.length = (size_t)n;
        bounded_buffer_push(&pa->ctx->log_buffer, &item);
    }

    close(pa->read_fd);
    free(pa);
    return NULL;
}

/* ───────────────────────────────────────────────────────────── */
/*  Container child entrypoint                                  */
/* ───────────────────────────────────────────────────────────── */

/*
 * child_fn — runs inside the new namespaces.
 *
 * What happens here (in order):
 *  1. Redirect stdout/stderr to the supervisor's log pipe write-end.
 *  2. Set hostname (UTS namespace).
 *  3. Bind-mount rootfs onto itself so it becomes a proper mountpoint.
 *  4. chroot into rootfs + cd to /.
 *  5. Mount /proc so the new PID namespace works correctly.
 *  6. Apply nice value if requested.
 *  7. exec the requested command.
 */
int child_fn(void *arg)
{
    child_config_t *cfg = (child_config_t *)arg;

    /* Redirect stdout + stderr into the log pipe */
    if (cfg->log_write_fd >= 0) {
        dup2(cfg->log_write_fd, STDOUT_FILENO);
        dup2(cfg->log_write_fd, STDERR_FILENO);
        close(cfg->log_write_fd);
    }

    /* Set hostname (isolated UTS namespace) */
    if(sethostname(cfg->id, strlen(cfg->id))){}

    /* Bind-mount rootfs onto itself to make it a mountpoint */
    if (mount(cfg->rootfs, cfg->rootfs, NULL, MS_BIND | MS_REC, NULL) != 0) {
        perror("mount --bind rootfs");
        return 1;
    }

    /* chroot into the rootfs */
    if (chdir(cfg->rootfs) != 0) { perror("chdir rootfs"); return 1; }
    if (chroot(".") != 0)         { perror("chroot");       return 1; }
    if (chdir("/") != 0)          { perror("chdir /");      return 1; }

    /* Mount /proc for new PID namespace */
    mkdir("/proc", 0555);
    mount("proc", "/proc", "proc", MS_NOEXEC | MS_NOSUID | MS_NODEV, NULL);

    /* Apply scheduling priority */
    if (cfg->nice_value != 0)
        if(nice(cfg->nice_value) == -1){}

    /* Execute the requested command */
    char *argv[] = { cfg->command, NULL };
    execv(cfg->command, argv);

    /* execv failed */
    perror("execv");
    return 1;
}

/* ───────────────────────────────────────────────────────────── */
/*  Monitor registration helpers                                */
/* ───────────────────────────────────────────────────────────── */

int register_with_monitor(int monitor_fd,
                          const char *container_id,
                          pid_t host_pid,
                          unsigned long soft_limit_bytes,
                          unsigned long hard_limit_bytes)
{
    struct monitor_request req;
    memset(&req, 0, sizeof(req));
    req.pid = host_pid;
    req.soft_limit_bytes = soft_limit_bytes;
    req.hard_limit_bytes = hard_limit_bytes;
    strncpy(req.container_id, container_id, sizeof(req.container_id) - 1);
    if (ioctl(monitor_fd, MONITOR_REGISTER, &req) < 0)
        return -1;
    return 0;
}

int unregister_from_monitor(int monitor_fd,
                            const char *container_id,
                            pid_t host_pid)
{
    struct monitor_request req;
    memset(&req, 0, sizeof(req));
    req.pid = host_pid;
    strncpy(req.container_id, container_id, sizeof(req.container_id) - 1);
    if (ioctl(monitor_fd, MONITOR_UNREGISTER, &req) < 0)
        return -1;
    return 0;
}

/* ───────────────────────────────────────────────────────────── */
/*  Child reaping                                               */
/* ───────────────────────────────────────────────────────────── */

static void reap_children(supervisor_ctx_t *ctx)
{
    int status;
    pid_t pid;

    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        pthread_mutex_lock(&ctx->metadata_lock);
        container_record_t *c = ctx->containers;
        while (c) {
            if (c->host_pid == pid) {
                if (WIFSIGNALED(status)) {
                    c->state      = CONTAINER_KILLED;
                    c->exit_signal = WTERMSIG(status);
                } else {
                    c->state     = CONTAINER_EXITED;
                    c->exit_code = WEXITSTATUS(status);
                }
                /* Unregister from kernel monitor */
                if (ctx->monitor_fd >= 0)
                    unregister_from_monitor(ctx->monitor_fd, c->id, pid);
                break;
            }
            c = c->next;
        }
        pthread_mutex_unlock(&ctx->metadata_lock);
    }
}

/* ───────────────────────────────────────────────────────────── */
/*  Signal handling                                             */
/* ───────────────────────────────────────────────────────────── */

static void sigchld_handler(int sig)
{
    (void)sig;
    /* Actual reaping done in the event loop via reap_children() */
}

static void sigterm_handler(int sig)
{
    (void)sig;
    if (g_ctx)
        g_ctx->should_stop = 1;
}

/* ───────────────────────────────────────────────────────────── */
/*  Launch a container (called from the supervisor)             */
/* ───────────────────────────────────────────────────────────── */

static void supervisor_launch_container(supervisor_ctx_t *ctx,
                                        const control_request_t *req,
                                        control_response_t *resp,
                                        int wait_fg)
{
    /* Check for duplicate ID */
    pthread_mutex_lock(&ctx->metadata_lock);
    container_record_t *existing = ctx->containers;
    while (existing) {
        if (strcmp(existing->id, req->container_id) == 0) {
            pthread_mutex_unlock(&ctx->metadata_lock);
            snprintf(resp->message, sizeof(resp->message),
                     "Container '%s' already exists", req->container_id);
            resp->status = -1;
            return;
        }
        existing = existing->next;
    }
    pthread_mutex_unlock(&ctx->metadata_lock);

    /* Create log directory */
    mkdir(LOG_DIR, 0755);

    /* Create the log pipe — IPC mechanism 1 (anonymous pipe) */
    int pipefd[2];
    if (pipe(pipefd) < 0) {
        snprintf(resp->message, sizeof(resp->message), "pipe: %s", strerror(errno));
        resp->status = -1;
        return;
    }

    /* Build child config */
    child_config_t *cfg = malloc(sizeof(child_config_t));
    if (!cfg) {
        close(pipefd[0]); close(pipefd[1]);
        resp->status = -1;
        snprintf(resp->message, sizeof(resp->message), "malloc failed");
        return;
    }
    memset(cfg, 0, sizeof(*cfg));
    strncpy(cfg->id,      req->container_id, CONTAINER_ID_LEN - 1);
    strncpy(cfg->rootfs,  req->rootfs,        PATH_MAX - 1);
    strncpy(cfg->command, req->command,       CHILD_COMMAND_LEN - 1);
    cfg->nice_value   = req->nice_value;
    cfg->log_write_fd = pipefd[1];

    /* Allocate stack for clone() */
    char *stack = malloc(STACK_SIZE);
    if (!stack) {
        free(cfg);
        close(pipefd[0]); close(pipefd[1]);
        resp->status = -1;
        snprintf(resp->message, sizeof(resp->message), "stack malloc failed");
        return;
    }

    /*
     * clone() with three namespace flags:
     *   CLONE_NEWPID  – new PID namespace (container is PID 1 inside)
     *   CLONE_NEWUTS  – new hostname namespace
     *   CLONE_NEWNS   – new mount namespace (so /proc mount stays inside)
     */
    pid_t pid = clone(child_fn,
                      stack + STACK_SIZE,
                      CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWNS | SIGCHLD,
                      cfg);
    free(stack);

    if (pid < 0) {
        free(cfg);
        close(pipefd[0]); close(pipefd[1]);
        snprintf(resp->message, sizeof(resp->message),
                 "clone failed: %s", strerror(errno));
        resp->status = -1;
        return;
    }

    /* Parent: close the write end of the pipe */
    close(pipefd[1]);

    /* Build and insert container metadata record */
    container_record_t *rec = calloc(1, sizeof(container_record_t));
    strncpy(rec->id, req->container_id, CONTAINER_ID_LEN - 1);
    rec->host_pid          = pid;
    rec->started_at        = time(NULL);
    rec->state             = CONTAINER_RUNNING;
    rec->soft_limit_bytes  = req->soft_limit_bytes;
    rec->hard_limit_bytes  = req->hard_limit_bytes;
    rec->log_pipe_read_fd  = pipefd[0];
    snprintf(rec->log_path, PATH_MAX, "%s/%s.log", LOG_DIR, req->container_id);

    pthread_mutex_lock(&ctx->metadata_lock);
    rec->next       = ctx->containers;
    ctx->containers = rec;
    pthread_mutex_unlock(&ctx->metadata_lock);

    /* Register with kernel memory monitor */
    if (ctx->monitor_fd >= 0) {
        if (register_with_monitor(ctx->monitor_fd,
                                   req->container_id, pid,
                                   req->soft_limit_bytes,
                                   req->hard_limit_bytes) < 0)
            fprintf(stderr, "[supervisor] warning: monitor registration failed\n");
        else
            fprintf(stderr, "[supervisor] registered pid=%d with kernel monitor\n", pid);
    }

    /* Spawn per-container log producer thread */
    producer_arg_t *pa = malloc(sizeof(producer_arg_t));
    pa->ctx      = ctx;
    pa->read_fd  = pipefd[0];
    strncpy(pa->container_id, req->container_id, CONTAINER_ID_LEN - 1);
    pthread_create(&rec->producer_tid, NULL, log_producer_thread, pa);
    pthread_detach(rec->producer_tid);

    fprintf(stderr, "[supervisor] started container '%s' pid=%d\n",
            req->container_id, pid);

    if (wait_fg) {
        int wstatus;
        waitpid(pid, &wstatus, 0);
        pthread_mutex_lock(&ctx->metadata_lock);
        if (WIFSIGNALED(wstatus)) {
            rec->state      = CONTAINER_KILLED;
            rec->exit_signal = WTERMSIG(wstatus);
        } else {
            rec->state    = CONTAINER_EXITED;
            rec->exit_code = WEXITSTATUS(wstatus);
        }
        pthread_mutex_unlock(&ctx->metadata_lock);
    }

    resp->status = 0;
    snprintf(resp->message, sizeof(resp->message),
             "Container '%s' started (pid=%d)", req->container_id, pid);
}

/* ───────────────────────────────────────────────────────────── */
/*  Handle one client connection in the supervisor              */
/* ───────────────────────────────────────────────────────────── */

static void handle_client(supervisor_ctx_t *ctx, int cfd)
{
    control_request_t req;
    control_response_t resp;

    memset(&resp, 0, sizeof(resp));

    ssize_t n = read(cfd, &req, sizeof(req));
    if (n != sizeof(req)) {
        resp.status = -1;
        snprintf(resp.message, sizeof(resp.message), "bad request size");
        if(write(cfd, &resp, sizeof(resp))){}
        close(cfd);
        return;
    }

    switch (req.kind) {

    case CMD_START:
        supervisor_launch_container(ctx, &req, &resp, 0);
        break;

    case CMD_RUN:
        supervisor_launch_container(ctx, &req, &resp, 1);
        break;

    case CMD_PS: {
        /* Build a text table of container metadata */
        char table[4096] = {0};
        snprintf(table, sizeof(table),
                 "%-20s %-8s %-10s %-26s %-12s %-12s\n",
                 "ID", "PID", "STATE", "STARTED",
                 "SOFT(MiB)", "HARD(MiB)");

        pthread_mutex_lock(&ctx->metadata_lock);
        container_record_t *c = ctx->containers;
        while (c) {
            char tbuf[32];
            struct tm *tm = localtime(&c->started_at);
            strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", tm);
            char row[256];
            snprintf(row, sizeof(row),
                     "%-20s %-8d %-10s %-26s %-12lu %-12lu\n",
                     c->id, c->host_pid,
                     state_to_string(c->state),
                     tbuf,
                     c->soft_limit_bytes >> 20,
                     c->hard_limit_bytes >> 20);
            strncat(table, row, sizeof(table) - strlen(table) - 1);
            c = c->next;
        }
        pthread_mutex_unlock(&ctx->metadata_lock);

        resp.status = 0;
        strncpy(resp.message, table, sizeof(resp.message) - 1);
        break;
    }

    case CMD_LOGS: {
        char log_path[PATH_MAX] = {0};
        pthread_mutex_lock(&ctx->metadata_lock);
        container_record_t *c = ctx->containers;
        while (c) {
            if (strcmp(c->id, req.container_id) == 0) {
                strncpy(log_path, c->log_path, PATH_MAX - 1);
                break;
            }
            c = c->next;
        }
        pthread_mutex_unlock(&ctx->metadata_lock);

        if (log_path[0] == '\0') {
            resp.status = -1;
            snprintf(resp.message, sizeof(resp.message),
                     "Container '%s' not found", req.container_id);
        } else {
            /* Send file contents directly over the socket */
            resp.status = 0;
            snprintf(resp.message, sizeof(resp.message),
                     "Log for '%s':", req.container_id);
            if(write(cfd, &resp, sizeof(resp))){}

            /* Send the log file in chunks */
            FILE *f = fopen(log_path, "r");
            if (f) {
                char buf[1024];
                size_t r;
                while ((r = fread(buf, 1, sizeof(buf), f)) > 0)
                    if(write(cfd, buf, r)){}
                fclose(f);
            }
            close(cfd);
            return;
        }
        break;
    }

    case CMD_STOP: {
        pthread_mutex_lock(&ctx->metadata_lock);
        container_record_t *c = ctx->containers;
        int found = 0;
        while (c) {
            if (strcmp(c->id, req.container_id) == 0) {
                found = 1;
                if (c->state == CONTAINER_RUNNING ||
                    c->state == CONTAINER_STARTING) {
                    kill(c->host_pid, SIGTERM);
                    c->state = CONTAINER_STOPPED;
                    resp.status = 0;
                    snprintf(resp.message, sizeof(resp.message),
                             "Sent SIGTERM to '%s' (pid=%d)",
                             req.container_id, c->host_pid);
                } else {
                    resp.status = -1;
                    snprintf(resp.message, sizeof(resp.message),
                             "Container '%s' is not running", req.container_id);
                }
                break;
            }
            c = c->next;
        }
        pthread_mutex_unlock(&ctx->metadata_lock);
        if (!found) {
            resp.status = -1;
            snprintf(resp.message, sizeof(resp.message),
                     "Container '%s' not found", req.container_id);
        }
        break;
    }

    default:
        resp.status = -1;
        snprintf(resp.message, sizeof(resp.message), "Unknown command");
        break;
    }

    if(write(cfd, &resp, sizeof(resp))){}
    close(cfd);
}

/* ───────────────────────────────────────────────────────────── */
/*  Supervisor main loop                                        */
/* ───────────────────────────────────────────────────────────── */

static int run_supervisor(const char *rootfs)
{
    supervisor_ctx_t ctx;
    int rc;

    memset(&ctx, 0, sizeof(ctx));
    ctx.server_fd  = -1;
    ctx.monitor_fd = -1;
    g_ctx          = &ctx;

    fprintf(stderr, "[supervisor] starting (pid=%d, rootfs=%s)\n",
            getpid(), rootfs);

    /* Init metadata lock */
    rc = pthread_mutex_init(&ctx.metadata_lock, NULL);
    if (rc != 0) { errno = rc; perror("pthread_mutex_init"); return 1; }

    /* Init bounded log buffer */
    rc = bounded_buffer_init(&ctx.log_buffer);
    if (rc != 0) {
        errno = rc; perror("bounded_buffer_init");
        pthread_mutex_destroy(&ctx.metadata_lock);
        return 1;
    }

    /* ── Step 1: open kernel monitor device ── */
    ctx.monitor_fd = open("/dev/container_monitor", O_RDWR);
    if (ctx.monitor_fd < 0)
        fprintf(stderr, "[supervisor] warning: cannot open /dev/%s — "
                        "memory limits disabled\n", "container_monitor");

    /* ── Step 2: create the UNIX domain socket (IPC mechanism 2) ── */
    unlink(CONTROL_PATH);
    ctx.server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (ctx.server_fd < 0) { perror("socket"); return 1; }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CONTROL_PATH, sizeof(addr.sun_path) - 1);

    if (bind(ctx.server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); close(ctx.server_fd); return 1;
    }
    listen(ctx.server_fd, 8);
    chmod(CONTROL_PATH, 0666);
    fprintf(stderr, "[supervisor] listening on %s\n", CONTROL_PATH);

    /* ── Step 3: install signal handlers ── */
    struct sigaction sa_chld;
    memset(&sa_chld, 0, sizeof(sa_chld));
    sa_chld.sa_handler = sigchld_handler;
    sa_chld.sa_flags   = SA_RESTART | SA_NOCLDSTOP;
    sigaction(SIGCHLD, &sa_chld, NULL);

    struct sigaction sa_term;
    memset(&sa_term, 0, sizeof(sa_term));
    sa_term.sa_handler = sigterm_handler;
    sigaction(SIGTERM, &sa_term, NULL);
    sigaction(SIGINT,  &sa_term, NULL);

    /* ── Step 4: start the logger (consumer) thread ── */
    rc = pthread_create(&ctx.logger_thread, NULL, logging_thread, &ctx);
    if (rc != 0) {
        errno = rc; perror("pthread_create logger");
        close(ctx.server_fd); unlink(CONTROL_PATH);
        bounded_buffer_destroy(&ctx.log_buffer);
        pthread_mutex_destroy(&ctx.metadata_lock);
        return 1;
    }

    /* ── Step 5: event loop ── */
    fprintf(stderr, "[supervisor] ready\n");
    while (!ctx.should_stop) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(ctx.server_fd, &rfds);
        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };

        int sel = select(ctx.server_fd + 1, &rfds, NULL, NULL, &tv);
        if (sel < 0 && errno == EINTR) {
            reap_children(&ctx);
            continue;
        }
        if (sel > 0 && FD_ISSET(ctx.server_fd, &rfds)) {
            int cfd = accept(ctx.server_fd, NULL, NULL);
            if (cfd >= 0)
                handle_client(&ctx, cfd);
        }
        reap_children(&ctx);
    }

    fprintf(stderr, "[supervisor] shutting down\n");

    /* Stop all running containers gracefully */
    pthread_mutex_lock(&ctx.metadata_lock);
    container_record_t *c = ctx.containers;
    while (c) {
        if (c->state == CONTAINER_RUNNING || c->state == CONTAINER_STARTING)
            kill(c->host_pid, SIGTERM);
        c = c->next;
    }
    pthread_mutex_unlock(&ctx.metadata_lock);

    sleep(1);
    reap_children(&ctx);

    /* Shutdown logger thread */
    bounded_buffer_begin_shutdown(&ctx.log_buffer);
    pthread_join(ctx.logger_thread, NULL);

    /* Free container list */
    pthread_mutex_lock(&ctx.metadata_lock);
    c = ctx.containers;
    while (c) {
        container_record_t *next = c->next;
        if (c->log_pipe_read_fd >= 0)
            close(c->log_pipe_read_fd);
        free(c);
        c = next;
    }
    pthread_mutex_unlock(&ctx.metadata_lock);

    /* Cleanup */
    bounded_buffer_destroy(&ctx.log_buffer);
    pthread_mutex_destroy(&ctx.metadata_lock);
    if (ctx.monitor_fd >= 0) close(ctx.monitor_fd);
    close(ctx.server_fd);
    unlink(CONTROL_PATH);

    fprintf(stderr, "[supervisor] done\n");
    return 0;
}

/* ───────────────────────────────────────────────────────────── */
/*  Client-side: send request over UNIX socket, print response  */
/* ───────────────────────────────────────────────────────────── */

static int send_control_request(const control_request_t *req)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return 1; }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CONTROL_PATH, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr,
                "Cannot connect to supervisor at %s. "
                "Is 'engine supervisor' running?\n", CONTROL_PATH);
        close(fd);
        return 1;
    }

    if(write(fd, req, sizeof(*req))){}

    /* Read the response header */
    control_response_t resp;
    ssize_t n = read(fd, &resp, sizeof(resp));
    if (n == sizeof(resp)) {
        printf("%s\n", resp.message);
        /* For logs: keep reading raw data until the server closes */
        if (req->kind == CMD_LOGS && resp.status == 0) {
            char buf[1024];
            ssize_t r;
            while ((r = read(fd, buf, sizeof(buf))) > 0)
                fwrite(buf, 1, r, stdout);
        }
    }

    close(fd);
    return (n == sizeof(resp) && resp.status == 0) ? 0 : 1;
}

/* ───────────────────────────────────────────────────────────── */
/*  CLI sub-commands                                            */
/* ───────────────────────────────────────────────────────────── */

static int cmd_start(int argc, char *argv[])
{
    control_request_t req;
    if (argc < 5) {
        fprintf(stderr,
                "Usage: %s start <id> <container-rootfs> <command> "
                "[--soft-mib N] [--hard-mib N] [--nice N]\n", argv[0]);
        return 1;
    }
    memset(&req, 0, sizeof(req));
    req.kind = CMD_START;
    strncpy(req.container_id, argv[2], sizeof(req.container_id) - 1);
    strncpy(req.rootfs,       argv[3], sizeof(req.rootfs)        - 1);
    strncpy(req.command,      argv[4], sizeof(req.command)       - 1);
    req.soft_limit_bytes = DEFAULT_SOFT_LIMIT;
    req.hard_limit_bytes = DEFAULT_HARD_LIMIT;
    if (parse_optional_flags(&req, argc, argv, 5) != 0) return 1;
    return send_control_request(&req);
}

static int cmd_run(int argc, char *argv[])
{
    control_request_t req;
    if (argc < 5) {
        fprintf(stderr,
                "Usage: %s run <id> <container-rootfs> <command> "
                "[--soft-mib N] [--hard-mib N] [--nice N]\n", argv[0]);
        return 1;
    }
    memset(&req, 0, sizeof(req));
    req.kind = CMD_RUN;
    strncpy(req.container_id, argv[2], sizeof(req.container_id) - 1);
    strncpy(req.rootfs,       argv[3], sizeof(req.rootfs)        - 1);
    strncpy(req.command,      argv[4], sizeof(req.command)       - 1);
    req.soft_limit_bytes = DEFAULT_SOFT_LIMIT;
    req.hard_limit_bytes = DEFAULT_HARD_LIMIT;
    if (parse_optional_flags(&req, argc, argv, 5) != 0) return 1;
    return send_control_request(&req);
}

static int cmd_ps(void)
{
    control_request_t req;
    memset(&req, 0, sizeof(req));
    req.kind = CMD_PS;
    return send_control_request(&req);
}

static int cmd_logs(int argc, char *argv[])
{
    control_request_t req;
    if (argc < 3) { fprintf(stderr, "Usage: %s logs <id>\n", argv[0]); return 1; }
    memset(&req, 0, sizeof(req));
    req.kind = CMD_LOGS;
    strncpy(req.container_id, argv[2], sizeof(req.container_id) - 1);
    return send_control_request(&req);
}

static int cmd_stop(int argc, char *argv[])
{
    control_request_t req;
    if (argc < 3) { fprintf(stderr, "Usage: %s stop <id>\n", argv[0]); return 1; }
    memset(&req, 0, sizeof(req));
    req.kind = CMD_STOP;
    strncpy(req.container_id, argv[2], sizeof(req.container_id) - 1);
    return send_control_request(&req);
}

/* ───────────────────────────────────────────────────────────── */
/*  main                                                        */
/* ───────────────────────────────────────────────────────────── */

int main(int argc, char *argv[])
{
    if (argc < 2) { usage(argv[0]); return 1; }

    if (strcmp(argv[1], "supervisor") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s supervisor <base-rootfs>\n", argv[0]);
            return 1;
        }
        return run_supervisor(argv[2]);
    }

    if (strcmp(argv[1], "start") == 0) return cmd_start(argc, argv);
    if (strcmp(argv[1], "run")   == 0) return cmd_run(argc, argv);
    if (strcmp(argv[1], "ps")    == 0) return cmd_ps();
    if (strcmp(argv[1], "logs")  == 0) return cmd_logs(argc, argv);
    if (strcmp(argv[1], "stop")  == 0) return cmd_stop(argc, argv);

    usage(argv[0]);
    return 1;
}
