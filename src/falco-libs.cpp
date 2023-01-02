#include "falco-libs.h"
#include "cli-parser.h"
#include <iostream>
#include <stdlib.h>
#include <sinsp.h>
#include <signal.h>
#include <stdlib.h>
#include <pthread.h>
#include <semaphore.h>
#include <unistd.h>

static std::string get_event_category(ppm_event_category category)
{
    switch(category)
    {
        case EC_UNKNOWN: return "UNKNOWN";
        case EC_OTHER: return "OTHER";
        case EC_FILE: return "FILE";
        case EC_NET: return "NET";
        case EC_IPC: return "IPC";
        case EC_MEMORY: return "MEMORY";
        case EC_PROCESS: return "PROCESS";
        case EC_SLEEP: return "SLEEP";
        case EC_SYSTEM: return "SYSTEM";
        case EC_SIGNAL: return "SIGNAL";
        case EC_USER: return "USER";
        case EC_TIME: return "TIME";
        case EC_PROCESSING: return "PROCESSING";
        case EC_IO_READ: return "IO_READ";
        case EC_IO_WRITE: return "IO_WRITE";
        case EC_IO_OTHER: return "IO_OTHER";
        case EC_WAIT: return "WAIT";
        case EC_SCHEDULER: return "SCHEDULER";
        case EC_INTERNAL: return "INTERNAL";
        default: return "ERROR CONDITION";
    };
}

static std::string get_syscal_name(std::string nativeID) {
    long id = strtol(nativeID.c_str(), NULL, 10);
    switch (id)
    {
    case 154:
        return "modify_ldt";
    case 187:
        return "readahead";
    case 214:
        return "epoll_ctl_old";
    case 215:
        return "epoll_wait_old";
    case 220:
        return "semtimedop";
    case 277:
        return "sync_file_range";
    case 301:
        return "fanotify_mark";
    case 314:
        return "sched_setattr";
    case 315:
        return "sched_getattr";
    case 319:
        return "memfd_create";
    case 324:
        return "membarrier";
    case 325:
        return "mlock2";
    case 327:
        return "preadv2";
    case 328:
        return "pwritev2";
    case 332:
        return "statx";
    default:
        return "";
        break;
    }
}

static std::string get_event_type(uint16_t type, sinsp_evt* ev, bool *after_arguments_resolving)
{
    switch(type)
    {
        //
        // File syscalls
        //
        case PPME_SYSCALL_ACCESS_E:
        case PPME_SYSCALL_ACCESS_X: return "access";
        case PPME_SYSCALL_CHMOD_E: 
        case PPME_SYSCALL_CHMOD_X: return "chmod";
        case PPME_SYSCALL_CLOSE_E:
        case PPME_SYSCALL_CLOSE_X: return "close";
        case PPME_SYSCALL_CREAT_E: 
        case PPME_SYSCALL_CREAT_X: return "creat";
        case PPME_SYSCALL_DUP_E:
        case PPME_SYSCALL_DUP_X: 
        case PPME_SYSCALL_DUP_1_E:
        case PPME_SYSCALL_DUP_1_X: return "dup";
        case PPME_SYSCALL_DUP2_E:
        case PPME_SYSCALL_DUP2_X: return "dup2";
        case PPME_SYSCALL_DUP3_E:
        case PPME_SYSCALL_DUP3_X: return "dup3";
        case PPME_SYSCALL_EPOLLWAIT_E:
        case PPME_SYSCALL_EPOLLWAIT_X: return "epoll_wait";
        case PPME_SYSCALL_EVENTFD_E:
        case PPME_SYSCALL_EVENTFD_X: return "eventfd";
        case PPME_SYSCALL_FCHMODAT_E:
        case PPME_SYSCALL_FCHMODAT_X: return "fchmodat";
        case PPME_SYSCALL_FCHMOD_E:
        case PPME_SYSCALL_FCHMOD_X: return "chmod";
        case PPME_SYSCALL_FCNTL_E:
        case PPME_SYSCALL_FCNTL_X: return "fcntl";
        case PPME_SYSCALL_FLOCK_E:
        case PPME_SYSCALL_FLOCK_X: return "flock";
        case PPME_SYSCALL_FSTAT_E:
        case PPME_SYSCALL_FSTAT_X: return "fstat";
        case PPME_SYSCALL_FSTAT64_E:
        case PPME_SYSCALL_FSTAT64_X: return "fstat64";
        case PPME_SYSCALL_GETDENTS_E:
        case PPME_SYSCALL_GETDENTS_X: return "getdents";
        case PPME_SYSCALL_GETDENTS64_E:
        case PPME_SYSCALL_GETDENTS64_X: return "getdents64";
        case PPME_SYSCALL_GETRLIMIT_E:
        case PPME_SYSCALL_GETRLIMIT_X: return "getrlimit";
        case PPME_SYSCALL_GETEGID_E:
        case PPME_SYSCALL_GETEGID_X: return "getegid";
        case PPME_SYSCALL_GETEUID_E:
        case PPME_SYSCALL_GETEUID_X: return "geteuid";
        case PPME_SYSCALL_GETGID_E:
        case PPME_SYSCALL_GETGID_X: return "getgid";
        case PPME_SYSCALL_GETRESGID_E:
        case PPME_SYSCALL_GETRESGID_X: return "getresgid";
        case PPME_SYSCALL_GETRESUID_E:
        case PPME_SYSCALL_GETRESUID_X: return "getresuid";
        case PPME_SYSCALL_GETUID_E:
        case PPME_SYSCALL_GETUID_X: return "getuid";
        case PPME_SYSCALL_IOCTL_2_E:
        case PPME_SYSCALL_IOCTL_3_E:
        case PPME_SYSCALL_IOCTL_2_X:
        case PPME_SYSCALL_IOCTL_3_X: return "ioctl";
        case PPME_SYSCALL_LINK_E:
        case PPME_SYSCALL_LINK_2_E:
        case PPME_SYSCALL_LINK_X:
        case PPME_SYSCALL_LINK_2_X: return "link";
        case PPME_SYSCALL_LINKAT_E:
        case PPME_SYSCALL_LINKAT_2_E:
        case PPME_SYSCALL_LINKAT_X:
        case PPME_SYSCALL_LINKAT_2_X: return "linkat";
        case PPME_SYSCALL_LSEEK_E:
        case PPME_SYSCALL_LSEEK_X: return "lseek";
        case PPME_SYSCALL_LLSEEK_E:
        case PPME_SYSCALL_LLSEEK_X: return "llseek";
        case PPME_SYSCALL_LSTAT_E:
        case PPME_SYSCALL_LSTAT_X: return "lstat";
        case PPME_SYSCALL_LSTAT64_E:
        case PPME_SYSCALL_LSTAT64_X: return "lstat64";
        case PPME_SYSCALL_MKDIR_E:
        case PPME_SYSCALL_MKDIR_2_E:
        case PPME_SYSCALL_MKDIR_X:
        case PPME_SYSCALL_MKDIR_2_X: return "mkdir";
        case PPME_SYSCALL_MKDIRAT_E:
        case PPME_SYSCALL_MKDIRAT_X: return "mkdirat";
        case PPME_SYSCALL_MOUNT_E:
        case PPME_SYSCALL_MOUNT_X: return "mount";
        case PPME_SYSCALL_NEWSELECT_E:
        case PPME_SYSCALL_NEWSELECT_X: return "newselect";
        case PPME_SYSCALL_OPEN_E:
        case PPME_SYSCALL_OPEN_X: return "open";
        case PPME_SYSCALL_OPENAT_E:
        case PPME_SYSCALL_OPENAT_2_E:
        case PPME_SYSCALL_OPENAT_X:
        case PPME_SYSCALL_OPENAT_2_X: return "openat";
        case PPME_SYSCALL_OPENAT2_X: return "openat2";
        case PPME_SYSCALL_OPEN_BY_HANDLE_AT_E:
        case PPME_SYSCALL_OPEN_BY_HANDLE_AT_X: return "open_by_handle_at";
        case PPME_SYSCALL_PIPE_E:
        case PPME_SYSCALL_PIPE_X: return "pipe";
        case PPME_SYSCALL_POLL_E:
        case PPME_SYSCALL_POLL_X: return "poll";
        case PPME_SYSCALL_PPOLL_E:
        case PPME_SYSCALL_PPOLL_X: return "ppoll";
        case PPME_SYSCALL_PREAD_E:
        case PPME_SYSCALL_PREAD_X: return "pread";
        case PPME_SYSCALL_PREADV_E:
        case PPME_SYSCALL_PREADV_X: return "preadv";
        case PPME_SYSCALL_PRLIMIT_E:
        case PPME_SYSCALL_PRLIMIT_X: return "prlimit";
        case PPME_SYSCALL_PWRITE_E:
        case PPME_SYSCALL_PWRITE_X: return "pwrite";
        case PPME_SYSCALL_PWRITEV_E:
        case PPME_SYSCALL_PWRITEV_X: return "pwritev";
        case PPME_SYSCALL_READ_E:
        case PPME_SYSCALL_READ_X: return "read";
        case PPME_SYSCALL_READV_E:
        case PPME_SYSCALL_READV_X: return "readv";
        case PPME_SYSCALL_RENAME_E:
        case PPME_SYSCALL_RENAME_X: return "rename";
        case PPME_SYSCALL_RENAMEAT_E:
        case PPME_SYSCALL_RENAMEAT_X: return "renameat";
        case PPME_SYSCALL_RENAMEAT2_E:
        case PPME_SYSCALL_RENAMEAT2_X: return "renameat2";
        case PPME_SYSCALL_RMDIR_E:
        case PPME_SYSCALL_RMDIR_2_E:
        case PPME_SYSCALL_RMDIR_X:
        case PPME_SYSCALL_RMDIR_2_X: return "rmdir";
        case PPME_SYSCALL_SELECT_E:
        case PPME_SYSCALL_SELECT_X: return "select";
        case PPME_SYSCALL_SENDFILE_E:
        case PPME_SYSCALL_SENDFILE_X: return "sendfile";
        case PPME_SYSCALL_SETGID_X:
        case PPME_SYSCALL_SETGID_E: return "setgid";
        case PPME_SYSCALL_SETRLIMIT_E:
        case PPME_SYSCALL_SETRLIMIT_X: return "setrlimit";
        case PPME_SYSCALL_SETUID_E:
        case PPME_SYSCALL_SETUID_X: return "setuid";
        case PPME_SYSCALL_SIGNALFD_E:
        case PPME_SYSCALL_SIGNALFD_X: return "signalfd";
        case PPME_SYSCALL_SPLICE_E:
        case PPME_SYSCALL_SPLICE_X: return "splice";
        case PPME_SYSCALL_STAT_E:
        case PPME_SYSCALL_STAT_X: return "stat";
        case PPME_SYSCALL_STAT64_E:
        case PPME_SYSCALL_STAT64_X: return "stat64";
        case PPME_SYSCALL_SYMLINK_E:
        case PPME_SYSCALL_SYMLINK_X: return "symlink";
        case PPME_SYSCALL_SYMLINKAT_E:
        case PPME_SYSCALL_SYMLINKAT_X: return "symlinkat";
        case PPME_SYSCALL_TIMERFD_CREATE_E:
        case PPME_SYSCALL_TIMERFD_CREATE_X: return "timerfd_create";
        case PPME_SYSCALL_UNLINK_E:
        case PPME_SYSCALL_UNLINK_2_E:
        case PPME_SYSCALL_UNLINK_X:
        case PPME_SYSCALL_UNLINK_2_X: return "unlink";
        case PPME_SYSCALL_UNLINKAT_E:
        case PPME_SYSCALL_UNLINKAT_2_E:
        case PPME_SYSCALL_UNLINKAT_X:
        case PPME_SYSCALL_UNLINKAT_2_X: return "unlinkat";
        case PPME_SYSCALL_WRITE_E:
        case PPME_SYSCALL_WRITE_X: return "write";
        case PPME_SYSCALL_WRITEV_E:
        case PPME_SYSCALL_WRITEV_X: return "writev";
        case PPME_SYSCALL_COPY_FILE_RANGE_E:
        case PPME_SYSCALL_COPY_FILE_RANGE_X: return "copy_file_range";
        case PPME_SYSCALL_IO_URING_ENTER_E:
        case PPME_SYSCALL_IO_URING_ENTER_X: return "io_uring_enter";
        case PPME_SYSCALL_IO_URING_REGISTER_E:
        case PPME_SYSCALL_IO_URING_REGISTER_X: return "io_uring_register";
        case PPME_SYSCALL_IO_URING_SETUP_E:
        case PPME_SYSCALL_IO_URING_SETUP_X: return "io_uring_setup";
        case PPME_SYSCALL_UMOUNT_E:
        case PPME_SYSCALL_UMOUNT_X: return "umount";

        //
        // Process syscalls
        //      
        case PPME_SYSCALL_BPF_E:
        case PPME_SYSCALL_BPF_X: return "bpf";
        case PPME_SYSCALL_BRK_1_E: 
        case PPME_SYSCALL_BRK_4_E:
        case PPME_SYSCALL_BRK_1_X:
        case PPME_SYSCALL_BRK_4_X: return "brk";
        case PPME_SYSCALL_CHDIR_E:
        case PPME_SYSCALL_CHDIR_X: return "chdir";
        case PPME_SYSCALL_CHROOT_E:
        case PPME_SYSCALL_CHROOT_X: return "chroot";
        case PPME_SYSCALL_CLONE_11_E:
        case PPME_SYSCALL_CLONE_16_E:
        case PPME_SYSCALL_CLONE_17_E:
        case PPME_SYSCALL_CLONE_20_E:
        case PPME_SYSCALL_CLONE_11_X:
        case PPME_SYSCALL_CLONE_16_X:
        case PPME_SYSCALL_CLONE_17_X:
        case PPME_SYSCALL_CLONE_20_X: return "clone";
        case PPME_SYSCALL_CLONE3_E:
        case PPME_SYSCALL_CLONE3_X: return "clone3";
        case PPME_SYSCALL_EXECVE_8_E:
        case PPME_SYSCALL_EXECVE_13_E:
        case PPME_SYSCALL_EXECVE_14_E:
        case PPME_SYSCALL_EXECVE_15_E:
        case PPME_SYSCALL_EXECVE_16_E:
        case PPME_SYSCALL_EXECVE_17_E:
        case PPME_SYSCALL_EXECVE_18_E:
        case PPME_SYSCALL_EXECVE_19_E:
        case PPME_SYSCALL_EXECVE_8_X:
        case PPME_SYSCALL_EXECVE_13_X:
        case PPME_SYSCALL_EXECVE_14_X:
        case PPME_SYSCALL_EXECVE_15_X:
        case PPME_SYSCALL_EXECVE_16_X:
        case PPME_SYSCALL_EXECVE_17_X:
        case PPME_SYSCALL_EXECVE_18_X:
        case PPME_SYSCALL_EXECVE_19_X: return "execve";
        case PPME_SYSCALL_EXECVEAT_E:
        case PPME_SYSCALL_EXECVEAT_X: return "execveat";
        case PPME_SYSCALL_FCHDIR_E:
        case PPME_SYSCALL_FCHDIR_X: return "fchdir";
        case PPME_SYSCALL_FORK_E:
        case PPME_SYSCALL_FORK_20_E:
        case PPME_SYSCALL_FORK_X:
        case PPME_SYSCALL_FORK_20_X: return "fork";
        case PPME_SYSCALL_FUTEX_E:
        case PPME_SYSCALL_FUTEX_X: return "futex";
        case PPME_SYSCALL_GETCWD_E:
        case PPME_SYSCALL_GETCWD_X: return "getcwd";
        case PPME_SYSCALL_KILL_E:
        case PPME_SYSCALL_KILL_X: return "kill";
        case PPME_SYSCALL_INOTIFY_INIT_E:
        case PPME_SYSCALL_INOTIFY_INIT_X: return "inotify_init";
        case PPME_SYSCALL_MMAP_E:
        case PPME_SYSCALL_MMAP_X: return "mmap";
        case PPME_SYSCALL_MUNMAP_E:
        case PPME_SYSCALL_MUNMAP_X: return "munmap";
        case PPME_SYSCALL_MLOCKALL_E:
        case PPME_SYSCALL_MLOCKALL_X: return "mlockall";
        case PPME_SYSCALL_MLOCK_E:
        case PPME_SYSCALL_MLOCK_X: return "mlock";
        case PPME_SYSCALL_MMAP2_E:
        case PPME_SYSCALL_MMAP2_X: return "mmap2";
        case PPME_SYSCALL_MPROTECT_E:
        case PPME_SYSCALL_MPROTECT_X: return "mprotect";
        case PPME_SYSCALL_MUNLOCKALL_E:
        case PPME_SYSCALL_MUNLOCKALL_X: return "munlockall";
        case PPME_SYSCALL_MUNLOCK_E:
        case PPME_SYSCALL_MUNLOCK_X: return "munlock";
        case PPME_SYSCALL_NANOSLEEP_E:
        case PPME_SYSCALL_NANOSLEEP_X: return "nanosleep";
        case PPME_SYSCALL_SETPGID_E:
        case PPME_SYSCALL_SETPGID_X: return "setpgid";
        case PPME_SYSCALL_PTRACE_E:
        case PPME_SYSCALL_PTRACE_X: return "ptrace";
        case PPME_SYSCALL_QUOTACTL_E:
        case PPME_SYSCALL_QUOTACTL_X: return "quotactl";
        case PPME_SYSCALL_SECCOMP_E:
        case PPME_SYSCALL_SECCOMP_X: return "seccomp";
        case PPME_SYSCALL_SEMCTL_E:
        case PPME_SYSCALL_SEMCTL_X: return "semctl";
        case PPME_SYSCALL_SEMGET_E:
        case PPME_SYSCALL_SEMGET_X: return "semget";
        case PPME_SYSCALL_SEMOP_E:
        case PPME_SYSCALL_SEMOP_X: return "semop";
        case PPME_SYSCALL_SETNS_E:
        case PPME_SYSCALL_SETNS_X: return "setns";
        case PPME_SYSCALL_SETRESGID_E:
        case PPME_SYSCALL_SETRESGID_X: return "setresgid";
        case PPME_SYSCALL_SETRESUID_E:
        case PPME_SYSCALL_SETRESUID_X: return "setresuid";
        case PPME_SYSCALL_SETSID_E:
        case PPME_SYSCALL_SETSID_X: return "setsid";
        case PPME_SYSCALL_TGKILL_E:
        case PPME_SYSCALL_TGKILL_X: return "tgkill";
        case PPME_SYSCALL_TKILL_E:
        case PPME_SYSCALL_TKILL_X: return "tkill";
        case PPME_SYSCALL_UNSHARE_E:
        case PPME_SYSCALL_UNSHARE_X: return "unshare";
        case PPME_SYSCALL_VFORK_E:
        case PPME_SYSCALL_VFORK_X:
        case PPME_SYSCALL_VFORK_17_E:
        case PPME_SYSCALL_VFORK_17_X: 
        case PPME_SYSCALL_VFORK_20_E:
        case PPME_SYSCALL_VFORK_20_X: return "vfork";
        case PPME_SYSCALL_CAPSET_E:
        case PPME_SYSCALL_CAPSET_X: return "capset";
        case PPME_SYSCALL_USERFAULTFD_E:
        case PPME_SYSCALL_USERFAULTFD_X: return "userfaultfd";

        //
        // Socket syscalls
        // 
        case PPME_SOCKET_SOCKET_E:
        case PPME_SOCKET_SOCKET_X: return "socket";
        case PPME_SOCKET_BIND_E:
        case PPME_SOCKET_BIND_X: return "bind";
        case PPME_SOCKET_CONNECT_E:
        case PPME_SOCKET_CONNECT_X: return "connect";
        case PPME_SOCKET_LISTEN_E:
        case PPME_SOCKET_LISTEN_X: return "listen";
        case PPME_SOCKET_ACCEPT_5_E:
        case PPME_SOCKET_ACCEPT_5_X: return "accept";
        case PPME_SOCKET_GETSOCKNAME_E:
        case PPME_SOCKET_GETSOCKNAME_X: return "getsockname";
        case PPME_SOCKET_GETPEERNAME_E:
        case PPME_SOCKET_GETPEERNAME_X: return "getpeername";
        case PPME_SOCKET_GETSOCKOPT_E:
        case PPME_SOCKET_GETSOCKOPT_X: return "getsockopt";
        case PPME_SOCKET_SOCKETPAIR_E:
        case PPME_SOCKET_SOCKETPAIR_X: return "socketpair";
        case PPME_SOCKET_SENDTO_E:
        case PPME_SOCKET_SENDTO_X: return "sendto";
        case PPME_SOCKET_RECVFROM_E:
        case PPME_SOCKET_RECVFROM_X: return "recvfrom";
        case PPME_SOCKET_SHUTDOWN_E:
        case PPME_SOCKET_SHUTDOWN_X: return "shutdown";
        case PPME_SOCKET_SETSOCKOPT_E:
        case PPME_SOCKET_SETSOCKOPT_X: return "setsockopt";
        case PPME_SOCKET_SENDMSG_E:
        case PPME_SOCKET_SENDMSG_X: return "sendmsg";
        case PPME_SOCKET_ACCEPT4_5_E:
        case PPME_SOCKET_ACCEPT4_5_X: return "accept";
        case PPME_SOCKET_SENDMMSG_E:
        case PPME_SOCKET_SENDMMSG_X: return "sendmmsg";
        case PPME_SOCKET_RECVMSG_E:
        case PPME_SOCKET_RECVMSG_X: return "recvmsg";
        case PPME_SOCKET_RECVMMSG_E:
        case PPME_SOCKET_RECVMMSG_X: return "recvmmsg";
        default: 
            // return "UNKNOWN " + to_string(type);
            if (type == 0) {
                *after_arguments_resolving = true;
                for (int i = 0; i < ev->get_num_params(); ++i) {
                    const char *param_name = ev->get_param_name(i);
                    std::string param_value = ev->get_param_value_str(param_name);
                    if (strcmp(param_name, "ID") == 0) {
                        if (strcmp(param_value.c_str(), "<unknown>") != 0) {
                            return param_value + "()";
                        }
                    } else if (strcmp(param_name, "nativeID") == 0) {
                        return get_syscal_name(param_value) + "()";
                    } 
                }
            }
            return "unknown";
    };
}

static sinsp_evt* get_event(sinsp& inspector, std::function<void(const std::string&)> handle_error)
{
	sinsp_evt* ev = nullptr;

	int32_t res = inspector.next(&ev);

	if(res == SCAP_SUCCESS)
	{
		return ev;
	}

	if(res != SCAP_TIMEOUT)
	{
		handle_error(inspector.getlasterr());
		std::this_thread::sleep_for(std::chrono::seconds(1));
	}

	return nullptr;
}

std::vector<char *> *aggregator;
std::vector<vector<char *> *> aggregators;
scap_stats stats;
int g_int;
uint64_t droppped_events;
map<pthread_t, pthread_t> thread_ids;
sem_t notifier_print_data_sem;
pid_t myppid;
void *g_cli_parser;
time_t start_timer_time;

static void endline_char_escaping(std::string& str, char c) {
    std::vector<int> characterLocations;

    for(int i =0; i < str.size(); i++) {
        if(str[i] == c)
            characterLocations.push_back(i);
    }

    int char_inserts_counter = 0;
    for(int i =0; i < characterLocations.size(); i++) {
        int charLocation = characterLocations[i];
        str.replace(charLocation+char_inserts_counter, 1, "\\n");
        char_inserts_counter += 1;
    }
}

static char* parse_event(sinsp_evt *ev) {
 
    char *data;
    int data_index = 0;
    bool after_arguments_resolving = false;
    sinsp_threadinfo* thread = ev->get_thread_info();
    std::string event_category, ppid_string, pid_string, event_type_string, param_value, exe;
    size_t param_name_size, param_value_size;
    const char *param_name;
    
    data = (char *)malloc(getpagesize());
    if (thread) {
        sinsp_threadinfo* p_thr = thread->get_parent_thread();
        int64_t parent_pid = -1;
        if(nullptr != p_thr) {
            parent_pid = p_thr->m_pid;
        }
        std::string type = get_event_type(ev->get_type(), ev, &after_arguments_resolving);
        
        if(filter_by_container_id(g_cli_parser, thread->m_container_id.c_str()) && myppid != parent_pid) {
            string cmdline;
            sinsp_threadinfo::populate_cmdline(cmdline, thread);
            // endline_char_escaping(cmdline, '\n');

            string date_time;
            sinsp_utils::ts_to_iso_8601(ev->get_ts(), &date_time);

            bool is_host_proc = thread->m_container_id.empty();
            if (!is_host_proc || (is_host_proc && (get_cli_options(g_cli_parser) & INCLUDING_HOST))) {

                // timestamp                
                memcpy(data, date_time.c_str(), date_time.size());
                data_index += date_time.size(); 
                memcpy(data + data_index, "]::[", sizeof("]::["));
                data_index += sizeof("]::[") - 1; 

                // container id
                if (is_host_proc) {
                    memcpy(data + data_index, "HOST", sizeof("HOST"));
                    data_index += sizeof("HOST"); 
                } else {
                    memcpy(data + data_index, thread->m_container_id.c_str(), thread->m_container_id.size());
                    data_index += thread->m_container_id.size(); 
                }
                memcpy(data + data_index, "]::[", sizeof("]::["));
                data_index += sizeof("]::[") - 1; 

                // event category
                memcpy(data + data_index, "CAT=", sizeof("CAT="));
                data_index += sizeof("CAT=") - 1; 
                event_category = get_event_category(ev->get_category());
                memcpy(data + data_index, event_category.c_str(), event_category.size());
                data_index += event_category.size();
                memcpy(data + data_index, "]::[", sizeof("]::["));
                data_index += sizeof("]::[") - 1;

                // event ppid
                memcpy(data + data_index, "PPID=", sizeof("PPID="));
                data_index += sizeof("PPID=") - 1;
                ppid_string = to_string(parent_pid);
                memcpy(data + data_index, ppid_string.c_str(), ppid_string.size());
                data_index += ppid_string.size();
                memcpy(data + data_index, "]::[", sizeof("]::["));
                data_index += sizeof("]::[") - 1;
                
                // event pid
                memcpy(data + data_index, "PID=", sizeof("PID="));
                data_index += sizeof("PID=") - 1;
                pid_string = to_string(thread->m_pid);
                memcpy(data + data_index, pid_string.c_str(), pid_string.size());
                data_index += pid_string.size();
                memcpy(data + data_index, "]::[", sizeof("]::["));
                data_index += sizeof("]::[") - 1;

                // event type
                memcpy(data + data_index, "TYPE=", sizeof("TYPE="));
                data_index += sizeof("TYPE=") - 1;
                if (type != "") {
                    memcpy(data + data_index, type.c_str(), type.size());
                    data_index += type.size();
                } else {
                    event_type_string = to_string(ev->get_type());
                    memcpy(data + data_index, type.c_str(), type.size());
                }
                
                // event parameters
                if (type != "" && after_arguments_resolving == false) {
                    if (ev->get_num_params()) {
                        memcpy(data + data_index, "(", sizeof("("));
                        data_index += 1;
                    }
                    for (int i = 0; i < ev->get_num_params(); ++i) {
                        // param name
                        param_name = ev->get_param_name(i);
                        param_name_size = strlen(param_name);
                        memcpy(data + data_index, param_name, param_name_size);
                        data_index += param_name_size;
                        
                        // param value
                        memcpy(data + data_index, ": ", sizeof(": "));
                        data_index += 2;
                        param_value = ev->get_param_value_str(param_name);
                        endline_char_escaping(param_value, '\n');
                        param_value_size = param_value.size();
                        memcpy(data + data_index, param_value.c_str(), param_value_size);
                        data_index += param_value_size;

                        if (i < ev->get_num_params() - 1) {
                            memcpy(data + data_index, ", ", sizeof(", "));
                            data_index += 2;
                        } else {
                            memcpy(data + data_index, ")", sizeof(")"));
                            data_index += 1;
                        }
                    }
                }
                memcpy(data + data_index, "]::[", sizeof("]::["));
                data_index += sizeof("]::[") - 1;

                // exe            
                memcpy(data + data_index, "EXE=", sizeof("EXE="));
                data_index += sizeof("EXE=") - 1;
                exe = thread->get_exepath();
                endline_char_escaping(exe, '\n');
                memcpy(data + data_index, exe.c_str(), thread->get_exepath().size());
                data_index += exe.size();
                memcpy(data + data_index, "]::[", sizeof("]::["));
                data_index += sizeof("]::[") - 1;

                // cmd
                memcpy(data + data_index, "CMD=", sizeof("CMD="));
                data_index += sizeof("CMD=") - 1;
                // memcpy(data + data_index, cmdline.c_str(), cmdline.size());

            }
        }
    }
    return data;
}

static void* print_data(void *args) {    
    std::vector<char *> *print_aggregator;
    char *data;

    while(g_int) {
        sem_wait(&notifier_print_data_sem);
        if (aggregators.size() > 0) {
            print_aggregator = aggregators[0];
            vector<char *>::iterator ptr;
            size_t print_aggregator_size = print_aggregator->size(); 
            for (int i=0; i < print_aggregator_size; ++i) {
                data = (*print_aggregator)[i];
                printf("%s\n",data);
                free(data);
            }
            aggregators.erase(aggregators.begin());

            delete print_aggregator;
        }
    }
    return NULL;
}

static bool is_timer_expired() {
    time_t current_time;
    double diff = 0;

    time(&current_time);
    diff = difftime(current_time, start_timer_time);
    if (diff > (double)1) {
        time(&start_timer_time);
        return true;
    }
    return false;
}

static void print_capture(sinsp& inspector)
{
	sinsp_evt* ev = get_event(inspector, [](const std::string& error_msg)
				  { cout << "[ERROR] " << error_msg << endl; });

    if (aggregator->size() == 50000 || is_timer_expired()) {
        aggregators.push_back(aggregator);
        aggregator = new vector<char *>;
        sem_post(&notifier_print_data_sem);
    }

	if(ev == nullptr) {
		return;
	}

    sinsp_threadinfo* thread = ev->get_thread_info();
    if (thread) {
        int64_t parent_pid = -1;
        sinsp_threadinfo* p_thr = thread->get_parent_thread();
        if(nullptr != p_thr) {
            parent_pid = p_thr->m_pid;
        }
        if(filter_by_container_id(g_cli_parser, thread->m_container_id.c_str()) && myppid != parent_pid) {
            bool is_host_proc = thread->m_container_id.empty();
            if (!is_host_proc || (is_host_proc && (get_cli_options(g_cli_parser) & INCLUDING_HOST))) {
                aggregator->push_back(parse_event(ev));
            }
        }
    }
}

static void print_stats(scap_stats *s)
{
    return;
	printf("\n---------------------- STATS -----------------------\n");
	printf("Seen by driver: %" PRIu64 "\n", s->n_evts);

	printf("Number of dropped events: %" PRIu64 "\n", s->n_drops);
	printf("Number of dropped events caused by full buffer (total / all buffer drops - includes all categories below, likely higher than sum of syscall categories): %" PRIu64 "\n", s->n_drops_buffer);
	printf("Number of dropped events caused by full buffer (n_drops_buffer_clone_fork_enter syscall category): %" PRIu64 "\n", s->n_drops_buffer_clone_fork_enter);
	printf("Number of dropped events caused by full buffer (n_drops_buffer_clone_fork_exit syscall category): %" PRIu64 "\n", s->n_drops_buffer_clone_fork_exit);
	printf("Number of dropped events caused by full buffer (n_drops_buffer_execve_enter syscall category): %" PRIu64 "\n", s->n_drops_buffer_execve_enter);
	printf("Number of dropped events caused by full buffer (n_drops_buffer_execve_exit syscall category): %" PRIu64 "\n", s->n_drops_buffer_execve_exit);
	printf("Number of dropped events caused by full buffer (n_drops_buffer_connect_enter syscall category): %" PRIu64 "\n", s->n_drops_buffer_connect_enter);
	printf("Number of dropped events caused by full buffer (n_drops_buffer_connect_exit syscall category): %" PRIu64 "\n", s->n_drops_buffer_connect_exit);
	printf("Number of dropped events caused by full buffer (n_drops_buffer_open_enter syscall category): %" PRIu64 "\n", s->n_drops_buffer_open_enter);
	printf("Number of dropped events caused by full buffer (n_drops_buffer_open_exit syscall category): %" PRIu64 "\n", s->n_drops_buffer_open_exit);
	printf("Number of dropped events caused by full buffer (n_drops_buffer_dir_file_enter syscall category): %" PRIu64 "\n", s->n_drops_buffer_dir_file_enter);
	printf("Number of dropped events caused by full buffer (n_drops_buffer_dir_file_exit syscall category): %" PRIu64 "\n", s->n_drops_buffer_dir_file_exit);
	printf("Number of dropped events caused by full buffer (n_drops_buffer_other_interest_enter syscall category): %" PRIu64 "\n", s->n_drops_buffer_other_interest_enter);
	printf("Number of dropped events caused by full buffer (n_drops_buffer_other_interest_exit syscall category): %" PRIu64 "\n", s->n_drops_buffer_other_interest_exit);
	printf("Number of dropped events caused by full scratch map: %" PRIu64 "\n", s->n_drops_scratch_map);
	printf("Number of dropped events caused by invalid memory access (page faults): %" PRIu64 "\n", s->n_drops_pf);
	printf("Number of dropped events caused by an invalid condition in the kernel instrumentation (bug): %" PRIu64 "\n", s->n_drops_bug);
	printf("Number of preemptions: %" PRIu64 "\n", s->n_preemptions);
	printf("Number of events skipped due to the tid being in a set of suppressed tids: %" PRIu64 "\n", s->n_suppressed);
	printf("Number of threads currently being suppressed: %" PRIu64 "\n", s->n_tids_suppressed);
	printf("-----------------------------------------------------\n");
}

static void signal_callback(int signal)
{
    g_int = 0;
}

void* drop_event_check_cb(void *args) {
    sinsp *insp = (sinsp *)args;
    scap_stats capture_stats;
    uint64_t new_droppped_events;
    
    sleep(5);
    while(g_int) {
        sleep(1);
        insp->get_capture_stats(&capture_stats);
        new_droppped_events = capture_stats.n_drops_buffer;
        if (new_droppped_events > droppped_events) {
            cout << "drop event occured" << endl;
            droppped_events = new_droppped_events;
        }
    }return NULL;
}

void start_capturer(void *cli_parser) {
    sinsp inspector;
    std::string filter;
    const char* filter_string = get_filter_string(cli_parser);
    const char* ebpf_path = get_ebpf_path(cli_parser);
    droppped_events = 0;
    pthread_t print_data_tid, drop_event_check_tid, timer_tid;
    myppid = getppid();

    g_cli_parser = cli_parser;
    aggregator = new std::vector<char *>;    
    g_int = 1;

    if(signal(SIGINT, signal_callback) == SIG_ERR)
	{
		fprintf(stderr, "An error occurred while setting SIGINT signal handler.\n");
		return;
	}

    if (sem_init(&notifier_print_data_sem, 0, 0) == -1) {
        fprintf(stderr, "An error occurred while setting semaphore with errno %d.\n", errno);
		return;
    } 

    pthread_create(&print_data_tid, NULL, print_data, NULL);
    pthread_create(&drop_event_check_tid, NULL, drop_event_check_cb, &inspector);

    if (filter_string) {
        filter = filter_string;
    }

    inspector.set_bpf_probe(ebpf_path);
    inspector.open();
    if (!filter.empty())
        inspector.set_filter(filter);

    time(&start_timer_time);
    while (g_int) {
        print_capture(inspector);
    }
    
    scap_stats capture_stats;
    inspector.get_capture_stats(&capture_stats);
    print_stats(&capture_stats);
}