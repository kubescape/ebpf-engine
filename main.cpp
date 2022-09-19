#include <iostream>
#include <sinsp.h>
#include <csignal>
#include <getopt.h>
#include "/home/raziel/armo/ebpf/armo-agent-v2/dependencies/falco-libs/userspace/libsinsp/container_engine/container_engine_base.h"

void plaintext_dump(sinsp& inspector);
sinsp_evt* get_event(sinsp& inspector, std::function<void(const std::string&)> handle_error);
std::function<void(sinsp& inspector)> dump;

static const uint8_t g_backoff_timeout_secs = 2;
static bool g_interrupted = false;
static bool g_all_threads = false;
string engine_string = "bpf";
string filter_string = "";
string file_path = "";
string bpf_path = "/etc/probe.o";
uint64_t buffer_dim = 0;

std::string get_event_category(ppm_event_category category)
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

//
// Get the string representation of a ppm_event_type
//
std::string get_event_type(uint16_t type)
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
        case PPME_SYSCALL_DUP_X: return "dup";
        case PPME_SYSCALL_EPOLLWAIT_E:
        case PPME_SYSCALL_EPOLLWAIT_X: return "epollwait";
        case PPME_SYSCALL_EVENTFD_E:
        case PPME_SYSCALL_EVENTFD_X: return "eventfd";
        case PPME_SYSCALL_FCHMODAT_E:
        case PPME_SYSCALL_FCHMODAT_X: return "fchmodat";
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

        //
        // Process syscalls
        //      
        case PPME_SYSCALL_BPF_E:
	case PPME_SYSCALL_BPF_2_E:
        case PPME_SYSCALL_BPF_X:
	case PPME_SYSCALL_BPF_2_X: return "bpf";
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
        case PPME_SYSCALL_VFORK_20_E:
        case PPME_SYSCALL_VFORK_X:
        case PPME_SYSCALL_VFORK_20_X: return "vfork";

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
        case PPME_SOCKET_SETSOCKOPT_X: return "setsocktopt";
        case PPME_SOCKET_SENDMSG_E:
        case PPME_SOCKET_SENDMSG_X: return "sendmsg";
        case PPME_SOCKET_ACCEPT4_5_E:
        case PPME_SOCKET_ACCEPT4_5_X: return "accept";
        case PPME_SOCKET_SENDMMSG_E:
        case PPME_SOCKET_SENDMMSG_X: return "sendmsg";
        case PPME_SOCKET_RECVMSG_E:
        case PPME_SOCKET_RECVMSG_X: return "recvmsg";
        case PPME_SOCKET_RECVMMSG_E:
        case PPME_SOCKET_RECVMMSG_X: return "recvmmsg";
        default: return "UNKNOWN " + to_string(type);
    };
}

static void sigint_handler(int signum)
{
	g_interrupted = true;
}

void open_engine(sinsp& inspector)
{
	std::cout << "-- Try to open: '" + engine_string + "' engine." << std::endl;

	if(!engine_string.compare(BPF_ENGINE))
	{
		if(bpf_path.empty())
		{
			std::cerr << "You must specify the path to the bpf probe if you use the 'bpf' engine" << std::endl;
			exit(EXIT_FAILURE);
		}
		else
		{
			std::cerr << bpf_path << std::endl;
		}
		inspector.open_bpf(buffer_dim, bpf_path.c_str());
	}
	else
	{
		std::cerr << "Unknown engine" << std::endl;
		exit(EXIT_FAILURE);
	}

	std::cout << "-- Engine '" + engine_string + "' correctly opened." << std::endl;
}

void parse_CLI_options(sinsp& inspector, int argc, char** argv)
{
	static struct option long_options[] = {
		{"help", no_argument, 0, 'h'},
		{"filter", required_argument, 0, 'f'},
		{"json", no_argument, 0, 'j'},
		{"all-threads", no_argument, 0, 'a'},
		{"engine", required_argument, 0, 'e'},
		{"bpf-path", required_argument, 0, 'b'},
		{"buffer-dim", required_argument, 0, 'd'},
		{"file-path", required_argument, 0, 's'},
		{0, 0, 0, 0}};

	int op;
	int long_index = 0;
	while((op = getopt_long(argc, argv,
				"h:f:j:a:e:b:d:s:",
				long_options, &long_index)) != -1)
	{
		switch(op)
		{
		case 'f':
			filter_string = optarg;
			break;
		case 'a':
			g_all_threads = true;
			break;
		case 'b':
			bpf_path = optarg;
			break;
		case 'd':
			buffer_dim = strtoul(optarg, NULL, 10);
			break;
		case 's':
			file_path = optarg;
			break;
		default:
			break;
		}
	}
}

int main(int argc, char** argv)
{
	sinsp inspector;
	dump = plaintext_dump;

    parse_CLI_options(inspector, argc, argv);
	signal(SIGPIPE, sigint_handler);

	signal(SIGPIPE, sigint_handler);
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);

	open_engine(inspector);

	std::cout << "-- Start capture" << std::endl;

	if(!filter_string.empty())
	{
		try
		{
			inspector.set_filter(filter_string);
            cout << "filter string: " << inspector.get_filter() << std::endl;
		}
		catch(const sinsp_exception& e)
		{
			cerr << "[ERROR] Unable to set filter: " << e.what() << endl;
		}
	}

	while(!g_interrupted)
	{
		dump(inspector);
	}

	// Cleanup JSON formatters
	// delete default_formatter;
	// delete process_formatter;
	// delete net_formatter;

	return 0;
}

sinsp_evt* get_event(sinsp& inspector, std::function<void(const std::string&)> handle_error)
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
		std::this_thread::sleep_for(std::chrono::seconds(g_backoff_timeout_secs));
	}

	return nullptr;
}

void plaintext_dump(sinsp& inspector)
{

	sinsp_evt* ev = get_event(inspector, [](const std::string& error_msg)
				  { cout << "[ERROR] " << error_msg << endl; });

	if(ev == nullptr)
	{
		return;
	}

	sinsp_threadinfo* thread = ev->get_thread_info();
	if(thread)
	{
		string cmdline;
		sinsp_threadinfo::populate_cmdline(cmdline, thread);

        g_all_threads = 1;
		if(g_all_threads || thread->is_main_thread())
		{
			string date_time;
			sinsp_utils::ts_to_iso_8601(ev->get_ts(), &date_time);

			bool is_host_proc = thread->m_container_id.empty();
			cout << "[" << date_time << "]:["
			     << (is_host_proc ? "HOST" : thread->m_container_id) << "]:";

            cout << "[" << ev->get_num_params() << "]";
            
			cout << "[CAT=";

			if(ev->get_category() == EC_PROCESS)
			{
				cout << "PROCESS]:";
			}
			else if(ev->get_category() == EC_NET)
			{
				cout << get_event_category(ev->get_category()) << "]:";
				sinsp_fdinfo_t* fd_info = ev->get_fd_info();

				// event subcategory should contain SC_NET if ipv4/ipv6
				if(nullptr != fd_info && (fd_info->get_l4proto() != SCAP_L4_UNKNOWN && fd_info->get_l4proto() != SCAP_L4_NA))
				{
					cout << "[" << fd_info->tostring() << "]:";
				}
			}
			else if(ev->get_category() == EC_IO_READ || ev->get_category() == EC_IO_WRITE)
			{
				cout << get_event_category(ev->get_category()) << "]:";

				sinsp_fdinfo_t* fd_info = ev->get_fd_info();
				if(nullptr != fd_info && (fd_info->get_l4proto() != SCAP_L4_UNKNOWN && fd_info->get_l4proto() != SCAP_L4_NA))
				{
					cout << "[" << fd_info->tostring() << "]:";
				}
			}
			else
			{
				cout << get_event_category(ev->get_category()) << "]:";
			}

			sinsp_threadinfo* p_thr = thread->get_parent_thread();
			int64_t parent_pid = -1;
			if(nullptr != p_thr)
			{
				parent_pid = p_thr->m_pid;
			}

			cout << "[PPID=" << parent_pid << "]:"
			     << "[PID=" << thread->m_pid << "]:"
			     << "[TYPE=" << get_event_type(ev->get_type()) << "]:"
			     << "[EXE=" << thread->get_exepath() << "]:"
			     << "[CMD=" << cmdline << "]"
			     << endl;
		}
	}
	else
	{
		cout << "[EVENT]:[" << get_event_category(ev->get_category()) << "]:"
		     << ev->get_name() << endl;
	}
}