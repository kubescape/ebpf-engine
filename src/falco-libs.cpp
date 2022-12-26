#include "falco-libs.h"
#include "cli-parser.h"
#include <iostream>
#include <stdlib.h>
#include <sinsp.h>
#include <signal.h>
#include <stdlib.h>
#include <pthread.h>

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

std::string get_event_type_name(sinsp& inspector, sinsp_evt* ev)
{
	uint16_t type = ev->get_type();
	if (type >= PPM_EVENT_MAX)
	{
		return "UNKNOWN " + to_string(type);
	}
	if (type != PPME_GENERIC_E && type != PPME_GENERIC_X)
	{
		return g_infotables.m_event_info[type].name;
	}

	auto tables = inspector.get_event_info_tables();
	sinsp_evt_param *parinfo = ev->get_param(0);
	uint16_t ppm_sc = *(uint16_t *)parinfo->m_val;
	return tables->m_syscall_info_table[ppm_sc].name;
}

static sinsp_evt* get_event(sinsp& inspector, std::function<void(const std::string&)> handle_error)
{
	sinsp_evt* ev = nullptr;

	int32_t res = inspector.next(&ev);

	if(res == SCAP_SUCCESS)
	{
		return ev;
	}

	if(res != SCAP_TIMEOUT && res != SCAP_FILTERED_EVENT)
	{
		handle_error(inspector.getlasterr());
		std::this_thread::sleep_for(std::chrono::seconds(1));
	}

	return nullptr;
}

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

std::vector<sinsp_evt> *aggregator;
std::vector<vector<sinsp_evt> *> aggregators;
scap_stats stats;
int g_int;
uint64_t droppped_events;
map<pthread_t, pthread_t> thread_ids;
pthread_mutex_t notifier_print_data_mutex;
struct timespec notifier_print_data_timeout;
sinsp *insp;

static std::string parse_event(sinsp_evt ev) {    
    // IMPROVMENT:
    // 1. create string with one big allocation and add parse event data to it 

	sinsp_threadinfo* thread = ev.get_thread_info();
    
    std::stringstream data;
    string cmdline;
    sinsp_threadinfo::populate_cmdline(cmdline, thread);
    endline_char_escaping(cmdline, '\n');

    string date_time;
    sinsp_utils::ts_to_iso_8601(ev.get_ts(), &date_time);
    bool is_host_proc = thread->m_container_id.empty();

    data << date_time << "]::[" << (is_host_proc? "HOST": thread->m_container_id) << "]::";
    data << "[CAT=" << get_event_category(ev.get_category()) << "]::";

    sinsp_threadinfo* p_thr = thread->get_parent_thread();
    int64_t parent_pid = -1;
    if(nullptr != p_thr)
    {
        parent_pid = p_thr->m_pid;
    }

    data << "[PPID=" << parent_pid << "]::"
            << "[PID=" << thread->m_pid << "]::"
            << "[TYPE=" << get_event_type_name(*insp, &ev);
    
    if (ev.get_num_params()) {
        data << "(";
    }
    for (int i = 0; i < ev.get_num_params(); ++i) {
        const char *param_name = ev.get_param_name(i);
        data << param_name << ": " << ev.get_param_value_str(param_name);
        if (i < ev.get_num_params() - 1)
            data << ", ";
        else
            data << ")";
    }
    data << "]::";
    data << "[EXE=" << thread->get_exepath() << "]::"
            << "[CMD=" << cmdline
            << endl;
    return data.str();
}

static void* print_data(void *args) {    
    std::vector<sinsp_evt> *print_aggregator;
    
    while(g_int) {
        pthread_mutex_timedlock(&notifier_print_data_mutex, &notifier_print_data_timeout);
        if (aggregators.size() > 0) {
            // get the first aggregator for print
            print_aggregator = aggregators[0];
            aggregators.erase(aggregators.begin());
            vector<sinsp_evt*>::iterator ptr;
            size_t print_aggregator_size = print_aggregator->size(); 
            // remove the 50000 in the branch
            // add the max aggregate event as process argument
            for (int i=0; i < print_aggregator_size; ++i) {
                cout << parse_event((*print_aggregator)[i]);
            }

            delete print_aggregator;
        }
    }
    return NULL;
}

static void aggregate_capture(sinsp& inspector, void *cli_parser, pid_t mypid, pid_t myppid)
{
	sinsp_evt* ev = get_event(inspector, [](const std::string& error_msg)
				  { cout << "[ERROR] " << error_msg << endl; });

    if (aggregator->size() == 50000) {
        aggregators.push_back(aggregator);
        aggregator = new vector<sinsp_evt>;
        pthread_mutex_unlock(&notifier_print_data_mutex);
    }

	if(ev == nullptr) {
        return;
	}
 
	sinsp_threadinfo* thread = ev->get_thread_info();
	if(thread && filter_by_container_id(cli_parser, thread->m_container_id.c_str()) && thread->m_pid != mypid && thread->m_pid != myppid) {
        bool is_host_proc = thread->m_container_id.empty();
        if (!is_host_proc || (is_host_proc && (get_cli_options(cli_parser) & INCLUDING_HOST))) {
            aggregator->push_back(*ev);
        }
    }
    
}

int get_modifies_state_tracepoints(OUT uint32_t tp_array[TP_VAL_MAX])
{
	if(tp_array == NULL)
	{
		return SCAP_FAILURE;
	}

	/* Clear the array before using it.
	 * This is not necessary but just to be future-proof.
	 */
	memset(tp_array, 0, sizeof(*tp_array) * TP_VAL_MAX);

	tp_array[SYS_ENTER] = 1;
	tp_array[SYS_EXIT] = 1;
	// tp_array[SCHED_PROC_EXIT] = 1;
	// tp_array[SCHED_SWITCH] = 1;
	/* With `aarch64` and `s390x` we need also this, 
	 * in `x86` they are not considered at all.
	 */
	// tp_array[SCHED_PROC_FORK] = 1;
	// tp_array[SCHED_PROC_EXEC] = 1;
	return SCAP_SUCCESS;
}


std::unordered_set<uint32_t> enforce_sinsp_state_tp(std::unordered_set<uint32_t> tp_of_interest)
{
	std::vector<uint32_t> minimum_tracepoints(TP_VAL_MAX, 0);

	/* Should never happen but just to be sure. */
	if(get_modifies_state_tracepoints(minimum_tracepoints.data()) != SCAP_SUCCESS)
	{
		throw sinsp_exception("'minimum_tracepoints' is an unexpected NULL vector!");
	}

	for(int tp = 0; tp < TP_VAL_MAX; tp++)
	{
		if(minimum_tracepoints[tp])
		{
			tp_of_interest.insert(tp);
		}
	}
	return tp_of_interest;
}

static void print_stats(scap_stats *s)
{

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

void *drop_event_check_cb(void *args) {
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
    }
    return NULL;
}

void start_capturer(void *cli_parser) {
    droppped_events = 0;
    sinsp inspector;
    std::string filter;
    const char* filter_string = get_filter_string(cli_parser);
    const char* ebpf_path = get_ebpf_path(cli_parser);
    std::unordered_set<uint32_t> tp_of_interest;
    std::unordered_set<uint32_t> tp_set = enforce_sinsp_state_tp(tp_of_interest);
	std::unordered_set<uint32_t> ppm_sc;
    unsigned long  driver_buffer_bytes = DEFAULT_DRIVER_BUFFER_BYTES_DIM * 16;
    pthread_t print_data_tid, drop_event_check_tid;
    pid_t mypid = getpid();
    pid_t myppid = getppid();

    aggregator = new std::vector<sinsp_evt>;
    insp = &inspector;   
    g_int = 1;

    if(signal(SIGINT, signal_callback) == SIG_ERR)
	{
		fprintf(stderr, "An error occurred while setting SIGINT signal handler.\n");
		return;
	}

    notifier_print_data_timeout.tv_sec = 1;
    pthread_create(&print_data_tid, NULL, print_data, NULL);
    pthread_create(&drop_event_check_tid, NULL, drop_event_check_cb, &inspector);

    if (filter_string) {
        filter = filter_string;
    }

    inspector.open_bpf(ebpf_path, driver_buffer_bytes, ppm_sc, tp_set);
    
    if (!filter.empty())
        inspector.set_filter(filter);

    while (g_int) {
        aggregate_capture(inspector, cli_parser, mypid, myppid);
    }

    inspector.get_capture_stats(&stats);
    print_stats(&stats);
}