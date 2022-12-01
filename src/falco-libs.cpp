#include "falco-libs.h"
#include "cli-parser.h"
#include <iostream>
#include <stdlib.h>
#include <sinsp.h>

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

static void print_capture(sinsp& inspector, void *cli_parser)
{
	sinsp_evt* ev = get_event(inspector, [](const std::string& error_msg)
				  { cout << "[ERROR] " << error_msg << endl; });

	if(ev == nullptr) {
		return;
	}

	sinsp_threadinfo* thread = ev->get_thread_info();
	if(thread && filter_by_container_id(cli_parser, thread->m_container_id.c_str())) {
		string cmdline;
		sinsp_threadinfo::populate_cmdline(cmdline, thread);
        endline_char_escaping(cmdline, '\n');

        string date_time;
        sinsp_utils::ts_to_iso_8601(ev->get_ts(), &date_time);

        bool is_host_proc = thread->m_container_id.empty();
        if (!is_host_proc || (is_host_proc && (get_cli_options(cli_parser) & INCLUDING_HOST))) {

            cout << date_time << "]::[" << (is_host_proc? "HOST": thread->m_container_id) << "]::";
            cout << "[CAT=" << get_event_category(ev->get_category()) << "]::";

            sinsp_threadinfo* p_thr = thread->get_parent_thread();
            int64_t parent_pid = -1;
            if(nullptr != p_thr)
            {
                parent_pid = p_thr->m_pid;
            }

            cout << "[PPID=" << parent_pid << "]::"
                    << "[PID=" << thread->m_pid << "]::"
                    << "[TYPE=" << get_event_type_name(inspector, ev);
            
            if (ev->get_num_params()) {
                cout << "(";
            }
            for (int i = 0; i < ev->get_num_params(); ++i) {
                const char *param_name = ev->get_param_name(i);
                cout << param_name << ": " << ev->get_param_value_str(param_name);
                if (i < ev->get_num_params() - 1)
                    cout << ", ";
                else
                    cout << ")";
            }
            cout << "]::";
            cout << "[EXE=" << thread->get_exepath() << "]::"
                    << "[CMD=" << cmdline
                    << endl;
        }
    }
}

void start_capturer(void *cli_parser) {
    sinsp inspector;
    std::string filter;
    const char* filter_string = get_filter_string(cli_parser);
    const char* ebpf_path = get_ebpf_path(cli_parser);
    std::unordered_set<uint32_t> tp_set = inspector.enforce_sinsp_state_tp();
	std::unordered_set<uint32_t> ppm_sc;

    if (filter_string) {
        filter = filter_string;
    }

    inspector.open_bpf(ebpf_path, DEFAULT_DRIVER_BUFFER_BYTES_DIM, ppm_sc, tp_set);
    
    // inspector.open();
    if (!filter.empty())
        inspector.set_filter(filter);

    while (1) {
        print_capture(inspector, cli_parser);
    }
}