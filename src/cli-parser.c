#include "cli-parser.h"
#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <stdio.h>
#include <string.h>

typedef struct cli_parser_t {
    char *filter_string;
    uint64_t options;
    char *container_id_filter;
    char *ebpf_path;
}cli_parser_t;

void *create_cli_parser() {
    cli_parser_t *cli_parser;

    cli_parser = (cli_parser_t *)calloc(1, sizeof(cli_parser_t));

    return cli_parser;
}

static void print_cli_help() {
    fprintf(stdout, 
            "Usage: <binary_name> [OPTIONS] -e [ebpf-kernel-code-path]\n"
            "Attach to syscall getting in filter option and apply the kernel code supplied by -e option\n"
             
            "options:\n"
            "\t -h: print this message\n"
            "\t -f: filter attached syscalls. example: -f evt.category=process and evt.type=execve\n"
            "\t     all catagery and type exist in the README.md in the source code\n"
            "\t -o: print host machine syscalls data as well(default behaviour: print only to syscalls that exist in containers)\n"
            "\t -m: print syscalls data exist only in main thread\n"
            "\t -c: print syscall data filtered by container id(short one), example: 087176b8eb75");
}

static void print_cli_error() {
    fprintf(stderr, "unknown option enter to the cli %c\n", optopt);
    print_cli_help();
}


kubescape_rc parse_cli(void *cli_parser_obj, int argc, char **argv) {
	
    kubescape_rc rc = KUBESCAPE_SUCCESS;
    int op;
	int long_index = 0;
    kubescape_bool stop = kubescape_false;
    cli_parser_t *cli_parser = (cli_parser_t *)cli_parser_obj;

    static struct option long_options[] = {
		{"help", no_argument, NULL, 'h'},
		{"filter", required_argument, NULL, 'f'},
		{"including_host", no_argument, NULL, 'o'},
		{"main_thread_only", no_argument, NULL, 'm'},
		{"ebpf_code_path", required_argument, NULL, 'e'},
		{"container_id", required_argument, NULL, 'c'},
		{0, 0, 0, 0}};

	while((op = getopt_long(argc, argv,
				"hf:ome:c:",
				long_options, &long_index)) != -1) {
		switch(op) {
		case 'f':
			cli_parser->filter_string = optarg;
			break;
		case 'o':
			cli_parser->options |= INCLUDING_HOST;
			break;
		case 'm':
			cli_parser->options |= MAIN_THREAD_ONLY;
			break;
		case 'e':
			cli_parser->ebpf_path = optarg;
			break;
        case 'c':
            cli_parser->container_id_filter = optarg;
            break;
        case 'h':
            print_cli_help();
            stop = kubescape_true;
            rc = KUBESCAPE_FAIL;
            break;
		default:
            print_cli_error();
            stop = kubescape_true;
            rc = KUBESCAPE_FAIL;
			break;
		}
        if (stop == kubescape_true)
            break;
	}

    return rc;
}

cli_options_t get_cli_options(void *cli_parser_obj) {
    cli_parser_t *cli_parser = (cli_parser_t *)cli_parser_obj;

    if (cli_parser) {
        return cli_parser->options;
    }
}

char* get_filter_string(void *cli_parser_obj) {
    cli_parser_t *cli_parser = (cli_parser_t *)cli_parser_obj;

    if (cli_parser) {
        return cli_parser->filter_string;
    }
}

char* get_ebpf_path(void *cli_parser_obj) {
    cli_parser_t *cli_parser = (cli_parser_t *)cli_parser_obj;

    if (cli_parser) {
        return cli_parser->ebpf_path;
    }
}

uint8_t filter_by_container_id(void *cli_parser_obj, const char *container_id) {
    cli_parser_t *cli_parser = (cli_parser_t *)cli_parser_obj;

    if (cli_parser) {
        return cli_parser->container_id_filter == NULL || strstr(cli_parser->container_id_filter, container_id) != NULL;
    }
    return 0;
}

void destroy_cli_parser(void *cli_parser_obj) {
    cli_parser_t *cli_parser = (cli_parser_t *)cli_parser_obj;

    if (cli_parser) {
        free(cli_parser);
    }
}