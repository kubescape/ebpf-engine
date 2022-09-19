#ifndef __CLI_PARSER_H__
#define __CLI_PARSER_H__

#ifdef __cplusplus
extern "C" {
#endif
    
#include "armo-types.h"
#include <stdint.h>

typedef enum cli_options_t{
    INCLUDING_HOST = 1,
    MAIN_THREAD_ONLY = 2
}cli_options_t;

void *create_cli_parser();
armo_rc parse_cli(void *cli_parser, int argc, char **argv);
cli_options_t get_cli_options(void *cli_parser);
char* get_filter_string(void *cli_parser);
char* get_ebpf_path(void *cli_parser);
uint8_t filter_by_container_id(void *cli_parser_obj, const char *container_id);
void destroy_cli_parser(void *cli_parser);

#ifdef __cplusplus
}
#endif

#endif //__CLI_PARSER_H__