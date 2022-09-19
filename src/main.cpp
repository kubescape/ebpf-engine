#include "armo-types.h"
#include "cli-parser.h"
#include "falco-libs.h"
  
static armo_rc parse_cli_options(void **cli_parser, int argc, char **argv) {
    armo_rc rc = ARMO_SUCCESS;
    *cli_parser = create_cli_parser();
    
    if (ARMO_FAIL == parse_cli(*cli_parser, argc, argv)) {
        destroy_cli_parser(*cli_parser);
        rc = ARMO_FAIL;
    }

    return rc;
}   

static void start_capture_job(void *cli_parser) {
    start_capturer(cli_parser);
}

int main(int argc, char **argv) {
    void *cli_parser;
    
    if (ARMO_FAIL == parse_cli_options(&cli_parser, argc, argv)) {
        return 0;
    }
	
	start_capture_job(cli_parser);
	
    return 0;
}