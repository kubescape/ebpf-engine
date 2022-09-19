#ifndef __ARMO_EBPF_AGENT_H__
#define __ARMO_EBPF_AGENT_H__

#include "armo-types.h"

typedef enum armo_return_code {
    ARMO_SUCCESS = 0,
    ARMO_FAIL
}armo_rc;

typedef enum agent_bool {
    armo_false,
    armo_true
}armo_bool;

#endif //__ARMO_EBPF_AGENT_H__
