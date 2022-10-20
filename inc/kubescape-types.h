#ifndef __KUBESCAPE_EBPF_AGENT_H__
#define __KUBESCAPE_EBPF_AGENT_H__

#include "kubescape-types.h"

typedef enum kubescape_return_code {
    KUBESCAPE_SUCCESS = 0,
    KUBESCAPE_FAIL
}kubescape_rc;

typedef enum agent_bool {
    kubescape_false,
    kubescape_true
}kubescape_bool;

#endif //__KUBESCAPE_EBPF_AGENT_H__
