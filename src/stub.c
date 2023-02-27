#include "stub.h"

unsigned rte_lcore_id_stub() {
    return rte_lcore_id();
}

int rte_gettid_stub() {
    return rte_gettid();
}

int rte_errno_stub() {
    return per_lcore__rte_errno;
}