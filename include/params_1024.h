// include/params_1024.h
#ifndef WSIDH_PARAMS_1024_H
#define WSIDH_PARAMS_1024_H

#include "params.h"

/*
 * Placeholder only. WSIDH_PARAMS_1024 needs bespoke parameter derivation,
 * wave tables, NTT twiddles, and failure-rate studies. Until those exist this
 * header aborts the build to avoid silently shipping a fake configuration.
 */
#error "WSIDH_PARAMS_1024 is declared but not defined: CNTR parameters not yet integrated."
extern const wsidh_params_t WSIDH_PARAMS_1024;

#endif // WSIDH_PARAMS_1024_H
