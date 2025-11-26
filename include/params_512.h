// include/params_512.h
#ifndef WSIDH_PARAMS_512_H
#define WSIDH_PARAMS_512_H

#include "params.h"

/*
 * TODO: CNTR-style WSIDH_PARAMS_512 is intentionally not implemented yet.
 * Any attempt to include this header should fail loudly so we remember that
 * fresh parameter generation, NTT tables, and security analysis are still
 * required before a 512-dimension configuration can exist in this tree.
 */
#error "WSIDH_PARAMS_512 is declared but not defined: CNTR parameters not yet integrated."
extern const wsidh_params_t WSIDH_PARAMS_512;

#endif // WSIDH_PARAMS_512_H
