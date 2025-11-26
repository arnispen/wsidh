#include "params_256.h"

#include <stddef.h>

/*
 * Active WSIDH build still assumes the historical N=256 ring with the wave
 * polynomial derived for q = 3329. Keeping the data in a single params struct
 * makes it trivial to plug in future CNTR-style parameter sets without touching
 * the rest of the implementation.
 */

static const int16_t wsidh_wave_table_256[WSIDH_N] = {
    0,33,66,99,132,164,195,227,257,287,316,344,371,397,422,446,
    468,490,510,528,546,562,576,589,600,610,619,626,631,635,638,639,
    639,637,635,630,625,619,611,602,593,582,571,559,546,532,518,504,
    489,474,458,442,427,411,395,379,363,348,333,318,303,289,276,263,
    250,238,227,216,206,196,188,179,172,165,159,154,149,145,141,138,
    135,133,132,131,130,130,130,130,131,132,133,134,135,136,137,138,
    139,140,140,141,141,141,140,140,138,137,135,133,130,127,123,119,
    115,110,105,99,93,87,80,73,66,58,50,42,34,26,17,9,
    0,2293,2285,2276,2268,2260,2252,2244,2236,2229,2222,2215,2209,2203,2197,2192,
    2187,2183,2179,2175,2172,2169,2167,2165,2164,2162,2162,2161,2161,2161,2162,2162,
    2163,2164,2165,2166,2167,2168,2169,2170,2171,2172,2172,2172,2172,2171,2170,2169,
    2167,2164,2161,2157,2153,2148,2143,2137,2130,2123,2114,2106,2096,2086,2075,2064,
    2052,2039,2026,2013,1999,1984,1969,1954,1939,1923,1907,1891,1875,1860,1844,1828,
    1813,1798,1784,1770,1756,1743,1731,1720,1709,1700,1691,1683,1677,1672,1667,1665,
    1663,1663,1664,1667,1671,1676,1683,1692,1702,1713,1726,1740,1756,1774,1792,1812,
    1834,1856,1880,1905,1931,1958,1986,2015,2045,2075,2107,2138,2170,2203,2236,2269
};

static const int16_t wsidh_ntt_zetas_fwd_256[] = {
    3328, 1729, 2580, 2642, 1062, 296, 289, 17
};

static const int16_t wsidh_ntt_zetas_inv_256[] = {
    3328, 1600, 40, 2481, 1583, 2508, 2419, 1175
};

static const wsidh_params_t *g_wsidh_params = NULL;

const wsidh_params_t WSIDH_PARAMS_256 = {
    .N = WSIDH_N,
    .Q = WSIDH_Q,
    .bound_s = WSIDH_BOUND_S,
    .bound_e = WSIDH_BOUND_E,
    .barrett_v = ((1u << 26) + (WSIDH_Q / 2)) / WSIDH_Q,
    .wave_table = wsidh_wave_table_256,
    .wave_table_len = WSIDH_N,
    .zetas = wsidh_ntt_zetas_fwd_256,
    .zetas_inv = wsidh_ntt_zetas_inv_256,
    .stage_count = sizeof(wsidh_ntt_zetas_fwd_256) / sizeof(wsidh_ntt_zetas_fwd_256[0]),
    .n_inv = 3316,
};

static const wsidh_params_t *wsidh_params_fallback(void) {
    if (!g_wsidh_params) {
        g_wsidh_params = &WSIDH_PARAMS_256;
    }
    return g_wsidh_params;
}

const wsidh_params_t *wsidh_params_active(void) {
    return wsidh_params_fallback();
}

void wsidh_params_select(const wsidh_params_t *params) {
    g_wsidh_params = params ? params : &WSIDH_PARAMS_256;
}

void wsidh_params_reset(void) {
    g_wsidh_params = &WSIDH_PARAMS_256;
}
