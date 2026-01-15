// SPDX-FileCopyrightText: 2026 historicattle <sirigere.naren@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef NPY_H
#define NPY_H

#include <rz_bin.h>

#define NPY_VERSION 3
#define NPY_MAGIC "\x93\x4e\x55\x4d\x50\x59"
#define NPY_MAJOR_VERSION_OFFSET 6
#define NPY_MINOR_VERSION_OFFSET 7
#define NPY_HEADER_LEN_SIZE1 2
#define NPY_HEADER_LEN_SIZE2 4
#define NPY_HEADER_LEN 

/**
 * \struct RzBinNpyObj_t
 * \brief Stores all information about the npy binary
 */
typedef struct RzBinNpyObj_t {
	RzPVector *magic_string;
	ut8 major; ///< major version
	ut8 minor; ///< minor version
	ut32 header_size; ///< size of header
	RzPVector *header;
	RzPVector *text;
} RzBinNpyObj;

void npy_parse();

#endif