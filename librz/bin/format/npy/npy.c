// SPDX-FileCopyrightText: 2026 historicattle <sirigere.naren@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file npy.c
 * \brief NPY Format Plugin
 *
 * A simple format for saving numpy arrays to disk with the full information about them.
 *
 * The .npy format is the standard binary file format in NumPy for
 * persisting a *single* arbitrary NumPy array on disk. The format stores all
 * of the shape and dtype information necessary to reconstruct the array
 * correctly even on another machine with a different architecture.
 **/

#include "npy.h"

void npy_parse(){}