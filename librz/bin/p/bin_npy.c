// SPDX-FileCopyrightText: 2026 historicattle <sirigere.naren@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin.h>
#include "../format/npy/npy.h"

static bool npy_load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *buf, Sdb *sdb) {
	rz_return_val_if_fail(obj, false);
	RzBinNpyObj *npy = RZ_NEW0(RzBinNpyObj);
	ut64 offset = 0;
	if (!npy) {
		RZ_LOG_ERROR("Unable to load buffer!");
		return false;
	}
	rz_buf_read_at(buf, &offset, &npy->magic_string, 6);
	rz_buf_read_ble8_offset(buf, &offset, &npy->major, rz_bin_object_is_big_endian(obj));
	rz_buf_read_ble8_offset(buf, &offset, &npy->minor, rz_bin_object_is_big_endian(obj));
	rz_buf_read_ble32_at(buf, &offset, &npy->header_size, rz_bin_object_is_big_endian(obj));
	rz_buf_read_at(buf, &offset, &npy->header, &npy->header_size);

	obj->bin_obj=npy;
	return true;
}

static void npy_destroy(RzBinNpyObj *bin) {
	if (!bin) {
		return;
	}
	rz_pvector_free(bin->magic_string);
	rz_pvector_free(bin->header);
	rz_pvector_free(bin->text);
	free(bin);
}

static ut64 npy_baddr(RzBinFile *bf) {
	return 0LL;
}

RzBinPlugin rz_bin_plugin_npy = {
	.name = "npy",
	.desc = "binary for .npy",
	.license = "LGPL3",
	.author = "historicattle",
	.load_buffer = &npy_load_buffer,
	.destroy = &npy_destroy,
	.baddr = &npy_baddr,
	// .info = info,
};