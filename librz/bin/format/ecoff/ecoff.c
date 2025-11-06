// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-License-Identifier: LGPL-3.0-only

#include "ecoff.h"

#define ECOFF_SECTION_TYPE_DATA_MASK (ECOFF_SECTION_TYPE_DATA | \
	ECOFF_SECTION_TYPE_BSS | \
	ECOFF_SECTION_TYPE_RDATA | \
	ECOFF_SECTION_TYPE_SDATA | \
	ECOFF_SECTION_TYPE_SBSS)

static bool ecoff_is_big_endian(const ut16 magic) {
	switch (magic) {
	case ECOFF_MACHINE_MIPS1_BE:
		return true;
	case ECOFF_MACHINE_MIPS2_BE:
		return true;
	case ECOFF_MACHINE_MIPS3_BE:
		return true;
	default:
		return false;
	}
}

static bool ecoff_is_little_endian(const ut16 magic) {
	switch (magic) {
	case ECOFF_MACHINE_MIPS1:
		return true;
	case ECOFF_MACHINE_MIPS1_EL:
		return true;
	case ECOFF_MACHINE_MIPS2_EL:
		return true;
	case ECOFF_MACHINE_MIPS3_EL:
		return true;
	case ECOFF_MACHINE_ALPHA:
		return true;
	case ECOFF_MACHINE_ALPHA_BSD:
		return true;
	default:
		return false;
	}
}

static inline bool ecoff_is_alpha(const ECoff *ecoff) {
	switch (ecoff->f_magic) {
	case ECOFF_MACHINE_ALPHA:
		return true;
	case ECOFF_MACHINE_ALPHA_BSD:
		return true;
	default:
		return false;
	}
}

static inline bool ecoff_is_ecoff64(const ECoff *ecoff) {
	switch (ecoff->f_magic) {
	case ECOFF_MACHINE_ALPHA:
		return true;
	case ECOFF_MACHINE_ALPHA_BSD:
		return true;
	default:
		return false;
	}
}

static inline bool ecoff_has_aouthdr(const ECoff *ecoff) {
	if (ecoff_is_ecoff64(ecoff)) {
		return ecoff->ecoff64.header.f_opthdr;
	}

	return ecoff->ecoff32.header.f_opthdr;
}

static inline st64 ecoff_header_f_symptr(const ECoff *ecoff) {
	if (ecoff_is_ecoff64(ecoff)) {
		return ecoff->ecoff64.header.f_symptr;
	}

	return ecoff->ecoff32.header.f_symptr;
}

static inline st32 ecoff_header_f_nsyms(const ECoff *ecoff) {
	if (ecoff_is_ecoff64(ecoff)) {
		return ecoff->ecoff64.header.f_nsyms;
	}

	return ecoff->ecoff32.header.f_nsyms;
}

static inline bool ecoff_has_symbolic_header(const ECoff *ecoff) {
	ut16 magic = 0;
	if (ecoff_is_ecoff64(ecoff)) {
		magic = ecoff->ecoff64.symhdr.magic;
	} else {
		magic = ecoff->ecoff32.symhdr.magic;
	}

	return magic == ECOFF_SYMBOLIC_HEADER_MAGIC ||
		magic == ECOFF_SYMBOLIC_HEADER_MAGIC_ALPHA;
}

static inline size_t ecoff_string_table_local(const ECoff *ecoff) {
	if (ecoff_is_ecoff64(ecoff)) {
		return ecoff->ecoff64.symhdr.cb_ss_offset;
	}
	return ecoff->ecoff32.symhdr.cb_ss_offset;
}

static inline size_t ecoff_string_table_extern(const ECoff *ecoff) {
	if (ecoff_is_ecoff64(ecoff)) {
		return ecoff->ecoff64.symhdr.cb_ss_offset;
	}
	return ecoff->ecoff32.symhdr.cb_ss_offset;
}

static inline size_t ecoff_string_table(const ECoff *ecoff, bool is_local) {
	if (!ecoff_has_symbolic_header(ecoff)) {
		return ecoff_header_f_symptr(ecoff);
	}

	if (is_local) {
		return ecoff_string_table_local(ecoff);
	}

	return ecoff_string_table_extern(ecoff);
}

void ecoff_free(ECoff *ecoff) {
	if (!ecoff) {
		return;
	}

	if (ecoff_is_ecoff64(ecoff)) {
		rz_vector_free(ecoff->ecoff64.sections);
		rz_vector_free(ecoff->ecoff64.file_descs);
		rz_vector_free(ecoff->ecoff64.proc_descs);
		rz_vector_free(ecoff->ecoff64.local_symbols);
		rz_vector_free(ecoff->ecoff64.extern_symbols);
	} else {
		rz_vector_free(ecoff->ecoff32.sections);
		rz_vector_free(ecoff->ecoff32.file_descs);
		rz_vector_free(ecoff->ecoff32.proc_descs);
		rz_vector_free(ecoff->ecoff32.local_symbols);
		rz_vector_free(ecoff->ecoff32.extern_symbols);
		rz_vector_free(ecoff->ecoff32.symbols_old);
	}

	free(ecoff);
}

static bool ecoff_parse_magic(RzBuffer *buffer, ut16 *magic, bool *big_endian) {
	if (!rz_buf_read_be16_at(buffer, 0, magic)) {
		return false;
	} else if (ecoff_is_big_endian(*magic)) {
		*big_endian = true;
		return true;
	}
	if (!rz_buf_read_le16_at(buffer, 0, magic)) {
		return false;
	} else if (ecoff_is_little_endian(*magic)) {
		*big_endian = false;
		return true;
	}
	return false;
}

bool ecoff_is_valid_buffer(RzBuffer *buffer) {
	ut16 magic = 0;
	bool big_endian = false;
	return ecoff_parse_magic(buffer, &magic, &big_endian);
}

static bool ecoff_init_hdr32(RzBuffer *b, ut64 *offset, ECoff_Header_32 *header, const bool big_endian) {
	return rz_buf_read_ble16_offset(b, offset, &header->f_magic, big_endian) &&
		rz_buf_read_ble16_offset(b, offset, &header->f_nscns, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, (ut32 *)&header->f_timedate, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, (ut32 *)&header->f_symptr, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, (ut32 *)&header->f_nsyms, big_endian) &&
		rz_buf_read_ble16_offset(b, offset, &header->f_opthdr, big_endian) &&
		rz_buf_read_ble16_offset(b, offset, &header->f_flags, big_endian);
}

static bool ecoff_init_hdr64(RzBuffer *b, ut64 *offset, ECoff_Header_64 *header, const bool big_endian) {
	return rz_buf_read_ble16_offset(b, offset, &header->f_magic, big_endian) &&
		rz_buf_read_ble16_offset(b, offset, &header->f_nscns, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, (ut32 *)&header->f_timedate, big_endian) &&
		rz_buf_read_ble64_offset(b, offset, (ut64 *)&header->f_symptr, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, (ut32 *)&header->f_nsyms, big_endian) &&
		rz_buf_read_ble16_offset(b, offset, &header->f_opthdr, big_endian) &&
		rz_buf_read_ble16_offset(b, offset, &header->f_flags, big_endian);
}

static bool ecoff_init_hdr(RzBuffer *b, ut64 *offset, ECoff *ecoff) {
	if (ecoff_is_ecoff64(ecoff)) {
		return ecoff_init_hdr64(b, offset, &ecoff->ecoff64.header, ecoff->big_endian);
	}

	return ecoff_init_hdr32(b, offset, &ecoff->ecoff32.header, ecoff->big_endian);
}

static bool ecoff_init_aouthdr_alpha(RzBuffer *b, ut64 *offset, ECoff_AOutHdr_Alpha *alpha, const bool big_endian) {
	return rz_buf_read_ble16_offset(b, offset, &alpha->magic, big_endian) &&
		rz_buf_read_offset(b, offset, alpha->vstamp, sizeof(alpha->vstamp)) &&
		rz_buf_read_ble16_offset(b, offset, &alpha->bldrev, big_endian) &&
		rz_buf_read_ble16_offset(b, offset, &alpha->padding, big_endian) &&
		rz_buf_read_ble64_offset(b, offset, &alpha->tsize, big_endian) &&
		rz_buf_read_ble64_offset(b, offset, &alpha->dsize, big_endian) &&
		rz_buf_read_ble64_offset(b, offset, &alpha->bsize, big_endian) &&
		rz_buf_read_ble64_offset(b, offset, &alpha->entry, big_endian) &&
		rz_buf_read_ble64_offset(b, offset, &alpha->text_start, big_endian) &&
		rz_buf_read_ble64_offset(b, offset, &alpha->data_start, big_endian) &&
		rz_buf_read_ble64_offset(b, offset, &alpha->bss_start, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &alpha->gpr_mask, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &alpha->fpr_mask, big_endian) &&
		rz_buf_read_ble64_offset(b, offset, &alpha->gp_value, big_endian);
}

static bool ecoff_init_aouthdr_mips(RzBuffer *b, ut64 *offset, ECoff_AOutHdr_Mips *mips, const bool big_endian) {
	return rz_buf_read_ble16_offset(b, offset, &mips->magic, big_endian) &&
		rz_buf_read_offset(b, offset, mips->vstamp, sizeof(mips->vstamp)) &&
		rz_buf_read_ble32_offset(b, offset, &mips->tsize, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &mips->dsize, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &mips->bsize, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &mips->entry, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &mips->text_start, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &mips->data_start, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &mips->bss_start, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &mips->gpr_mask, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &mips->cpr_mask[0], big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &mips->cpr_mask[1], big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &mips->cpr_mask[2], big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &mips->cpr_mask[3], big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &mips->gp_value, big_endian);
}

static bool ecoff_init_aouthdr(RzBuffer *b, ut64 *offset, ECoff *ecoff) {
	if (!ecoff_has_aouthdr(ecoff)) {
		// optional header is not present.
		return true;
	}

	if (ecoff_is_alpha(ecoff)) {
		return ecoff_init_aouthdr_alpha(b, offset, &ecoff->aouthdr.alpha, ecoff->big_endian);
	}

	return ecoff_init_aouthdr_mips(b, offset, &ecoff->aouthdr.mips, ecoff->big_endian);
}

static char *ecoff_resolve_name32(RzBuffer *b, const ECoff_32 *ecoff, const char name[8], ut64 location) {
	ut32 zero = rz_read_at_ble32((const ut8 *)name, 0, ecoff->big_endian);
	if (zero) {
		// if the 4 bytes are non-zero, then it must contain a name
		return rz_str_ndup((const char *)name, 8);
	}

	// if the 4 bytes are zero, then it must contain an offset to the ascii name
	ut64 offset = rz_read_at_ble32((const ut8 *)name, 4, ecoff->big_endian);
	if (!offset) {
		return rz_str_newf("unknown_%08" PFMT64x, location);
	}
	offset += ecoff_header_f_symptr(ecoff);
	offset += (ecoff_header_f_nsyms(ecoff) * COFF_SYMBOL_OLD_SIZE);
	ut8 resolved[256] = { 0 };
	st64 len = rz_buf_read_at(b, offset, resolved, sizeof(resolved) - 1);
	if (len < 1) {
		return rz_str_newf("unknown_%08" PFMT64x, location);
	}
	resolved[sizeof(resolved) - 1] = 0;
	return rz_str_dup((const char *)resolved);
}

static char *ecoff_resolve_name64(RzBuffer *b, const ECoff_64 *ecoff, const char name[8], ut64 location) {
	ut32 zero = rz_read_at_ble32((const ut8 *)name, 0, ecoff->big_endian);
	if (zero) {
		// if the 4 bytes are non-zero, then it must contain a name
		return rz_str_ndup((const char *)name, 8);
	}

	// if the 4 bytes are zero, then it must contain an offset to the ascii name
	ut64 offset = rz_read_at_ble32((const ut8 *)name, 4, ecoff->big_endian);
	if (!offset) {
		return rz_str_newf("unknown_%08" PFMT64x, location);
	}
	offset += ecoff_header_f_symptr(ecoff);
	offset += (ecoff_header_f_nsyms(ecoff) * COFF_SYMBOL_OLD_SIZE);
	ut8 resolved[256] = { 0 };
	st64 len = rz_buf_read_at(b, offset, resolved, sizeof(resolved) - 1);
	if (len < 1) {
		return rz_str_newf("unknown_%08" PFMT64x, location);
	}
	resolved[sizeof(resolved) - 1] = 0;
	return rz_str_dup((const char *)resolved);
}

static bool ecoff_init_section_64(RzBuffer *b, ut64 *offset, ECoff_Section_64 *section, const bool big_endian) {
	return rz_buf_read_offset(b, offset, (ut8 *)section->s_name, sizeof(section->s_name)) &&
		rz_buf_read_ble64_offset(b, offset, &section->s_paddr, big_endian) &&
		rz_buf_read_ble64_offset(b, offset, &section->s_vaddr, big_endian) &&
		rz_buf_read_ble64_offset(b, offset, &section->s_size, big_endian) &&
		rz_buf_read_ble64_offset(b, offset, &section->s_scnptr, big_endian) &&
		rz_buf_read_ble64_offset(b, offset, &section->s_relptr, big_endian) &&
		rz_buf_read_ble64_offset(b, offset, &section->s_lnnoptr, big_endian) &&
		rz_buf_read_ble16_offset(b, offset, &section->s_nreloc, big_endian) &&
		rz_buf_read_ble16_offset(b, offset, &section->s_nlnno, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &section->s_flags, big_endian);
}

static bool ecoff_init_section_32(RzBuffer *b, ut64 *offset, ECoff_Section_32 *section, const bool big_endian) {
	return rz_buf_read_offset(b, offset, (ut8 *)section->s_name, sizeof(section->s_name)) &&
		rz_buf_read_ble32_offset(b, offset, &section->s_paddr, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &section->s_vaddr, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &section->s_size, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &section->s_scnptr, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &section->s_relptr, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &section->s_lnnoptr, big_endian) &&
		rz_buf_read_ble16_offset(b, offset, &section->s_nreloc, big_endian) &&
		rz_buf_read_ble16_offset(b, offset, &section->s_nlnno, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, &section->s_flags, big_endian);
}

static void ecoff_section_64_fini(void *element, void *) {
	ECoff_Section_64 *section = element;
	free(section->resolved_name);
}

static bool ecoff_init_sections_64(RzBuffer *b, ut64 *offset, ECoff_64 *ecoff, const bool big_endian) {
	ecoff->sections = rz_vector_new(sizeof(ECoff_Section_64), ecoff_section_64_fini, NULL);
	if (!ecoff->sections) {
		return false;
	}

	const size_t count = ecoff->header.f_nscns;
	for (size_t i = 0; i < count; ++i) {
		ut64 location = *offset;
		ECoff_Section_64 section = { 0 };
		if (!ecoff_init_section_64(b, offset, &section, big_endian)) {
			return false;
		}
		section.resolved_name = ecoff_resolve_name(b, ecoff, section.s_name, location);
		rz_vector_push(ecoff->sections, &section);
	}
	return true;
}

static void ecoff_section_32_fini(void *element, void *) {
	ECoff_Section_32 *section = element;
	free(section->resolved_name);
}

static bool ecoff_init_sections_32(RzBuffer *b, ut64 *offset, ECoff_32 *ecoff, const bool big_endian) {
	ecoff->sections = rz_vector_new(sizeof(ECoff_Section_32), ecoff_section_32_fini, NULL);
	if (!ecoff->sections) {
		return false;
	}

	const size_t count = ecoff->header.f_nscns;
	for (size_t i = 0; i < count; ++i) {
		ut64 location = *offset;
		ECoff_Section_32 section = { 0 };
		if (!ecoff_init_section_32(b, offset, &section, big_endian)) {
			return false;
		}
		section.resolved_name = ecoff_resolve_name(b, ecoff, section.s_name, location);
		rz_vector_push(ecoff->sections, &section);
	}
	return true;
}

static bool ecoff_init_sections(RzBuffer *b, ut64 *offset, ECoff *ecoff) {
	if (ecoff_is_ecoff64(ecoff)) {
		return ecoff_init_sections_64(b, offset, &ecoff->ecoff64, ecoff->big_endian);
	}
	return ecoff_init_sections_32(b, offset, &ecoff->ecoff32, ecoff->big_endian);
}

static bool ecoff_init_symbol_old(RzBuffer *b, ut64 *offset, ECoff_Symbol_Mips *symbol, const bool big_endian) {
	return rz_buf_read_offset(b, offset, (ut8 *)symbol->e_name, sizeof(symbol->e_name)) &&
		rz_buf_read_ble32_offset(b, offset, &symbol->e_value, big_endian) &&
		rz_buf_read_ble16_offset(b, offset, (ut16 *)&symbol->e_scnum, big_endian) &&
		rz_buf_read_ble16_offset(b, offset, &symbol->e_type, big_endian) &&
		rz_buf_read_ble8_offset(b, offset, (ut8 *)&symbol->e_sclass, big_endian) &&
		rz_buf_read_ble8_offset(b, offset, &symbol->e_numaux, big_endian);
}

static void ecoff_symbol_old_fini(void *element, void *) {
	ECoff_Symbol_Old *symbol = element;
	free(symbol->resolved_name);
}

static bool ecoff_init_old_symbols(RzBuffer *b, ECoff_32 *ecoff, const bool big_endian) {
	if (ecoff->header.f_symptr < 0) {
		return false;
	}

	ecoff->mips.symbols_old = rz_vector_new(sizeof(ECoff_Symbol_Old), ecoff_symbol_old_fini, NULL);
	if (!ecoff->mips.symbols_old) {
		return false;
	} else if (!ecoff->header.f_symptr) {
		// there are no symbols_old
		return true;
	}

	ut64 offset = ecoff->header.f_symptr;
	const size_t count = ecoff->header.f_nsyms;
	for (size_t i = 0; i < count; ++i) {
		ut64 location = offset;
		ECoff_Symbol_Old symbol = { 0 };
		if (!ecoff_init_symbol_old(b, &offset, &symbol, big_endian)) {
			return false;
		}
		symbol.resolved_name = ecoff_resolve_name(b, ecoff, symbol.e_name, location);
		rz_vector_push(ecoff->old.symbols_old, &symbol);
	}

	return true;
}

static bool ecoff_init_symbolic_header_alpha(RzBuffer *b, ut64 *offset, ECoff_SymHdr_Alpha *symhdr, bool big_endian) {
	return rz_buf_read_ble16_offset(b, offset, (ut16 *)&symhdr->magic, big_endian) &&
		rz_buf_read_offset(b, offset, symhdr->vstamp, sizeof(symhdr->vstamp)) &&
		rz_buf_read_ble32_offset(b, offset, (ut32 *)&symhdr->iline_max, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, (ut32 *)&symhdr->idn_max, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, (ut32 *)&symhdr->ipd_max, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, (ut32 *)&symhdr->isym_max, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, (ut32 *)&symhdr->iopt_max, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, (ut32 *)&symhdr->iaux_max, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, (ut32 *)&symhdr->iss_max, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, (ut32 *)&symhdr->iss_ext_max, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, (ut32 *)&symhdr->ifd_max, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, (ut32 *)&symhdr->crfd, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, (ut32 *)&symhdr->iext_max, big_endian) &&
		rz_buf_read_ble64_offset(b, offset, (ut64 *)&symhdr->cb_line, big_endian) &&
		rz_buf_read_ble64_offset(b, offset, &symhdr->cb_line_offset, big_endian) &&
		rz_buf_read_ble64_offset(b, offset, &symhdr->cb_dn_offset, big_endian) &&
		rz_buf_read_ble64_offset(b, offset, &symhdr->cb_pd_offset, big_endian) &&
		rz_buf_read_ble64_offset(b, offset, &symhdr->cb_sym_offset, big_endian) &&
		rz_buf_read_ble64_offset(b, offset, &symhdr->cb_opt_offset, big_endian) &&
		rz_buf_read_ble64_offset(b, offset, &symhdr->cb_aux_offset, big_endian) &&
		rz_buf_read_ble64_offset(b, offset, &symhdr->cb_ss_offset, big_endian) &&
		rz_buf_read_ble64_offset(b, offset, &symhdr->cb_ss_ext_offset, big_endian) &&
		rz_buf_read_ble64_offset(b, offset, &symhdr->cb_fd_offset, big_endian) &&
		rz_buf_read_ble64_offset(b, offset, &symhdr->cb_rfd_offset, big_endian) &&
		rz_buf_read_ble64_offset(b, offset, &symhdr->cb_ext_offset, big_endian);
}

static bool ecoff_init_file_descriptor_entry_alpha(RzBuffer *b, ut64 *offset, ECoff_FileDescEntry_Alpha *fde, bool big_endian) {
	// stores the bit fields that needs to be extracted later
	ut16 bit_fields = 0;

	bool ok = rz_buf_read_ble64_offset(b, offset, &fde->adr, big_endian) &&
		rz_buf_read_ble64_offset(b, offset, (ut64 *)&fde->cb_line_offset, big_endian) &&
		rz_buf_read_ble64_offset(b, offset, (ut64 *)&fde->cb_line, big_endian) &&
		rz_buf_read_ble64_offset(b, offset, (ut64 *)&fde->cb_ss, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, (ut32 *)&fde->rss, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, (ut32 *)&fde->iss_base, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, (ut32 *)&fde->isym_base, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, (ut32 *)&fde->csym, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, (ut32 *)&fde->iline_base, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, (ut32 *)&fde->cline, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, (ut32 *)&fde->iopt_base, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, (ut32 *)&fde->copt, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, (ut32 *)&fde->ipd_first, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, (ut32 *)&fde->cpd, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, (ut32 *)&fde->iaux_base, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, (ut32 *)&fde->caux, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, (ut32 *)&fde->rfd_base, big_endian) &&
		rz_buf_read_ble32_offset(b, offset, (ut32 *)&fde->crfd, big_endian) &&
		rz_buf_read_ble16_offset(b, offset, &bit_fields, big_endian) &&
		rz_buf_read_offset(b, offset, fde->vstamp, sizeof(fde->vstamp)) &&
		rz_buf_read_ble32_offset(b, offset, &fde->reserved2, big_endian);

	if (ok) {
		fde->lang = bit_fields & 0x1f; // lang : 5;
		fde->f_merge = (bit_fields >> 5) & 1; // f_merge : 1;
		fde->f_readin = (bit_fields >> 6) & 1; // f_readin : 1;
		fde->f_bigendian = (bit_fields >> 7) & 1; // f_bigendian : 1;
		fde->glevel = (bit_fields >> 8) & 3; // glevel : 2;
		fde->f_trim = (bit_fields >> 10) & 1; // f_trim : 1;
		fde->reserved = (bit_fields >> 11) & 0x1f; // reserved : 5;
	}
	return ok;
}

static bool ecoff_init_file_descriptor_entries_alpha(RzBuffer *b, ECoff *ecoff) {
	ecoff->alpha.file_descs = rz_vector_new(sizeof(ECoff_FileDescEntry_Alpha), NULL, NULL);
	if (!ecoff->alpha.file_descs) {
		return false;
	} else if (ecoff->alpha.symhdr.ifd_max < 1) {
		// nothing to parse.
		return true;
	}

	ut64 offset = ecoff->alpha.symhdr.cb_fd_offset;
	size_t count = ecoff->alpha.symhdr.ifd_max;
	for (size_t i = 0; i < count; ++i) {
		ECoff_FileDescEntry_Alpha fde = { 0 };
		if (!ecoff_init_file_descriptor_entry_alpha(b, &offset, &fde, ecoff->big_endian)) {
			return false;
		}

		rz_vector_push(ecoff->alpha.file_descs, &fde);
	}
	return true;
}

static bool ecoff_init_alpha_symbols(RzBuffer *b, ECoff *ecoff, const st64 f_symptr) {
	ut64 offset = f_symptr;
	if (!f_symptr) {
		// there are no symbols
		return true;
	}

	// ecoff->alpha.proc_descs = rz_vector_new(sizeof(ECoff_ProcDescrEntry_Alpha), NULL, NULL);
	// if (!ecoff->alpha.proc_descs) {
	// 	return false;
	// }

	return ecoff_init_symbolic_header_alpha(b, &offset, &ecoff->alpha.symhdr, ecoff->big_endian) &&
		ecoff_init_file_descriptor_entries_alpha(b, ecoff);
}

static bool ecoff_init_symbols(RzBuffer *b, ECoff *ecoff) {
	st64 f_symptr = ecoff_header_f_symptr(ecoff);
	if (f_symptr < 0) {
		// invalid
		return false;
	}

	if (ecoff_is_alpha(ecoff)) {
		return ecoff_init_alpha_symbols(b, ecoff, f_symptr);
	}

	return ecoff_init_old_symbols(b, ecoff, f_symptr);
}

ECoff *ecoff_parse_from_buffer(RzBuffer *buffer) {
	ut64 offset = 0;
	ECoff *ecoff = RZ_NEW0(ECoff);
	if (!ecoff) {
		return NULL;
	} else if (!ecoff_parse_magic(buffer, &ecoff->f_magic, &ecoff->big_endian)) {
		RZ_LOG_ERROR("ecoff: is not an ecoff file\n");
		goto fail;
	} else if (!ecoff_init_hdr(buffer, &offset, ecoff)) {
		RZ_LOG_ERROR("ecoff: failed to read ecoff header\n");
		goto fail;
	} else if (!ecoff_init_aouthdr(buffer, &offset, ecoff)) {
		RZ_LOG_ERROR("ecoff: failed to read ecoff aouthdr\n");
		goto fail;
	} else if (!ecoff_init_sections(buffer, &offset, ecoff)) {
		RZ_LOG_ERROR("ecoff: failed to read ecoff section table\n");
		goto fail;
	} else if (!ecoff_init_symbols(buffer, ecoff)) {
		RZ_LOG_ERROR("ecoff: failed to read ecoff symbol table\n");
		goto fail;
	}

	return ecoff;
fail:
	ecoff_free(ecoff);
	return NULL;
}

static ut32 ecoff_section_flags_to_perms(ut64 s_flags) {
	ut32 perms = 0;
	if (s_flags & ECOFF_SECTION_TYPE_REG) {
		// Regular section: allocated, relocated, loaded.
		perms |= RZ_PERM_RWX;
	}
	if (s_flags & ECOFF_SECTION_TYPE_TEXT) {
		// Text section
		perms |= RZ_PERM_RW;
	}
	if (s_flags & ECOFF_SECTION_TYPE_DATA) {
		// Data section
		perms |= RZ_PERM_RW;
	}
	if (s_flags & ECOFF_SECTION_TYPE_BSS) {
		// Bss section
		perms |= RZ_PERM_RW;
	}
	if (s_flags & ECOFF_SECTION_TYPE_RDATA) {
		// Read-only data section
		perms |= RZ_PERM_R;
	}
	if (s_flags & ECOFF_SECTION_TYPE_SDATA) {
		// Small data
		perms |= RZ_PERM_RW;
	}
	if (s_flags & ECOFF_SECTION_TYPE_SBSS) {
		// Small bss
		perms |= RZ_PERM_RW;
	}
	if (s_flags & ECOFF_SECTION_TYPE_UCODE) {
		// U-Code
		perms |= RZ_PERM_RX;
	}
	if (s_flags & ECOFF_SECTION_TYPE_GOT1) {
		// Global offset table
		perms |= RZ_PERM_R;
	}
	if (s_flags & ECOFF_SECTION_TYPE_DYNAMIC1) {
		// Dynamic linking information
		perms |= RZ_PERM_R;
	}
	if (s_flags & ECOFF_SECTION_TYPE_DYNSYM1) {
		// Dynamic linking symbol table
		perms |= RZ_PERM_R;
	}
	if (s_flags & ECOFF_SECTION_TYPE_REL_DYN1) {
		// Dynamic relocation information
		perms |= RZ_PERM_R;
	}
	if (s_flags & ECOFF_SECTION_TYPE_DYNSTR1) {
		// Dynamic linking symbol table
		perms |= RZ_PERM_R;
	}
	if (s_flags & ECOFF_SECTION_TYPE_HASH1) {
		// Dynamic symbol hash table
		perms |= RZ_PERM_R;
	}
	if (s_flags & ECOFF_SECTION_TYPE_DSOLIST1) {
		// Shared library dependency list
		perms |= RZ_PERM_R | RZ_PERM_SHAR;
	}
	if (s_flags & ECOFF_SECTION_TYPE_MSYM1) {
		// Additional dynamic linking symbol table
		perms |= RZ_PERM_R;
	}
	if (s_flags & ECOFF_SECTION_TYPE_LIT4) {
		// 4-byte literals
		perms |= RZ_PERM_R;
	}
	if (s_flags & ECOFF_SECTION_TYPE_NRELOC_OVFL2) {
		// Indicates that section header field s_nreloc overflowed
		perms |= RZ_PERM_R;
	}
	if (s_flags & ECOFF_SECTION_TYPE_LIB) {
		// Shared Library
		perms |= RZ_PERM_RX | RZ_PERM_SHAR;
	}
	if (s_flags & ECOFF_SECTION_TYPE_INIT) {
		// Initialization text
		perms |= RZ_PERM_RX;
	}

	ut32 extmask = s_flags & ECOFF_SECTION_EXT_TYPE_MASK;
	if (extmask == ECOFF_SECTION_EXT_TYPE_CONFLICT1) {
		// Additional dynamic linking information
		perms |= RZ_PERM_R;
	} else if (extmask == ECOFF_SECTION_EXT_TYPE_RESOURCE) {
		// Resource
		perms |= RZ_PERM_R;
	} else if (extmask == ECOFF_SECTION_EXT_TYPE_FINI) {
		// Termination text
		perms |= RZ_PERM_RX;
	} else if (extmask == ECOFF_SECTION_EXT_TYPE_RCONST) {
		// Read-only constants
		perms |= RZ_PERM_R;
	} else if (extmask == ECOFF_SECTION_EXT_TYPE_XDATA) {
		// Exception scope table
		perms |= RZ_PERM_R;
	} else if (extmask == ECOFF_SECTION_EXT_TYPE_TLSDATA) {
		// Initialized TLS data
		perms |= RZ_PERM_RW;
	} else if (extmask == ECOFF_SECTION_EXT_TYPE_TLSBSS) {
		// Uninitialized TLS data
		perms |= RZ_PERM_RW;
	} else if (extmask == ECOFF_SECTION_EXT_TYPE_TLSINIT) {
		// Initialization for TLS data
		perms |= RZ_PERM_R;
	} else if (extmask == ECOFF_SECTION_EXT_TYPE_PDATA) {
		// Exception procedure table
		perms |= RZ_PERM_R;
	} else if (extmask == ECOFF_SECTION_EXT_TYPE_LITA) {
		// Address literals
		perms |= RZ_PERM_R;
	} else if (extmask == ECOFF_SECTION_EXT_TYPE_LIT8) {
		// 8-byte literals
		perms |= RZ_PERM_R;
	}

	return perms;
}

static bool ecoff_is_data_section(const ut32 s_flags) {
	const ut32 extflag = s_flags & ECOFF_SECTION_EXT_TYPE_MASK;

	return (s_flags & ECOFF_SECTION_TYPE_DATA_MASK) ||
		extflag == ECOFF_SECTION_EXT_TYPE_RESOURCE ||
		extflag == ECOFF_SECTION_EXT_TYPE_RCONST ||
		extflag == ECOFF_SECTION_EXT_TYPE_XDATA ||
		extflag == ECOFF_SECTION_EXT_TYPE_TLSDATA ||
		extflag == ECOFF_SECTION_EXT_TYPE_TLSBSS ||
		extflag == ECOFF_SECTION_EXT_TYPE_PDATA;
}

static bool ecoff_find_paddr_from_vaddr_alpha(const ECoff *ecoff, const ut64 vaddr, ut64 *paddr) {
	const ECoff_Section_Alpha *esec;
	rz_vector_foreach (ecoff->alpha.sections, esec) {
		ut64 pstart = esec->s_scnptr;
		ut64 vend = esec->s_vaddr + esec->s_size;
		ut64 vstart = esec->s_vaddr;
		if (vaddr >= vstart && vaddr <= vend) {
			*paddr = pstart + (vaddr - vstart);
			return true;
		}
	}
	return false;
}

static bool ecoff_find_paddr_from_vaddr_mips(const ECoff *ecoff, const ut64 vaddr, ut64 *paddr) {
	const ECoff_Section_Mips *esec;
	rz_vector_foreach (ecoff->mips.sections, esec) {
		ut64 pstart = esec->s_scnptr;
		ut64 vend = esec->s_vaddr + esec->s_size;
		ut64 vstart = esec->s_vaddr;
		if (vaddr >= vstart && vaddr <= vend) {
			*paddr = pstart + (vaddr - vstart);
			return true;
		}
	}
	return false;
}

static bool ecoff_find_paddr_from_vaddr(const ECoff *ecoff, const ut64 vaddr, ut64 *paddr) {
	if (ecoff_is_alpha(ecoff)) {
		return ecoff_find_paddr_from_vaddr_alpha(ecoff, vaddr, paddr);
	}

	return ecoff_find_paddr_from_vaddr_mips(ecoff, vaddr, paddr);
}

static RzBinAddr *ecoff_get_entrypoint(const ECoff *ecoff) {
	ut64 vaddr = 0;
	if (ecoff_is_alpha(ecoff)) {
		vaddr = ecoff->alpha.aouthdr.entry;
	} else {
		vaddr = ecoff->mips.aouthdr.entry;
	}

	if (!vaddr) {
		// entry is invalid.
		return NULL;
	}

	RzBinAddr *baddr = RZ_NEW0(RzBinAddr);
	if (!baddr) {
		return NULL;
	}

	baddr->type = RZ_BIN_ENTRY_TYPE_INIT;
	baddr->paddr = UT64_MAX;
	baddr->vaddr = vaddr;
	ecoff_find_paddr_from_vaddr(ecoff, baddr->vaddr, &baddr->paddr);
	return baddr;
}

static RzBinAddr *ecoff_get_main(const ECoff *ecoff) {
	ut64 vaddr = 0;

	if (ecoff_is_alpha(ecoff)) {
		// TODO
		return NULL;
	}

	const ECoff_Symbol_Mips *esym;
	rz_vector_foreach (ecoff->mips.symbols, esym) {
		if (esym->resolved_name && RZ_STR_EQ(esym->resolved_name, "main")) {
			vaddr = esym->e_value;
			break;
		}
	}

	if (!vaddr) {
		// main pointer is invalid.
		return NULL;
	}

	RzBinAddr *baddr = RZ_NEW0(RzBinAddr);
	if (!baddr) {
		return NULL;
	}

	baddr->type = RZ_BIN_ENTRY_TYPE_MAIN;
	baddr->paddr = UT64_MAX;
	baddr->vaddr = vaddr;
	ecoff_find_paddr_from_vaddr(ecoff, baddr->vaddr, &baddr->paddr);
	return baddr;
}

RzPVector /*<RzBinAddr *>*/ *ecoff_get_entries(const ECoff *ecoff) {
	RzPVector *ret = rz_pvector_new((RzPVectorFree)free);
	if (!ret) {
		return NULL;
	}

	RzBinAddr *baddr = ecoff_get_entrypoint(ecoff);
	if (baddr) {
		rz_pvector_push(ret, baddr);
	}

	baddr = ecoff_get_main(ecoff);
	if (baddr) {
		rz_pvector_push(ret, baddr);
	}

	return ret;
}

static RzBinSection *ecoff_section_alpha_to_bin_section(const ECoff *ecoff, const ECoff_Section_Alpha *esec) {
	RzBinSection *bsec = RZ_NEW0(RzBinSection);
	if (!bsec) {
		return NULL;
	}

	bsec->size = esec->s_size;
	bsec->vsize = esec->s_size;
	bsec->paddr = esec->s_scnptr;
	bsec->vaddr = esec->s_vaddr;
	bsec->flags = esec->s_flags;
	bsec->perm = ecoff_section_flags_to_perms(bsec->flags);
	bsec->name = rz_str_dup(esec->resolved_name);
	if (ecoff_is_data_section(bsec->flags)) {
		bsec->is_data = true;
	}
	return bsec;
}

static RzBinSection *ecoff_section_mips_to_bin_section(const ECoff *ecoff, const ECoff_Section_Mips *esec) {
	RzBinSection *bsec = RZ_NEW0(RzBinSection);
	if (!bsec) {
		return NULL;
	}

	bsec->size = esec->s_size;
	bsec->vsize = esec->s_size;
	bsec->paddr = esec->s_scnptr;
	bsec->vaddr = esec->s_vaddr;
	bsec->flags = esec->s_flags;
	bsec->perm = ecoff_section_flags_to_perms(bsec->flags);
	bsec->name = rz_str_dup(esec->resolved_name);
	if (ecoff_is_data_section(bsec->flags)) {
		bsec->is_data = true;
	}
	return bsec;
}

RzPVector /*<RzBinSection *>*/ *ecoff_get_sections(const ECoff *ecoff) {
	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_section_free);
	if (!ret) {
		return NULL;
	}

	const bool is_alpha = ecoff_is_alpha(ecoff);

	const RzVector *sections = NULL;
	if (is_alpha) {
		sections = ecoff->alpha.sections;
	} else {
		sections = ecoff->mips.sections;
	}

	const void *esec;
	rz_vector_foreach (sections, esec) {
		RzBinSection *bsec = NULL;
		if (is_alpha) {
			bsec = ecoff_section_alpha_to_bin_section(ecoff, (const ECoff_Section_Alpha *)esec);
		} else {
			bsec = ecoff_section_mips_to_bin_section(ecoff, (const ECoff_Section_Mips *)esec);
		}
		if (!bsec) {
			return ret;
		}
		rz_pvector_push(ret, bsec);
	}
	return ret;
}

static bool ecoff_symbol_mips_is_function(const ECoff_Symbol_Mips *esym) {
	ut16 derived_type = (esym->e_type & ECOFF_SYMBOL_DERIVED_TYPE_MASK) >> 4;
	if (!derived_type) {
		return true;
	}
	return derived_type == ECOFF_SYMBOL_DERIVED_TYPE_FCN;
}

static bool ecoff_symbol_mips_is_imported(const ECoff_Symbol_Mips *esym) {
	return esym->e_scnum == ECOFF_SYMBOL_SECT_NUM_UNDEF &&
		esym->e_sclass == ECOFF_SYMBOL_SCLASS_EFCN;
}

static bool ecoff_symbol_mips_has_vaddr(const ECoff_Symbol_Mips *esym) {
	ut16 derived_type = (esym->e_type & ECOFF_SYMBOL_DERIVED_TYPE_MASK) >> 4;
	if (!derived_type) {
		return true;
	}
	return derived_type == ECOFF_SYMBOL_DERIVED_TYPE_PTR ||
		derived_type == ECOFF_SYMBOL_DERIVED_TYPE_FCN;
}

static ut32 ecoff_symbol_mips_type_to_size(const ECoff_Symbol_Mips *esym) {
	switch (esym->e_type & ECOFF_SYMBOL_BASE_TYPE_MASK) {
	default: return 0;
	case ECOFF_SYMBOL_BASE_TYPE_CHAR: return 1;
	case ECOFF_SYMBOL_BASE_TYPE_SHORT: return 2;
	case ECOFF_SYMBOL_BASE_TYPE_INT: return 4;
	case ECOFF_SYMBOL_BASE_TYPE_LONG: return 8;
	case ECOFF_SYMBOL_BASE_TYPE_FLOAT: return 4;
	case ECOFF_SYMBOL_BASE_TYPE_DOUBLE: return 8;
	case ECOFF_SYMBOL_BASE_TYPE_ENUM: return 4;
	case ECOFF_SYMBOL_BASE_TYPE_UCHAR: return 1;
	case ECOFF_SYMBOL_BASE_TYPE_USHORT: return 2;
	case ECOFF_SYMBOL_BASE_TYPE_UINT: return 4;
	case ECOFF_SYMBOL_BASE_TYPE_ULONG: return 8;
	}
}

static const char *ecoff_symbol_mips_type_to_bin_symbol_type(const ECoff_Symbol_Mips *esym) {
	ut16 derived_type = (esym->e_type & ECOFF_SYMBOL_DERIVED_TYPE_MASK) >> 4;
	switch (derived_type) {
	default: return NULL;
	case ECOFF_SYMBOL_DERIVED_TYPE_PTR: return RZ_BIN_TYPE_OBJECT_STR;
	case ECOFF_SYMBOL_DERIVED_TYPE_FCN: return RZ_BIN_TYPE_FUNC_STR;
	case ECOFF_SYMBOL_DERIVED_TYPE_ARY: return RZ_BIN_TYPE_STATIC_STR;
	}
}

static RzBinSymbol *ecoff_symbol_mips_to_bin_symbol(const ECoff *ecoff, const ECoff_Symbol_Mips *esym) {
	RzBinSymbol *bsym = RZ_NEW0(RzBinSymbol);
	if (!bsym) {
		return NULL;
	}

	bsym->type = ecoff_symbol_mips_type_to_bin_symbol_type(esym);
	bsym->size = ecoff_symbol_mips_type_to_size(esym);
	bsym->name = rz_str_dup(esym->resolved_name);
	bsym->forwarder = "NONE";
	bsym->is_imported = ecoff_symbol_mips_is_imported(esym);
	if (bsym->is_imported) {
		bsym->bind = RZ_BIN_BIND_IMPORT_STR;
	} else if (ecoff_symbol_mips_is_function(esym)) {
		bsym->bind = RZ_BIN_BIND_GLOBAL_STR;
	} else {
		bsym->bind = RZ_BIN_BIND_LOCAL_STR;
	}
	bsym->paddr = UT64_MAX;
	bsym->vaddr = UT64_MAX;
	if (esym->e_value && ecoff_symbol_mips_has_vaddr(esym)) {
		bsym->vaddr = esym->e_value;
		ecoff_find_paddr_from_vaddr(ecoff, bsym->vaddr, &bsym->paddr);
	}
	return bsym;
}

// this is a special symbol that is used for analysis.
// the analysis step will use `loc._gp` to know how to
// resolve values, pointers and functions.
static RzBinSymbol *ecoff_gp_to_bin_symbol(const ECoff *ecoff) {
	ut64 vaddr = 0;
	if (ecoff_is_alpha(ecoff)) {
		vaddr = ecoff->alpha.aouthdr.gp_value;
	} else {
		vaddr = ecoff->mips.aouthdr.gp_value;
	}

	if (!vaddr) {
		return NULL;
	}

	RzBinSymbol *bsym = RZ_NEW0(RzBinSymbol);
	if (!bsym) {
		return NULL;
	}

	bsym->name = rz_str_dup("_gp");
	bsym->forwarder = "NONE";
	bsym->bind = RZ_BIN_BIND_LOCAL_STR;
	bsym->type = RZ_BIN_TYPE_NOTYPE_STR;
	bsym->paddr = UT64_MAX;
	bsym->vaddr = vaddr;
	ecoff_find_paddr_from_vaddr(ecoff, bsym->vaddr, &bsym->paddr);

	return bsym;
}

RzPVector /*<RzBinSymbol *>*/ *ecoff_get_symbols(const ECoff *ecoff) {
	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_symbol_free);
	if (!ret) {
		return NULL;
	}

	RzBinSymbol *bsym = ecoff_gp_to_bin_symbol(ecoff);
	if (bsym) {
		// only push the _gp symbol if valid
		rz_pvector_push(ret, bsym);
	}

	if (ecoff_is_alpha(ecoff)) {
		// TODO
		return ret;
	} else {
		const ECoff_Symbol_Mips *esym;
		rz_vector_foreach (ecoff->mips.symbols, esym) {
			bsym = ecoff_symbol_mips_to_bin_symbol(ecoff, esym);
			if (!bsym) {
				return ret;
			}
			rz_pvector_push(ret, bsym);
		}
	}

	return ret;
}

static ut64 ecoff_to_debug_info(const ECoff *ecoff) {
	ut64 dbg_info = 0;
	const ut16 f_flags = ecoff->header.f_flags;
	st64 f_symptr = ecoff_header_f_symptr(ecoff);

	if (f_flags & ECOFF_F_FLAGS_IS_STRIPPED || !f_symptr) {
		return RZ_BIN_DBG_STRIPPED;
	}
	if (!(f_flags & ECOFF_F_FLAGS_RELFLG)) {
		dbg_info |= RZ_BIN_DBG_RELOCS;
	}
	if (!(f_flags & ECOFF_F_FLAGS_LNNO)) {
		dbg_info |= RZ_BIN_DBG_LINENUMS;
	}
	if (!(f_flags & ECOFF_F_FLAGS_LSYMS)) {
		dbg_info |= RZ_BIN_DBG_SYMS;
	}
	return dbg_info;
}

RzBinInfo *ecoff_get_info(const ECoff *ecoff) {
	RzBinInfo *ret = RZ_NEW0(RzBinInfo);
	if (!ret) {
		return NULL;
	}

	ret->rclass = rz_str_dup("ecoff");
	ret->bclass = rz_str_dup("coff");
	ret->type = rz_str_dup("ECOFF (Executable file)");
	ret->os = rz_str_dup("any");
	ret->subsystem = rz_str_dup("any");
	ret->has_va = true;
	ret->dbg_info = ecoff_to_debug_info(ecoff);
	ret->bits = 32;

	switch (ecoff->header.f_magic) {
	case ECOFF_MACHINE_MIPS1:
		ret->machine = rz_str_dup("MIPS I");
		ret->arch = rz_str_dup("mips");
		ret->cpu = rz_str_dup("mips1");
		break;
	case ECOFF_MACHINE_MIPS1_EL:
		ret->machine = rz_str_dup("MIPS I LE");
		ret->arch = rz_str_dup("mips");
		ret->cpu = rz_str_dup("mips1");
		break;
	case ECOFF_MACHINE_MIPS1_BE:
		ret->big_endian = true;
		ret->machine = rz_str_dup("MIPS I BE");
		ret->arch = rz_str_dup("mips");
		ret->cpu = rz_str_dup("mips1");
		break;
	case ECOFF_MACHINE_MIPS2_EL:
		ret->machine = rz_str_dup("MIPS II EL");
		ret->arch = rz_str_dup("mips");
		ret->cpu = rz_str_dup("mips2");
		break;
	case ECOFF_MACHINE_MIPS2_BE:
		ret->big_endian = true;
		ret->machine = rz_str_dup("MIPS II BE");
		ret->arch = rz_str_dup("mips");
		ret->cpu = rz_str_dup("mips2");
		break;
	case ECOFF_MACHINE_MIPS3_EL:
		ret->machine = rz_str_dup("MIPS III EL");
		ret->arch = rz_str_dup("mips");
		ret->cpu = rz_str_dup("mips3");
		break;
	case ECOFF_MACHINE_MIPS3_BE:
		ret->big_endian = true;
		ret->machine = rz_str_dup("MIPS III BE");
		ret->arch = rz_str_dup("mips");
		ret->cpu = rz_str_dup("mips3");
		break;
	case ECOFF_MACHINE_ALPHA:
		ret->machine = rz_str_dup("Alpha");
		ret->arch = rz_str_dup("alpha");
		break;
	case ECOFF_MACHINE_ALPHA_BSD:
		ret->machine = rz_str_dup("Alpha BSD");
		ret->arch = rz_str_dup("alpha");
		ret->bits = 64;
		break;
	default:
		ret->machine = rz_str_dup("unknown");
		ret->arch = rz_str_dup("mips");
		ret->cpu = rz_str_dup("mips32");
		break;
	}
	return ret;
}

static const char *ecoff_header_magic_to_string(const ECoff *ecoff) {
	switch (ecoff->header.f_magic) {
	case ECOFF_MACHINE_MIPS1:
		return "MIPS1 (" RZ_STR_DEF(ECOFF_MACHINE_MIPS1) ")";
	case ECOFF_MACHINE_MIPS1_EL:
		return "MIPS1 little endian (" RZ_STR_DEF(ECOFF_MACHINE_MIPS1_EL) ")";
	case ECOFF_MACHINE_MIPS1_BE:
		return "MIPS1 big endian (" RZ_STR_DEF(ECOFF_MACHINE_MIPS1_BE) ")";
	case ECOFF_MACHINE_MIPS2_EL:
		return "MIPS2 little endian (" RZ_STR_DEF(ECOFF_MACHINE_MIPS2_EL) ")";
	case ECOFF_MACHINE_MIPS2_BE:
		return "MIPS2 big endian (" RZ_STR_DEF(ECOFF_MACHINE_MIPS2_BE) ")";
	case ECOFF_MACHINE_MIPS3_EL:
		return "MIPS3 little endian (" RZ_STR_DEF(ECOFF_MACHINE_MIPS3_EL) ")";
	case ECOFF_MACHINE_MIPS3_BE:
		return "MIPS3 big endian (" RZ_STR_DEF(ECOFF_MACHINE_MIPS3_BE) ")";
	case ECOFF_MACHINE_ALPHA:
		return "ALPHA (" RZ_STR_DEF(ECOFF_MACHINE_ALPHA) ")";
	case ECOFF_MACHINE_ALPHA_BSD:
		return "ALPHA (" RZ_STR_DEF(ECOFF_MACHINE_ALPHA_BSD) ")";
	default:
		return "unknown magic";
	}
}

static bool ecoff_header_timedate_to_string(const ECoff *ecoff, RzStructuredData *parent) {
	if (ecoff->header.f_timedate <= 0) {
		// can be zero or negative, we ignore it.
		return rz_structured_data_map_add_unsigned(parent, "f_timdat", ecoff->header.f_timedate, true);
	}
	char *timestamp = rz_time_stamp_to_str(ecoff->header.f_timedate);
	if (!timestamp) {
		return false;
	}
	bool res = rz_structured_data_map_add_string(parent, "f_timdat", timestamp);
	free(timestamp);
	return res;
}

static bool ecoff_header_flags_to_structure(const ECoff *ecoff, RzStructuredData *parent) {
	if (!parent) {
		return false;
	}
	RzStructuredData *f_flags = rz_structured_data_map_add_map(parent, "f_flags");
	if (!f_flags) {
		return false;
	}
	rz_structured_data_map_add_unsigned(f_flags, "value", ecoff->header.f_flags, true);

	RzStructuredData *readable = rz_structured_data_map_add_array(f_flags, "readable");
	if (!readable) {
		return false;
	}

#define HAS_FLAG(flag, name) \
	if (ecoff->header.f_flags & flag && !rz_structured_data_array_add_string(readable, name)) { \
		return false; \
	}

	HAS_FLAG(ECOFF_F_FLAGS_RELFLG, "F_RELFLG");
	HAS_FLAG(ECOFF_F_FLAGS_EXEC, "F_EXEC");
	HAS_FLAG(ECOFF_F_FLAGS_LNNO, "F_LNNO");
	HAS_FLAG(ECOFF_F_FLAGS_LSYMS, "F_LSYMS");
	HAS_FLAG(ECOFF_F_FLAGS_NO_SHARED, "F_NO_SHARED");
	HAS_FLAG(ECOFF_F_FLAGS_NO_CALL_SHARED, "F_NO_CALL_SHARED");
	HAS_FLAG(ECOFF_F_FLAGS_LOMAP, "F_LOMAP");
	HAS_FLAG(ECOFF_F_FLAGS_NO_REORG, "F_NO_REORG");
	HAS_FLAG(ECOFF_F_FLAGS_NO_REMOVE, "F_NO_REMOVE");
#undef HAS_FLAG

	if (ecoff->header.f_magic == ECOFF_MACHINE_ALPHA ||
		ecoff->header.f_magic == ECOFF_MACHINE_ALPHA_BSD) {
		const ut16 object = ecoff->header.f_flags & ECOFF_F_FLAGS_ALPHA_OBJ_MASK;
		if (object == ECOFF_F_FLAGS_ALPHA_NO_SHARED && !rz_structured_data_array_add_string(readable, "NO_SHARED")) {
			return false;
		} else if (object == ECOFF_F_FLAGS_ALPHA_SHARABLE && !rz_structured_data_array_add_string(readable, "SHARABLE")) {
			return false;
		} else if (object == ECOFF_F_FLAGS_ALPHA_CALL_SHARED && !rz_structured_data_array_add_string(readable, "CALL_SHARED")) {
			return false;
		}
	}

	return true;
}

static bool ecoff_header_to_structure(const ECoff *ecoff, RzStructuredData *parent) {
	if (!parent) {
		return false;
	}

	RzStructuredData *filehdr = rz_structured_data_map_add_map(parent, "filehdr");
	if (!filehdr) {
		return false;
	}

	st64 f_symptr = ecoff_header_f_symptr(ecoff);

	const char *f_magic = ecoff_header_magic_to_string(ecoff);
	return rz_structured_data_map_add_string(filehdr, "f_magic", f_magic) &&
		rz_structured_data_map_add_unsigned(filehdr, "f_nscns", ecoff->header.f_nscns, false) &&
		ecoff_header_timedate_to_string(ecoff, filehdr) &&
		rz_structured_data_map_add_unsigned(filehdr, "f_symptr", f_symptr, true) &&
		rz_structured_data_map_add_signed(filehdr, "f_nsyms", ecoff->header.f_nsyms) &&
		rz_structured_data_map_add_unsigned(filehdr, "f_opthdr", ecoff->header.f_opthdr, true) &&
		ecoff_header_flags_to_structure(ecoff, filehdr);
}

static const char *ecoff_aouthdr_magic_to_string(const ut16 magic) {
	switch (magic) {
	case ECOFF_AOUTHDR_OMAGIC:
		return "OMAGIC (" RZ_STR_DEF(ECOFF_AOUTHDR_OMAGIC) ")";
	case ECOFF_AOUTHDR_NMAGIC:
		return "NMAGIC (" RZ_STR_DEF(ECOFF_AOUTHDR_NMAGIC) ")";
	case ECOFF_AOUTHDR_SMAGIC:
		return "SMAGIC (" RZ_STR_DEF(ECOFF_AOUTHDR_SMAGIC) ")";
	case ECOFF_AOUTHDR_ZMAGIC:
		return "ZMAGIC (" RZ_STR_DEF(ECOFF_AOUTHDR_ZMAGIC) ")";
	case ECOFF_AOUTHDR_LIBMAGIC:
		return "LIBMAGIC (" RZ_STR_DEF(ECOFF_AOUTHDR_LIBMAGIC) ")";
	default:
		rz_warn_if_reached();
		return "unknown";
	}
}

static bool ecoff_aouthdr_alpha_to_structure(const ECoff *ecoff, RzStructuredData *parent) {
	if (!parent) {
		return false;
	}
	char vstamp[16] = { 0 };
	const ECoff_AOutHdr_Alpha *alpha = &ecoff->alpha.aouthdr;
	const char *magic = ecoff_aouthdr_magic_to_string(alpha->magic);
	rz_strf(vstamp, "v%u.%u", alpha->vstamp[1], alpha->vstamp[0]);

	return rz_structured_data_map_add_string(parent, "magic", magic) &&
		rz_structured_data_map_add_string(parent, "vstamp", vstamp) &&
		rz_structured_data_map_add_unsigned(parent, "bldrev", alpha->bldrev, true) &&
		rz_structured_data_map_add_unsigned(parent, "padding", alpha->padding, true) &&
		rz_structured_data_map_add_unsigned(parent, "tsize", alpha->tsize, true) &&
		rz_structured_data_map_add_unsigned(parent, "dsize", alpha->dsize, true) &&
		rz_structured_data_map_add_unsigned(parent, "bsize", alpha->bsize, true) &&
		rz_structured_data_map_add_unsigned(parent, "entry", alpha->entry, true) &&
		rz_structured_data_map_add_unsigned(parent, "text_start", alpha->text_start, true) &&
		rz_structured_data_map_add_unsigned(parent, "data_start", alpha->data_start, true) &&
		rz_structured_data_map_add_unsigned(parent, "bss_start", alpha->bss_start, true) &&
		rz_structured_data_map_add_unsigned(parent, "gpr_mask", alpha->gpr_mask, true) &&
		rz_structured_data_map_add_unsigned(parent, "fpr_mask", alpha->fpr_mask, true) &&
		rz_structured_data_map_add_unsigned(parent, "gp_value", alpha->gp_value, true);
}

static bool ecoff_aouthdr_mips_to_structure(const ECoff *ecoff, RzStructuredData *parent) {
	if (!parent) {
		return false;
	}
	char vstamp[16] = { 0 };
	const ECoff_AOutHdr_Mips *mips = &ecoff->mips.aouthdr;
	const char *magic = ecoff_aouthdr_magic_to_string(mips->magic);
	rz_strf(vstamp, "v%u.%u", mips->vstamp[0], mips->vstamp[1]);

	bool res = rz_structured_data_map_add_string(parent, "magic", magic) &&
		rz_structured_data_map_add_string(parent, "vstamp", vstamp) &&
		rz_structured_data_map_add_unsigned(parent, "tsize", mips->tsize, true) &&
		rz_structured_data_map_add_unsigned(parent, "dsize", mips->dsize, true) &&
		rz_structured_data_map_add_unsigned(parent, "bsize", mips->bsize, true) &&
		rz_structured_data_map_add_unsigned(parent, "entry", mips->entry, true) &&
		rz_structured_data_map_add_unsigned(parent, "text_start", mips->text_start, true) &&
		rz_structured_data_map_add_unsigned(parent, "data_start", mips->data_start, true) &&
		rz_structured_data_map_add_unsigned(parent, "bss_start", mips->bss_start, true) &&
		rz_structured_data_map_add_unsigned(parent, "gpr_mask", mips->gpr_mask, true);
	if (!res) {
		return false;
	}

	RzStructuredData *cpr_mask = rz_structured_data_map_add_array(parent, "cpr_mask");
	if (!cpr_mask) {
		return false;
	}

	return rz_structured_data_array_add_unsigned(cpr_mask, mips->cpr_mask[0], true) &&
		rz_structured_data_array_add_unsigned(cpr_mask, mips->cpr_mask[1], true) &&
		rz_structured_data_array_add_unsigned(cpr_mask, mips->cpr_mask[2], true) &&
		rz_structured_data_array_add_unsigned(cpr_mask, mips->cpr_mask[3], true) &&
		rz_structured_data_map_add_unsigned(parent, "gp_value", mips->gp_value, true);
}

static bool ecoff_aouthdr_to_structure(const ECoff *ecoff, RzStructuredData *parent) {
	RzStructuredData *aouthdr = rz_structured_data_map_add_map(parent, "aouthdr");
	if (!aouthdr) {
		return false;
	} else if (ecoff_is_alpha(ecoff)) {
		return ecoff_aouthdr_alpha_to_structure(ecoff, aouthdr);
	}
	return ecoff_aouthdr_mips_to_structure(ecoff, aouthdr);
}

static bool ecoff_section_flags_to_structure(const ut32 flags, RzStructuredData *parent) {
	const ut32 extflag = flags & ECOFF_SECTION_EXT_TYPE_MASK;
	if (!parent) {
		return false;
	}
	RzStructuredData *s_flags = rz_structured_data_map_add_map(parent, "s_flags");
	if (!s_flags) {
		return false;
	}
	rz_structured_data_map_add_unsigned(s_flags, "value", flags, true);

	RzStructuredData *readable = rz_structured_data_map_add_array(s_flags, "readable");
	if (!readable) {
		return false;
	}

	if (flags == ECOFF_SECTION_TYPE_REG) {
		// when zero is always this type.
		return rz_structured_data_array_add_string(readable, "STYP_REG");
	}

#define HAS_FLAG(flag, name) \
	if (flags & flag && !rz_structured_data_array_add_string(readable, name)) { \
		return false; \
	}
	HAS_FLAG(ECOFF_SECTION_TYPE_TEXT, "STYP_TEXT");
	HAS_FLAG(ECOFF_SECTION_TYPE_DATA, "STYP_DATA");
	HAS_FLAG(ECOFF_SECTION_TYPE_BSS, "STYP_BSS");

	HAS_FLAG(ECOFF_SECTION_TYPE_RDATA, "STYP_RDATA");
	HAS_FLAG(ECOFF_SECTION_TYPE_SDATA, "STYP_SDATA");
	HAS_FLAG(ECOFF_SECTION_TYPE_SBSS, "STYP_SBSS");
	HAS_FLAG(ECOFF_SECTION_TYPE_UCODE, "STYP_UCODE");
	HAS_FLAG(ECOFF_SECTION_TYPE_GOT1, "STYP_GOT1");
	HAS_FLAG(ECOFF_SECTION_TYPE_DYNAMIC1, "STYP_DYNAMIC1");
	HAS_FLAG(ECOFF_SECTION_TYPE_DYNSYM1, "STYP_DYNSYM1");
	HAS_FLAG(ECOFF_SECTION_TYPE_REL_DYN1, "STYP_REL_DYN1");
	HAS_FLAG(ECOFF_SECTION_TYPE_DYNSTR1, "STYP_DYNSTR1");
	HAS_FLAG(ECOFF_SECTION_TYPE_HASH1, "STYP_HASH1");
	HAS_FLAG(ECOFF_SECTION_TYPE_DSOLIST1, "STYP_DSOLIST1");
	HAS_FLAG(ECOFF_SECTION_TYPE_MSYM1, "STYP_MSYM1");
	HAS_FLAG(ECOFF_SECTION_TYPE_LIT4, "STYP_LIT4");
	HAS_FLAG(ECOFF_SECTION_TYPE_NRELOC_OVFL2, "STYP_NRELOC_OVFL2");
	HAS_FLAG(ECOFF_SECTION_TYPE_LIB, "STYP_LIB");
	HAS_FLAG(ECOFF_SECTION_TYPE_INIT, "STYP_INIT");
#undef HAS_FLAG

#define HAS_EXT_FLAG(flag, name) \
	if (extflag == flag && !rz_structured_data_array_add_string(readable, name)) { \
		return false; \
	}
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_CONFLICT1, "STYP_CONFLICT1");
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_RESOURCE, "STYP_RESOURCE");
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_FINI, "STYP_FINI");
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_COMMENT1, "STYP_COMMENT1");
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_COMMENT2, "STYP_COMMENT2");
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_RCONST, "STYP_RCONST");
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_XDATA, "STYP_XDATA");
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_TLSDATA, "STYP_TLSDATA");
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_TLSBSS, "STYP_TLSBSS");
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_TLSINIT, "STYP_TLSINIT");
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_PDATA, "STYP_PDATA");
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_LITA, "STYP_LITA");
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_LIT8, "STYP_LIT8");
#undef HAS_EXT_FLAG

	return true;
}

static bool ecoff_section_alpha_to_structure(const ECoff_Section_Alpha *alpha, RzStructuredData *parent) {
	return rz_structured_data_map_add_string(parent, "s_name", alpha->resolved_name) &&
		rz_structured_data_map_add_unsigned(parent, "s_paddr", alpha->s_paddr, true) &&
		rz_structured_data_map_add_unsigned(parent, "s_vaddr", alpha->s_vaddr, true) &&
		rz_structured_data_map_add_unsigned(parent, "s_size", alpha->s_size, true) &&
		rz_structured_data_map_add_unsigned(parent, "s_scnptr", alpha->s_scnptr, true) &&
		rz_structured_data_map_add_unsigned(parent, "s_relptr", alpha->s_relptr, true) &&
		rz_structured_data_map_add_unsigned(parent, "s_lnnoptr", alpha->s_lnnoptr, true) &&
		rz_structured_data_map_add_unsigned(parent, "s_nreloc", alpha->s_nreloc, true) &&
		rz_structured_data_map_add_unsigned(parent, "s_nlnno", alpha->s_nlnno, true) &&
		ecoff_section_flags_to_structure(alpha->s_flags, parent);
}

static bool ecoff_section_mips_to_structure(const ECoff_Section_Mips *mips, RzStructuredData *parent) {
	return rz_structured_data_map_add_string(parent, "s_name", mips->resolved_name) &&
		rz_structured_data_map_add_unsigned(parent, "s_paddr", mips->s_paddr, true) &&
		rz_structured_data_map_add_unsigned(parent, "s_vaddr", mips->s_vaddr, true) &&
		rz_structured_data_map_add_unsigned(parent, "s_size", mips->s_size, true) &&
		rz_structured_data_map_add_unsigned(parent, "s_scnptr", mips->s_scnptr, true) &&
		rz_structured_data_map_add_unsigned(parent, "s_relptr", mips->s_relptr, true) &&
		rz_structured_data_map_add_unsigned(parent, "s_lnnoptr", mips->s_lnnoptr, true) &&
		rz_structured_data_map_add_unsigned(parent, "s_nreloc", mips->s_nreloc, true) &&
		rz_structured_data_map_add_unsigned(parent, "s_nlnno", mips->s_nlnno, true) &&
		ecoff_section_flags_to_structure(mips->s_flags, parent);
}

static bool ecoff_sections_to_structure(const ECoff *ecoff, RzStructuredData *parent) {
	if (!parent) {
		return false;
	}
	RzStructuredData *sections_arr = rz_structured_data_map_add_array(parent, "sections");
	if (!sections_arr) {
		return false;
	}

	const bool is_alpha = ecoff_is_alpha(ecoff);

	const RzVector *sections = NULL;
	if (is_alpha) {
		sections = ecoff->alpha.sections;
	} else {
		sections = ecoff->mips.sections;
	}

	const void *esec;
	rz_vector_foreach (sections, esec) {
		bool ok = false;

		RzStructuredData *section = rz_structured_data_array_add_map(sections_arr);
		if (!section) {
			return false;
		} else if (is_alpha) {
			ok = ecoff_section_alpha_to_structure((const ECoff_Section_Alpha *)esec, section);
		} else {
			ok = ecoff_section_mips_to_structure((const ECoff_Section_Mips *)esec, section);
		}
		if (!ok) {
			return false;
		}
	}

	return true;
}

static const char *ecoff_symbol_sclass(const ECoff_Symbol_Mips *symbol) {
	switch (symbol->e_sclass) {
	case ECOFF_SYMBOL_SCLASS_EFCN:
		return "C_EFCN";
	case ECOFF_SYMBOL_SCLASS_NULL:
		return "C_NULL";
	case ECOFF_SYMBOL_SCLASS_AUTO:
		return "C_AUTO";
	case ECOFF_SYMBOL_SCLASS_EXT:
		return "C_EXT";
	case ECOFF_SYMBOL_SCLASS_STAT:
		return "C_STAT";
	case ECOFF_SYMBOL_SCLASS_REG:
		return "C_REG";
	case ECOFF_SYMBOL_SCLASS_EXTDEF:
		return "C_EXTDEF";
	case ECOFF_SYMBOL_SCLASS_LABEL:
		return "C_LABEL";
	case ECOFF_SYMBOL_SCLASS_ULABEL:
		return "C_ULABEL";
	case ECOFF_SYMBOL_SCLASS_MOS:
		return "C_MOS";
	case ECOFF_SYMBOL_SCLASS_ARG:
		return "C_ARG";
	case ECOFF_SYMBOL_SCLASS_STRTAG:
		return "C_STRTAG";
	case ECOFF_SYMBOL_SCLASS_MOU:
		return "C_MOU";
	case ECOFF_SYMBOL_SCLASS_UNTAG:
		return "C_UNTAG";
	case ECOFF_SYMBOL_SCLASS_TPDEF:
		return "C_TPDEF";
	case ECOFF_SYMBOL_SCLASS_USTATIC:
		return "C_USTATIC";
	case ECOFF_SYMBOL_SCLASS_ENTAG:
		return "C_ENTAG";
	case ECOFF_SYMBOL_SCLASS_MOE:
		return "C_MOE";
	case ECOFF_SYMBOL_SCLASS_REGPARM:
		return "C_REGPARM";
	case ECOFF_SYMBOL_SCLASS_FIELD:
		return "C_FIELD";
	case ECOFF_SYMBOL_SCLASS_BLOCK:
		return "C_BLOCK";
	case ECOFF_SYMBOL_SCLASS_FCN:
		return "C_FCN";
	case ECOFF_SYMBOL_SCLASS_EOS:
		return "C_EOS";
	case ECOFF_SYMBOL_SCLASS_FILE:
		return "C_FILE";
	case ECOFF_SYMBOL_SCLASS_LINE:
		return "C_LINE";
	case ECOFF_SYMBOL_SCLASS_ALIAS:
		return "C_ALIAS";
	case ECOFF_SYMBOL_SCLASS_HIDDEN:
		return "C_HIDDEN";
	default:
		rz_warn_if_reached();
		return "unknown";
	}
}

static bool ecoff_symbol_mips_to_structure(const ECoff *ecoff, const ECoff_Symbol_Mips *symbol, RzStructuredData *parent) {
	const char *e_scnum = "unknown";
	const char *e_sclass = ecoff_symbol_sclass(symbol);

	if (symbol->e_scnum == ECOFF_SYMBOL_SECT_NUM_DEBUG) {
		// Special symbolic debugging symbol
		e_scnum = "N_DEBUG";
	} else if (symbol->e_scnum == ECOFF_SYMBOL_SECT_NUM_ABS) {
		// Absolute symbol
		e_scnum = "N_ABS";
	} else if (symbol->e_scnum == ECOFF_SYMBOL_SECT_NUM_UNDEF) {
		// Undefined external symbol
		e_scnum = "N_UNDEF";
	} else if (symbol->e_scnum > 0 && symbol->e_scnum < rz_vector_len(ecoff->mips.sections)) {
		const ECoff_Section_Mips *esec = rz_vector_index_ptr(ecoff->mips.sections, symbol->e_scnum);
		if (esec) {
			e_scnum = esec->resolved_name;
		}
	}

	return rz_structured_data_map_add_string(parent, "e_name", symbol->resolved_name) &&
		rz_structured_data_map_add_unsigned(parent, "e_value", symbol->e_value, true) &&
		rz_structured_data_map_add_string(parent, "e_scnum", e_scnum) &&
		rz_structured_data_map_add_unsigned(parent, "e_type", symbol->e_type, true) &&
		rz_structured_data_map_add_string(parent, "e_sclass", e_sclass) &&
		rz_structured_data_map_add_unsigned(parent, "e_numaux", symbol->e_numaux, true);
}

static bool ecoff_mips_symbols_to_structure(const ECoff *ecoff, RzStructuredData *parent) {
	RzStructuredData *symbols = rz_structured_data_map_add_array(parent, "symbols");
	if (!symbols) {
		return false;
	}

	const ECoff_Symbol_Mips *symbol;
	rz_vector_foreach (ecoff->mips.symbols, symbol) {
		RzStructuredData *section = rz_structured_data_array_add_map(symbols);
		if (!section) {
			return false;
		} else if (!ecoff_symbol_mips_to_structure(ecoff, symbol, section)) {
			return false;
		}
	}

	return true;
}

static bool ecoff_alpha_symbolic_hdr_to_structure(const ECoff *ecoff, RzStructuredData *parent) {
	const ECoff_SymHdr_Alpha *symhdr = &ecoff->alpha.symhdr;
	RzStructuredData *symbolic_hdr = rz_structured_data_map_add_map(parent, "symbolic_hdr");
	if (!symbolic_hdr) {
		return false;
	}
	char vstamp[16] = { 0 };
	rz_strf(vstamp, "v%u.%u", symhdr->vstamp[1], symhdr->vstamp[0]);

	return rz_structured_data_map_add_unsigned(symbolic_hdr, "magic", symhdr->magic, true) &&
		rz_structured_data_map_add_string(symbolic_hdr, "vstamp", vstamp) &&
		rz_structured_data_map_add_signed(symbolic_hdr, "iline_max", symhdr->iline_max) &&
		rz_structured_data_map_add_signed(symbolic_hdr, "idn_max", symhdr->idn_max) &&
		rz_structured_data_map_add_signed(symbolic_hdr, "ipd_max", symhdr->ipd_max) &&
		rz_structured_data_map_add_signed(symbolic_hdr, "isym_max", symhdr->isym_max) &&
		rz_structured_data_map_add_signed(symbolic_hdr, "iopt_max", symhdr->iopt_max) &&
		rz_structured_data_map_add_signed(symbolic_hdr, "iaux_max", symhdr->iaux_max) &&
		rz_structured_data_map_add_signed(symbolic_hdr, "iss_max", symhdr->iss_max) &&
		rz_structured_data_map_add_signed(symbolic_hdr, "iss_ext_max", symhdr->iss_ext_max) &&
		rz_structured_data_map_add_signed(symbolic_hdr, "ifd_max", symhdr->ifd_max) &&
		rz_structured_data_map_add_signed(symbolic_hdr, "crfd", symhdr->crfd) &&
		rz_structured_data_map_add_signed(symbolic_hdr, "iext_max", symhdr->iext_max) &&
		rz_structured_data_map_add_signed(symbolic_hdr, "cb_line", symhdr->cb_line) &&
		rz_structured_data_map_add_unsigned(symbolic_hdr, "cb_line_offset", symhdr->cb_line_offset, true) &&
		rz_structured_data_map_add_unsigned(symbolic_hdr, "cb_dn_offset", symhdr->cb_dn_offset, true) &&
		rz_structured_data_map_add_unsigned(symbolic_hdr, "cb_pd_offset", symhdr->cb_pd_offset, true) &&
		rz_structured_data_map_add_unsigned(symbolic_hdr, "cb_sym_offset", symhdr->cb_sym_offset, true) &&
		rz_structured_data_map_add_unsigned(symbolic_hdr, "cb_opt_offset", symhdr->cb_opt_offset, true) &&
		rz_structured_data_map_add_unsigned(symbolic_hdr, "cb_aux_offset", symhdr->cb_aux_offset, true) &&
		rz_structured_data_map_add_unsigned(symbolic_hdr, "cb_ss_offset", symhdr->cb_ss_offset, true) &&
		rz_structured_data_map_add_unsigned(symbolic_hdr, "cb_ss_ext_offset", symhdr->cb_ss_ext_offset, true) &&
		rz_structured_data_map_add_unsigned(symbolic_hdr, "cb_fd_offset", symhdr->cb_fd_offset, true) &&
		rz_structured_data_map_add_unsigned(symbolic_hdr, "cb_rfd_offset", symhdr->cb_rfd_offset, true) &&
		rz_structured_data_map_add_unsigned(symbolic_hdr, "cb_ext_offset", symhdr->cb_ext_offset, true);
}

static const char *ecoff_alpha_file_descr_entry_get_lang(const ECoff_FileDescEntry_Alpha *fde) {
	switch (fde->lang) {
	case ECOFF_FDE_LANG_C:
		return "C";
	case ECOFF_FDE_LANG_PASCAL:
		return "Pascal";
	case ECOFF_FDE_LANG_FORTRAN:
		return "Fortran";
	case ECOFF_FDE_LANG_ASSEMBLER:
		return "Assembly";
	case ECOFF_FDE_LANG_MACHINE:
		return "Machine";
	case ECOFF_FDE_LANG_NIL:
		return "Nil";
	case ECOFF_FDE_LANG_ADA:
		return "Ada";
	case ECOFF_FDE_LANG_PL1:
		return "Pl1";
	case ECOFF_FDE_LANG_COBOL:
		return "Cobol";
	case ECOFF_FDE_LANG_STDC:
		return "stdC";
	case ECOFF_FDE_LANG_MIPS_CXX:
		return "Mips C++";
	case ECOFF_FDE_LANG_DEC_CXX:
		return "Dec C++";
	case ECOFF_FDE_LANG_CXX:
		return "C++";
	case ECOFF_FDE_LANG_FORTRAN90:
		return "Fortran 90";
	case ECOFF_FDE_LANG_BLISS:
		return "Bliss";
	case ECOFF_FDE_LANG_PTAL:
		return "PTAL";
	case ECOFF_FDE_LANG_CXX_V1:
		return "C++v1";
	case ECOFF_FDE_LANG_CXX_V2:
		return "C++v2";
	default:
		return "unknown";
	}
}

static const char *ecoff_alpha_file_descr_entry_get_glevel(const ECoff_FileDescEntry_Alpha *fde) {
	switch (fde->glevel) {
	case ECOFF_FDE_GLEVEL_0:
		return "-g0";
	case ECOFF_FDE_GLEVEL_1:
		return "-g1";
	case ECOFF_FDE_GLEVEL_2:
		return "-g2";
	case ECOFF_FDE_GLEVEL_3:
		return "-g3";
	default:
		return "unknown";
	}
}

static bool ecoff_alpha_file_descr_entry_to_structure(const ECoff_FileDescEntry_Alpha *fde, RzStructuredData *parent) {
	RzStructuredData *fde_info = rz_structured_data_array_add_map(parent);
	if (!fde_info) {
		return false;
	}

	const char *glevel = ecoff_alpha_file_descr_entry_get_glevel(fde);
	const char *lang = ecoff_alpha_file_descr_entry_get_lang(fde);
	char vstamp[16] = { 0 };
	rz_strf(vstamp, "v%u.%u", fde->vstamp[1], fde->vstamp[0]);

	return rz_structured_data_map_add_unsigned(fde_info, "adr", fde->adr, true) &&
		rz_structured_data_map_add_signed(fde_info, "cb_line_offset", fde->cb_line_offset) &&
		rz_structured_data_map_add_signed(fde_info, "cb_line", fde->cb_line) &&
		rz_structured_data_map_add_signed(fde_info, "cb_ss", fde->cb_ss) &&
		rz_structured_data_map_add_signed(fde_info, "rss", fde->rss) &&
		rz_structured_data_map_add_signed(fde_info, "iss_base", fde->iss_base) &&
		rz_structured_data_map_add_signed(fde_info, "isym_base", fde->isym_base) &&
		rz_structured_data_map_add_signed(fde_info, "csym", fde->csym) &&
		rz_structured_data_map_add_signed(fde_info, "iline_base", fde->iline_base) &&
		rz_structured_data_map_add_signed(fde_info, "cline", fde->cline) &&
		rz_structured_data_map_add_signed(fde_info, "iopt_base", fde->iopt_base) &&
		rz_structured_data_map_add_signed(fde_info, "copt", fde->copt) &&
		rz_structured_data_map_add_signed(fde_info, "ipd_first", fde->ipd_first) &&
		rz_structured_data_map_add_signed(fde_info, "cpd", fde->cpd) &&
		rz_structured_data_map_add_signed(fde_info, "iaux_base", fde->iaux_base) &&
		rz_structured_data_map_add_signed(fde_info, "caux", fde->caux) &&
		rz_structured_data_map_add_signed(fde_info, "rfd_base", fde->rfd_base) &&
		rz_structured_data_map_add_signed(fde_info, "crfd", fde->crfd) &&
		rz_structured_data_map_add_string(fde_info, "lang", lang) &&
		rz_structured_data_map_add_boolean(fde_info, "f_merge", fde->f_merge) &&
		rz_structured_data_map_add_boolean(fde_info, "f_readin", fde->f_readin) &&
		rz_structured_data_map_add_boolean(fde_info, "f_bigendian", fde->f_bigendian) &&
		rz_structured_data_map_add_string(fde_info, "glevel", glevel) &&
		rz_structured_data_map_add_boolean(fde_info, "f_trim", fde->f_trim) &&
		rz_structured_data_map_add_unsigned(fde_info, "reserved", fde->reserved, true) &&
		rz_structured_data_map_add_string(fde_info, "vstamp", vstamp) &&
		rz_structured_data_map_add_unsigned(fde_info, "reserved2", fde->reserved2, true);
}

static bool ecoff_alpha_file_descr_entries_to_structure(const ECoff *ecoff, RzStructuredData *parent) {
	RzStructuredData *fdes = rz_structured_data_map_add_array(parent, "fdes");
	if (!fdes) {
		return false;
	}

	const ECoff_FileDescEntry_Alpha *fde;
	rz_vector_foreach (ecoff->alpha.file_descs, fde) {
		if (!ecoff_alpha_file_descr_entry_to_structure(fde, fdes)) {
			return false;
		}
	}
	return true;
}

static bool ecoff_alpha_symbols_to_structure(const ECoff *ecoff, RzStructuredData *parent) {
	return ecoff_alpha_symbolic_hdr_to_structure(ecoff, parent) &&
		ecoff_alpha_file_descr_entries_to_structure(ecoff, parent);
}

static bool ecoff_symbols_to_structure(const ECoff *ecoff, RzStructuredData *parent) {
	if (!parent) {
		return false;
	}

	if (ecoff_is_alpha(ecoff)) {
		return ecoff_alpha_symbols_to_structure(ecoff, parent);
	}

	return ecoff_mips_symbols_to_structure(ecoff, parent);
}

bool ecoff_new_structure(const ECoff *ecoff, RzStructuredData *parent) {
	return ecoff_header_to_structure(ecoff, parent) &&
		ecoff_aouthdr_to_structure(ecoff, parent) &&
		ecoff_sections_to_structure(ecoff, parent) &&
		ecoff_symbols_to_structure(ecoff, parent);
}

RzList /*<char *>*/ *ecoff_resolve_section_flags(ut64 s_flags) {
	const ut32 extflag = s_flags & ECOFF_SECTION_EXT_TYPE_MASK;
	RzList *flags = rz_list_new();
	if (!flags) {
		return false;
	}

	if (s_flags == ECOFF_SECTION_TYPE_REG) {
		// when zero is always this type.
		rz_list_append(flags, "STYP_REG");
		return flags;
	}

#define HAS_FLAG(flag, name) \
	if (s_flags & flag) { \
		rz_list_append(flags, name); \
	}
	HAS_FLAG(ECOFF_SECTION_TYPE_TEXT, "STYP_TEXT");
	HAS_FLAG(ECOFF_SECTION_TYPE_DATA, "STYP_DATA");
	HAS_FLAG(ECOFF_SECTION_TYPE_BSS, "STYP_BSS");

	HAS_FLAG(ECOFF_SECTION_TYPE_RDATA, "STYP_RDATA");
	HAS_FLAG(ECOFF_SECTION_TYPE_SDATA, "STYP_SDATA");
	HAS_FLAG(ECOFF_SECTION_TYPE_SBSS, "STYP_SBSS");
	HAS_FLAG(ECOFF_SECTION_TYPE_UCODE, "STYP_UCODE");
	HAS_FLAG(ECOFF_SECTION_TYPE_GOT1, "STYP_GOT1");
	HAS_FLAG(ECOFF_SECTION_TYPE_DYNAMIC1, "STYP_DYNAMIC1");
	HAS_FLAG(ECOFF_SECTION_TYPE_DYNSYM1, "STYP_DYNSYM1");
	HAS_FLAG(ECOFF_SECTION_TYPE_REL_DYN1, "STYP_REL_DYN1");
	HAS_FLAG(ECOFF_SECTION_TYPE_DYNSTR1, "STYP_DYNSTR1");
	HAS_FLAG(ECOFF_SECTION_TYPE_HASH1, "STYP_HASH1");
	HAS_FLAG(ECOFF_SECTION_TYPE_DSOLIST1, "STYP_DSOLIST1");
	HAS_FLAG(ECOFF_SECTION_TYPE_MSYM1, "STYP_MSYM1");
	HAS_FLAG(ECOFF_SECTION_TYPE_LIT4, "STYP_LIT4");
	HAS_FLAG(ECOFF_SECTION_TYPE_NRELOC_OVFL2, "STYP_NRELOC_OVFL2");
	HAS_FLAG(ECOFF_SECTION_TYPE_LIB, "STYP_LIB");
	HAS_FLAG(ECOFF_SECTION_TYPE_INIT, "STYP_INIT");
#undef HAS_FLAG

#define HAS_EXT_FLAG(flag, name) \
	if (extflag == flag) { \
		rz_list_append(flags, name); \
	}
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_CONFLICT1, "STYP_CONFLICT1");
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_RESOURCE, "STYP_RESOURCE");
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_FINI, "STYP_FINI");
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_COMMENT1, "STYP_COMMENT1");
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_COMMENT2, "STYP_COMMENT2");
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_RCONST, "STYP_RCONST");
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_XDATA, "STYP_XDATA");
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_TLSDATA, "STYP_TLSDATA");
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_TLSBSS, "STYP_TLSBSS");
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_TLSINIT, "STYP_TLSINIT");
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_PDATA, "STYP_PDATA");
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_LITA, "STYP_LITA");
	HAS_EXT_FLAG(ECOFF_SECTION_EXT_TYPE_LIT8, "STYP_LIT8");
#undef HAS_EXT_FLAG

	return flags;
}
