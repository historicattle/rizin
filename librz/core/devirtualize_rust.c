// SPDX-FileCopyrightText: 2026 historicattle <sirigere.naren@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_analysis.h>
#include <rz_core.h>
#include "core_private.h"

#define RUST_VTABLE_HEADER_SLOTS    3
#define RUST_MAX_TRAIT_METHOD_SLOTS 128
#define RUST_TYPE_ID_BYTES          16
#define RUST_MAX_CALL_ARGS          8
#define RUST_TRACK_MEM_ADDR         0x10000000
#define RUST_TRACK_MEM_SIZE         0x50000
#define RUST_STACK_PTR              (RUST_TRACK_MEM_ADDR + (RUST_TRACK_MEM_SIZE / 2))
#define RUST_SCRATCH_HEAP_ADDR      (RUST_TRACK_MEM_ADDR + 0x30000)
#define RUST_SCRATCH_HEAP_SIZE      0x20000
#define RUST_SCRATCH_ALLOC_STEP     0x100

typedef struct rust_any_vtable_t {
	ut64 vtable_addr;
	ut64 type_id_method;
	ut64 type_id_low;
	ut64 type_id_high;
	bool has_type_id;
	bool has_type_id_high;
	char *concrete_type;
} RustAnyVTable;

typedef struct rust_arg_regs_t {
	const char *regs[RUST_MAX_CALL_ARGS];
	ut64 count;
} RustArgRegs;

typedef struct rust_call_seed_t {
	const char *regs[RUST_MAX_CALL_ARGS];
	ut64 values[RUST_MAX_CALL_ARGS];
	bool has_value[RUST_MAX_CALL_ARGS];
	ut64 count;
} RustCallSeed;

static void rust_any_vtable_fini(void *e, RZ_UNUSED void *user) {
	RustAnyVTable *vtable = e;
	RZ_FREE(vtable->concrete_type);
}

static ut64 ptr_size(RzCore *core) {
	return rz_asm_get_bits(core->rasm) == 64 ? 8 : 4;
}

static bool read_ptr(RzCore *core, ut64 addr, ut64 *out) {
	return rz_io_read_i(core->io, addr, out, ptr_size(core), rz_asm_is_big_endian_set(core->rasm));
}

static bool addr_is_executable(RzCore *core, ut64 addr) {
	RzBinObject *obj = rz_bin_cur_object(core->bin);
	if (!obj) {
		return false;
	}
	RzBinSection *section = rz_bin_get_section_at(obj, addr, true);
	return section && (section->perm & RZ_PERM_X);
}

static RZ_OWN ut8 *read_mapped_range(RzCore *core, ut64 start, ut64 end) {
	if (end <= start) {
		return NULL;
	}
	ut8 *bytes = malloc(end - start);
	if (!bytes) {
		return NULL;
	}
	if (!rz_io_read_at_mapped(core->io, start, bytes, end - start)) {
		RZ_FREE(bytes);
		return NULL;
	}
	return bytes;
}

static RZ_OWN char *get_method_name(RzCore *core, ut64 addr) {
	if (!addr || addr == UT64_MAX || !rz_io_is_valid_offset(core->io, addr, RZ_PERM_R)) {
		return NULL;
	}
	RzAnalysisFunction *function = rz_analysis_get_fcn_in(core->analysis, addr, RZ_ANALYSIS_FCN_TYPE_NULL);
	if (function && RZ_STR_ISNOTEMPTY(function->name)) {
		return rz_str_dup(function->name);
	}
	RzFlagItem *flag = rz_flag_get_i(core->flags, addr);
	if (flag) {
		return rz_str_dup(flag->name);
	}
	return NULL;
}

static bool is_any_trait_name(const char *trait_name) {
	if (RZ_STR_ISEMPTY(trait_name)) {
		return false;
	}

	return (rz_str_startswith(trait_name, "core") || rz_str_startswith(trait_name, "std")) &&
		(rz_str_endswith(trait_name, "any::Any") || rz_str_endswith(trait_name, "any::Any_"));
}

static const char *rust_trait_name_from_class_name(const char *class_name) {
	if (RZ_STR_ISEMPTY(class_name)) {
		return NULL;
	}
	if (rz_str_startswith(class_name, "impl ")) {
		const char *as = rz_str_rstr(class_name, " as ");
		if (!as) {
			return NULL;
		}
		const char *trait_name = as + strlen(" as ");
		if (RZ_STR_ISNOTEMPTY(trait_name)) {
			return trait_name;
		}
		return NULL;
	}

	const char *as = rz_str_rstr(class_name, "_as_");
	if (!as || as == class_name) {
		return NULL;
	}
	const char *trait_name = as + strlen("_as_");
	if (RZ_STR_ISNOTEMPTY(trait_name)) {
		return trait_name;
	}
	return NULL;
}

static bool is_any_class_name(const char *class_name) {
	return is_any_trait_name(rust_trait_name_from_class_name(class_name));
}

static RZ_OWN char *concrete_type_from_any_class_name(const char *class_name) {
	if (!is_any_class_name(class_name)) {
		return NULL;
	}
	if (rz_str_startswith(class_name, "impl ")) {
		const char *impl_type = class_name + strlen("impl ");
		const char *as = rz_str_rstr(class_name, " as ");
		if (as > impl_type) {
			return rz_str_ndup(impl_type, (as - impl_type));
		}
		return NULL;
	}

	const char *as = rz_str_rstr(class_name, "_as_");
	if (as > class_name) {
		return rz_str_ndup(class_name, (as - class_name));
	}
	return NULL;
}

static bool is_rust_vtable(RzCore *core, ut64 vtable_addr) {
	ut64 drop = UT64_MAX;
	ut64 size = UT64_MAX;
	ut64 align = UT64_MAX;
	ut64 psize = ptr_size(core);
	if (!read_ptr(core, vtable_addr, &drop) || !read_ptr(core, vtable_addr + psize, &size) ||
		!read_ptr(core, vtable_addr + (2 * psize), &align)) {
		return false;
	}

	if (drop && !addr_is_executable(core, drop)) {
		return false;
	}
	if (rz_bits_count_ones_ut64(align) != 1) {
		return false;
	}
	return !size || (!(size % align) && align <= size);
}

static bool rust_type_id_push_imm(ut64 values[2], ut64 *count, ut64 value) {
	if (value == UT64_MAX) {
		return false;
	}

	for (ut64 i = 0; i < *count; i++) {
		if (values[i] == value) {
			return true;
		}
	}

	if (*count >= 2) {
		return false;
	}

	values[(*count)++] = value;
	return true;
}

static bool rust_type_id_push_data(RzCore *core, ut64 values[2], ut64 *count, ut64 addr) {
	ut8 buf[RUST_TYPE_ID_BYTES] = { 0 };
	if (!addr || addr == UT64_MAX || !rz_io_read_at_mapped(core->io, addr, buf, sizeof(buf))) {
		return false;
	}

	bool big_endian = rz_asm_is_big_endian_set(core->rasm);
	values[0] = rz_read_ble64(buf, big_endian);
	values[1] = rz_read_ble64(buf + 8, big_endian);
	*count = 2;
	return true;
}

static bool rust_type_id_from_method(RzCore *core, ut64 method_addr, RZ_OUT ut64 *low, RZ_OUT ut64 *high, RZ_OUT bool *has_high) {
	RzAnalysisFunction *function = rz_analysis_get_fcn_in(core->analysis, method_addr, RZ_ANALYSIS_FCN_TYPE_NULL);
	if (!function) {
		return false;
	}

	ut64 start = function->addr;
	ut64 end = rz_analysis_function_max_addr(function);
	if (end <= start) {
		return false;
	}

	ut8 *bytes = read_mapped_range(core, start, end);
	if (!bytes) {
		return false;
	}

	ut64 values[2] = { 0 };
	ut64 count = 0;
	ut64 offset = 0;
	RzAnalysisOp *op = rz_analysis_op_new();
	if (!op) {
		RZ_FREE(bytes);
		return false;
	}

	while (start < end && count < 2) {
		if (rz_analysis_op(core->analysis, op, start, bytes + offset, end - start, RZ_ANALYSIS_OP_MASK_ALL) <= 0 || op->size < 1) {
			break;
		}
		ut32 type = op->type & RZ_ANALYSIS_OP_TYPE_MASK;
		if (op->ptr && op->ptr != UT64_MAX && op->refptr >= RUST_TYPE_ID_BYTES &&
			rust_type_id_push_data(core, values, &count, op->ptr)) {
			rz_analysis_op_fini(op);
			break;
		}
		if (type == RZ_ANALYSIS_OP_TYPE_MOV || type == RZ_ANALYSIS_OP_TYPE_CMOV) {
			if (op->val != UT64_MAX) {
				rust_type_id_push_imm(values, &count, op->val);
			}
			for (ut64 i = 0; i < RZ_ARRAY_SIZE(op->analysis_vals); i++) {
				if (op->analysis_vals[i].imm != ST64_MAX && op->analysis_vals[i].imm) {
					rust_type_id_push_imm(values, &count, op->analysis_vals[i].imm);
				}
			}
		}
		if (type == RZ_ANALYSIS_OP_TYPE_RET) {
			rz_analysis_op_fini(op);
			break;
		}
		start += op->size;
		offset += op->size;
		rz_analysis_op_fini(op);
	}

	rz_analysis_op_free(op);
	RZ_FREE(bytes);
	if (!count) {
		return false;
	}

	*low = values[0];
	*high = 0;
	if (count > 1) {
		*high = values[1];
	}
	*has_high = count > 1;
	return true;
}

static bool rust_method_is_type_id(RzAnalysisMethod *method) {
	if (!method) {
		return false;
	}
	if (rz_str_startswith(method->name, "type_id") || rz_str_startswith(method->name, "get_type_id")) {
		return true;
	}
	return method->real_name && (strstr(method->real_name, "::type_id") || strstr(method->real_name, "::get_type_id"));
}

static RzAnalysisMethod *rust_any_type_id_method(RzVector /*<RzAnalysisMethod>*/ *methods) {
	if (!methods) {
		return NULL;
	}

	RzAnalysisMethod *method;
	rz_vector_foreach (methods, method) {
		if (rust_method_is_type_id(method)) {
			return method;
		}
	}
	return NULL;
}

static bool push_any_vtable_from_class(RzCore *core, RzVector /*<RustAnyVTable>*/ *any_vtables, const char *class_name, RzAnalysisVTable *vtable, RzAnalysisMethod *type_id_method) {
	if (!type_id_method || !type_id_method->addr || type_id_method->addr == UT64_MAX ||
		(vtable && (!vtable->addr || vtable->addr == UT64_MAX))) {
		return false;
	}

	RustAnyVTable any = {
		.vtable_addr = UT64_MAX,
		.type_id_method = type_id_method->addr,
		.concrete_type = concrete_type_from_any_class_name(class_name),
	};
	if (vtable) {
		any.vtable_addr = vtable->addr;
	}

	if (!any.concrete_type) {
		return false;
	}

	any.has_type_id = rust_type_id_from_method(core, any.type_id_method, &any.type_id_low, &any.type_id_high, &any.has_type_id_high);
	if (!rz_vector_push(any_vtables, &any)) {
		rust_any_vtable_fini(&any, NULL);
		return false;
	}
	return true;
}

static RZ_OWN RzVector /*<RustAnyVTable>*/ *rust_any_vtables_from_classes(RzCore *core) {
	RzPVector *classes = rz_analysis_class_get_all(core->analysis, false);
	if (!classes) {
		return NULL;
	}

	RzVector *any_vtables = rz_vector_new(sizeof(RustAnyVTable), rust_any_vtable_fini, NULL);
	if (!any_vtables) {
		rz_pvector_free(classes);
		return NULL;
	}

	void **iter;
	rz_pvector_foreach (classes, iter) {
		SdbKv *kv = *iter;
		const char *class_name = sdbkv_key(kv);
		if (!is_any_class_name(class_name)) {
			continue;
		}

		RzVector *methods = rz_analysis_class_method_get_all(core->analysis, class_name);
		RzAnalysisMethod *type_id_method = rust_any_type_id_method(methods);
		if (!type_id_method) {
			rz_vector_free(methods);
			continue;
		}

		RzVector *vtables = rz_analysis_class_vtable_get_all(core->analysis, class_name);
		if (!vtables || rz_vector_empty(vtables)) {
			push_any_vtable_from_class(core, any_vtables, class_name, NULL, type_id_method);
			rz_vector_free(vtables);
			rz_vector_free(methods);
			continue;
		}

		RzAnalysisVTable *vtable;
		rz_vector_foreach (vtables, vtable) {
			push_any_vtable_from_class(core, any_vtables, class_name, vtable, type_id_method);
		}
		rz_vector_free(vtables);
		rz_vector_free(methods);
	}

	rz_pvector_free(classes);
	if (rz_vector_empty(any_vtables)) {
		rz_vector_free(any_vtables);
		return NULL;
	}
	return any_vtables;
}

static RustAnyVTable *any_vtable_by_addr(RzVector /*<RustAnyVTable>*/ *vtables, ut64 vtable_addr) {
	if (!vtables || !vtable_addr || vtable_addr == UT64_MAX) {
		return NULL;
	}

	RustAnyVTable *any;
	rz_vector_foreach (vtables, any) {
		if (any->vtable_addr == vtable_addr) {
			return any;
		}
	}
	return NULL;
}

static RustAnyVTable *any_vtable_by_type_id_method(RzVector /*<RustAnyVTable>*/ *vtables, ut64 method_addr) {
	if (!vtables) {
		return NULL;
	}

	RustAnyVTable *any;
	rz_vector_foreach (vtables, any) {
		if (any->type_id_method == method_addr) {
			return any;
		}
	}
	return NULL;
}

static bool type_id_values_match(ut64 low, ut64 high, bool has_high, RustAnyVTable *any) {
	if (!any || !any->has_type_id) {
		return false;
	}
	if (has_high && any->has_type_id_high) {
		return low == any->type_id_low && high == any->type_id_high;
	}

	return low == any->type_id_low;
}

static RustAnyVTable *any_vtable_by_type_id_values(RzVector /*<RustAnyVTable>*/ *vtables, ut64 low, ut64 high, bool has_high) {
	if (!vtables) {
		return NULL;
	}

	RustAnyVTable *any;
	rz_vector_foreach (vtables, any) {
		if (type_id_values_match(low, high, has_high, any)) {
			return any;
		}
	}
	return NULL;
}

static bool resolve_slot(RzCore *core, ut64 vtable_addr, ut64 slot_addr, RZ_OUT ut64 *target) {
	ut64 psize = ptr_size(core);
	if (slot_addr < vtable_addr) {
		return false;
	}

	ut64 method_offset = slot_addr - vtable_addr;
	if (method_offset < RUST_VTABLE_HEADER_SLOTS * psize || method_offset % psize) {
		return false;
	}

	ut64 method_slot = (method_offset / psize) - RUST_VTABLE_HEADER_SLOTS;
	if (method_slot >= RUST_MAX_TRAIT_METHOD_SLOTS || !is_rust_vtable(core, vtable_addr)) {
		return false;
	}

	return read_ptr(core, slot_addr, target) && *target && *target != UT64_MAX && addr_is_executable(core, *target);
}

static ut64 il_value_to_ut64(RZ_NULLABLE RzILVal *val) {
	if (!val) {
		return UT64_MAX;
	}

	RzBitVector *bv = rz_il_value_to_bv(val);
	if (!bv) {
		return UT64_MAX;
	}

	ut64 ret = rz_bv_to_ut64(bv);
	rz_bv_free(bv);
	return ret;
}

static ut64 get_reg_value(RzAnalysis *analysis, const char *reg_name) {
	if (!reg_name) {
		return UT64_MAX;
	}

	RzAnalysisILVM *vm = rz_analysis_get_il_vm(analysis);
	if (!vm) {
		return UT64_MAX;
	}

	RzILVal *il_reg = rz_il_vm_get_var_value(vm->vm, RZ_IL_VAR_KIND_GLOBAL, reg_name);
	return il_value_to_ut64(il_reg);
}

static bool is_real_reg_name(RzCore *core, const char *reg_name) {
	if (RZ_STR_ISEMPTY(reg_name) || !strcmp(reg_name, "none")) {
		return false;
	}

	RzReg *reg = rz_analysis_get_reg(core->analysis);
	return reg && rz_reg_get(reg, reg_name, RZ_REG_TYPE_ANY);
}

static void advance_il_pc(RzCore *core, ut64 addr) {
	RzReg *reg = rz_analysis_get_reg(core->analysis);
	if (reg) {
		rz_reg_set_value_by_role(reg, RZ_REG_NAME_PC, addr);
	}
}

static bool analysis_value_is_mem(RzAnalysisValue *value) {
	return value && value->memref > 0;
}

static bool reg_name_is_pc(RzCore *core, const char *reg_name) {
	RzReg *reg = rz_analysis_get_reg(core->analysis);
	if (!reg) {
		return false;
	}
	const char *pc = rz_reg_get_name(reg, RZ_REG_NAME_PC);
	return pc && !strcmp(reg_name, pc);
}

static bool analysis_value_addr(RzCore *core, RZ_NULLABLE const RzAnalysisOp *op, RzAnalysisValue *value, RZ_OUT ut64 *addr) {
	if (!analysis_value_is_mem(value)) {
		return false;
	}

	ut64 result = value->base;
	const char *base_reg = NULL;
	if (value->reg) {
		base_reg = value->reg->name;
	}
	if (base_reg) {
		ut64 base = UT64_MAX;
		if (op && reg_name_is_pc(core, base_reg)) {
			base = op->addr + op->size;
		} else {
			base = get_reg_value(core->analysis, base_reg);
		}
		if (!base || base == UT64_MAX) {
			return false;
		}
		result += base;
	}

	if (value->regdelta) {
		ut64 index = get_reg_value(core->analysis, value->regdelta->name);
		if (index == UT64_MAX) {
			return false;
		}
		ut64 scale = value->mul;
		if (!scale) {
			scale = 1;
		}
		result += index * scale;
	}

	result += value->delta;
	if (!result) {
		return false;
	}
	*addr = result;
	return true;
}

static bool value_mem_access_is_safe(RzCore *core, RzAnalysisOp *op, RzAnalysisValue *value, bool write) {
	if (!analysis_value_is_mem(value)) {
		return true;
	}

	ut64 addr = UT64_MAX;
	if (!analysis_value_addr(core, op, value, &addr)) {
		return false;
	}

	ut64 access_size = value->memref;
	if (addr >= RUST_TRACK_MEM_ADDR) {
		ut64 offset = addr - RUST_TRACK_MEM_ADDR;
		if (offset < RUST_TRACK_MEM_SIZE && access_size <= RUST_TRACK_MEM_SIZE - offset) {
			return true;
		}
	}

	if (write || !rz_io_is_valid_offset(core->io, addr, RZ_PERM_R)) {
		return false;
	}

	RzBinObject *obj = rz_bin_cur_object(core->bin);
	RzBinSection *section = NULL;
	if (obj) {
		section = rz_bin_get_section_at(obj, addr, true);
	}
	return section && !(section->perm & RZ_PERM_X);
}

static bool op_memory_access_is_safe(RzCore *core, RzAnalysisOp *op) {
	if ((op->type & RZ_ANALYSIS_OP_TYPE_MASK) == RZ_ANALYSIS_OP_TYPE_LEA) {
		return true;
	}
	if (op->dst && analysis_value_is_mem(op->dst) && !value_mem_access_is_safe(core, op, op->dst, true)) {
		return false;
	}

	for (ut64 i = 0; i < RZ_ARRAY_SIZE(op->src); i++) {
		if (op->src[i] && analysis_value_is_mem(op->src[i]) &&
			!value_mem_access_is_safe(core, op, op->src[i], false)) {
			return false;
		}
	}
	return true;
}

static const char *op_dst_reg_name(RzAnalysisOp *op) {
	if (!op->dst || op->dst->type != RZ_ANALYSIS_VAL_REG || !op->dst->reg) {
		return NULL;
	}
	return op->dst->reg->name;
}

static void get_arg_regs(RzCore *core, RzAnalysisFunction *function, RZ_OUT RustArgRegs *args) {
	const char *cc = function->cc ? function->cc : rz_analysis_cc_default(core->analysis);
	for (ut64 i = 0; i < RUST_MAX_CALL_ARGS; i++) {
		const char *reg = rz_analysis_cc_arg(core->analysis, cc, (int)i);
		if (!reg || !is_real_reg_name(core, reg)) {
			break;
		}
		args->regs[args->count++] = reg;
	}
}

static bool seed_contains_rust_vtable(RzCore *core, RustCallSeed *seed) {
	for (ut64 i = 0; i < seed->count; i++) {
		if (seed->has_value[i] && is_rust_vtable(core, seed->values[i])) {
			return true;
		}
	}
	return false;
}

static bool seed_equals(RustCallSeed *a, RustCallSeed *b) {
	if (a->count != b->count) {
		return false;
	}

	for (ut64 i = 0; i < a->count; i++) {
		if (a->has_value[i] != b->has_value[i]) {
			return false;
		}
		if (a->has_value[i] && a->values[i] != b->values[i]) {
			return false;
		}
	}
	return true;
}

static void push_unique_seed(RzCore *core, RzVector /*<RustCallSeed>*/ *seeds, RustCallSeed *seed) {
	if (!seed_contains_rust_vtable(core, seed)) {
		return;
	}

	RustCallSeed *it;
	rz_vector_foreach (seeds, it) {
		if (seed_equals(it, seed)) {
			return;
		}
	}
	rz_vector_push(seeds, seed);
}

static bool is_vtable_slot_disp(RzCore *core, ut64 disp) {
	ut64 psize = ptr_size(core);
	ut64 min = RUST_VTABLE_HEADER_SLOTS * psize;
	ut64 max = (RUST_VTABLE_HEADER_SLOTS + RUST_MAX_TRAIT_METHOD_SLOTS) * psize;
	return disp >= min && disp < max && !(disp % psize);
}

static bool op_type_is_unknown_call_or_jump(ut32 type) {
	ut32 base = type & RZ_ANALYSIS_OP_TYPE_MASK;
	return base == RZ_ANALYSIS_OP_TYPE_UCALL || base == RZ_ANALYSIS_OP_TYPE_UCCALL || base == RZ_ANALYSIS_OP_TYPE_UJMP || base == RZ_ANALYSIS_OP_TYPE_UCJMP;
}

static bool op_type_is_memory_jump(ut32 type) {
	ut32 base = type & RZ_ANALYSIS_OP_TYPE_MASK;
	return (type & RZ_ANALYSIS_OP_TYPE_MEM) && (base == RZ_ANALYSIS_OP_TYPE_JMP || base == RZ_ANALYSIS_OP_TYPE_CJMP);
}

static bool op_is_vtable_slot_dispatch(RzCore *core, RzAnalysisOp *op) {
	return is_real_reg_name(core, op->reg) && is_vtable_slot_disp(core, op->disp) &&
		(op->type & (RZ_ANALYSIS_OP_TYPE_IND | RZ_ANALYSIS_OP_TYPE_MEM)) &&
		(op_type_is_unknown_call_or_jump(op->type) || op_type_is_memory_jump(op->type));
}

static bool op_is_register_target_dispatch(RzCore *core, RzAnalysisOp *op) {
	return is_real_reg_name(core, op->reg) && (op->type & RZ_ANALYSIS_OP_TYPE_REG) &&
		!(op->type & (RZ_ANALYSIS_OP_TYPE_IND | RZ_ANALYSIS_OP_TYPE_MEM)) && op_type_is_unknown_call_or_jump(op->type);
}

static bool op_is_dispatch_candidate(RzCore *core, RzAnalysisOp *op) {
	return op_is_vtable_slot_dispatch(core, op) || op_is_register_target_dispatch(core, op);
}

static void track_init(RzCore *core, RZ_NULLABLE const RustCallSeed *seed) {
	RzReg *reg = rz_analysis_get_reg(core->analysis);
	if (reg) {
		rz_reg_set_value_by_role(reg, RZ_REG_NAME_SP, RUST_STACK_PTR);
		rz_reg_set_value_by_role(reg, RZ_REG_NAME_BP, RUST_STACK_PTR);
		if (seed) {
			for (ut64 i = 0; i < seed->count; i++) {
				if (!seed->has_value[i]) {
					continue;
				}
				RzRegItem *item = rz_reg_get(reg, seed->regs[i], RZ_REG_TYPE_ANY);
				if (item) {
					rz_reg_set_value(reg, item, seed->values[i]);
				}
			}
		}
	}
	rz_core_analysis_esil_init_mem(core, NULL, RUST_TRACK_MEM_ADDR, RUST_TRACK_MEM_SIZE);
	rz_core_analysis_il_reinit(core);
}

static void track_fini(RzCore *core) {
	rz_core_analysis_il_reinit(core);
	rz_core_analysis_esil_init_mem_del(core, NULL, RUST_TRACK_MEM_ADDR, RUST_TRACK_MEM_SIZE);
}

static void add_virtual_xrefs(RzAnalysis *analysis, const char *method_name, ut64 addr) {
	bool found = false;
	HtSP *ht_virtual_xrefs = rz_analysis_get_virtual_xrefs(analysis);
	if (!ht_virtual_xrefs) {
		return;
	}

	RzSetU *set = ht_sp_find(ht_virtual_xrefs, method_name, &found);
	if (!found) {
		set = rz_set_u_new();
		if (!set) {
			return;
		}
		if (!ht_sp_insert(ht_virtual_xrefs, method_name, set)) {
			rz_set_u_free(set);
			return;
		}
	}
	if (!set) {
		return;
	}
	rz_set_u_add(set, addr);
}

static void add_virtual_xrefs_for_method(RzCore *core, const char *method_name, ut64 method_addr, ut64 xref_addr) {
	add_virtual_xrefs(core->analysis, method_name, xref_addr);
	const RzList *flags = rz_flag_get_list(core->flags, method_addr);
	RzListIter *it;
	RzFlagItem *flag;
	rz_list_foreach (flags, it, flag) {
		if (RZ_STR_ISNOTEMPTY(flag->name) && strcmp(flag->name, method_name)) {
			add_virtual_xrefs(core->analysis, flag->name, xref_addr);
		}
	}
}

static bool type_id_data_matches(RzCore *core, ut64 addr, ut64 low, ut64 high, bool has_high) {
	ut8 buf[RUST_TYPE_ID_BYTES] = { 0 };
	if (!addr || addr == UT64_MAX || !rz_io_read_at_mapped(core->io, addr, buf, sizeof(buf))) {
		return false;
	}

	bool big_endian = rz_asm_is_big_endian_set(core->rasm);
	ut64 data_low = rz_read_ble64(buf, big_endian);
	ut64 data_high = rz_read_ble64(buf + 8, big_endian);
	if (has_high) {
		return data_low == low && data_high == high;
	}
	return data_low == low || data_high == low;
}

static bool op_mem_value_has_type_id(RzCore *core, RzAnalysisOp *op, RzAnalysisValue *value, ut64 low, ut64 high, bool has_high) {
	if (!analysis_value_is_mem(value) || value->memref < RUST_TYPE_ID_BYTES) {
		return false;
	}

	ut64 addr = UT64_MAX;
	return analysis_value_addr(core, op, value, &addr) && type_id_data_matches(core, addr, low, high, has_high);
}

static bool op_has_scalar_imm(RzAnalysisOp *op, ut64 value) {
	if (op->val != UT64_MAX && op->val == value) {
		return true;
	}

	for (ut64 i = 0; i < RZ_ARRAY_SIZE(op->analysis_vals); i++) {
		if (op->analysis_vals[i].imm != ST64_MAX && op->analysis_vals[i].imm == value) {
			return true;
		}
	}
	return false;
}

static bool op_has_type_id(RzCore *core, RzAnalysisOp *op, ut64 low, ut64 high, bool has_high) {
	if (op->ptr && op->ptr != UT64_MAX && op->refptr >= RUST_TYPE_ID_BYTES &&
		type_id_data_matches(core, op->ptr, low, high, has_high)) {
		return true;
	}

	for (ut64 i = 0; i < RZ_ARRAY_SIZE(op->src); i++) {
		if (op_mem_value_has_type_id(core, op, op->src[i], low, high, has_high)) {
			return true;
		}
	}
	if (op_mem_value_has_type_id(core, op, op->dst, low, high, has_high)) {
		return true;
	}

	return op_has_scalar_imm(op, low) || (has_high && op_has_scalar_imm(op, high));
}

static bool annotate_any_type_id_compare(RzCore *core, RzAnalysisOp *op, RzVector /*<RustAnyVTable>*/ *any_vtables, RZ_NULLABLE RustAnyVTable *pending_any) {
	ut32 type = op->type & RZ_ANALYSIS_OP_TYPE_MASK;
	if (type != RZ_ANALYSIS_OP_TYPE_CMP && type != RZ_ANALYSIS_OP_TYPE_ACMP) {
		return false;
	}

	RustAnyVTable *matched = pending_any;
	if (!matched && any_vtables) {
		RustAnyVTable *any;
		rz_vector_foreach (any_vtables, any) {
			if (any->has_type_id && op_has_type_id(core, op, any->type_id_low, any->type_id_high, any->has_type_id_high)) {
				matched = any;
				break;
			}
		}
	}
	if (matched) {
		char *comment = rz_str_newf("Any downcast: %s", matched->concrete_type);
		if (comment) {
			rz_core_meta_comment_add(core, comment, op->addr);
			free(comment);
		}
	}
	return true;
}

static RZ_NULLABLE RustAnyVTable *devirtualize_step(RzCore *core, RzAnalysisOp *op, RzVector /*<RustAnyVTable>*/ *any_vtables) {
	ut64 target = UT64_MAX;
	ut64 vtable_addr = UT64_MAX;
	RustAnyVTable *target_any = NULL;
	bool target_is_any_type_id = false;
	bool found = false;
	if (op_is_vtable_slot_dispatch(core, op)) {
		ut64 slot_addr = UT64_MAX;
		vtable_addr = get_reg_value(core->analysis, op->reg);
		if (!vtable_addr || vtable_addr == UT64_MAX) {
			return NULL;
		}

		slot_addr = vtable_addr + op->disp;
		if (slot_addr == UT64_MAX) {
			return NULL;
		}

		if (is_real_reg_name(core, op->ireg)) {
			ut64 index = get_reg_value(core->analysis, op->ireg);
			if (index == UT64_MAX) {
				return NULL;
			}
			ut64 scale = op->scale;
			if (!scale) {
				scale = 1;
			}
			slot_addr += index * scale;
		}
		found = resolve_slot(core, vtable_addr, slot_addr, &target);
	} else if (op_is_register_target_dispatch(core, op)) {
		target = get_reg_value(core->analysis, op->reg);
		if (!target || target == UT64_MAX) {
			return NULL;
		}

		target_any = any_vtable_by_type_id_method(any_vtables, target);
		if (!target_any) {
			ut64 type_id_low = 0;
			ut64 type_id_high = 0;
			bool type_id_has_high = false;
			if (rust_type_id_from_method(core, target, &type_id_low, &type_id_high, &type_id_has_high)) {
				target_any = any_vtable_by_type_id_values(any_vtables, type_id_low, type_id_high, type_id_has_high);
			}
		}
		if (target_any) {
			vtable_addr = target_any->vtable_addr;
			target_is_any_type_id = true;
		}
		found = true;
	} else {
		return NULL;
	}

	if (!found) {
		return NULL;
	}

	char *method_name = get_method_name(core, target);
	if (!method_name) {
		return NULL;
	}

	RustAnyVTable *any = target_any;
	if (!any) {
		any = any_vtable_by_addr(any_vtables, vtable_addr);
	}
	bool is_any_type_id = any && (target_is_any_type_id || target == any->type_id_method);
	char *comment = NULL;
	if (is_any_type_id) {
		comment = rz_str_newf("Any::type_id: %s", any->concrete_type);
	} else {
		comment = rz_str_newf("Virtual call: %s", method_name);
	}

	if (comment) {
		rz_core_meta_comment_add(core, comment, op->addr);
		RZ_FREE(comment);
	}

	add_virtual_xrefs_for_method(core, method_name, target, op->addr);
	if (target_is_any_type_id && any->type_id_method != target) {
		char *class_method_name = get_method_name(core, any->type_id_method);
		if (class_method_name) {
			add_virtual_xrefs_for_method(core, class_method_name, any->type_id_method, op->addr);
			RZ_FREE(class_method_name);
		}
	}
	RZ_FREE(method_name);
	return is_any_type_id ? any : NULL;
}

static bool set_il_reg_unsigned(RzCore *core, const char *reg_name, ut64 value) {
	if (!is_real_reg_name(core, reg_name)) {
		return false;
	}
	RzAnalysisILVM *vm = rz_analysis_get_il_vm(core->analysis);
	RzILVal *current = vm ? rz_il_vm_get_var_value(vm->vm, RZ_IL_VAR_KIND_GLOBAL, reg_name) : NULL;
	RzBitVector *bv = current ? rz_il_value_to_bv(current) : NULL;
	if (!bv) {
		return false;
	}
	rz_bv_free(bv);
	return rz_analysis_il_vm_set_unsigned(core->analysis, reg_name, value);
}

static void clear_dst_reg_for_skipped_op(RzCore *core, RzAnalysisOp *op) {
	set_il_reg_unsigned(core, op_dst_reg_name(op), 0);
}

static void clear_register_dispatch_targets(RzCore *core, ut64 start, ut64 end, const ut8 *bytes) {
	RzAnalysisOp *op = rz_analysis_op_new();
	if (!op) {
		return;
	}
	ut64 offset = 0;
	while (start < end) {
		if (rz_analysis_op(core->analysis, op, start, bytes + offset, end - start, RZ_ANALYSIS_OP_MASK_BASIC) <= 0 || op->size < 1) {
			break;
		}
		if (op_is_register_target_dispatch(core, op)) {
			set_il_reg_unsigned(core, op->reg, 0);
		}
		start += op->size;
		offset += op->size;
		rz_analysis_op_fini(op);
	}
	rz_analysis_op_free(op);
}

static void track_step_or_skip(RzCore *core, RzAnalysisOp *op, ut64 next_addr) {
	if (!op->il_op || !op_memory_access_is_safe(core, op)) {
		clear_dst_reg_for_skipped_op(core, op);
		advance_il_pc(core, next_addr);
		return;
	}

	advance_il_pc(core, op->addr);
	if (!rz_core_il_step(core, 1)) {
		advance_il_pc(core, next_addr);
		return;
	}
}

static bool function_has_rust_dispatch_candidate(RzCore *core, RzAnalysisFunction *function) {
	ut64 start = function->addr;
	ut64 end = rz_analysis_function_max_addr(function);
	if (!addr_is_executable(core, start)) {
		return false;
	}

	ut8 *bytes = read_mapped_range(core, start, end);
	if (!bytes) {
		return false;
	}

	bool found = false;
	ut64 offset = 0;
	RzAnalysisOp *op = rz_analysis_op_new();
	if (!op) {
		RZ_FREE(bytes);
		return false;
	}

	while (start < end) {
		if (rz_analysis_op(core->analysis, op, start, bytes + offset, end - start, RZ_ANALYSIS_OP_MASK_ALL) <= 0 || op->size < 1) {
			break;
		}
		if (op_is_dispatch_candidate(core, op)) {
			found = true;
			rz_analysis_op_fini(op);
			break;
		}
		start += op->size;
		offset += op->size;
		rz_analysis_op_fini(op);
	}

	rz_analysis_op_free(op);
	RZ_FREE(bytes);
	return found;
}

static void devirtualize_rust_function(RzCore *core, RzAnalysisFunction *function, RzVector /*<RustAnyVTable>*/ *any_vtables, RZ_NULLABLE const RustCallSeed *seed) {
	ut64 start = function->addr;
	ut64 end = rz_analysis_function_max_addr(function);
	if (!addr_is_executable(core, start)) {
		return;
	}

	RzAnalysisOp *op = rz_analysis_op_new();
	if (!op) {
		return;
	}

	ut8 *bytes = read_mapped_range(core, start, end);
	if (!bytes) {
		RZ_LOG_ERROR("Cannot read at offset 0x%08" PFMT64x "\n", start);
		rz_analysis_op_free(op);
		return;
	}

	ut64 old_offset = core->offset;
	ut64 offset = 0;
	core->offset = start;
	track_init(core, seed);
	clear_register_dispatch_targets(core, start, end, bytes);
	RustAnyVTable *pending_any = NULL;
	while (start < end) {
		if (rz_analysis_op(core->analysis, op, start, bytes + offset, end - start, RZ_ANALYSIS_OP_MASK_ALL) <= 0 || op->size < 1) {
			break;
		}

		RustAnyVTable *called_any = devirtualize_step(core, op, any_vtables);
		if (called_any) {
			pending_any = called_any;
		}
		if (annotate_any_type_id_compare(core, op, any_vtables, pending_any)) {
			pending_any = NULL;
		}
		ut64 next = start + op->size;
		if (rz_analysis_op_is_eob(op) || rz_analysis_op_is_call(op)) {
			advance_il_pc(core, next);
		} else {
			track_step_or_skip(core, op, next);
		}

		start = next;
		offset += op->size;
		core->offset = start;
		rz_analysis_op_fini(op);
	}

	core->offset = old_offset;
	track_fini(core);
	rz_analysis_op_free(op);
	RZ_FREE(bytes);
}

static void caller_replay_step(RzCore *core, RzAnalysisOp *op, ut64 next_addr, const char *ret_reg, RZ_INOUT ut64 *next_scratch) {
	if (rz_analysis_op_is_call(op)) {
		if (is_real_reg_name(core, ret_reg)) {
			ut64 heap_end = RUST_SCRATCH_HEAP_ADDR + RUST_SCRATCH_HEAP_SIZE;
			if (*next_scratch <= heap_end - RUST_SCRATCH_ALLOC_STEP) {
				set_il_reg_unsigned(core, ret_reg, *next_scratch);
				*next_scratch += RUST_SCRATCH_ALLOC_STEP;
			} else {
				set_il_reg_unsigned(core, ret_reg, 0);
			}
		}
		advance_il_pc(core, next_addr);
		return;
	}

	if (rz_analysis_op_is_eob(op)) {
		advance_il_pc(core, next_addr);
		return;
	}

	track_step_or_skip(core, op, next_addr);
}

static void collect_caller_args_from_site(RzCore *core, RzAnalysisFunction *caller, ut64 call_addr, RustArgRegs *args, RzVector /*<RustCallSeed>*/ *seeds) {
	ut64 start = caller->addr;
	ut64 end = RZ_MIN(call_addr, rz_analysis_function_max_addr(caller));
	if (!addr_is_executable(core, start)) {
		return;
	}

	ut8 *bytes = read_mapped_range(core, start, end);
	if (!bytes) {
		return;
	}

	RzAnalysisOp *op = rz_analysis_op_new();
	if (!op) {
		RZ_FREE(bytes);
		return;
	}

	RustCallSeed seed = {
		.count = args->count,
	};

	for (ut64 i = 0; i < args->count; i++) {
		seed.regs[i] = args->regs[i];
	}

	const char *cc = rz_analysis_cc_default(core->analysis);
	const char *ret_reg = rz_analysis_cc_ret(core->analysis, cc);
	ut64 old_offset = core->offset;
	ut64 next_scratch = RUST_SCRATCH_HEAP_ADDR;
	ut64 offset = 0;
	core->offset = start;
	track_init(core, NULL);
	while (start < end) {
		if (rz_analysis_op(core->analysis, op, start, bytes + offset, end - start, RZ_ANALYSIS_OP_MASK_ALL) <= 0 || op->size < 1) {
			break;
		}

		ut64 next = start + op->size;
		caller_replay_step(core, op, next, ret_reg, &next_scratch);
		start = next;
		offset += op->size;
		core->offset = start;
		rz_analysis_op_fini(op);
	}

	for (ut64 i = 0; i < args->count; i++) {
		ut64 value = get_reg_value(core->analysis, args->regs[i]);
		if (value && value != UT64_MAX) {
			seed.values[i] = value;
			seed.has_value[i] = true;
		}
	}

	push_unique_seed(core, seeds, &seed);
	core->offset = old_offset;
	track_fini(core);
	rz_analysis_op_free(op);
	RZ_FREE(bytes);
}

static RZ_OWN RzVector /*<RustCallSeed>*/ *collect_caller_args(RzCore *core, RzAnalysisFunction *function, RustArgRegs *args) {
	RzVector *seeds = rz_vector_new(sizeof(RustCallSeed), NULL, NULL);
	if (!seeds) {
		return NULL;
	}

	RzList *xrefs = rz_analysis_xrefs_get_to(core->analysis, function->addr);
	if (!xrefs) {
		rz_vector_free(seeds);
		return NULL;
	}

	RzListIter *it;
	RzAnalysisXRef *xref;
	rz_list_foreach (xrefs, it, xref) {
		if (xref->type != RZ_ANALYSIS_XREF_TYPE_CALL && xref->type != RZ_ANALYSIS_XREF_TYPE_CODE) {
			continue;
		}
		RzAnalysisFunction *caller = rz_analysis_get_fcn_in(core->analysis, xref->from, RZ_ANALYSIS_FCN_TYPE_NULL);
		if (!caller) {
			continue;
		}
		collect_caller_args_from_site(core, caller, xref->from, args, seeds);
	}
	rz_list_free(xrefs);

	if (rz_vector_empty(seeds)) {
		rz_vector_free(seeds);
		return NULL;
	}
	return seeds;
}

static void devirtualize_rust_trait_object(RzCore *core) {
	RzAnalysisFunction *function = rz_analysis_get_fcn_in(core->analysis, core->offset, RZ_ANALYSIS_FCN_TYPE_NULL);
	if (!function) {
		RZ_LOG_ERROR("Cannot find function at 0x%08" PFMT64x "\n", core->offset);
		return;
	}

	if (!function_has_rust_dispatch_candidate(core, function)) {
		return;
	}

	RustArgRegs args = { 0 };
	get_arg_regs(core, function, &args);
	RzVector *any_vtables = rust_any_vtables_from_classes(core);
	devirtualize_rust_function(core, function, any_vtables, NULL);

	RzVector *seeds = NULL;
	if (args.count) {
		seeds = collect_caller_args(core, function, &args);
	}
	RustCallSeed *seed;
	if (seeds) {
		rz_vector_foreach (seeds, seed) {
			devirtualize_rust_function(core, function, any_vtables, seed);
		}
	}

	rz_vector_free(seeds);
	rz_vector_free(any_vtables);
}

/**
 * \brief devirtualize Rust trait object calls in the current function
 */
RZ_IPI void rz_core_analysis_devirtualize_rust_methods(RZ_NULLABLE RzCore *core) {
	if (!core) {
		return;
	}
	devirtualize_rust_trait_object(core);
}
