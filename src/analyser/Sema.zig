const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const log = std.log.scoped(.zls_sema);

const Sema = @This();
const Zir = @import("../stage2/Zir.zig");
const Module = @import("Module.zig");
const trace = @import("../tracy.zig").trace;
const Namespace = Module.Namespace;

const LazySrcLoc = @import("../stage2/Module.zig").LazySrcLoc;

// const offsets = @import("../offsets.zig");
const InternPool = @import("InternPool.zig");
const Index = InternPool.Index;
const Decl = InternPool.Decl;
const DeclIndex = InternPool.DeclIndex;
const OptionalDeclIndex = InternPool.OptionalDeclIndex;

mod: *Module,
gpa: Allocator,
arena: Allocator,
code: Zir,
index_map: IndexMap = .{},

pub const IndexMap = struct {
    items: []Index = &[_]Index{},
    start: Zir.Inst.Index = 0,

    pub fn deinit(map: IndexMap, allocator: Allocator) void {
        allocator.free(map.items);
    }

    pub fn get(map: IndexMap, key: Zir.Inst.Index) ?Index {
        if (!map.contains(key)) return null;
        return map.items[key - map.start];
    }

    pub fn putAssumeCapacity(
        map: *IndexMap,
        key: Zir.Inst.Index,
        index: Index,
    ) void {
        map.items[key - map.start] = index;
    }

    pub fn putAssumeCapacityNoClobber(
        map: *IndexMap,
        key: Zir.Inst.Index,
        index: Index,
    ) void {
        assert(!map.contains(key));
        map.putAssumeCapacity(key, index);
    }

    pub const GetOrPutResult = struct {
        value_ptr: *Index,
        found_existing: bool,
    };

    pub fn getOrPutAssumeCapacity(
        map: *IndexMap,
        key: Zir.Inst.Index,
    ) GetOrPutResult {
        const index = key - map.start;
        return GetOrPutResult{
            .value_ptr = &map.items[index],
            .found_existing = map.items[index] != .none,
        };
    }

    pub fn remove(map: IndexMap, key: Zir.Inst.Index) bool {
        if (!map.contains(key)) return false;
        map.items[key - map.start] = .none;
        return true;
    }

    pub fn contains(map: IndexMap, key: Zir.Inst.Index) bool {
        return map.items[key - map.start] != .none;
    }

    pub fn ensureSpaceForInstructions(
        map: *IndexMap,
        allocator: Allocator,
        insts: []const Zir.Inst.Index,
    ) !void {
        const min_max = std.mem.minMax(Zir.Inst.Index, insts);
        const start = min_max.min;
        const end = min_max.max;
        if (map.start <= start and end < map.items.len + map.start)
            return;

        const old_start = if (map.items.len == 0) start else map.start;
        var better_capacity = map.items.len;
        var better_start = old_start;
        while (true) {
            const extra_capacity = better_capacity / 2 + 16;
            better_capacity += extra_capacity;
            better_start -|= @intCast(Zir.Inst.Index, extra_capacity / 2);
            if (better_start <= start and end < better_capacity + better_start)
                break;
        }

        const start_diff = old_start - better_start;
        const new_items = try allocator.alloc(Index, better_capacity);
        @memset(new_items[0..start_diff], .none);
        @memcpy(new_items[start_diff..][0..map.items.len], map.items);
        @memset(new_items[start_diff + map.items.len ..], .none);

        allocator.free(map.items);
        map.items = new_items;
        map.start = @intCast(Zir.Inst.Index, better_start);
    }
};

pub const Block = struct {
    parent: ?*Block,
    namespace: InternPool.NamespaceIndex,
    params: std.ArrayListUnmanaged(Param) = .{},
    label: ?*Label = null,
    src_decl: DeclIndex,
    is_comptime: bool,

    const Param = struct {
        ty: Index,
        is_comptime: bool,
        name: []const u8,
    };

    pub const Label = struct {
        zir_block: Zir.Inst.Index,
        results: std.ArrayListUnmanaged(Index),
    };

    pub fn getHandle(block: *Block, mod: *Module) *Module.Handle {
        return Module.getHandle(mod.declPtr(block.src_decl).*, mod);
    }
};

pub fn deinit(sema: *Sema) void {
    const gpa = sema.gpa;
    sema.index_map.deinit(gpa);
    sema.* = undefined;
}

const always_noreturn: Allocator.Error!Zir.Inst.Index = @as(Zir.Inst.Index, std.math.maxInt(u32));

fn analyzeBodyInner(
    sema: *Sema,
    block: *Block,
    body: []const Zir.Inst.Index,
) Allocator.Error!Zir.Inst.Index {
    const map = &sema.index_map;
    const tags = sema.code.instructions.items(.tag);
    const datas = sema.code.instructions.items(.data);

    try map.ensureSpaceForInstructions(sema.gpa, body);

    const result: Allocator.Error!Zir.Inst.Index = for (body) |inst| {
        const index: Index = switch (tags[inst]) {
            // zig fmt: off
            .alloc                        => .none,
            .alloc_inferred               => .none,
            .alloc_inferred_mut           => .none,
            .alloc_inferred_comptime      => .none,
            .alloc_inferred_comptime_mut  => .none,
            .alloc_mut                    => .none,
            .alloc_comptime_mut           => .none,
            .make_ptr_const               => .none,
            .anyframe_type                => .none,
            .array_cat                    => .none,
            .array_mul                    => .none,
            .array_type                   => try sema.zirArrayType(block, inst),
            .array_type_sentinel          => try sema.zirArrayTypeSentinel(block, inst),
            .vector_type                  => try sema.zirVectorType(block, inst),
            .as                           => try sema.zirAs(block, inst),
            .as_node                      => try sema.zirAsNode(block, inst),
            .as_shift_operand             => .none,
            .bit_and                      => .none,
            .bit_not                      => .none,
            .bit_or                       => .none,
            .bitcast                      => .none,
            .suspend_block                => .none,
            .bool_not                     => .none,
            .bool_br_and                  => .none,
            .bool_br_or                   => .none,
            .c_import                     => .none,
            .call                         => .none,
            .closure_get                  => .none,
            .cmp_lt                       => .none,
            .cmp_lte                      => .none,
            .cmp_eq                       => try sema.zirCmpEq(block, inst, .eq),
            .cmp_gte                      => .none,
            .cmp_gt                       => .none,
            .cmp_neq                      => try sema.zirCmpEq(block, inst, .neq),
            .coerce_result_ptr            => .none,
            .decl_ref                     => .none,
            .decl_val                     => try sema.zirDeclVal(block, inst),
            .load                         => .none,
            .elem_ptr                     => .none,
            .elem_ptr_node                => .none,
            .elem_ptr_imm                 => .none,
            .elem_val                     => .none,
            .elem_val_node                => .none,
            .elem_type_index              => .none,
            .enum_literal                 => .none,
            .enum_to_int                  => .none,
            .int_to_enum                  => .none,
            .err_union_code               => .none,
            .err_union_code_ptr           => .none,
            .err_union_payload_unsafe     => .none,
            .err_union_payload_unsafe_ptr => .none,
            .error_union_type             => .none,
            .error_value                  => .none,
            .field_ptr                    => .none,
            .field_ptr_init               => .none,
            .field_ptr_named              => .none,
            .field_val                    => try sema.zirFieldVal(block, inst),
            .field_val_named              => .none,
            .field_call_bind              => .none,
            .func                         => try sema.zirFunc(block, inst, false),
            .func_inferred                => try sema.zirFunc(block, inst, true),
            .func_fancy                   => .none,
            .import                       => .none,
            .indexable_ptr_len            => .none,
            .int                          => try sema.zirInt(block, inst),
            .int_big                      => .none,
            .float                        => try sema.zirFloat(block, inst),
            .float128                     => try sema.zirFloat128(block, inst),
            .int_type                     => try sema.zirIntType(block, inst),
            .is_non_err                   => .none,
            .is_non_err_ptr               => .none,
            .ret_is_non_err               => .none,
            .is_non_null                  => .none,
            .is_non_null_ptr              => .none,
            .merge_error_sets             => .none,
            .negate                       => .none,
            .negate_wrap                  => .none,
            .optional_payload_safe        => .none,
            .optional_payload_safe_ptr    => .none,
            .optional_payload_unsafe      => .none,
            .optional_payload_unsafe_ptr  => .none,
            .optional_type                => try sema.zirOptionalType(block, inst),
            .ref                          => .none,
            .ptr_type                     => try sema.zirPtrType(block, inst),
            .ret_err_value_code           => .none,
            .shr                          => .none,
            .shr_exact                    => .none,
            .slice_end                    => .none,
            .slice_sentinel               => .none,
            .slice_start                  => .none,
            .str                          => .none,
            .switch_block                 => .none,
            .switch_cond                  => .none,
            .switch_cond_ref              => .none,
            .switch_capture               => .none,
            .switch_capture_ref           => .none,
            .switch_capture_multi         => .none,
            .switch_capture_multi_ref     => .none,
            .switch_capture_tag           => .none,
            .type_info                    => .none,
            .size_of                      => .none,
            .bit_size_of                  => .none,
            .typeof                       => try sema.zirTypeof(block, inst),
            .typeof_builtin               => try sema.zirTypeofBuiltin(block, inst),
            .typeof_log2_int_type         => .none,
            .xor                          => .none,
            .struct_init_empty            => .none,
            .struct_init                  => .none,
            .struct_init_ref              => .none,
            .struct_init_anon             => .none,
            .struct_init_anon_ref         => .none,
            .array_init                   => .none,
            .array_init_ref               => .none,
            .array_init_anon              => .none,
            .array_init_anon_ref          => .none,
            .union_init                   => .none,
            .field_type                   => .none,
            .field_type_ref               => .none,
            .ptr_to_int                   => .none,
            .align_of                     => .none,
            .bool_to_int                  => try sema.zirBoolToInt(block, inst),
            .embed_file                   => .none,
            .error_name                   => .none,
            .tag_name                     => .none,
            .type_name                    => .none,
            .frame_type                   => .none,
            .frame_size                   => .none,
            .float_to_int                 => .none,
            .int_to_float                 => .none,
            .int_to_ptr                   => .none,
            .float_cast                   => .none,
            .int_cast                     => .none,
            .ptr_cast                     => .none,
            .truncate                     => .none,
            .align_cast                   => .none,
            .has_decl                     => .none,
            .has_field                    => .none,
            .byte_swap                    => .none,
            .bit_reverse                  => .none,
            .bit_offset_of                => .none,
            .offset_of                    => .none,
            .splat                        => .none,
            .reduce                       => .none,
            .shuffle                      => .none,
            .atomic_load                  => .none,
            .atomic_rmw                   => .none,
            .mul_add                      => .none,
            .builtin_call                 => .none,
            .field_parent_ptr             => .none,
            .@"resume"                    => .none,
            .@"await"                     => .none,
            .array_base_ptr               => .none,
            .field_base_ptr               => .none,
            .for_len                      => .none,

            .clz       => .none,
            .ctz       => .none,
            .pop_count => .none,

            .sqrt  => .none,
            .sin   => .none,
            .cos   => .none,
            .tan   => .none,
            .exp   => .none,
            .exp2  => .none,
            .log   => .none,
            .log2  => .none,
            .log10 => .none,
            .fabs  => .none,
            .floor => .none,
            .ceil  => .none,
            .round => .none,
            .trunc => .none,

            .error_set_decl      => .none,
            .error_set_decl_anon => .none,
            .error_set_decl_func => .none,

            .add       => .none,
            .addwrap   => .none,
            .add_sat   => .none,
            .add_unsafe=> .none,
            .mul       => .none,
            .mulwrap   => .none,
            .mul_sat   => .none,
            .sub       => .none,
            .subwrap   => .none,
            .sub_sat   => .none,

            .div       => .none,
            .div_exact => .none,
            .div_floor => .none,
            .div_trunc => .none,

            .mod_rem   => .none,
            .mod       => .none,
            .rem       => .none,

            .max => .none,
            .min => .none,

            .shl       => .none,
            .shl_exact => .none,
            .shl_sat   => .none,

            .ret_ptr  => .none,
            .ret_type => .none,

            // Instructions that we know to *always* be noreturn based solely on their tag.
            // These functions match the return type of analyzeBody so that we can
            // tail call them here.
            .compile_error  => break always_noreturn,
            .ret_implicit   => break always_noreturn,
            .ret_node       => break always_noreturn,
            .ret_load       => break always_noreturn,
            .ret_err_value  => break always_noreturn,
            .@"unreachable" => break always_noreturn,
            .panic          => break always_noreturn,
            .trap           => break always_noreturn,
            // zig fmt: on

            .extended => blk: {
                const extended = datas[inst].extended;
                break :blk switch (extended.opcode) {
                    // zig fmt: off
                    .variable              => .none,
                    .struct_decl           => try sema.zirStructDecl(        block, extended, inst),
                    .enum_decl             => .none,
                    .union_decl            => .none,
                    .opaque_decl           => .none,
                    .this                  => .none,
                    .ret_addr              => .none,
                    .builtin_src           => .none,
                    .error_return_trace    => .none,
                    .frame                 => .none,
                    .frame_address         => .none,
                    .alloc                 => .none,
                    .builtin_extern        => .none,
                    .@"asm"                => .none,
                    .asm_expr              => .none,
                    .typeof_peer           => try sema.zirTypeofPeer(        block, extended),
                    .compile_log           => .none,
                    .min_multi             => .none,
                    .max_multi             => .none,
                    .add_with_overflow     => .none,
                    .sub_with_overflow     => .none,
                    .mul_with_overflow     => .none,
                    .shl_with_overflow     => .none,
                    .c_undef               => .none,
                    .c_include             => .none,
                    .c_define              => .none,
                    .wasm_memory_size      => .none,
                    .wasm_memory_grow      => .none,
                    .prefetch              => .none,
                    .field_call_bind_named => .none,
                    .err_set_cast          => .none,
                    .await_nosuspend       => .none,
                    .select                => .none,
                    .error_to_int          => .none,
                    .int_to_error          => .none,
                    .reify                 => .none,
                    .builtin_async_call    => .none,
                    .cmpxchg               => .none,
                    .addrspace_cast        => .none,
                    .c_va_arg              => .none,
                    .c_va_copy             => .none,
                    .c_va_end              => .none,
                    .c_va_start            => .none,
                    .const_cast,           => .none,
                    .volatile_cast,        => .none,
                    .work_item_id          => .none,
                    .work_group_size       => .none,
                    .work_group_id         => .none,
                    .in_comptime           => .none,
                    // zig fmt: on

                    .fence,
                    .set_float_mode,
                    .set_align_stack,
                    .set_cold,
                    .breakpoint,
                    => continue,
                    .errdefer_err_code => unreachable, // never appears in a body
                };
            },

            // Instructions that we know can *never* be noreturn based solely on
            // their tag. We avoid needlessly checking if they are noreturn and
            // continue the loop.
            // We also know that they cannot be referenced later, so we avoid
            // putting them into the map.
            .dbg_stmt => {
                continue;
            },
            .dbg_var_ptr => {
                continue;
            },
            .dbg_var_val => {
                continue;
            },
            .dbg_block_begin => {
                continue;
            },
            .dbg_block_end => {
                continue;
            },
            .ensure_err_union_payload_void => {
                continue;
            },
            .ensure_result_non_error => {
                continue;
            },
            .ensure_result_used => {
                continue;
            },
            .set_eval_branch_quota => {
                continue;
            },
            .atomic_store => {
                continue;
            },
            .store => {
                continue;
            },
            .store_node => {
                continue;
            },
            .store_to_block_ptr => {
                continue;
            },
            .store_to_inferred_ptr => {
                continue;
            },
            .resolve_inferred_alloc => {
                continue;
            },
            .validate_array_init_ty => {
                continue;
            },
            .validate_struct_init_ty => {
                continue;
            },
            .validate_struct_init => {
                continue;
            },
            .validate_array_init => {
                continue;
            },
            .validate_deref => {
                continue;
            },
            .@"export" => {
                continue;
            },
            .export_value => {
                continue;
            },
            .set_runtime_safety => {
                continue;
            },
            .param => {
                try sema.zirParam(block, inst, false);
                continue;
            },
            .param_comptime => {
                try sema.zirParam(block, inst, true);
                continue;
            },
            .param_anytype => {
                continue;
            },
            .param_anytype_comptime => {
                continue;
            },
            .closure_capture => {
                continue;
            },
            .memcpy => {
                continue;
            },
            .memset => {
                continue;
            },
            .check_comptime_control_flow => {
                continue;
            },
            .save_err_ret_index => {
                continue;
            },
            .restore_err_ret_index => {
                continue;
            },

            // Special case instructions to handle comptime control flow.
            .@"break" => {
                if (block.is_comptime) {
                    break inst; // same as break_inline
                } else {
                    break try sema.zirBreak(block, inst);
                }
            },
            .break_inline => {
                if (block.is_comptime) {
                    break inst;
                } else {
                    @panic("TODO");
                    // sema.comptime_break_inst = inst;
                    // return error.ComptimeBreak;
                }
            },
            .repeat => @panic("TODO"),
            .repeat_inline => @panic("TODO"),
            .loop => @panic("TODO"),
            .block, .block_comptime, .block_inline => blk: {
                if (tags[inst] != .block_inline) {
                    if (!block.is_comptime) {
                        break :blk try sema.zirBlock(block, inst, tags[inst] == .block_comptime);
                    }
                }
                const inst_data = datas[inst].pl_node;
                const extra = sema.code.extraData(Zir.Inst.Block, inst_data.payload_index);
                const inline_body = sema.code.extra[extra.end..][0..extra.data.body_len];

                const opt_break_data = try sema.analyzeBodyBreak(block, inline_body);

                const break_data = opt_break_data orelse break always_noreturn;
                if (inst == break_data.block_inst) {
                    break :blk sema.resolveIndex(break_data.operand);
                } else {
                    break break_data.inst;
                }
            },
            .condbr, .condbr_inline => blk: {
                if (tags[inst] != .condbr_inline) {
                    if (!block.is_comptime) break sema.zirCondbr(block, inst);
                }

                const inst_data = datas[inst].pl_node;
                //const cond_src: LazySrcLoc = .{ .node_offset_if_cond = inst_data.src_node };
                const extra = sema.code.extraData(Zir.Inst.CondBr, inst_data.payload_index);
                const then_body = sema.code.extra[extra.end..][0..extra.data.then_body_len];
                const else_body = sema.code.extra[extra.end + then_body.len ..][0..extra.data.else_body_len];

                const cond = sema.resolveIndex(extra.data.condition);
                assert(sema.indexToKey(cond).typeOf() == .bool_type);
                const inline_body = if (cond == .bool_true) then_body else if (cond == .bool_false) else_body else {
                    std.debug.panic("TODO: comptime branch on unknown value", .{});
                    break always_noreturn;
                };

                const break_data = (try sema.analyzeBodyBreak(block, inline_body)) orelse break always_noreturn;
                if (inst == break_data.block_inst) {
                    break :blk sema.resolveIndex(break_data.operand);
                } else {
                    break break_data.inst;
                }
            },
            .@"try" => @panic("TODO"),
            .try_ptr => @panic("TODO"),
            .@"defer" => @panic("TODO"),
            .defer_err_code => @panic("TODO"),
        };

        const index_ty = if (index != .none) sema.indexToKey(index).typeOf() else .none;

        log.debug("ZIR %{d:<3} {s:<14} ({})({})", .{
            inst,
            @tagName(tags[inst]),
            index_ty.fmtDebug(sema.mod.ip),
            index.fmtDebug(sema.mod.ip),
        });
        if (index_ty == .noreturn_type) {
            break always_noreturn;
        }
        if (index != .none) {
            map.putAssumeCapacity(inst, index);
        }
    } else unreachable;
    return result;
}

fn zirParam(
    sema: *Sema,
    block: *Block,
    inst: Zir.Inst.Index,
    comptime_syntax: bool,
) Allocator.Error!void {
    const inst_data = sema.code.instructions.items(.data)[inst].pl_tok;
    // const src = inst_data.src();
    const extra = sema.code.extraData(Zir.Inst.Param, inst_data.payload_index);
    const param_name = sema.code.nullTerminatedString(extra.data.name);
    const body = sema.code.extra[extra.end..][0..extra.data.body_len];

    const param_ty_inst = try sema.resolveBody(block, body);
    const param_ty = try sema.coerce(block, .type_type, param_ty_inst);

    try block.params.append(sema.gpa, .{
        .ty = param_ty,
        .is_comptime = comptime_syntax,
        .name = param_name,
    });
}

fn zirBreak(sema: *Sema, start_block: *Block, inst: Zir.Inst.Index) !Zir.Inst.Index {
    const tracy = trace(@src());
    defer tracy.end();

    const inst_data = sema.code.instructions.items(.data)[inst].@"break";
    const extra = sema.code.extraData(Zir.Inst.Break, inst_data.payload_index).data;
    const operand = sema.resolveIndex(inst_data.operand);
    const zir_block = extra.block_inst;

    var block = start_block;
    while (true) {
        if (block.label) |label| {
            if (label.zir_block == zir_block) {
                try label.results.append(sema.gpa, operand);
                return inst;
            }
        }
        block = block.parent.?;
    }
}

fn zirBlock(sema: *Sema, parent_block: *Block, inst: Zir.Inst.Index, force_comptime: bool) Allocator.Error!Index {
    const pl_node = sema.code.instructions.items(.data)[inst].pl_node;
    // const src: Module.LazySrcLoc = pl_node.src();
    const extra = sema.code.extraData(Zir.Inst.Block, pl_node.payload_index);
    const body = sema.code.extra[extra.end..][0..extra.data.body_len];

    var label: Block.Label = .{
        .zir_block = inst,
        .results = .{},
    };

    // TODO fix src loc
    // const src_loc = src.toSrcLoc(sema.mod.declPtr(parent_block.src_decl));

    // const span = try src_loc.span(sema.gpa);

    var child_block: Block = .{
        .parent = parent_block,
        .namespace = parent_block.namespace,
        // .current_scope = try sema.doc_scope.addScope(parent_block.current_scope, .{ .start = span.start, .end = span.end }, parent_block.src_decl),
        .src_decl = parent_block.src_decl,
        .label = &label,
        .is_comptime = parent_block.is_comptime or force_comptime,
    };
    defer child_block.params.deinit(sema.gpa);

    if (child_block.is_comptime) {
        return try sema.resolveBody(&child_block, body);
    } else {
        _ = try sema.analyzeBodyInner(&child_block, body);
        return try sema.mod.ip.resolvePeerTypes(sema.gpa, label.results.items, builtin.target);
    }
}

fn zirCondbr(sema: *Sema, block: *Block, inst: Zir.Inst.Index) Allocator.Error!Zir.Inst.Index {
    const inst_data = sema.code.instructions.items(.data)[inst].pl_node;
    const extra = sema.code.extraData(Zir.Inst.CondBr, inst_data.payload_index);

    const then_body = sema.code.extra[extra.end..][0..extra.data.then_body_len];
    const else_body = sema.code.extra[extra.end + then_body.len ..][0..extra.data.else_body_len];

    _ = try sema.analyzeBodyInner(block, then_body);
    _ = try sema.analyzeBodyInner(block, else_body);

    return always_noreturn;
}

//
//
//

pub fn resolveIndex(sema: *Sema, zir_ref: Zir.Inst.Ref) Index {
    var i: usize = @enumToInt(zir_ref);

    if (i < Zir.ref_start_index) return @intToEnum(Index, i);
    i -= Zir.ref_start_index;

    return sema.index_map.get(@intCast(u32, i)) orelse .unknown_unknown;
}

pub fn resolveType(sema: *Sema, zir_ref: Zir.Inst.Ref) Index {
    const index = sema.resolveIndex(zir_ref);
    const ty = sema.indexToKey(index);
    if (ty.typeOf() != .type_type) {
        // TODO report error
        return .unknown_type;
    }
    return index;
}

fn resolveInt(
    sema: *Sema,
    block: *Block,
    zir_ref: Zir.Inst.Ref,
    dest_ty: Index,
    reason: []const u8,
) !?u64 {
    const index = sema.resolveIndex(zir_ref);
    return sema.analyzeAsInt(block, index, dest_ty, reason);
}

fn analyzeAsInt(
    sema: *Sema,
    block: *Block,
    src: Index,
    dest_ty: Index,
    reason: []const u8,
) !?u64 {
    _ = reason;
    const coerced = try sema.coerce(block, dest_ty, src);
    return sema.indexToKey(coerced).getUnsignedInt();
}

fn resolveBody(
    sema: *Sema,
    block: *Block,
    body: []const Zir.Inst.Index,
) Allocator.Error!Index {
    const break_data = try sema.analyzeBodyBreak(block, body) orelse return .none;
    return sema.resolveIndex(break_data.operand);
}

const BreakData = struct {
    block_inst: Zir.Inst.Index,
    operand: Zir.Inst.Ref,
    inst: Zir.Inst.Index,
};

pub fn analyzeBodyBreak(
    sema: *Sema,
    block: *Block,
    body: []const Zir.Inst.Index,
) Allocator.Error!?BreakData {
    const break_inst = try sema.analyzeBodyInner(block, body);
    const break_data = sema.code.instructions.items(.data)[break_inst].@"break";
    const extra = sema.code.extraData(Zir.Inst.Break, break_data.payload_index).data;
    return BreakData{
        .block_inst = extra.block_inst,
        .operand = break_data.operand,
        .inst = break_inst,
    };
}

//
//
//

fn zirArrayType(sema: *Sema, block: *Block, inst: Zir.Inst.Index) Allocator.Error!Index {
    const tracy = trace(@src());
    defer tracy.end();

    const inst_data = sema.code.instructions.items(.data)[inst].pl_node;
    const extra = sema.code.extraData(Zir.Inst.Bin, inst_data.payload_index).data;
    const len = (try sema.resolveInt(block, extra.lhs, .usize_type, "array length must be comptime-known")) orelse return .none;
    const elem_type = sema.resolveType(extra.rhs);

    return try sema.get(.{ .array_type = .{
        .len = len,
        .child = elem_type,
        .sentinel = .none,
    } });
}

fn zirArrayTypeSentinel(sema: *Sema, block: *Block, inst: Zir.Inst.Index) Allocator.Error!Index {
    const tracy = trace(@src());
    defer tracy.end();

    const inst_data = sema.code.instructions.items(.data)[inst].pl_node;
    const extra = sema.code.extraData(Zir.Inst.ArrayTypeSentinel, inst_data.payload_index).data;
    const len = (try sema.resolveInt(block, extra.len, .usize_type, "array length must be comptime-known")) orelse return .none;
    const elem_type = sema.resolveType(extra.elem_type);

    const uncasted_sentinel = sema.resolveIndex(extra.sentinel);
    const sentinel = try sema.coerce(block, elem_type, uncasted_sentinel);

    return try sema.get(.{ .array_type = .{
        .len = len,
        .child = elem_type,
        .sentinel = sentinel,
    } });
}

fn zirVectorType(sema: *Sema, block: *Block, inst: Zir.Inst.Index) Allocator.Error!Index {
    const tracy = trace(@src());
    defer tracy.end();

    const inst_data = sema.code.instructions.items(.data)[inst].pl_node;
    const extra = sema.code.extraData(Zir.Inst.Bin, inst_data.payload_index).data;
    const len = (try sema.resolveInt(block, extra.lhs, .u32_type, "vector length must be comptime-known")) orelse return .none;
    const elem_type = sema.resolveType(extra.rhs);

    // TODO error invalid vector element type
    // try sema.checkVectorElemType(block, elem_type_src, elem_type);

    return try sema.get(.{ .vector_type = .{
        .len = @intCast(u32, len),
        .child = elem_type,
    } });
}

fn zirAs(sema: *Sema, block: *Block, inst: Zir.Inst.Index) Allocator.Error!Index {
    const tracy = trace(@src());
    defer tracy.end();

    const bin_inst = sema.code.instructions.items(.data)[inst].bin;
    const dest_ty = sema.resolveType(bin_inst.lhs);
    const operand = sema.resolveIndex(bin_inst.rhs);

    return try sema.coerce(block, dest_ty, operand);
}

fn zirAsNode(sema: *Sema, block: *Block, inst: Zir.Inst.Index) Allocator.Error!Index {
    const tracy = trace(@src());
    defer tracy.end();

    const inst_data = sema.code.instructions.items(.data)[inst].pl_node;
    // const src = inst_data.src();
    const extra = sema.code.extraData(Zir.Inst.As, inst_data.payload_index).data;
    //sema.src = src;
    const dest_ty = sema.resolveType(extra.dest_type);
    const operand = sema.resolveIndex(extra.operand);

    return try sema.coerce(block, dest_ty, operand);
}

/// Only called for equality operators. See also `zirCmp`.
fn zirCmpEq(
    sema: *Sema,
    block: *Block,
    inst: Zir.Inst.Index,
    op: std.math.CompareOperator,
) Allocator.Error!Index {
    const tracy = trace(@src());
    defer tracy.end();
    _ = block;

    const inst_data = sema.code.instructions.items(.data)[inst].pl_node;
    const extra = sema.code.extraData(Zir.Inst.Bin, inst_data.payload_index).data;
    const lhs = sema.resolveIndex(extra.lhs);
    const rhs = sema.resolveIndex(extra.rhs);

    const lhs_key = sema.indexToKey(lhs);
    const rhs_key = sema.indexToKey(rhs);

    const lhs_ty = lhs_key.typeOf();
    const rhs_ty = rhs_key.typeOf();

    const lhs_ty_key = sema.indexToKey(lhs_ty);
    const rhs_ty_key = sema.indexToKey(rhs_ty);

    if (lhs_key == .unknown_value or rhs_key == .unknown_value) {
        return try sema.get(.{ .unknown_value = .{ .ty = .bool_type } });
    }

    if (lhs_ty_key.zigTypeTag() == .Bool and rhs_ty_key.zigTypeTag() == .Bool) {
        assert(lhs == .bool_false or lhs == .bool_true and
            rhs == .bool_false or rhs == .bool_true);
        return if ((lhs == rhs) == (op == .eq)) .bool_true else .bool_false;
    }

    if (lhs_ty == .null_type or rhs_ty == .null_type) {
        if (lhs_ty == .null_type and rhs_ty == .null_type) {
            return if (op == .eq) .bool_true else .bool_false;
        }
        const non_null_type = if (lhs_ty == .null_type) rhs_ty_key else lhs_ty_key;
        if (non_null_type == .optional_type or non_null_type.isCPtr()) {
            const non_null_val = if (lhs_ty == .null_type) rhs_key else lhs_key;
            const is_null = non_null_val.isNull();
            return if (is_null == (op == .eq)) .bool_true else .bool_false;
        }
        // TODO return sema.fail(block, src, "comparison of '{}' with null", .{non_null_type.fmt(sema.mod)});
        return try sema.get(.{ .unknown_value = .{ .ty = .bool_type } });
    }

    if (lhs_ty == .null_type and rhs_ty == .null_type) {
        return if (op == .eq) .bool_true else .bool_false;
    } else if (lhs_ty == .null_type and (rhs_ty_key == .optional_type or rhs_ty_key.isCPtr())) {
        // TODO return sema.analyzeIsNull(block, src, rhs, op == .neq);
    } else if (rhs_ty == .null_type and (lhs_ty_key == .optional_type or lhs_ty_key.isCPtr())) {
        // TODO return sema.analyzeIsNull(block, src, lhs, op == .neq);
    } else if (lhs_ty == .null_type or rhs_ty == .null_type) {
        // const non_null_type = if (lhs_ty == .null_type) rhs_ty else lhs_ty;
        // TODO return sema.fail(block, src, "comparison of '{}' with null", .{non_null_type.fmt(sema.mod)});
        return try sema.get(.{ .unknown_value = .{ .ty = .bool_type } });
    }

    // if (lhs_ty_key == .union_type and (rhs_ty_tag == .EnumLiteral or rhs_ty_key == .enum_type)) {
    //     // TODO return sema.analyzeCmpUnionTag(block, src, lhs, lhs_src, rhs, rhs_src, op);
    //     return try sema.get(.{ .unknown_value = .{ .ty = .bool_type } });
    // } else if (rhs_ty_key == .union_type and (lhs_ty_tag == .EnumLiteral or lhs_ty_key == .enum_type)) {
    //     // TODO return sema.analyzeCmpUnionTag(block, src, rhs, rhs_src, lhs, lhs_src, op);
    //     return try sema.get(.{ .unknown_value = .{ .ty = .bool_type } });
    // }

    if (lhs_ty_key == .error_set_type and rhs_ty_key == .error_set_type) {
        // TODO return block.addBinOp(air_tag, lhs, rhs);
    }

    if (lhs_ty == .type_type and rhs_ty == .type_type) {
        return if ((lhs == rhs) == (op == .eq)) .bool_true else .bool_false;
    }

    // TODO return sema.analyzeCmp(block, src, lhs, rhs, op, lhs_src, rhs_src, true);
    return try sema.get(.{ .unknown_value = .{ .ty = .bool_type } });
}

fn zirDeclVal(sema: *Sema, block: *Block, inst: Zir.Inst.Index) Allocator.Error!Index {
    const inst_data = sema.code.instructions.items(.data)[inst].str_tok;
    const decl_name = inst_data.get(sema.code);
    const decl_index = (try sema.lookupIdentifier(block, decl_name)) orelse return .none;
    try sema.ensureDeclAnalyzed(decl_index);
    const decl = sema.mod.declPtr(decl_index);
    return decl.index;
}

fn lookupIdentifier(sema: *Sema, block: *Block, name: []const u8) !?DeclIndex {
    var namespace_index = block.namespace;

    while (namespace_index != .none) {
        const namespace = sema.mod.namespacePtr(namespace_index);
        if (try sema.lookupInNamespace(block, namespace, name)) |decl_index| {
            return decl_index;
        }
        namespace_index = namespace.parent;
    }
    // TODO lazily analyse symbols in the root scope
    return null;
    // unreachable; // AstGen detects use of undeclared identifier errors.
}

fn lookupInNamespace(
    sema: *Sema,
    block: *Block,
    namespace: *Namespace,
    ident_name: []const u8,
) Allocator.Error!?DeclIndex {
    const mod = sema.mod;
    _ = block;

    if (namespace.decls.getKeyAdapted(ident_name, Module.DeclAdapter{ .mod = mod })) |decl_index| {
        return decl_index;
    }

    return null;
}

fn zirFieldVal(sema: *Sema, block: *Block, inst: Zir.Inst.Index) Allocator.Error!Index {
    const tracy = trace(@src());
    defer tracy.end();

    const inst_data = sema.code.instructions.items(.data)[inst].pl_node;
    // const src = inst_data.src();
    // const field_name_src: LazySrcLoc = .{ .node_offset_field_name = inst_data.src_node };
    const extra = sema.code.extraData(Zir.Inst.Field, inst_data.payload_index).data;
    const field_name = sema.code.nullTerminatedString(extra.field_name_start);
    const object = sema.resolveIndex(extra.lhs);
    return sema.fieldVal(block, object, field_name);
}

fn fieldVal(
    sema: *Sema,
    block: *Block,
    object: Index,
    field_name: []const u8,
) Allocator.Error!Index {
    const val = sema.indexToKey(object);
    std.debug.assert(val.typeOf() != .none);
    const ty = sema.indexToKey(val.typeOf());

    const inner_ty = switch (ty) {
        .pointer_type => |info| if (info.size == .One) sema.indexToKey(info.elem_type) else ty,
        else => ty,
    };

    const can_have_fields: bool = switch (inner_ty) {
        .simple_type => |simple| switch (simple) {
            .type => blk: {
                const namespace_index = val.getNamespace(sema.mod.ip);

                if (try sema.lookupInNamespace(block, sema.mod.namespacePtr(namespace_index), field_name)) |decl_index| {
                    const decl = sema.mod.declPtr(decl_index);
                    return decl.index;
                }

                if (val == .unknown_value) {
                    return .unknown_unknown;
                }

                switch (val) {
                    .error_set_type => |error_set_info| { // TODO
                        _ = error_set_info;
                    },
                    .union_type => {}, // TODO
                    .enum_type => |enum_index| { // TODO
                        const enum_info = sema.mod.ip.getEnum(enum_index);
                        if (enum_info.fields.get(field_name)) |field| {
                            _ = field;
                            return .unknown_unknown; // TODO
                        }
                    },
                    else => break :blk false,
                }
                break :blk true;
            },
            .unknown => return .unknown_unknown,
            else => false,
        },
        .pointer_type => |pointer_info| blk: {
            if (pointer_info.size == .Slice) {
                if (std.mem.eql(u8, field_name, "ptr")) {
                    var many_ptr_info = InternPool.Key{ .pointer_type = pointer_info };
                    many_ptr_info.pointer_type.size = .Many;
                    // TODO resolve ptr of Slice
                    return try sema.get(.{ .unknown_value = .{ .ty = try sema.get(many_ptr_info) } });
                } else if (std.mem.eql(u8, field_name, "len")) {
                    // TODO resolve length of Slice
                    return try sema.get(.{ .unknown_value = .{ .ty = .usize_type } });
                }
            } else if (sema.indexToKey(pointer_info.elem_type) == .array_type) {
                if (std.mem.eql(u8, field_name, "len")) {
                    // TODO resolve length of Slice
                    return try sema.get(.{ .unknown_value = .{ .ty = .usize_type } });
                }
            }
            break :blk true;
        },
        .array_type => |array_info| blk: {
            if (std.mem.eql(u8, field_name, "len")) {
                return try sema.get(.{ .int_u64_value = .{
                    .ty = .usize_type,
                    .int = array_info.len,
                } });
            }
            break :blk true;
        },
        .optional_type => |optional_info| blk: {
            if (!std.mem.eql(u8, field_name, "?")) break :blk false;

            if (object == .type_type) {
                std.debug.panic("tried to unwrap optional of type `{}` which was null", .{
                    optional_info.payload_type.fmt(sema.mod.ip),
                });
            }
            return switch (val) {
                .optional_value => |optional_val| optional_val.val,
                .unknown_value => object,
                else => unreachable, // TODO return error.InvalidOperation
            };
        },
        .struct_type => |struct_index| blk: {
            const struct_info = sema.mod.ip.getStruct(struct_index);
            try sema.semaStructFields(struct_info);
            if (struct_info.fields.getIndex(field_name)) |field_index| {
                const field = struct_info.fields.values()[field_index];

                return switch (val) {
                    .aggregate => |aggregate| aggregate.values[field_index],
                    .unknown_value => try sema.get(.{ .unknown_value = .{ .ty = field.ty } }),
                    else => unreachable, // TODO return error.InvalidOperation
                };
            }
            break :blk true;
        },
        .enum_type => |enum_info| blk: { // TODO
            _ = enum_info;
            break :blk true;
        },
        .union_type => |union_info| blk: { // TODO
            _ = union_info;
            break :blk true;
        },
        .int_type,
        .error_union_type,
        .error_set_type,
        .function_type,
        .tuple_type,
        .vector_type,
        .anyframe_type,
        => false,

        .simple_value,
        .int_u64_value,
        .int_i64_value,
        .int_big_value,
        .float_16_value,
        .float_32_value,
        .float_64_value,
        .float_80_value,
        .float_128_value,
        .float_comptime_value,
        => unreachable,

        .bytes,
        .optional_value,
        .slice,
        .aggregate,
        .union_value,
        .null_value,
        .undefined_value,
        .unknown_value,
        => unreachable,
    };

    const accessed_ty = if (inner_ty == .simple_type and inner_ty.simple_type == .type) val else inner_ty;
    if (can_have_fields) {
        std.debug.panic(
            "`{}` has no member '{s}'",
            .{ accessed_ty.fmt(sema.mod.ip), field_name },
        );
    } else {
        std.debug.panic(
            "`{}` does not support field access",
            .{accessed_ty.fmt(sema.mod.ip)},
        );
    }
}

fn zirFunc(
    sema: *Sema,
    block: *Block,
    inst: Zir.Inst.Index,
    inferred_error_set: bool,
) Allocator.Error!Index {
    _ = inferred_error_set;
    const tracy = trace(@src());
    defer tracy.end();

    const inst_data = sema.code.instructions.items(.data)[inst].pl_node;
    const extra = sema.code.extraData(Zir.Inst.Func, inst_data.payload_index);
    // const target = sema.mod.getTarget();
    // const ret_ty_src: LazySrcLoc = .{ .node_offset_fn_type_ret_ty = inst_data.src_node };

    var extra_index = extra.end;

    const ret_ty: Index = switch (extra.data.ret_body_len) {
        0 => .void_type,
        1 => blk: {
            const ret_ty_ref = @intToEnum(Zir.Inst.Ref, sema.code.extra[extra_index]);
            extra_index += 1;
            break :blk sema.resolveType(ret_ty_ref);
        },
        else => blk: {
            const ret_ty_body = sema.code.extra[extra_index..][0..extra.data.ret_body_len];
            extra_index += ret_ty_body.len;

            // TODO
            break :blk .unknown_unknown;
        },
    };

    var src_locs: Zir.Inst.Func.SrcLocs = undefined;
    const has_body = extra.data.body_len != 0;
    if (has_body) {
        extra_index += extra.data.body_len;
        src_locs = sema.code.extraData(Zir.Inst.Func.SrcLocs, extra_index).data;
    }

    const args = try sema.arena.alloc(Index, block.params.items.len);
    defer sema.arena.free(args);

    for (block.params.items, args) |param, *out_arg| {
        out_arg.* = param.ty;
    }

    return try sema.get(InternPool.Key{
        .function_type = InternPool.Function{
            .args = args,
            .return_type = ret_ty,
        },
    });
}

fn zirInt(sema: *Sema, block: *Block, inst: Zir.Inst.Index) Allocator.Error!Index {
    const tracy = trace(@src());
    defer tracy.end();
    _ = block;

    const int = sema.code.instructions.items(.data)[inst].int;

    return try sema.get(.{ .int_u64_value = .{
        .ty = .comptime_int_type,
        .int = int,
    } });
}

fn zirFloat(sema: *Sema, block: *Block, inst: Zir.Inst.Index) Allocator.Error!Index {
    const tracy = trace(@src());
    defer tracy.end();
    _ = block;

    const number = sema.code.instructions.items(.data)[inst].float;

    return try sema.get(.{ .float_comptime_value = number });
}

fn zirFloat128(sema: *Sema, block: *Block, inst: Zir.Inst.Index) Allocator.Error!Index {
    const tracy = trace(@src());
    defer tracy.end();
    _ = block;

    const inst_data = sema.code.instructions.items(.data)[inst].pl_node;
    const extra = sema.code.extraData(Zir.Inst.Float128, inst_data.payload_index).data;
    const number = extra.get();

    return try sema.get(.{ .float_comptime_value = number });
}

fn zirIntType(sema: *Sema, block: *Block, inst: Zir.Inst.Index) Allocator.Error!Index {
    const tracy = trace(@src());
    defer tracy.end();
    _ = block;

    const int_type = sema.code.instructions.items(.data)[inst].int_type;

    return try sema.get(.{ .int_type = .{
        .signedness = int_type.signedness,
        .bits = int_type.bit_count,
    } });
}

fn zirOptionalType(sema: *Sema, block: *Block, inst: Zir.Inst.Index) Allocator.Error!Index {
    const tracy = trace(@src());
    defer tracy.end();
    _ = block;

    const inst_data = sema.code.instructions.items(.data)[inst].un_node;
    const child_type = sema.resolveType(inst_data.operand);

    return try sema.get(.{
        .optional_type = .{ .payload_type = child_type },
    });
}

fn zirPtrType(sema: *Sema, block: *Block, inst: Zir.Inst.Index) Allocator.Error!Index {
    const tracy = trace(@src());
    defer tracy.end();

    const inst_data = sema.code.instructions.items(.data)[inst].ptr_type;
    const extra = sema.code.extraData(Zir.Inst.PtrType, inst_data.payload_index);

    const elem_ty = sema.resolveType(extra.data.elem_type);

    var extra_i = extra.end;

    const sentinel = if (inst_data.flags.has_sentinel) blk: {
        const ref = @intToEnum(Zir.Inst.Ref, sema.code.extra[extra_i]);
        extra_i += 1;
        break :blk sema.resolveIndex(ref);
    } else .none;

    const abi_align: u16 = if (inst_data.flags.has_align) blk: {
        const ref = @intToEnum(Zir.Inst.Ref, sema.code.extra[extra_i]);
        extra_i += 1;
        const abi_align = (try sema.resolveInt(block, ref, .u16_type, "pointer alignment must be comptime-known")) orelse 0;
        break :blk @intCast(u16, abi_align);
    } else 0;

    const address_space: std.builtin.AddressSpace = if (inst_data.flags.has_addrspace) blk: {
        const ref = @intToEnum(Zir.Inst.Ref, sema.code.extra[extra_i]);
        _ = ref;
        extra_i += 1;
        // TODO
        break :blk .generic;
    } else .generic;

    const bit_offset: u16 = if (inst_data.flags.has_bit_range) blk: {
        const ref = @intToEnum(Zir.Inst.Ref, sema.code.extra[extra_i]);
        extra_i += 1;
        const bit_offset = (try sema.resolveInt(block, ref, .u16_type, "pointer bit-offset must be comptime-known")) orelse 0;
        break :blk @intCast(u16, bit_offset);
    } else 0;

    const host_size: u16 = if (inst_data.flags.has_bit_range) blk: {
        const ref = @intToEnum(Zir.Inst.Ref, sema.code.extra[extra_i]);
        extra_i += 1;
        const host_size = (try sema.resolveInt(block, ref, .u16_type, "pointer host size must be comptime-known")) orelse 0;
        break :blk @intCast(u16, host_size);
    } else 0;

    return try sema.get(.{ .pointer_type = .{
        .elem_type = elem_ty,
        .sentinel = sentinel,
        .size = inst_data.size,
        .alignment = abi_align,
        .bit_offset = bit_offset,
        .host_size = host_size,
        .is_const = !inst_data.flags.is_mutable,
        .is_volatile = inst_data.flags.is_volatile,
        .is_allowzero = inst_data.flags.is_allowzero,
        .address_space = address_space,
    } });
}

fn zirTypeof(sema: *Sema, block: *Block, inst: Zir.Inst.Index) Allocator.Error!Index {
    const tracy = trace(@src());
    defer tracy.end();

    _ = block;
    const zir_datas = sema.code.instructions.items(.data);
    const inst_data = zir_datas[inst].un_node;
    const operand = sema.resolveIndex(inst_data.operand);
    return sema.indexToKey(operand).typeOf();
}

fn zirTypeofBuiltin(sema: *Sema, block: *Block, inst: Zir.Inst.Index) Allocator.Error!Index {
    const tracy = trace(@src());
    defer tracy.end();

    const pl_node = sema.code.instructions.items(.data)[inst].pl_node;
    const extra = sema.code.extraData(Zir.Inst.Block, pl_node.payload_index);
    const body = sema.code.extra[extra.end..][0..extra.data.body_len];

    const operand = try sema.resolveBody(block, body);
    if (operand == .none) return .none;
    return sema.indexToKey(operand).typeOf();
}

fn zirTypeofPeer(
    sema: *Sema,
    block: *Block,
    extended: Zir.Inst.Extended.InstData,
) Allocator.Error!Index {
    const tracy = trace(@src());
    defer tracy.end();

    const extra = sema.code.extraData(Zir.Inst.TypeOfPeer, extended.operand);
    const body = sema.code.extra[extra.data.body_index..][0..extra.data.body_len];

    _ = try sema.analyzeBodyBreak(block, body);

    const args = sema.code.refSlice(extra.end, extended.small);

    const types = try sema.gpa.alloc(Index, args.len);
    defer sema.gpa.free(types);

    for (args, types) |arg_ref, *ty| {
        const arg = sema.resolveIndex(arg_ref);
        ty.* = sema.indexToKey(arg).typeOf();
    }

    return sema.mod.ip.resolvePeerTypes(sema.gpa, types, builtin.target);
}

fn zirBoolToInt(sema: *Sema, block: *Block, inst: Zir.Inst.Index) Allocator.Error!Index {
    const tracy = trace(@src());
    defer tracy.end();
    _ = block;

    const inst_data = sema.code.instructions.items(.data)[inst].un_node;
    const operand = sema.resolveIndex(inst_data.operand);

    const operand_key = sema.indexToKey(operand);

    assert(operand_key.typeOf() == .bool_type);

    if (operand_key == .unknown_value) {
        return try sema.get(.{ .unknown_value = .{ .ty = .u1_type } });
    }

    return switch (operand) {
        .bool_false => .zero,
        .bool_true => .one,
        else => unreachable,
    };
}

fn zirStructDecl(
    sema: *Sema,
    block: *Block,
    extended: Zir.Inst.Extended.InstData,
    inst: Zir.Inst.Index,
) Allocator.Error!Index {
    const small = @bitCast(Zir.Inst.StructDecl.Small, extended.small);
    // const src: LazySrcLoc = if (small.has_src_node) blk: {
    //     const node_offset = @bitCast(i32, sema.code.extra[extended.operand]);
    //     break :blk LazySrcLoc.nodeOffset(node_offset);
    // } else sema.src;

    const mod = sema.mod;
    const struct_index = try mod.ip.createStruct(mod.gpa, .{
        .fields = .{},
        .owner_decl = undefined, // set below
        .zir_index = inst,
        .namespace = undefined, // set below
        .layout = small.layout,
        .backing_int_ty = .none,
        .status = .none,
    });
    const struct_ty = try mod.get(.{ .struct_type = struct_index });

    const namespace_index = try mod.createNamespace(.{
        .parent = block.namespace,
        .handle = block.getHandle(mod),
        .ty = struct_ty,
    });

    const decl_index = try mod.allocateNewDecl(namespace_index, 0);
    const decl = mod.declPtr(decl_index);

    const struct_obj = mod.ip.getStruct(struct_index);
    struct_obj.owner_decl = decl_index.toOptional();
    struct_obj.namespace = namespace_index;
    // struct_obj.is_tuple = small.is_tuple;

    const ns = mod.namespacePtr(block.namespace);
    try ns.anon_decls.putNoClobber(mod.gpa, decl_index, {});

    decl.name = try sema.resolveAnonymousDeclTypeName(block, decl_index, small.name_strategy, "struct", inst);
    decl.index = struct_ty;
    decl.alignment = 0;
    decl.analysis = .complete;

    try sema.analyzeStructDecl(decl, inst, struct_obj);

    return struct_ty;
}

fn resolveAnonymousDeclTypeName(
    sema: *Sema,
    block: *Block,
    new_decl_index: DeclIndex,
    name_strategy: Zir.Inst.NameStrategy,
    anon_prefix: []const u8,
    inst: ?Zir.Inst.Index,
) Allocator.Error![]u8 {
    const mod = sema.mod;
    const src_decl = mod.declPtr(block.src_decl);

    switch (name_strategy) {
        .anon => {
            // It would be neat to have "struct:line:column" but this name has
            // to survive incremental updates, where it may have been shifted down
            // or up to a different line, but unchanged, and thus not unnecessarily
            // semantically analyzed.
            // This name is also used as the key in the parent namespace so it cannot be
            // renamed.
            return try std.fmt.allocPrint(sema.gpa, "{s}__{s}_{d}", .{
                src_decl.name, anon_prefix, @enumToInt(new_decl_index),
            });
        },
        .parent => return try sema.gpa.dupe(u8, std.mem.sliceTo(mod.declPtr(block.src_decl).name, 0)),
        .func => {
            return sema.resolveAnonymousDeclTypeName(block, new_decl_index, .anon, anon_prefix, null);
            // TODO
            // const fn_info = sema.code.getFnInfo(sema.func.?.zir_body_inst);
            // const zir_tags = sema.code.instructions.items(.tag);

            // var buf = std.ArrayList(u8).init(sema.gpa);
            // defer buf.deinit();
            // try buf.appendSlice(std.mem.sliceTo(mod.declPtr(block.src_decl).name, 0));
            // try buf.appendSlice("(");

            // var arg_i: usize = 0;
            // for (fn_info.param_body) |zir_inst| {
            //     switch (zir_tags[zir_inst]) {
            //         .param, .param_comptime, .param_anytype, .param_anytype_comptime => {
            //             const arg = sema.inst_map.get(zir_inst).?;
            //             if (arg_i != 0) try buf.appendSlice(",");

            //             try buf.writer().print("{}", .{arg.fmt(mod)});

            //             arg_i += 1;
            //             continue;
            //         },
            //         else => continue,
            //     }
            // }

            // try buf.appendSlice(")");
            // return try buf.toOwnedSlice();
        },
        .dbg_var => {
            const ref = Zir.indexToRef(inst.?);
            const zir_tags = sema.code.instructions.items(.tag);
            const zir_data = sema.code.instructions.items(.data);
            var i = inst.?;
            while (i < zir_tags.len) : (i += 1) switch (zir_tags[i]) {
                .dbg_var_ptr, .dbg_var_val => {
                    if (zir_data[i].str_op.operand != ref) continue;

                    return try std.fmt.allocPrint(sema.gpa, "{s}.{s}", .{
                        src_decl.name, zir_data[i].str_op.getStr(sema.code),
                    });
                },
                else => {},
            };
            return sema.resolveAnonymousDeclTypeName(block, new_decl_index, .anon, anon_prefix, null);
        },
    }
}

//
//
//

fn coerce(
    sema: *Sema,
    block: *Block,
    dest_ty: Index,
    inst: Index,
) Allocator.Error!Index {
    _ = block;
    return try sema.mod.ip.coerce(sema.gpa, sema.arena, dest_ty, inst, builtin.target);
}

//
//
//

fn ensureDeclAnalyzed(sema: *Sema, decl_index: DeclIndex) Allocator.Error!void {
    const decl = sema.mod.declPtr(decl_index);
    switch (decl.analysis) {
        .unreferenced => {
            try sema.mod.semaDecl(decl_index);
        },
        .in_progress => @panic("TODO: report error"),
        .complete => return,
    }
}

pub fn analyzeStructDecl(
    sema: *Sema,
    new_decl: *Decl,
    inst: Zir.Inst.Index,
    struct_obj: *InternPool.Struct,
) !void {
    const extended: Zir.Inst.Extended.InstData = sema.code.instructions.items(.data)[inst].extended;
    assert(extended.opcode == .struct_decl);
    const small = @bitCast(Zir.Inst.StructDecl.Small, extended.small);

    // struct_obj.known_non_opv = small.known_non_opv;

    var extra_index: usize = extended.operand;
    extra_index += @boolToInt(small.has_src_node);
    extra_index += @boolToInt(small.has_fields_len);
    const decls_len = if (small.has_decls_len) blk: {
        const decls_len = sema.code.extra[extra_index];
        extra_index += 1;
        break :blk decls_len;
    } else 0;

    if (small.has_backing_int) {
        const backing_int_body_len = sema.code.extra[extra_index];
        extra_index += 1; // backing_int_body_len
        if (backing_int_body_len == 0) {
            extra_index += 1; // backing_int_ref
        } else {
            extra_index += backing_int_body_len; // backing_int_body_inst
        }
    }

    const namespace = sema.mod.namespacePtr(struct_obj.namespace);
    _ = try sema.scanNamespace(namespace, struct_obj.namespace, extra_index, decls_len, new_decl);
}

pub fn semaStructFields(sema: *Sema, struct_obj: *InternPool.Struct) !void {
    const decl_index = struct_obj.owner_decl.unwrap().?;
    const namespace = sema.mod.namespacePtr(struct_obj.namespace);
    const zir: Zir = namespace.handle.zir;
    const extended = zir.instructions.items(.data)[struct_obj.zir_index].extended;
    assert(extended.opcode == .struct_decl);
    const small = @bitCast(Zir.Inst.StructDecl.Small, extended.small);
    var extra_index: usize = extended.operand;

    extra_index += @boolToInt(small.has_src_node);

    const fields_len = if (small.has_fields_len) blk: {
        const fields_len = zir.extra[extra_index];
        extra_index += 1;
        break :blk fields_len;
    } else 0;

    const decls_len = if (small.has_decls_len) decls_len: {
        const decls_len = zir.extra[extra_index];
        extra_index += 1;
        break :decls_len decls_len;
    } else 0;

    // The backing integer cannot be handled until `resolveStructLayout()`.
    if (small.has_backing_int) {
        const backing_int_body_len = zir.extra[extra_index];
        extra_index += 1; // backing_int_body_len
        if (backing_int_body_len == 0) {
            extra_index += 1; // backing_int_ref
        } else {
            extra_index += backing_int_body_len; // backing_int_body_inst
        }
    }

    // Skip over decls.
    var decls_it = zir.declIteratorInner(extra_index, decls_len);
    while (decls_it.next()) |_| {}
    extra_index = decls_it.extra_index;

    if (fields_len == 0) return;

    var block_scope: Block = .{
        .parent = null,
        .namespace = struct_obj.namespace,
        .src_decl = decl_index,
        .is_comptime = true,
    };
    defer block_scope.params.deinit(sema.gpa);

    try struct_obj.fields.ensureTotalCapacity(sema.gpa, fields_len);

    const Field = struct {
        type_body_len: u32 = 0,
        align_body_len: u32 = 0,
        init_body_len: u32 = 0,
        type_ref: Zir.Inst.Ref = .none,
    };
    const fields = try sema.arena.alloc(Field, fields_len);
    var any_inits = false;

    {
        const bits_per_field = 4;
        const fields_per_u32 = 32 / bits_per_field;
        const bit_bags_count = std.math.divCeil(usize, fields_len, fields_per_u32) catch unreachable;
        const flags_index = extra_index;
        var bit_bag_index: usize = flags_index;
        extra_index += bit_bags_count;
        var cur_bit_bag: u32 = undefined;
        var field_i: u32 = 0;
        while (field_i < fields_len) : (field_i += 1) {
            if (field_i % fields_per_u32 == 0) {
                cur_bit_bag = zir.extra[bit_bag_index];
                bit_bag_index += 1;
            }
            const has_align = @truncate(u1, cur_bit_bag) != 0;
            cur_bit_bag >>= 1;
            const has_init = @truncate(u1, cur_bit_bag) != 0;
            cur_bit_bag >>= 1;
            const is_comptime = @truncate(u1, cur_bit_bag) != 0;
            cur_bit_bag >>= 1;
            const has_type_body = @truncate(u1, cur_bit_bag) != 0;
            cur_bit_bag >>= 1;

            const field_name_zir = zir.nullTerminatedString(zir.extra[extra_index]);
            extra_index += 1;
            extra_index += 1; // doc_comment

            fields[field_i] = .{};

            if (has_type_body) {
                fields[field_i].type_body_len = zir.extra[extra_index];
            } else {
                fields[field_i].type_ref = @intToEnum(Zir.Inst.Ref, zir.extra[extra_index]);
            }
            extra_index += 1;

            const field_name = try sema.arena.dupe(u8, field_name_zir);

            const gop = struct_obj.fields.getOrPutAssumeCapacity(field_name);
            if (gop.found_existing) continue;

            gop.value_ptr.* = .{
                .ty = .noreturn_type,
                // .abi_align = 0,
                .default_value = .none,
                .is_comptime = is_comptime,
            };

            if (has_align) {
                fields[field_i].align_body_len = zir.extra[extra_index];
                extra_index += 1;
            }
            if (has_init) {
                fields[field_i].init_body_len = zir.extra[extra_index];
                extra_index += 1;
                any_inits = true;
            }
        }
    }

    for (fields, struct_obj.fields.values()) |zir_field, *field| {
        field.ty = ty: {
            if (zir_field.type_ref != .none) {
                break :ty resolveType(sema, zir_field.type_ref);
            }
            assert(zir_field.type_body_len != 0);
            const body = zir.extra[extra_index..][0..zir_field.type_body_len];
            extra_index += body.len;
            break :ty try resolveBody(sema, &block_scope, body);
        };
        extra_index += zir_field.init_body_len;
    }
    struct_obj.status = .have_field_types;
}

pub fn scanNamespace(
    sema: *Sema,
    namespace: *Namespace,
    namespace_index: InternPool.NamespaceIndex,
    extra_start: usize,
    decls_len: u32,
    parent_decl: *Decl,
) Allocator.Error!usize {
    const zir = namespace.handle.zir;

    try namespace.decls.ensureTotalCapacity(sema.gpa, decls_len);

    const bit_bags_count = std.math.divCeil(usize, decls_len, 8) catch unreachable;
    var extra_index = extra_start + bit_bags_count;
    var bit_bag_index: usize = extra_start;
    var cur_bit_bag: u32 = undefined;
    var decl_i: u32 = 0;
    var scan_decl_iter: ScanDeclIter = .{
        .module = sema.mod,
        .namespace = namespace,
        .namespace_index = namespace_index,
        .parent_decl = parent_decl,
    };
    while (decl_i < decls_len) : (decl_i += 1) {
        if (decl_i % 8 == 0) {
            cur_bit_bag = zir.extra[bit_bag_index];
            bit_bag_index += 1;
        }
        const flags = @truncate(u4, cur_bit_bag);
        cur_bit_bag >>= 4;

        const decl_sub_index = extra_index;
        extra_index += 8; // src_hash(4) + line(1) + name(1) + value(1) + doc_comment(1)
        extra_index += @truncate(u1, flags >> 2); // Align
        extra_index += @as(u2, @truncate(u1, flags >> 3)) * 2; // Link section or address space, consists of 2 Refs

        try sema.scanDecl(&scan_decl_iter, decl_sub_index, flags);
    }
    return extra_index;
}

const ScanDeclIter = struct {
    module: *Module,
    namespace: *Namespace,
    namespace_index: InternPool.NamespaceIndex,
    parent_decl: *Decl,
    usingnamespace_index: usize = 0,
    comptime_index: usize = 0,
    unnamed_test_index: usize = 0,
};

fn scanDecl(sema: *Sema, iter: *ScanDeclIter, decl_sub_index: usize, flags: u4) Allocator.Error!void {
    const mod = iter.module;
    const namespace = iter.namespace;
    const namespace_index = iter.namespace_index;
    const gpa = mod.gpa;
    const zir = namespace.handle.zir;

    // zig fmt: off
    const is_pub                       = (flags & 0b0001) != 0;
    const export_bit                   = (flags & 0b0010) != 0;
    const has_align                    = (flags & 0b0100) != 0;
    const has_linksection_or_addrspace = (flags & 0b1000) != 0;
    // zig fmt: on
    _ = has_align;
    _ = has_linksection_or_addrspace;

    // const line_off = zir.extra[decl_sub_index + 4];
    // const line = iter.parent_decl.relativeToLine(line_off);
    const decl_name_index = zir.extra[decl_sub_index + 5];
    const decl_doccomment_index = zir.extra[decl_sub_index + 7];
    const decl_zir_index = zir.extra[decl_sub_index + 6];
    const decl_block_inst_data = zir.instructions.items(.data)[decl_zir_index].pl_node;
    const decl_node = Module.relativeToNodeIndex(iter.parent_decl.*, decl_block_inst_data.src_node);

    // Every Decl needs a name.
    var kind: Decl.Kind = .named;
    const decl_name: []const u8 = switch (decl_name_index) {
        0 => name: {
            if (export_bit) {
                const i = iter.usingnamespace_index;
                iter.usingnamespace_index += 1;
                kind = .@"usingnamespace";
                break :name try std.fmt.allocPrint(gpa, "usingnamespace_{d}", .{i});
            } else {
                const i = iter.comptime_index;
                iter.comptime_index += 1;
                kind = .@"comptime";
                break :name try std.fmt.allocPrint(gpa, "comptime_{d}", .{i});
            }
        },
        1 => name: {
            const i = iter.unnamed_test_index;
            iter.unnamed_test_index += 1;
            kind = .@"test";
            break :name try std.fmt.allocPrint(gpa, "test_{d}", .{i});
        },
        2 => name: {
            const test_name = zir.nullTerminatedString(decl_doccomment_index);
            kind = .@"test";
            break :name try std.fmt.allocPrint(gpa, "decltest.{s}", .{test_name});
        },
        else => name: {
            const raw_name = zir.nullTerminatedString(decl_name_index);
            if (raw_name.len == 0) {
                const test_name = zir.nullTerminatedString(decl_name_index + 1);
                kind = .@"test";
                break :name try std.fmt.allocPrint(gpa, "test.{s}", .{test_name});
            } else {
                break :name try gpa.dupe(u8, raw_name);
            }
        },
    };
    const is_exported = export_bit and decl_name_index != 0;
    if (kind == .@"usingnamespace") try namespace.usingnamespace_set.ensureUnusedCapacity(gpa, 1);

    // We create a Decl for it regardless of analysis status.
    const gop = try namespace.decls.getOrPutContextAdapted(
        gpa,
        decl_name,
        Module.DeclAdapter{ .mod = mod },
        Namespace.DeclContext{ .module = mod },
    );

    if (!gop.found_existing) {
        const new_decl_index = try mod.allocateNewDecl(namespace_index, decl_node);
        const new_decl = mod.declPtr(new_decl_index);
        new_decl.name = decl_name;
        if (kind == .@"usingnamespace") {
            namespace.usingnamespace_set.putAssumeCapacity(new_decl_index, is_pub);
        }
        gop.key_ptr.* = new_decl_index;

        new_decl.is_pub = is_pub;
        new_decl.is_exported = is_exported;
        // new_decl.has_align = has_align;
        // new_decl.has_linksection_or_addrspace = has_linksection_or_addrspace;
        new_decl.zir_decl_index = @intCast(u32, decl_sub_index);

        try sema.ensureDeclAnalyzed(new_decl_index);
    } else {
        gpa.free(decl_name);
    }

    const decl_index = gop.key_ptr.*;
    const decl = mod.declPtr(decl_index);

    decl.node_idx = decl_node;
    // decl.src_line = line;

    decl.is_pub = is_pub;
    decl.is_exported = is_exported;
    decl.kind = kind;
    // decl.has_align = has_align;
    // decl.has_linksection_or_addrspace = has_linksection_or_addrspace;
    decl.zir_decl_index = @intCast(u32, decl_sub_index);
}

//
//
//

fn get(sema: *Sema, key: InternPool.Key) Allocator.Error!Index {
    return sema.mod.ip.get(sema.mod.gpa, key);
}

fn indexToKey(sema: *Sema, index: Index) InternPool.Key {
    return sema.mod.ip.indexToKey(index);
}