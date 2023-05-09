const std = @import("std");
const zls = @import("zls");
const builtin = @import("builtin");

const helper = @import("helper.zig");
const ErrorBuilder = @import("ErrorBuilder.zig");

const Module = zls.analyser.Module;
const Sema = zls.analyser.Sema;
const InternPool = zls.analyser.InternPool;
const Index = InternPool.Index;
const Key = InternPool.Key;
const offsets = zls.offsets;

const allocator: std.mem.Allocator = std.testing.allocator;

// TODO run semantic analysis on the zls codebase to detect potential crashes
test "semantic analysis" {
    const current_file_dir = comptime std.fs.path.dirname(@src().file).?;
    const sema_dir = try std.fs.path.join(allocator, &.{ current_file_dir, "sema" });
    defer allocator.free(sema_dir);

    var dir = try std.fs.cwd().openIterableDir(sema_dir, .{});
    defer dir.close();

    var dir_it = dir.iterateAssumeFirstIteration();
    while (try dir_it.next()) |entry| {
        if (entry.kind != .File) continue;

        const file = try dir.dir.openFile(entry.name, .{});
        defer file.close();
        var file_content = try file.readToEndAlloc(allocator, std.math.maxInt(u32));
        defer allocator.free(file_content);

        try testSemanticAnalysis(file_content);
    }
}

fn testSemanticAnalysis(source: []const u8) !void {
    var document_store = zls.DocumentStore{
        .allocator = allocator,
        .config = &zls.Config{
            .analysis_backend = .astgen_analyser,
            .enable_ast_check_diagnostics = true,
            .prefer_ast_check_as_child_process = false,
        },
        .runtime_zig_version = &@as(?zls.ZigVersionWrapper, null),
    };
    defer document_store.deinit();
    std.debug.assert(document_store.wantZir());

    const test_uri: []const u8 = switch (builtin.os.tag) {
        .windows => "file:///C:\\test.zig",
        else => "file:///test.zig",
    };

    // add the given source file to the document store
    _ = try document_store.openDocument(test_uri, try allocator.dupeZ(u8, source));
    const handle = document_store.handles.get(test_uri).?;
    std.debug.assert(handle.zir_status == .done);
    std.debug.assert(!handle.zir.hasCompileErrors());

    // create a Module that stores data which is used across multiple files
    // like type, values and declarations
    var mod = try Module.init(allocator, &document_store);
    defer mod.deinit();

    // add the given file to the module
    // this will also analyse all declarations in the root scope
    try mod.semaFile(handle);
    std.debug.assert(handle.root_decl != .none);

    const decl_index: InternPool.DeclIndex = handle.root_decl.unwrap().?;
    const decl: *InternPool.Decl = mod.declPtr(decl_index);
    defer mod.destroyDecl(decl_index);

    const struct_index: InternPool.StructIndex = mod.ip.indexToKey(decl.index).struct_type;
    const struct_obj: *InternPool.Struct = mod.ip.getStruct(struct_index);
    const namespace: *Module.Namespace = mod.namespacePtr(struct_obj.namespace);

    // this will print all top-level declarations and their value
    for (namespace.decls.keys()) |namespace_decl_index| {
        const namespace_decl = mod.declPtr(namespace_decl_index);
        _ = namespace_decl;
        // std.debug.print("{s:<18} {}\n", .{ namespace_decl.name, namespace_decl.index.fmtDebug(mod.ip) });
    }

    var arena = std.heap.ArenaAllocator.init(mod.gpa);
    defer arena.deinit();

    // `Sema` stores temporary information that is required during semantic analysis
    var sema = Sema{
        .mod = &mod,
        .gpa = allocator,
        .arena = arena.allocator(),
        .code = handle.zir,
    };
    defer sema.deinit();

    // this will resolve the types of all top-level container fields
    // try sema.semaStructFields(struct_obj);

    var error_builder = ErrorBuilder.init(allocator);
    defer error_builder.deinit();
    errdefer error_builder.writeDebug();

    try error_builder.addFile(test_uri, source);

    const annotations = try helper.collectAnnotatedSourceLocations(allocator, source);
    defer allocator.free(annotations);

    for (annotations) |annotation| {
        const identifier_loc = annotation.loc;
        const identifier = offsets.locToSlice(source, identifier_loc);
        const test_item = try parseAnnotatedSourceLoc(annotation);

        var adapter = Module.DeclAdapter{ .mod = &mod };
        const found_decl_index: InternPool.DeclIndex = namespace.decls.getKeyAdapted(identifier, adapter) orelse {
            try error_builder.msgAtLoc("couldn't find identifier `{s}` here", test_uri, identifier_loc, .err, .{identifier});
            return error.IdentifierNotFound;
        };
        const found_decl: *InternPool.Decl = mod.declPtr(found_decl_index);

        if (test_item.expected_type) |expected_type| {
            const val: InternPool.Key = mod.ip.indexToKey(found_decl.index);
            const ty: InternPool.Index = val.typeOf();
            const actual_type = try std.fmt.allocPrint(allocator, "{}", .{ty.fmtDebug(mod.ip)});
            defer allocator.free(actual_type);
            if (!std.mem.eql(u8, expected_type, actual_type)) {
                try error_builder.msgAtLoc("expected type `{s}` but got `{s}`", test_uri, identifier_loc, .err, .{
                    expected_type,
                    actual_type,
                });
                return error.WrongType;
            }
        }

        if (test_item.expected_value) |expected_value| {
            const val: InternPool.Index = found_decl.index;
            const actual_value = try std.fmt.allocPrint(allocator, "{}", .{val.fmtDebug(mod.ip)});
            defer allocator.free(actual_value);
            if (!std.mem.eql(u8, expected_value, actual_value)) {
                try error_builder.msgAtLoc("expected value `{s}` but got `{s}`", test_uri, identifier_loc, .err, .{
                    expected_value,
                    actual_value,
                });
                return error.WrongValue;
            }
        }
    }
}

const TestItem = struct {
    loc: offsets.Loc,
    expected_type: ?[]const u8,
    expected_value: ?[]const u8,
};

fn parseAnnotatedSourceLoc(annotation: helper.AnnotatedSourceLoc) !TestItem {
    const str = annotation.content;

    if (!std.mem.startsWith(u8, str, "(")) return error.InvalidTestItem;
    const expected_type_start = 1;
    const expected_type_end = expected_type_start + (findClosingBrace(str[expected_type_start..]) orelse return error.InvalidTestItem);

    if (!std.mem.startsWith(u8, str[expected_type_end + 1 ..], "(")) return error.InvalidTestItem;
    const expected_value_start = expected_type_end + 2;
    const expected_value_end = expected_value_start + (findClosingBrace(str[expected_value_start..]) orelse return error.InvalidTestItem);

    const expected_type = offsets.locToSlice(str, .{ .start = expected_type_start, .end = expected_type_end });
    const expected_value = offsets.locToSlice(str, .{ .start = expected_value_start, .end = expected_value_end });

    return .{
        .loc = annotation.loc,
        .expected_type = if (expected_type.len != 0) expected_type else null,
        .expected_value = if (expected_value.len != 0) expected_value else null,
    };
}

fn findClosingBrace(source: []const u8) ?usize {
    var depth: usize = 0;
    var i: usize = 0;
    while (i < source.len) : (i += 1) {
        switch (source[i]) {
            '(' => depth += 1,
            ')' => {
                if (depth == 0) return i;
                depth -= 1;
            },
            else => continue,
        }
    }
    return null;
}
