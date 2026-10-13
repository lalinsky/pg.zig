// Helpers for supporting both Zig 0.16 and 0.17.
// Zig 0.17 replaced the lists of `StructField`, `Declaration` and `Error`
// structs in `std.builtin.Type` with separate slices of names, types and
// attributes.

const std = @import("std");

const has_field_names = @hasField(std.builtin.Type.Struct, "field_names");

pub fn fieldNames(comptime T: type) []const [:0]const u8 {
    const info = @typeInfo(T).@"struct";
    if (has_field_names) return info.field_names;
    return comptime blk: {
        var names: [info.fields.len][:0]const u8 = undefined;
        for (info.fields, &names) |f, *n| n.* = f.name;
        const final = names;
        break :blk &final;
    };
}

pub fn fieldTypes(comptime T: type) []const type {
    const info = @typeInfo(T).@"struct";
    if (has_field_names) return info.field_types;
    return comptime blk: {
        var types: [info.fields.len]type = undefined;
        for (info.fields, &types) |f, *ft| ft.* = f.type;
        const final = types;
        break :blk &final;
    };
}

pub fn fieldDefaults(comptime T: type) []const ?*const anyopaque {
    const info = @typeInfo(T).@"struct";
    return comptime blk: {
        var defaults: [fieldNames(T).len]?*const anyopaque = undefined;
        if (has_field_names) {
            for (info.field_attrs, &defaults) |a, *d| d.* = a.default_value_ptr;
        } else {
            for (info.fields, &defaults) |f, *d| d.* = f.default_value_ptr;
        }
        const final = defaults;
        break :blk &final;
    };
}

pub fn declNames(comptime T: type) []const [:0]const u8 {
    const info = @typeInfo(T).@"struct";
    if (has_field_names) return info.decl_names;
    return comptime blk: {
        var names: [info.decls.len][:0]const u8 = undefined;
        for (info.decls, &names) |d, *n| n.* = d.name;
        const final = names;
        break :blk &final;
    };
}

pub fn errorNames(comptime E: type) []const [:0]const u8 {
    const info = @typeInfo(E).error_set;
    if (has_field_names) return info.error_names.?;
    return comptime blk: {
        const errors = info.?;
        var names: [errors.len][:0]const u8 = undefined;
        for (errors, &names) |e, *n| n.* = e.name;
        const final = names;
        break :blk &final;
    };
}
