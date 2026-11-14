const std = @import("std");

const TlsOption = enum { none, ztls, libssl };

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // setup our dependencies
    const dep_opts = .{ .target = target, .optimize = optimize };

    const tls_option = b.option(
        TlsOption,
        "tls",
        "TLS: none (default), ztls (native ztls), or libssl (ztls on AWS-LC's libssl)",
    ) orelse .none;

    // Expose this as a module that others can import
    const pg_module = b.addModule("pg", .{
        .target = target,
        .optimize = optimize,
        .root_source_file = b.path("src/pg.zig"),
        .imports = &.{
            .{ .name = "buffer", .module = b.dependency("buffer", dep_opts).module("buffer") },
            .{ .name = "metrics", .module = b.dependency("metrics", dep_opts).module("metrics") },
        },
    });
    const has_tls = addTls(b, pg_module, tls_option, target, optimize);

    var column_names = false;
    const column_names_opt = b.option(bool, "column_names", "");

    if (column_names_opt) |val| {
        column_names = val;
    }

    {
        const options = b.addOptions();
        options.addOption(bool, "tls", has_tls);
        options.addOption(bool, "column_names", column_names);
        pg_module.addOptions("config", options);
    }

    {
        const lib_test = b.addTest(.{
            .root_module = b.createModule(.{
                .target = target,
                .optimize = optimize,
                .root_source_file = b.path("src/pg.zig"),
                .imports = &.{
                    .{ .name = "buffer", .module = b.dependency("buffer", dep_opts).module("buffer") },
                    .{ .name = "metrics", .module = b.dependency("metrics", dep_opts).module("metrics") },
                },
            }),
            .use_llvm = true,
            .test_runner = .{ .path = b.path("test_runner.zig"), .mode = .simple },
        });
        const test_has_tls = addTls(b, lib_test.root_module, tls_option, target, optimize);

        {
            const options = b.addOptions();
            options.addOption(bool, "tls", test_has_tls);
            options.addOption(bool, "column_names", false);
            lib_test.root_module.addOptions("config", options);
        }

        const run_test = b.addRunArtifact(lib_test);
        run_test.has_side_effects = true;

        const test_step = b.step("test", "Run unit tests");
        test_step.dependOn(&run_test.step);
    }
}

// ztls is a lazy dependency, fetched and built only when TLS is on; `libssl`
// builds it with its libssl engine. Returns whether `module` has TLS.
fn addTls(b: *std.Build, module: *std.Build.Module, tls_option: TlsOption, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) bool {
    switch (tls_option) {
        .none => return false,
        .ztls, .libssl => {
            const ztls = b.lazyDependency("ztls", .{
                .target = target,
                .optimize = optimize,
                .impl = @as(enum { native, libssl }, if (tls_option == .libssl) .libssl else .native),
            }) orelse return true;
            module.addImport("tls", ztls.module("ztls"));
            return true;
        },
    }
}
