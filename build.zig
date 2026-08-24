const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const force_poll = b.option(
        bool,
        "poll",
        "Force the portable poll(2) backend instead of epoll/kqueue",
    ) orelse false;

    // How much memory the daemon is allowed to be. Both of these are
    // compile-time because every buffer and table is fixed-size: the point of
    // the design is that the ceiling is known before the process starts.
    const max_io_kib = b.option(
        u32,
        "max-io",
        "Largest read/write in KiB (default 256). Bigger means fewer round trips and more memory per connection",
    ) orelse 256;
    const max_connections = b.option(
        u32,
        "connections",
        "Concurrent connections (default 32)",
    ) orelse 32;

    const build_options = b.addOptions();
    build_options.addOption(bool, "force_poll", force_poll);
    build_options.addOption(u32, "max_io_kib", max_io_kib);
    build_options.addOption(u32, "max_connections", max_connections);

    const options_module = build_options.createModule();

    const easysamba = b.addModule("easysamba", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "build_options", .module = options_module }},
    });

    const exe = b.addExecutable(.{
        .name = "easysambad",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "easysamba", .module = easysamba },
                .{ .name = "build_options", .module = options_module },
            },
        }),
    });
    // Server, connection table and buffer pool are one value in main's frame.
    // That does not fit the 8 MiB the OS hands us by default.
    exe.stack_size = 256 * 1024 * 1024;
    b.installArtifact(exe);

    const bench = b.addExecutable(.{
        .name = "bench",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "easysamba", .module = easysamba }},
        }),
    });
    bench.stack_size = 64 * 1024 * 1024;
    const bench_run = b.addRunArtifact(bench);
    const bench_step = b.step("bench", "Measure the dispatch path (use -Doptimize=ReleaseFast)");
    bench_step.dependOn(&bench_run.step);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);
    const run_step = b.step("run", "Run easysambad");
    run_step.dependOn(&run_cmd.step);

    const tests = b.addTest(.{ .root_module = easysamba });
    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_tests.step);

    // Zig only analyzes reachable code, so `zig build -Dtarget=...` proves very
    // little about a platform's backend. Building the test binary forces
    // analysis of the whole tree — the only way to catch a broken epoll path
    // from a macOS host.
    const check_step = b.step("check", "Compile everything without running (for cross-targets)");
    check_step.dependOn(&tests.step);
    check_step.dependOn(&exe.step);
    check_step.dependOn(&bench.step);

    const test_bin_step = b.step("test-bin", "Install the test binary for running elsewhere");
    test_bin_step.dependOn(&b.addInstallArtifact(tests, .{}).step);
}
