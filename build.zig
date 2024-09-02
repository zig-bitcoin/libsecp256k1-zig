const std = @import("std");

fn buildSecp256k1(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) !*std.Build.Step.Compile {
    const lib = b.addStaticLibrary(.{ .name = "libsecp", .target = target, .optimize = optimize });

    lib.addIncludePath(b.path("libsecp256k1/"));
    lib.addIncludePath(b.path("libsecp256k1/src"));

    var flags = std.ArrayList([]const u8).init(b.allocator);
    defer flags.deinit();

    try flags.appendSlice(&.{"-DENABLE_MODULE_RECOVERY=1"});
    try flags.appendSlice(&.{"-DENABLE_MODULE_SCHNORRSIG=1"});
    try flags.appendSlice(&.{"-DENABLE_MODULE_ECDH=1"});
    try flags.appendSlice(&.{"-DENABLE_MODULE_EXTRAKEYS=1"});

    lib.addCSourceFiles(.{ .root = b.path("libsecp256k1/"), .flags = flags.items, .files = &.{ "./src/secp256k1.c", "./src/precomputed_ecmult.c", "./src/precomputed_ecmult_gen.c" } });
    lib.defineCMacro("USE_FIELD_10X26", "1");
    lib.defineCMacro("USE_SCALAR_8X32", "1");
    lib.defineCMacro("USE_ENDOMORPHISM", "1");
    lib.defineCMacro("USE_NUM_NONE", "1");
    lib.defineCMacro("USE_FIELD_INV_BUILTIN", "1");
    lib.defineCMacro("USE_SCALAR_INV_BUILTIN", "1");
    lib.installHeadersDirectory(b.path("libsecp256k1/src"), "", .{ .include_extensions = &.{".h"} });
    lib.installHeadersDirectory(b.path("libsecp256k1/include/"), "", .{ .include_extensions = &.{".h"} });
    lib.linkLibC();

    return lib;
}

// Although this function looks imperative, note that its job is to
// declaratively construct a build graph that will be executed by an external
// runner.
pub fn build(b: *std.Build) !void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    // Standard optimization options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall. Here we do not
    // set a preferred release mode, allowing the user to decide how to optimize.
    const optimize = b.standardOptimizeOption(.{});

    // libsecp256k1 static C library.
    const libsecp256k1 = try buildSecp256k1(b, target, optimize);
    b.installArtifact(libsecp256k1);

    const lib = b.addModule("secp256k1", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    lib.linkLibrary(libsecp256k1);

    // This declares intent for the library to be installed into the standard
    // location when the user invokes the "install" step (the default step when
    // running `zig build`).
    b.installArtifact(lib);

    const exe = b.addExecutable(.{
        .name = "libsecp256k1-zig",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    exe.linkLibrary(libsecp256k1);

    // This declares intent for the executable to be installed into the
    // standard location when the user invokes the "install" step (the default
    // step when running `zig build`).
    b.installArtifact(exe);

    // This *creates* a Run step in the build graph, to be executed when another
    // step is evaluated that depends on it. The next line below will establish
    // such a dependency.
    const run_cmd = b.addRunArtifact(exe);

    // By making the run step depend on the install step, it will be run from the
    // installation directory rather than directly from within the cache directory.
    // This is not necessary, however, if the application depends on other installed
    // files, this ensures they will be present and in the expected location.
    run_cmd.step.dependOn(b.getInstallStep());

    // This allows the user to pass arguments to the application in the build
    // command itself, like this: `zig build run -- arg1 arg2 etc`
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    // This creates a build step. It will be visible in the `zig build --help` menu,
    // and can be selected like this: `zig build run`
    // This will evaluate the `run` step rather than the default, which is "install".
    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    // Creates a step for unit testing. This only builds the test executable
    // but does not run it.
    const lib_unit_tests = b.addTest(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    lib_unit_tests.linkLibrary(libsecp256k1);

    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);

    // Similar to creating the run step earlier, this exposes a `test` step to
    // the `zig build --help` menu, providing a way for the user to request
    // running the unit tests.
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);
}
