const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.resolveTargetQuery(.{
        .cpu_arch = .x86_64,
        .os_tag = .freestanding,
        .abi = .none,
    });

    const exe = b.addExecutable(.{
        .name = "vm16",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = .ReleaseSmall,
        }),
    });
    exe.root_module.red_zone = false;
    exe.root_module.stack_protector = false;
    exe.pie = true;
    exe.linker_script = b.path("link.ld");
    exe.root_module.link_libc = false;
    exe.root_module.single_threaded = true;
    exe.entry = .{ .symbol_name = "_start" };
    exe.rdynamic = false;
    exe.link_z_max_page_size = 4096;
    const trim_exe = b.addExecutable(.{
        .name = "trim-elf",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/trim_elf.zig"),
            .target = b.graph.host,
            .optimize = .ReleaseSafe,
        }),
    });
    const trim = b.addRunArtifact(trim_exe);
    trim.addArtifactArg(exe);
    const image = trim.addOutputFileArg("vm16");
    const install = b.addInstallBinFile(image, "vm16");
    b.getInstallStep().dependOn(&install.step);

    const tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/vm_test.zig"),
            .target = b.graph.host,
            .optimize = .Debug,
            .error_tracing = false,
        }),
    });
    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run VM safety tests");
    test_step.dependOn(&run_tests.step);

    const check = b.addSystemCommand(&.{
        "sh",        "-c",
        \\bytes=$(wc -c < "$1")
        \\echo "vm16: $bytes / 24576 bytes"
        \\test "$bytes" -le 24576
        ,
        "vm16-size",
    });
    check.addFileArg(image);
    const size_step = b.step("size", "Enforce the 24 KiB release limit");
    size_step.dependOn(&check.step);

    b.getInstallStep().dependOn(&run_tests.step);
    b.getInstallStep().dependOn(&check.step);
}
