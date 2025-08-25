const std = @import("std");

pub const FileType = enum {
    PDF,
    Word,
    Excel,
    PowerPoint,
    Unsupported,
};

pub fn detectFileType(file_path: []const u8) !FileType {
    const file = try std.fs.cwd().openFile(file_path, .{});
    defer file.close();

    var buffer: [8]u8 = undefined;
    const bytes_read = try file.read(buffer[0..]);
    if (bytes_read < 4) return FileType.Unsupported;

    // Check PDF
    if (std.mem.startsWith(u8, buffer[0..bytes_read], "%PDF")) {
        return FileType.PDF;
    }

    // Check ZIP (Office files)
    if (buffer[0] == 0x50 and buffer[1] == 0x4B and buffer[2] == 0x03 and buffer[3] == 0x04) {
        // Later: check internal XML files to determine Word/Excel/PowerPoint
        // For now, return generic Unsupported ZIP
        return FileType.Unsupported; 
    }

    return FileType.Unsupported;
}

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();
    const file_path = "test.pdf"; // replace with your test file
    const file_type = try detectFileType(file_path);

    try stdout.print("Detected file type: {}\n", .{file_type});
}
