const std = @import("std");

pub const FileType = enum {
    PDF,
    Unsupported,
};

pub fn detectFileType(file_path: []const u8) !FileType {
    const file = try std.fs.cwd().openFile(file_path, .{});
    defer file.close();

    var buffer: [8]u8 = undefined;
    const bytes_read = try file.read(buffer[0..]);
    if (bytes_read < 4) return FileType.Unsupported;

    if (std.mem.startsWith(u8, buffer[0..bytes_read], "%PDF")) {
        return FileType.PDF;
    }
    
    return FileType.Unsupported;
}
