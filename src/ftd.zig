const std = @import("std");

pub const FileType = enum {
    PDF,
    ZIP,
    Unsupported,
};

pub fn detectFileType(file_path: []const u8) !FileType {
    const file = try std.fs.cwd().openFile(file_path, .{});
    defer file.close();

    var buffer: [8]u8 = undefined;
    const bytes_read = try file.read(buffer[0..]);
    if (bytes_read < 4) return FileType.Unsupported;

    // Check PDF signature
    if (std.mem.startsWith(u8, buffer[0..bytes_read], "%PDF")) {
        return FileType.PDF;
    }
    
    // Check ZIP signature (PK\x03\x04 or 0x504B0304)
    if (bytes_read >= 4) {
        const zip_sig = [_]u8{ 0x50, 0x4B, 0x03, 0x04 }; // "PK" + 0x03 0x04
        if (std.mem.eql(u8, buffer[0..4], &zip_sig)) {
            return FileType.ZIP;
        }
        
        // Also check for empty archive signature (PK\x05\x06)
        const empty_zip_sig = [_]u8{ 0x50, 0x4B, 0x05, 0x06 };
        if (std.mem.eql(u8, buffer[0..4], &empty_zip_sig)) {
            return FileType.ZIP;
        }
        
        // Spanned archive signature (PK\x07\x08)
        const spanned_zip_sig = [_]u8{ 0x50, 0x4B, 0x07, 0x08 };
        if (std.mem.eql(u8, buffer[0..4], &spanned_zip_sig)) {
            return FileType.ZIP;
        }
    }
    
    return FileType.Unsupported;
}
