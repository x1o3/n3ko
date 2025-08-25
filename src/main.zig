const std = @import("std");
const file_type = @import("ftd.zig");
const cout = std.debug.print;
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();

    _ = args.skip();

    var file: ?[]const u8 = null;
    var wordlist: ?[]const u8 = null;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-f")) {
            file = args.next() orelse return error.MissingFileArg;
        } else if (std.mem.eql(u8, arg, "-wl")) {
            wordlist = args.next() orelse return error.MissingWordlistArg;
        } else if (std.mem.eql(u8, arg, "--help")) {
            cout("Usage: n3ko -f <path> -wl <path>\n", .{});
            return;
        }
    }
    if (file == null or wordlist == null) {
        cout("Error: -f and -wl are required\n", .{});
        return;
    }

    cout("Using file: {s}\nUsing wordlist: {s}\n", .{ file.?, wordlist.? });
    const ftype = try file_type.detectFileType(file.?);
    cout("Detected file type: {}\n", .{ftype});
}
