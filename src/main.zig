const std = @import("std");
const file_type = @import("ftd.zig");
const ext = @import("hash_ext.zig");
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
    
    const pdf_content = try std.fs.cwd().readFileAlloc(allocator, file.?, std.math.maxInt(usize));
    defer allocator.free(pdf_content);
    
    const enc = try ext.extractEncryptionDict(file.?, allocator);
    defer enc.deinit(allocator);
    
    if (enc.O) |o| {
        cout("Owner (O): ", .{});
        printHex(o);
        cout("\n", .{});
    }
    if (enc.U) |u| {
        cout("User (U): ", .{});
        printHex(u);
        cout("\n", .{});
    }
    if (enc.P) |p| cout("Permissions (P): {s}\n", .{p});
    if (enc.V) |v| cout("Version (V): {s}\n", .{v});
    if (enc.R) |r| cout("Revision (R): {s}\n", .{r});
    if (enc.Length) |l| cout("Length: {s}\n", .{l});
    
    if (enc.U != null and enc.O != null) {
        const hash_format = try ext.formatForHashcat(&enc, pdf_content, allocator);
        defer allocator.free(hash_format);
        cout("\nHashcat format:\n{s}\n", .{hash_format});
    }
}

fn printHex(data: []const u8) void {
    for (data) |byte| {
        cout("{x:0>2}", .{byte});
    }
}
