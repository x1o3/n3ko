const std = @import("std");
const file_type = @import("ftd.zig");
const ext = @import("hash_ext.zig");
const cracker = @import("wl.zig");
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
            cout("  -f   <path>  PDF file to crack\n", .{});
            cout("  -wl  <path>  Wordlist file\n", .{});
            cout("  --help       Show this help message\n", .{});
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
    
    // Extract encryption info - FIXED: use extractEncryptionInfo
    const result = try ext.extractEncryptionInfo(file.?, allocator);
    defer result.enc_dict.deinit(allocator);
    defer allocator.free(result.pdf_id);
    
    cout("\n=== Encryption Information ===\n", .{});
    if (result.enc_dict.O) |o| {
        cout("Owner (O): ", .{});
        printHex(o);
        cout("\n", .{});
    }
    if (result.enc_dict.U) |u| {
        cout("User (U): ", .{});
        printHex(u);
        cout("\n", .{});
    }
    if (result.enc_dict.P) |p| cout("Permissions (P): {s}\n", .{p});
    if (result.enc_dict.V) |v| cout("Version (V): {s}\n", .{v});
    if (result.enc_dict.R) |r| cout("Revision (R): {s}\n", .{r});
    if (result.enc_dict.Length) |l| cout("Length: {s}\n", .{l});
    
    cout("\nPDF ID: ", .{});
    printHex(result.pdf_id);
    cout("\n", .{});
    
    // Format for hashcat/john
    if (result.enc_dict.U != null and result.enc_dict.O != null) {
        const hash_format = try ext.formatForHashcat(&result.enc_dict, result.pdf_id, allocator);
        defer allocator.free(hash_format);
        cout("\nHashcat format:\n{s}\n", .{hash_format});
    }
    
    // Start cracking
    var pdf_cracker = cracker.PdfCracker.init(allocator);
    if (try pdf_cracker.crackPassword(&result.enc_dict, result.pdf_id, wordlist.?)) |password| {
        defer allocator.free(password);
        cout("\n✓ SUCCESS! Password: {s}\n", .{password});
    } else {
        cout("\n✗ FAILED - Password not found in wordlist\n", .{});
    }
}

fn printHex(data: []const u8) void {
    for (data) |byte| {
        cout("{x:0>2}", .{byte});
    }
}
