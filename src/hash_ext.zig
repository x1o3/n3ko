const std = @import("std");
const parser = @import("parser.zig");

pub const EncryptionDict = struct {
    O: ?[]const u8 = null,
    U: ?[]const u8 = null,
    P: ?[]const u8 = null,
    V: ?[]const u8 = null,
    R: ?[]const u8 = null,
    Length: ?[]const u8 = null,
    
    pub fn deinit(self: *const EncryptionDict, allocator: std.mem.Allocator) void {
        if (self.O) |o| allocator.free(o);
        if (self.U) |u| allocator.free(u);
        if (self.P) |p| allocator.free(p);
        if (self.V) |v| allocator.free(v);
        if (self.R) |r| allocator.free(r);
        if (self.Length) |l| allocator.free(l);
    }
};

pub const ExtractionResult = struct {
    enc_dict: EncryptionDict,
    pdf_id: []const u8,
};

/// Extract encryption info and PDF ID
pub fn extractEncryptionInfo(file_path: []const u8, allocator: std.mem.Allocator) !ExtractionResult {
    const file = try std.fs.cwd().openFile(file_path, .{});
    defer file.close();
    
    const stat = try file.stat();
    const size: usize = stat.size;
    const buffer = try allocator.alloc(u8, size);
    defer allocator.free(buffer);
    _ = try file.readAll(buffer);
    
    // Extract encryption dictionary
    const enc_dict = try extractEncryptionDictFromBuffer(buffer, allocator);
    
    // Extract PDF ID
    const pdf_id = try extractPdfId(buffer, allocator);
    
    return ExtractionResult{
        .enc_dict = enc_dict,
        .pdf_id = pdf_id,
    };
}

fn extractEncryptionDictFromBuffer(buffer: []const u8, allocator: std.mem.Allocator) !EncryptionDict {
    // Find "trailer" and locate /Encrypt
    const trailer_pos = std.mem.indexOf(u8, buffer, "trailer") orelse return error.NoTrailer;
    const trailer_slice = buffer[trailer_pos .. @min(trailer_pos + 1024, buffer.len)];
    const enc_pos = std.mem.indexOf(u8, trailer_slice, "/Encrypt") orelse return error.NoEncrypt;
    
    var i = enc_pos;
    while (i < trailer_slice.len and !std.ascii.isDigit(trailer_slice[i])) : (i += 1) {}
    const obj_start = i;
    while (i < trailer_slice.len and std.ascii.isDigit(trailer_slice[i])) : (i += 1) {}
    const obj_ref = trailer_slice[obj_start..i];
    const obj_num = try std.fmt.parseInt(u32, obj_ref, 10);
    
    // Find "obj" for that number
    var obj_search_buf: [64]u8 = undefined;
    const obj_str = try std.fmt.bufPrint(&obj_search_buf, "{d} 0 obj", .{obj_num});
    const obj_pos = std.mem.indexOf(u8, buffer, obj_str) orelse return error.EncryptObjectNotFound;
    const endobj_pos = std.mem.indexOfPos(u8, buffer, obj_pos, "endobj") orelse return error.InvalidEncryptObject;
    const obj_slice = buffer[obj_pos .. endobj_pos];
    
    // Find dictionary inside << >>
    const dict_start = std.mem.indexOf(u8, obj_slice, "<<") orelse return error.NoDict;
    const dict_end = std.mem.indexOfPos(u8, obj_slice, dict_start, ">>") orelse return error.NoDictEnd;
    const dict_slice = obj_slice[dict_start .. dict_end + 2];
    
    // Parse dictionary
    var dict = try parser.parseDictionary(dict_slice, allocator);
    defer dict.deinit();
    
    // Collect fields and decode hex strings
    var result = EncryptionDict{};
    
    if (dict.get("O")) |o| {
        result.O = try decodeValue(o, allocator);
    }
    if (dict.get("U")) |u| {
        result.U = try decodeValue(u, allocator);
    }
    if (dict.get("P")) |p| {
        result.P = try allocator.dupe(u8, p);
    }
    if (dict.get("V")) |v| {
        result.V = try allocator.dupe(u8, v);
    }
    if (dict.get("R")) |r| {
        result.R = try allocator.dupe(u8, r);
    }
    if (dict.get("Length")) |l| {
        result.Length = try allocator.dupe(u8, l);
    }
    
    return result;
}

/// Extract PDF ID from trailer
fn extractPdfId(pdf_content: []const u8, allocator: std.mem.Allocator) ![]const u8 {
    if (std.mem.indexOf(u8, pdf_content, "/ID")) |id_pos| {
        const search_area = pdf_content[id_pos..@min(id_pos + 300, pdf_content.len)];
        if (std.mem.indexOf(u8, search_area, "[<")) |bracket_pos| {
            const start = id_pos + bracket_pos + 2;
            if (std.mem.indexOfPos(u8, pdf_content, start, ">")) |end_pos| {
                const hex_id = pdf_content[start..end_pos];
                
                if (hex_id.len % 2 == 0 and hex_id.len > 0) {
                    var decoded = try allocator.alloc(u8, hex_id.len / 2);
                    for (0..decoded.len) |i| {
                        const hex_byte = hex_id[i * 2 .. i * 2 + 2];
                        decoded[i] = std.fmt.parseInt(u8, hex_byte, 16) catch 0;
                    }
                    return decoded;
                }
            }
        }
    }
    
    return try allocator.alloc(u8, 0);
}

/// Decode hex string - handles <HEXDATA> format and double-encoding
fn decodeValue(value: []const u8, allocator: std.mem.Allocator) ![]const u8 {
    // Check if it's wrapped in angle brackets < >
    if (value.len > 2 and value[0] == '<' and value[value.len - 1] == '>') {
        const hex_content = value[1 .. value.len - 1];
        
        if (hex_content.len % 2 != 0) {
            return error.InvalidHexLength;
        }
        
        var decoded = try allocator.alloc(u8, hex_content.len / 2);
        for (0..decoded.len) |i| {
            const hex_byte = hex_content[i * 2 .. i * 2 + 2];
            decoded[i] = try std.fmt.parseInt(u8, hex_byte, 16);
        }
        return decoded;
    }
    
    // Check if it's raw hex (all hex characters, even length)
    if (value.len % 2 == 0 and value.len > 0) {
        var is_all_hex = true;
        for (value) |char| {
            if (!std.ascii.isHex(char)) {
                is_all_hex = false;
                break;
            }
        }
        
        if (is_all_hex) {
            var decoded = try allocator.alloc(u8, value.len / 2);
            for (0..decoded.len) |i| {
                const hex_byte = value[i * 2 .. i * 2 + 2];
                decoded[i] = try std.fmt.parseInt(u8, hex_byte, 16);
            }
            return decoded;
        }
    }
    
    // Not hex, just duplicate as-is
    return try allocator.dupe(u8, value);
}

pub fn formatForHashcat(enc_dict: *const EncryptionDict, pdf_id: []const u8, allocator: std.mem.Allocator) ![]u8 {
    if (enc_dict.U == null or enc_dict.O == null) {
        return error.InsufficientData;
    }
    
    const v = if (enc_dict.V) |v_str| std.fmt.parseInt(u32, v_str, 10) catch 2 else 2;
    const r = if (enc_dict.R) |r_str| std.fmt.parseInt(u32, r_str, 10) catch 3 else 3;
    const p = if (enc_dict.P) |p_str| std.fmt.parseInt(i32, p_str, 10) catch -4 else -4;
    const length = if (enc_dict.Length) |l_str| std.fmt.parseInt(u32, l_str, 10) catch 128 else 128;
    
    const u_hex = try bytesToHex(enc_dict.U.?, allocator);
    defer allocator.free(u_hex);
    const o_hex = try bytesToHex(enc_dict.O.?, allocator);
    defer allocator.free(o_hex);
    const id_hex = try bytesToHex(pdf_id, allocator);
    defer allocator.free(id_hex);
    
    // Include metadata encryption flag (1 = not encrypted, 0 = encrypted)
    // Default to 1 for R < 4
    const metadata_encrypted: u32 = 1;
    
    const hash_line = try std.fmt.allocPrint(
        allocator,
        "$pdf${d}*{d}*{d}*{d}*{d}*{d}*{s}*{d}*{s}*{d}*{s}",
        .{ 
            v, r, length, p,
            metadata_encrypted,
            pdf_id.len, id_hex,
            enc_dict.U.?.len, u_hex,
            enc_dict.O.?.len, o_hex
        }
    );
    
    return hash_line;
}

fn bytesToHex(bytes: []const u8, allocator: std.mem.Allocator) ![]u8 {
    var hex = try allocator.alloc(u8, bytes.len * 2);
    for (bytes, 0..) |byte, i| {
        _ = try std.fmt.bufPrint(hex[i * 2 .. i * 2 + 2], "{x:0>2}", .{byte});
    }
    return hex;
}
