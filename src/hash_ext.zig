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

/// Extract the /Encrypt dictionary from a PDF
pub fn extractEncryptionDict(file_path: []const u8, allocator: std.mem.Allocator) !EncryptionDict {
    const file = try std.fs.cwd().openFile(file_path, .{});
    defer file.close();
    
    const stat = try file.stat();
    const size: usize = stat.size;
    var buffer = try allocator.alloc(u8, size);
    defer allocator.free(buffer);
    _ = try file.readAll(buffer);
    
    // 1. Find "trailer" and locate /Encrypt
    const trailer_pos = std.mem.indexOf(u8, buffer, "trailer") orelse return error.NoTrailer;
    const trailer_slice = buffer[trailer_pos .. @min(trailer_pos + 1024, buffer.len)];
    const enc_pos = std.mem.indexOf(u8, trailer_slice, "/Encrypt") orelse return error.NoEncrypt;
    
    var i = enc_pos;
    while (i < trailer_slice.len and !std.ascii.isDigit(trailer_slice[i])) : (i += 1) {}
    const obj_start = i;
    while (i < trailer_slice.len and std.ascii.isDigit(trailer_slice[i])) : (i += 1) {}
    const obj_ref = trailer_slice[obj_start..i];
    const obj_num = try std.fmt.parseInt(u32, obj_ref, 10);
    
    // 2. Find "obj" for that number
    var obj_search_buf: [64]u8 = undefined;
    const obj_str = try std.fmt.bufPrint(&obj_search_buf, "{d} 0 obj", .{obj_num});
    const obj_pos = std.mem.indexOf(u8, buffer, obj_str) orelse return error.EncryptObjectNotFound;
    const endobj_pos = std.mem.indexOfPos(u8, buffer, obj_pos, "endobj") orelse return error.InvalidEncryptObject;
    const obj_slice = buffer[obj_pos .. endobj_pos];
    
    // 3. Find dictionary inside << >>
    const dict_start = std.mem.indexOf(u8, obj_slice, "<<") orelse return error.NoDict;
    const dict_end = std.mem.indexOfPos(u8, obj_slice, dict_start, ">>") orelse return error.NoDictEnd;
    const dict_slice = obj_slice[dict_start .. dict_end + 2];
    
    // 4. Parse dictionary (now returns by value, not pointer)
    var dict = try parser.parseDictionary(dict_slice, allocator);
    defer dict.deinit();
    
    // 5. Collect fields and decode hex strings
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
/// handles the double-encoding issue
fn decodeValue(value: []const u8, allocator: std.mem.Allocator) ![]const u8 {
    // Check if it's a hex string enclosed in < >
    if (value.len > 2 and value[0] == '<' and value[value.len - 1] == '>') {
        const hex_content = value[1 .. value.len - 1];
        
        // Ensure even length for proper hex decoding
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
    
    // This handles cases where PDF stores "4445343838424243" instead of <4445343838424243>
    if (value.len % 2 == 0 and value.len > 0) {
        var is_all_hex = true;
        for (value) |char| {
            if (!std.ascii.isHex(char)) {
                is_all_hex = false;
                break;
            }
        }
        
        if (is_all_hex) {
            // First decode the hex string to get another hex string
            var first_decode = try allocator.alloc(u8, value.len / 2);
            defer allocator.free(first_decode);
            
            for (0..first_decode.len) |i| {
                const hex_byte = value[i * 2 .. i * 2 + 2];
                first_decode[i] = try std.fmt.parseInt(u8, hex_byte, 16);
            }
            
            // Check if the result is still all hex characters (ASCII)
            var is_still_hex = true;
            for (first_decode) |char| {
                if (!std.ascii.isHex(char)) {
                    is_still_hex = false;
                    break;
                }
            }
            
            if (is_still_hex and first_decode.len % 2 == 0) {
                // Double-encoded! Decode again
                var final_decode = try allocator.alloc(u8, first_decode.len / 2);
                for (0..final_decode.len) |i| {
                    const hex_byte = first_decode[i * 2 .. i * 2 + 2];
                    final_decode[i] = try std.fmt.parseInt(u8, hex_byte, 16);
                }
                return final_decode;
            } else {
                // Single-encoded, return first decode
                return try allocator.dupe(u8, first_decode);
            }
        }
    }
    return try allocator.dupe(u8, value);
}

fn bytesToHex(bytes: []const u8, allocator: std.mem.Allocator) ![]u8 {
    const hex_chars = "0123456789abcdef";
    var result = try allocator.alloc(u8, bytes.len * 2);
    
    for (bytes, 0..) |byte, i| {
        result[i * 2] = hex_chars[byte >> 4];
        result[i * 2 + 1] = hex_chars[byte & 0x0f];
    }
    
    return result;
}
/// extract the PDF ID from the trailer
fn extractPdfId(pdf_content: []const u8, allocator: std.mem.Allocator) ![]const u8 {
    // Look for /ID in trailer
    if (std.mem.indexOf(u8, pdf_content, "/ID")) |id_pos| {
        // Find the array [<hex1><hex2>] or [<hex>]
        const search_area = pdf_content[id_pos..@min(id_pos + 300, pdf_content.len)];
        if (std.mem.indexOf(u8, search_area, "[<")) |bracket_pos| {
            const start = id_pos + bracket_pos + 2; // Skip "[<"
            if (std.mem.indexOfPos(u8, pdf_content, start, ">")) |end_pos| {
                const hex_id = pdf_content[start..end_pos];
                
                // Decode the hex ID
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

/// PDF ID extraction
pub fn formatForHashcat(enc_dict: *const EncryptionDict, pdf_content: []const u8, allocator: std.mem.Allocator) ![]u8 {
    if (enc_dict.U == null or enc_dict.O == null) {
        return error.InsufficientData;
    }
    
    const v = if (enc_dict.V) |v_str| std.fmt.parseInt(u32, v_str, 10) catch 2 else 2;
    const r = if (enc_dict.R) |r_str| std.fmt.parseInt(u32, r_str, 10) catch 3 else 3;
    const p = if (enc_dict.P) |p_str| std.fmt.parseInt(i32, p_str, 10) catch -4 else -4;
    const length = if (enc_dict.Length) |l_str| std.fmt.parseInt(u32, l_str, 10) catch 128 else 128;
    
    // Extract PDF ID
    const pdf_id = try extractPdfId(pdf_content, allocator);
    defer allocator.free(pdf_id);
    
    // Convert binary data to hex strings
    const u_hex = try bytesToHex(enc_dict.U.?, allocator);
    defer allocator.free(u_hex);
    const o_hex = try bytesToHex(enc_dict.O.?, allocator);
    defer allocator.free(o_hex);
    const id_hex = try bytesToHex(pdf_id, allocator);
    defer allocator.free(id_hex);
    
    // Format: $pdf$V*R*keylen*P*id_len*id*U_len*U*O_len*O
    const hash_line = try std.fmt.allocPrint(
        allocator,
        "$pdf${d}*{d}*{d}*{d}*{d}*{s}*{d}*{s}*{d}*{s}",
        .{ 
            v,                    // Version (2)
            r,                    // Revision (3) 
            length,               // Key length (128)
            p,                    // Permissions (-4)
            pdf_id.len,           // ID length
            id_hex,               // ID as hex
            enc_dict.U.?.len,     // U length 
            u_hex,                // U value as hex
            enc_dict.O.?.len,     // O length  
            o_hex                 // O value as hex
        }
    );
    
    return hash_line;
}
