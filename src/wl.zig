// wl.zig - PDF password cracking implementation
const std = @import("std");
const hash_ext = @import("hash_ext.zig");

pub const PdfCracker = struct {
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator) PdfCracker {
        return .{ .allocator = allocator };
    }
    
    /// Crack PDF password using wordlist
    pub fn crackPassword(
        self: *PdfCracker,
        enc_dict: *const hash_ext.EncryptionDict,
        pdf_id: []const u8,
        wordlist_path: []const u8,
    ) !?[]const u8 {
        const file = try std.fs.cwd().openFile(wordlist_path, .{});
        defer file.close();
        
        var buf_reader = std.io.bufferedReader(file.reader());
        var reader = buf_reader.reader();
        
        var line_buf: [1024]u8 = undefined;
        var attempts: usize = 0;
        const start_time = std.time.nanoTimestamp();
        
        std.debug.print("\n[*] Starting password cracking...\n", .{});
        std.debug.print("[*] Target hash (U): ", .{});
        printHex(enc_dict.U.?);
        std.debug.print("\n", .{});
        std.debug.print("[*] PDF ID: ", .{});
        printHex(pdf_id);
        std.debug.print("\n\n", .{});
        
        while (try reader.readUntilDelimiterOrEof(&line_buf, '\n')) |line| {
            attempts += 1;
            
            // Trim whitespace
            const password = std.mem.trim(u8, line, " \t\r\n");
            if (password.len == 0) continue;
            
            // Progress indicator every 1000 attempts
            if (attempts % 1000 == 0) {
                const elapsed = @as(f64, @floatFromInt(std.time.nanoTimestamp() - start_time)) / 1_000_000_000.0;
                const rate = @as(f64, @floatFromInt(attempts)) / elapsed;
                std.debug.print("\r[*] Tried {d} passwords ({d:.2} pwd/sec)...", .{ attempts, rate });
            }
            
            // Compute hash for this password
            const computed_hash = try self.computePdfHash(
                password,
                enc_dict,
                pdf_id,
            );
            defer self.allocator.free(computed_hash);
            
            // Compare with target hash (user password hash)
            // For R=3, we compare first 16 bytes
            const r = if (enc_dict.R) |r_str| try std.fmt.parseInt(u32, r_str, 10) else 3;
            const compare_len: usize = if (r >= 3) 16 else 32;
            
            if (std.mem.eql(u8, computed_hash[0..compare_len], enc_dict.U.?[0..compare_len])) {
                std.debug.print("\n\n[+] PASSWORD FOUND: {s}\n", .{password});
                std.debug.print("[+] Attempts: {d}\n", .{attempts});
                const end_time = std.time.nanoTimestamp();
                const total_time = @as(f64, @floatFromInt(end_time - start_time)) / 1_000_000_000.0;
                std.debug.print("[+] Time taken: {d:.2} seconds\n", .{ total_time });
                return try self.allocator.dupe(u8, password);
            }
        }
        
        std.debug.print("\n\n[-] Password not found in wordlist\n", .{});
        std.debug.print("[-] Total attempts: {d}\n", .{attempts});
        return null;
    }
    
    /// Compute PDF password hash (Algorithm 3.2 from PDF specification)
    fn computePdfHash(
        self: *PdfCracker,
        password: []const u8,
        enc_dict: *const hash_ext.EncryptionDict,
        pdf_id: []const u8,
    ) ![]u8 {
        const r = if (enc_dict.R) |r_str| try std.fmt.parseInt(u32, r_str, 10) else 3;
        const p = if (enc_dict.P) |p_str| try std.fmt.parseInt(i32, p_str, 10) else -4;
        const key_len_bits = if (enc_dict.Length) |l_str| 
            try std.fmt.parseInt(u32, l_str, 10)
        else 
            40;
        const key_len = key_len_bits / 8;
        
        // PDF password padding string
        const padding = [_]u8{
            0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41,
            0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08,
            0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80,
            0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A,
        };
        
        // Algorithm 3.2: Computing an encryption key
        // Step 1: Pad or truncate password to 32 bytes
        var padded_password: [32]u8 = undefined;
        const copy_len = @min(password.len, 32);
        @memcpy(padded_password[0..copy_len], password[0..copy_len]);
        if (copy_len < 32) {
            @memcpy(padded_password[copy_len..], padding[0 .. 32 - copy_len]);
        }
        
        // Step 2: Initialize MD5 hash with padded password
        var hasher = std.crypto.hash.Md5.init(.{});
        hasher.update(&padded_password);
        
        // Step 3: Pass owner password hash (O entry)
        if (enc_dict.O) |o_value| {
            hasher.update(o_value);
        }
        
        // Step 4: Pass permissions as 4-byte little-endian integer
        var p_bytes: [4]u8 = undefined;
        std.mem.writeInt(i32, &p_bytes, p, .little);
        hasher.update(&p_bytes);
        
        // Step 5: Pass PDF file identifier
        hasher.update(pdf_id);
        
        // Step 6: For R >= 4, additional step (not encrypting metadata)
        if (r >= 4) {
            const extra = [_]u8{0xFF, 0xFF, 0xFF, 0xFF};
            hasher.update(&extra);
        }
        
        // Step 7: Finish the hash
        var hash: [16]u8 = undefined;
        hasher.final(&hash);
        
        // Step 8: For R >= 3, do 50 iterations of MD5 on the key
        if (r >= 3) {
            var i: usize = 0;
            while (i < 50) : (i += 1) {
                var round_hasher = std.crypto.hash.Md5.init(.{});
                round_hasher.update(hash[0..key_len]);
                round_hasher.final(&hash);
            }
        }
        
        // The encryption key is now in hash[0..key_len]
        const encryption_key = hash[0..key_len];
        
        // Algorithm 3.4/3.5: Computing the user password (U)
        if (r == 2) {
            // Algorithm 3.4 (R=2): Encrypt padding string with RC4
            const result = try self.allocator.alloc(u8, 32);
            @memcpy(result, &padding);
            rc4Encrypt(result, encryption_key);
            return result;
        } else {
            // Algorithm 3.5 (R>=3): More complex procedure
            // Step a: Create hash of padding + PDF ID
            var u_hasher = std.crypto.hash.Md5.init(.{});
            u_hasher.update(&padding);
            u_hasher.update(pdf_id);
            var u_hash: [16]u8 = undefined;
            u_hasher.final(&u_hash);
            
            // Step b: Encrypt the hash with RC4 using encryption key
            var encrypted: [16]u8 = undefined;
            @memcpy(&encrypted, &u_hash);
            rc4Encrypt(&encrypted, encryption_key);
            
            // Step c: Do 19 more iterations with modified keys
            var iteration: usize = 1;
            while (iteration <= 19) : (iteration += 1) {
                var modified_key: [16]u8 = undefined;
                for (encryption_key, 0..) |byte, i| {
                    modified_key[i] = byte ^ @as(u8, @intCast(iteration));
                }
                rc4Encrypt(&encrypted, modified_key[0..key_len]);
            }
            
            // Step d: Pad result to 32 bytes (remaining 16 bytes are arbitrary)
            const result = try self.allocator.alloc(u8, 32);
            @memcpy(result[0..16], &encrypted);
            // Use padding bytes for the rest (though they're not compared)
            @memcpy(result[16..32], padding[16..32]);
            
            return result;
        }
    }
};

/// RC4 encryption (stream cipher)
fn rc4Encrypt(data: []u8, key: []const u8) void {
    // Initialize S box
    var s: [256]u8 = undefined;
    for (&s, 0..) |*byte, i| {
        byte.* = @intCast(i);
    }
    
    // Key scheduling algorithm (KSA)
    var j: usize = 0;
    for (0..256) |i| {
        j = (j + s[i] + key[i % key.len]) % 256;
        const temp = s[i];
        s[i] = s[j];
        s[j] = temp;
    }
    
    // Pseudo-random generation algorithm (PRGA)
    var i: usize = 0;
    j = 0;
    for (data) |*byte| {
        i = (i + 1) % 256;
        j = (j + s[i]) % 256;
        const temp = s[i];
        s[i] = s[j];
        s[j] = temp;
        const idx = (@as(u16, s[i]) + @as(u16, s[j])) % 256;
        const k = s[@intCast(idx)];
        byte.* ^= k;
    }
}

/// Helper to print hex
fn printHex(data: []const u8) void {
    for (data) |byte| {
        std.debug.print("{x:0>2}", .{byte});
    }
}
