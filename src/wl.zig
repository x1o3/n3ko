// wl.zig - PDF password cracking implementation with multithreading
const std = @import("std");
const hash_ext = @import("hash_ext.zig");

const CrackResult = struct {
    found: bool,
    password: ?[]const u8,
};

const ThreadContext = struct {
    allocator: std.mem.Allocator,
    enc_dict: *const hash_ext.EncryptionDict,
    pdf_id: []const u8,
    passwords: [][]const u8,
    // Shared atomic pointer to found password
    result_ptr: *std.atomic.Value(?[*]const u8),
    // Shared length of found password
    result_len: *std.atomic.Value(usize),
    // Shared attempts counter
    attempts: *std.atomic.Value(usize),
};

pub const PdfCracker = struct {
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) PdfCracker {
        return .{ .allocator = allocator };
    }

    /// Multithreaded password cracking
    pub fn crackPasswordMultithreaded(
        self: *PdfCracker,
        enc_dict: *const hash_ext.EncryptionDict,
        pdf_id: []const u8,
        wordlist_path: []const u8,
        num_threads: usize,
    ) !?[]const u8 {
        std.debug.print("\n[*] Starting multithreaded password cracking...\n", .{});
        std.debug.print("[*] Using {d} threads\n", .{num_threads});
        std.debug.print("[*] Target hash (U): ", .{});
        if (enc_dict.U) |u| {
            printHex(u);
        } else {
            std.debug.print("(none)", .{});
        }
        std.debug.print("\n", .{});
        std.debug.print("[*] PDF ID: ", .{});
        printHex(pdf_id);
        std.debug.print("\n\n", .{});

        // Read entire wordlist into memory
        const passwords = try self.readWordlist(wordlist_path);
        defer {
            for (passwords) |pwd| {
                self.allocator.free(pwd);
            }
            self.allocator.free(passwords);
        }

        if (passwords.len == 0) {
            std.debug.print("[-] Empty wordlist\n", .{});
            return null;
        }

        std.debug.print("[*] Loaded {d} passwords from wordlist\n\n", .{passwords.len});

        // Shared result storage (pointer + length) and attempts counter
        var result_ptr = std.atomic.Value(?[*]const u8).init(null);
        var result_len = std.atomic.Value(usize).init(0);
        var total_attempts = std.atomic.Value(usize).init(0);

        // Split work among threads
        const chunk_size = (passwords.len + num_threads - 1) / num_threads;
        const threads = try self.allocator.alloc(std.Thread, num_threads);
        defer self.allocator.free(threads);

        const start_time = std.time.nanoTimestamp();

        // Spawn worker threads
        for (threads, 0..) |*thread, i| {
            const start_idx = i * chunk_size;
            const end_idx = @min(start_idx + chunk_size, passwords.len);

            if (start_idx >= passwords.len) {
                // No more work for this thread
                continue;
            }

            const context = try self.allocator.create(ThreadContext);
            context.* = .{
                .allocator = self.allocator,
                .enc_dict = enc_dict,
                .pdf_id = pdf_id,
                .passwords = passwords[start_idx..end_idx],
                .result_ptr = &result_ptr,
                .result_len = &result_len,
                .attempts = &total_attempts,
            };

            thread.* = try std.Thread.spawn(.{}, workerThread, .{ context });
        }

        // Progress monitor thread
        const monitor_thread = try std.Thread.spawn(
            .{},
            progressMonitor,
            .{ &total_attempts, &result_ptr, start_time, passwords.len },
        );

        // Wait for all worker threads
        for (threads, 0..) |thread, i| {
            const start_idx = i * chunk_size;
            if (start_idx >= passwords.len) continue;
            thread.join();
        }

        // Stop monitor
        monitor_thread.join();

        const end_time = std.time.nanoTimestamp();
        const total_time = @as(f64, @floatFromInt(end_time - start_time)) / 1_000_000_000.0;
        const attempts = total_attempts.load(.acquire);

        if (result_ptr.load(.acquire)) |ptr| {
            const len = result_len.load(.acquire);
            const password_slice = ptr[0..len];

            std.debug.print("\n\n[+] PASSWORD FOUND: {s}\n", .{password_slice});
            std.debug.print("[+] Attempts: {d}\n", .{attempts});
            std.debug.print("[+] Time taken: {d:.2} seconds\n", .{total_time});
            std.debug.print("[+] Speed: {d:.2} passwords/sec\n",
                .{ @as(f64, @floatFromInt(attempts)) / total_time });

            return try self.allocator.dupe(u8, password_slice);
        }

        std.debug.print("\n\n[-] Password not found in wordlist\n", .{});
        std.debug.print("[-] Total attempts: {d}\n", .{attempts});
        std.debug.print("[-] Time taken: {d:.2} seconds\n", .{total_time});
        return null;
    }

    /// Single-threaded cracking (legacy)
    pub fn crackPassword(
        self: *PdfCracker,
        enc_dict: *const hash_ext.EncryptionDict,
        pdf_id: []const u8,
        wordlist_path: []const u8,
    ) !?[]const u8 {
        return self.crackPasswordMultithreaded(enc_dict, pdf_id, wordlist_path, 1);
    }

    fn readWordlist(self: *PdfCracker, wordlist_path: []const u8) ![][]const u8 {
        const file = try std.fs.cwd().openFile(wordlist_path, .{});
        defer file.close();

        var passwords = std.ArrayList([]const u8).init(self.allocator);
        errdefer {
            for (passwords.items) |pwd| {
                self.allocator.free(pwd);
            }
            passwords.deinit();
        }

        var buf_reader = std.io.bufferedReader(file.reader());
        var reader = buf_reader.reader();

        var line_buf: [1024]u8 = undefined;
        while (try reader.readUntilDelimiterOrEof(&line_buf, '\n')) |line| {
            const password = std.mem.trim(u8, line, " \t\r\n");
            if (password.len == 0) continue;
            try passwords.append(try self.allocator.dupe(u8, password));
        }

        return passwords.toOwnedSlice();
    }

    /// Compute PDF password hash (Algorithm 3.2 + 3.4/3.5 from PDF specification)
    fn computePdfHash(
        self: *PdfCracker,
        password: []const u8,
        enc_dict: *const hash_ext.EncryptionDict,
        pdf_id: []const u8,
    ) ![]u8 {
        const r = if (enc_dict.R) |r_str|
            try std.fmt.parseInt(u32, r_str, 10)
        else
            3;
        const p = if (enc_dict.P) |p_str|
            try std.fmt.parseInt(i32, p_str, 10)
        else
            -4;
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
            const extra = [_]u8{ 0xFF, 0xFF, 0xFF, 0xFF };
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

        const encryption_key = hash[0..key_len];

        // Algorithm 3.4/3.5: Computing the user password (U)
        if (r == 2) {
            // Algorithm 3.4 (R=2): Encrypt padding string with RC4
            const result = try self.allocator.alloc(u8, 32);
            @memcpy(result, &padding);
            rc4Encrypt(result, encryption_key);
            return result;
        } else {
            // Algorithm 3.5 (R>=3)
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

            // Step d: Pad result to 32 bytes
            const result = try self.allocator.alloc(u8, 32);
            @memcpy(result[0..16], &encrypted);
            @memcpy(result[16..32], padding[16..32]);
            return result;
        }
    }
};

fn workerThread(context: *ThreadContext) void {
    defer context.allocator.destroy(context);

    const r = if (context.enc_dict.R) |r_str|
        std.fmt.parseInt(u32, r_str, 10) catch 3
    else
        3;
    const compare_len: usize = if (r >= 3) 16 else 32;

    for (context.passwords) |password| {
        // Check if another thread found the password
        if (context.result_ptr.load(.acquire) != null) {
            break;
        }

        var cracker = PdfCracker.init(context.allocator);
        const computed_hash = cracker.computePdfHash(
            password,
            context.enc_dict,
            context.pdf_id,
        ) catch continue;
        defer context.allocator.free(computed_hash);

        _ = context.attempts.fetchAdd(1, .monotonic);

        if (context.enc_dict.U) |u_val| {
            if (std.mem.eql(u8, computed_hash[0..compare_len], u_val[0..compare_len])) {
                const password_copy = context.allocator.dupe(u8, password) catch continue;
                context.result_len.store(password_copy.len, .release);
                context.result_ptr.store(password_copy.ptr, .release);
                break;
            }
        }
    }
}

fn progressMonitor(
    attempts: *std.atomic.Value(usize),
    result_ptr: *std.atomic.Value(?[*]const u8),
    start_time: i128,
    total: usize,
) void {
    while (result_ptr.load(.acquire) == null) {
        std.time.sleep(500 * std.time.ns_per_ms);

        const current_attempts = attempts.load(.acquire);
        if (current_attempts == 0) continue;

        const elapsed = @as(f64, @floatFromInt(std.time.nanoTimestamp() - start_time)) / 1_000_000_000.0;
        const rate = @as(f64, @floatFromInt(current_attempts)) / elapsed;
        const progress = (@as(f64, @floatFromInt(current_attempts)) /
            @as(f64, @floatFromInt(total))) * 100.0;

        std.debug.print(
            "\r[*] Progress: {d:.1}% | Tried: {d}/{d} | Speed: {d:.2} pwd/sec     ",
            .{ progress, current_attempts, total, rate },
        );

        if (current_attempts >= total) break;
    }
}

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

