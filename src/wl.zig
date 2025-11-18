// wl.zig - PDF password cracking implementation with multithreading and streaming
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
    result_ptr: *std.atomic.Value(?[*]const u8),
    result_len: *std.atomic.Value(usize),
    attempts: *std.atomic.Value(usize),
    cancel_ptr: *std.atomic.Value(bool),
};

pub const PdfCracker = struct {
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) PdfCracker {
        return .{ .allocator = allocator };
    }

    /// Multithreaded password cracking with automatic streaming for large wordlists
    pub fn crackPasswordMultithreaded(
        self: *PdfCracker,
        enc_dict: *const hash_ext.EncryptionDict,
        pdf_id: []const u8,
        wordlist_path: []const u8,
        num_threads: usize,
    ) !?[]const u8 {
        std.debug.print("\n╔══════════════════════════════════════════════════════════╗\n", .{});
        std.debug.print("║          PDF PASSWORD CRACKER                           ║\n", .{});
        std.debug.print("╚══════════════════════════════════════════════════════════╝\n\n", .{});
        
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
        std.debug.print("\n", .{});

        // Count total passwords
        std.debug.print("\n[*] Counting passwords in wordlist...\n", .{});
        const total_passwords = try countPasswordsInFile(wordlist_path);
        std.debug.print("[*] Total passwords: {d}\n", .{total_passwords});

        // Check file size
        const file_stat = try std.fs.cwd().statFile(wordlist_path);
        const file_size_mb = @as(f64, @floatFromInt(file_stat.size)) / (1024.0 * 1024.0);
        std.debug.print("[*] Wordlist size: {d:.2} MB\n", .{file_size_mb});

        // Decide: load all or stream based on size
        const load_threshold_mb = 100.0; // Load into memory if < 100MB
        
        if (file_size_mb < load_threshold_mb) {
            std.debug.print("[*] Loading entire wordlist into memory...\n", .{});
            return try self.crackWithPreloadedWordlist(enc_dict, pdf_id, wordlist_path, num_threads, total_passwords);
        } else {
            std.debug.print("[*] Using streaming mode for large wordlist...\n", .{});
            return try self.crackWithStreamingWordlist(enc_dict, pdf_id, wordlist_path, num_threads, total_passwords);
        }
    }

    /// Original method: load entire wordlist into memory
    fn crackWithPreloadedWordlist(
        self: *PdfCracker,
        enc_dict: *const hash_ext.EncryptionDict,
        pdf_id: []const u8,
        wordlist_path: []const u8,
        num_threads: usize,
        total_passwords: usize,
    ) !?[]const u8 {
        const passwords = try self.readWordlist(wordlist_path);
        defer {
            for (passwords) |pwd| self.allocator.free(pwd);
            self.allocator.free(passwords);
        }

        if (passwords.len == 0) {
            std.debug.print("[-] Empty wordlist\n", .{});
            return null;
        }

        std.debug.print("[*] Loaded {d} passwords\n\n", .{passwords.len});

        var cancel = std.atomic.Value(bool).init(false);
        var result_ptr = std.atomic.Value(?[*]const u8).init(null);
        var result_len = std.atomic.Value(usize).init(0);
        var total_attempts = std.atomic.Value(usize).init(0);

        const start_time = std.time.nanoTimestamp();

        // Launch worker threads
        const chunk_size = (passwords.len + num_threads - 1) / num_threads;
        const threads = try self.allocator.alloc(std.Thread, num_threads);
        defer self.allocator.free(threads);

        var spawned: usize = 0;
        for (threads, 0..) |*thread, i| {
            const start_idx = i * chunk_size;
            const end_idx = @min(start_idx + chunk_size, passwords.len);
            if (start_idx >= passwords.len) continue;

            const context = try self.allocator.create(ThreadContext);
            errdefer self.allocator.destroy(context);

            context.* = .{
                .allocator = self.allocator,
                .enc_dict = enc_dict,
                .pdf_id = pdf_id,
                .passwords = passwords[start_idx..end_idx],
                .result_ptr = &result_ptr,
                .result_len = &result_len,
                .attempts = &total_attempts,
                .cancel_ptr = &cancel,
            };

            thread.* = std.Thread.spawn(.{}, workerThread, .{context}) catch |err| {
                self.allocator.destroy(context);
                cancel.store(true, .release);
                for (0..spawned) |j| threads[j].join();
                return err;
            };
            spawned += 1;
        }

        const monitor_thread = std.Thread.spawn(.{}, progressMonitor, .{
            &total_attempts,
            &result_ptr,
            &cancel,
            start_time,
            total_passwords,
        }) catch |err| {
            cancel.store(true, .release);
            for (0..spawned) |j| threads[j].join();
            return err;
        };

        for (0..spawned) |i| threads[i].join();
        cancel.store(true, .release);
        monitor_thread.join();

        const end_time = std.time.nanoTimestamp();
        const crack_time_ns = end_time - start_time;
        
        return self.handleResult(&result_ptr, &result_len, &total_attempts, start_time, crack_time_ns);
    }

    /// New method: stream wordlist in chunks
    fn crackWithStreamingWordlist(
        self: *PdfCracker,
        enc_dict: *const hash_ext.EncryptionDict,
        pdf_id: []const u8,
        wordlist_path: []const u8,
        num_threads: usize,
        total_passwords: usize,
    ) !?[]const u8 {
        const chunk_size = 50000; // Load 50k passwords at a time
        
        var cancel = std.atomic.Value(bool).init(false);
        var result_ptr = std.atomic.Value(?[*]const u8).init(null);
        var result_len = std.atomic.Value(usize).init(0);
        var total_attempts = std.atomic.Value(usize).init(0);
        var total_crack_time = std.atomic.Value(i128).init(0);

        const start_time = std.time.nanoTimestamp();

        std.debug.print("[*] Starting streaming attack (chunk size: {d})...\n\n", .{chunk_size});

        const file = try std.fs.cwd().openFile(wordlist_path, .{});
        defer file.close();

        var buf_reader = std.io.bufferedReader(file.reader());
        var reader = buf_reader.reader();

        var chunk_passwords = std.ArrayList([]const u8).init(self.allocator);
        defer {
            for (chunk_passwords.items) |pwd| self.allocator.free(pwd);
            chunk_passwords.deinit();
        }

        var line_buf: [1024]u8 = undefined;
        var chunk_num: usize = 0;

        while (true) {
            // Load chunk
            chunk_passwords.clearRetainingCapacity();
            
            var loaded: usize = 0;
            while (loaded < chunk_size) : (loaded += 1) {
                const line = reader.readUntilDelimiterOrEof(&line_buf, '\n') catch |err| {
                    std.debug.print("[!] Read error: {}\n", .{err});
                    break;
                } orelse break;

                const password = std.mem.trim(u8, line, " \t\r\n");
                if (password.len == 0) continue;
                
                try chunk_passwords.append(try self.allocator.dupe(u8, password));
            }

            if (chunk_passwords.items.len == 0) break;

            chunk_num += 1;
            
            // Process this chunk
            const found = try self.processChunk(
                enc_dict,
                pdf_id,
                chunk_passwords.items,
                num_threads,
                &result_ptr,
                &result_len,
                &total_attempts,
                &cancel,
                &total_crack_time,
            );

            if (found) break;

            // Free chunk passwords
            for (chunk_passwords.items) |pwd| self.allocator.free(pwd);
            
            // Show progress with actual cracking speed
            const current_attempts = total_attempts.load(.acquire);
            const crack_time_ns = total_crack_time.load(.acquire);
            const crack_time_s = @as(f64, @floatFromInt(crack_time_ns)) / 1_000_000_000.0;
            const rate = if (crack_time_s > 0.001) @as(f64, @floatFromInt(current_attempts)) / crack_time_s else 0.0;
            const progress = (@as(f64, @floatFromInt(current_attempts)) / @as(f64, @floatFromInt(total_passwords))) * 100.0;
            
            std.debug.print("\r[*] Progress: {d:.1}% | Chunk {d} | Tried: {d}/{d} | Speed: {d:.0} pwd/sec     ", 
                .{ progress, chunk_num, current_attempts, total_passwords, rate });
        }

        const crack_time_ns = total_crack_time.load(.acquire);
        return self.handleResult(&result_ptr, &result_len, &total_attempts, start_time, crack_time_ns);
    }

    fn processChunk(
        self: *PdfCracker,
        enc_dict: *const hash_ext.EncryptionDict,
        pdf_id: []const u8,
        passwords: [][]const u8,
        num_threads: usize,
        result_ptr: *std.atomic.Value(?[*]const u8),
        result_len: *std.atomic.Value(usize),
        total_attempts: *std.atomic.Value(usize),
        cancel: *std.atomic.Value(bool),
        crack_time: *std.atomic.Value(i128),
    ) !bool {
        if (cancel.load(.acquire)) return true;

        const chunk_size = (passwords.len + num_threads - 1) / num_threads;
        const threads = try self.allocator.alloc(std.Thread, num_threads);
        defer self.allocator.free(threads);

        const chunk_start_time = std.time.nanoTimestamp();

        var spawned: usize = 0;
        for (threads, 0..) |*thread, i| {
            const start_idx = i * chunk_size;
            const end_idx = @min(start_idx + chunk_size, passwords.len);
            if (start_idx >= passwords.len) continue;

            const context = try self.allocator.create(ThreadContext);
            errdefer self.allocator.destroy(context);

            context.* = .{
                .allocator = self.allocator,
                .enc_dict = enc_dict,
                .pdf_id = pdf_id,
                .passwords = passwords[start_idx..end_idx],
                .result_ptr = result_ptr,
                .result_len = result_len,
                .attempts = total_attempts,
                .cancel_ptr = cancel,
            };

            thread.* = std.Thread.spawn(.{}, workerThread, .{context}) catch |err| {
                self.allocator.destroy(context);
                cancel.store(true, .release);
                for (0..spawned) |j| threads[j].join();
                return err;
            };
            spawned += 1;
        }

        for (0..spawned) |i| threads[i].join();

        const chunk_end_time = std.time.nanoTimestamp();
        const chunk_duration = chunk_end_time - chunk_start_time;
        _ = crack_time.fetchAdd(chunk_duration, .monotonic);

        return result_ptr.load(.acquire) != null;
    }

    fn handleResult(
        self: *PdfCracker,
        result_ptr: *std.atomic.Value(?[*]const u8),
        result_len: *std.atomic.Value(usize),
        total_attempts: *std.atomic.Value(usize),
        start_time: i128,
        crack_time_ns: i128,
    ) !?[]const u8 {
        const total_elapsed = @as(f64, @floatFromInt(std.time.nanoTimestamp() - start_time)) / 1_000_000_000.0;
        const crack_elapsed = @as(f64, @floatFromInt(crack_time_ns)) / 1_000_000_000.0;
        const attempts = total_attempts.load(.acquire);
        
        // Calculate speed based on actual cracking time (excluding I/O)
        const speed = if (crack_elapsed > 0.001) 
            @as(f64, @floatFromInt(attempts)) / crack_elapsed 
        else 
            @as(f64, @floatFromInt(attempts)) / 0.001;

        if (result_ptr.load(.acquire)) |ptr| {
            const len = result_len.load(.acquire);
            const password_str = ptr[0..len];

            std.debug.print("\r                                                              \r", .{});
            std.debug.print("\n╔══════════════════════════════════════════════════════════╗\n", .{});
            std.debug.print("║                    SUCCESS!                             ║\n", .{});
            std.debug.print("╚══════════════════════════════════════════════════════════╝\n\n", .{});
            std.debug.print("[+] Password Found: \x1b[32m{s}\x1b[0m\n", .{password_str});
            std.debug.print("[+] Attempts: {d}\n", .{attempts});
            std.debug.print("[+] Total Time: {d:.3}s (Cracking: {d:.3}s, I/O: {d:.3}s)\n", .{total_elapsed, crack_elapsed, total_elapsed - crack_elapsed});
            std.debug.print("[+] Avg Speed: {d:.0} passwords/sec\n\n", .{speed});

            const result = try self.allocator.dupe(u8, password_str);
            self.allocator.free(password_str);
            return result;
        }

        std.debug.print("\r                                                              \r", .{});
        std.debug.print("\n╔══════════════════════════════════════════════════════════╗\n", .{});
        std.debug.print("║                    FAILED                               ║\n", .{});
        std.debug.print("╚══════════════════════════════════════════════════════════╝\n\n", .{});
        std.debug.print("[-] Password not found in wordlist\n", .{});
        std.debug.print("[-] Total attempts: {d}\n", .{attempts});
        std.debug.print("[-] Total Time: {d:.3}s (Cracking: {d:.3}s, I/O: {d:.3}s)\n\n", .{total_elapsed, crack_elapsed, total_elapsed - crack_elapsed});
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
};

fn countPasswordsInFile(path: []const u8) !usize {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    var buf_reader = std.io.bufferedReader(file.reader());
    var reader = buf_reader.reader();

    var count: usize = 0;
    var line_buf: [1024]u8 = undefined;
    
    while (try reader.readUntilDelimiterOrEof(&line_buf, '\n')) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r\n");
        if (trimmed.len > 0) count += 1;
    }

    return count;
}

/// Compute PDF password hash (Algorithm 3.2 + 3.4/3.5 from PDF specification)
/// Writes 32 bytes into `out` (for both R=2 and R>=3).
fn computePdfHashInto(
    password: []const u8,
    r: u32,
    p: i32,
    key_len: usize,
    enc_dict: *const hash_ext.EncryptionDict,
    pdf_id: []const u8,
    out: *[32]u8,
) void {
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
        @memcpy(out, &padding);
        rc4Encrypt(out[0..32], encryption_key);
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
        @memcpy(out[0..16], &encrypted);
        @memcpy(out[16..32], padding[16..32]);
    }
}

fn workerThread(context: *ThreadContext) void {
    defer context.allocator.destroy(context);

    // Pre-parse R, P, Length once per thread (instead of per-password)
    const r_value: u32 = blk: {
        if (context.enc_dict.R) |r_str| {
            break :blk std.fmt.parseInt(u32, r_str, 10) catch 3;
        } else break :blk 3;
    };

    const p_value: i32 = blk: {
        if (context.enc_dict.P) |p_str| {
            break :blk std.fmt.parseInt(i32, p_str, 10) catch -4;
        } else break :blk -4;
    };

    const key_len_bits_raw: u32 = blk: {
        if (context.enc_dict.Length) |l_str| {
            break :blk std.fmt.parseInt(u32, l_str, 10) catch 40;
        } else break :blk 40;
    };

    // Clamp to 128 bits max (spec for R=3/4)
    const key_len_bits = @min(key_len_bits_raw, 128);
    const key_len = @as(usize, @intCast(key_len_bits / 8));

    const compare_len: usize = if (r_value >= 3) 16 else 32;

    var hash_buf: [32]u8 = undefined;

    for (context.passwords) |password| {
        // Check if another thread found the password or cancel was requested
        if (context.cancel_ptr.load(.acquire)) break;
        if (context.result_ptr.load(.acquire) != null) break;

        // Compute hash into stack buffer
        computePdfHashInto(
            password,
            r_value,
            p_value,
            key_len,
            context.enc_dict,
            context.pdf_id,
            &hash_buf,
        );

        _ = context.attempts.fetchAdd(1, .monotonic);

        if (context.enc_dict.U) |u_val| {
            if (u_val.len < compare_len) continue;

            if (std.mem.eql(u8, hash_buf[0..compare_len], u_val[0..compare_len])) {
                const password_copy = context.allocator.dupe(u8, password) catch continue;

                const exchange_result = context.result_ptr.cmpxchgStrong(
                    null,
                    password_copy.ptr,
                    .acq_rel,
                    .acquire,
                );

                if (exchange_result) |_| {
                    context.allocator.free(password_copy);
                } else {
                    context.result_len.store(password_copy.len, .release);
                    context.cancel_ptr.store(true, .release);
                }
                break;
            }
        }
    }
}

fn progressMonitor(
    attempts: *std.atomic.Value(usize),
    result: *std.atomic.Value(?[*]const u8),
    cancel: *std.atomic.Value(bool),
    start_time: i128,
    total: usize,
) void {
    while (!cancel.load(.acquire)) {
        std.time.sleep(500 * std.time.ns_per_ms);

        const current_attempts = attempts.load(.acquire);
        if (current_attempts == 0) continue;

        const elapsed = @as(f64, @floatFromInt(std.time.nanoTimestamp() - start_time)) / 1_000_000_000.0;
        const rate = if (elapsed > 0.001) @as(f64, @floatFromInt(current_attempts)) / elapsed else 0.0;
        const progress = (@as(f64, @floatFromInt(current_attempts)) / @as(f64, @floatFromInt(total))) * 100.0;

        std.debug.print(
            "\r[*] Progress: {d:.1}% | Tried: {d}/{d} | Speed: {d:.2} pwd/sec     ",
            .{ progress, current_attempts, total, rate },
        );

        if (result.load(.acquire) != null or current_attempts >= total) break;
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
