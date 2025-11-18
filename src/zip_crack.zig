// zip_crack.zig - ZIP password cracking with streaming for large wordlists
const std = @import("std");

pub const ZipEncryption = enum {
    ZipCrypto,
    AES128,
    AES192,
    AES256,
    Unknown,

    pub fn getName(self: ZipEncryption) []const u8 {
        return switch (self) {
            .ZipCrypto => "ZipCrypto (Traditional PKWARE)",
            .AES128 => "AES-128 (WinZip)",
            .AES192 => "AES-192 (WinZip)",
            .AES256 => "AES-256 (WinZip)",
            .Unknown => "Unknown",
        };
    }

    pub fn getHashcatMode(self: ZipEncryption) u32 {
        return switch (self) {
            .ZipCrypto => 17200,
            .AES128 => 13600,
            .AES192 => 13600,
            .AES256 => 13600,
            .Unknown => 0,
        };
    }
};

pub const ZipFileInfo = struct {
    filename: []const u8,
    compression_method: u16,
    encryption_method: ZipEncryption,
    crc32: u32,
    compressed_size: u32,
    uncompressed_size: u32,
    encryption_header: [12]u8,
    has_data_descriptor: bool,
    modification_time: u16,
    flags: u16,
    encrypted_data: []const u8,

    pub fn deinit(self: *const ZipFileInfo, allocator: std.mem.Allocator) void {
        allocator.free(self.filename);
        allocator.free(self.encrypted_data);
    }
};

const ZipThreadContext = struct {
    allocator: std.mem.Allocator,
    zip_info: *const ZipFileInfo,
    passwords: [][]const u8,
    result_ptr: *std.atomic.Value(?[*]const u8),
    result_len: *std.atomic.Value(usize),
    attempts: *std.atomic.Value(usize),
    cancel_ptr: *std.atomic.Value(bool),
};

pub const ZipCracker = struct {
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) ZipCracker {
        return .{ .allocator = allocator };
    }

    pub fn extractZipInfo(self: *ZipCracker, zip_path: []const u8) !ZipFileInfo {
        const file = try std.fs.cwd().openFile(zip_path, .{});
        defer file.close();

        var header_buf: [30]u8 = undefined;
        _ = try file.readAll(&header_buf);

        const signature = std.mem.readInt(u32, header_buf[0..4], .little);
        if (signature != 0x04034b50) return error.InvalidZipFile;

        const version = std.mem.readInt(u16, header_buf[4..6], .little);
        const flags = std.mem.readInt(u16, header_buf[6..8], .little);
        const compression = std.mem.readInt(u16, header_buf[8..10], .little);
        const mod_time = std.mem.readInt(u16, header_buf[10..12], .little);
        const crc = std.mem.readInt(u32, header_buf[14..18], .little);
        const compressed_size = std.mem.readInt(u32, header_buf[18..22], .little);
        const uncompressed_size = std.mem.readInt(u32, header_buf[22..26], .little);
        const filename_len = std.mem.readInt(u16, header_buf[26..28], .little);
        const extra_len = std.mem.readInt(u16, header_buf[28..30], .little);

        _ = version;

        const is_encrypted = (flags & 0x0001) != 0;
        if (!is_encrypted) return error.ZipNotEncrypted;
        if (compressed_size < 12) return error.UnsupportedZipLayout;

        const filename = try self.allocator.alloc(u8, filename_len);
        errdefer self.allocator.free(filename);
        _ = try file.readAll(filename);

        if (extra_len > 0) try file.seekBy(extra_len);

        var enc_header: [12]u8 = undefined;
        _ = try file.readAll(&enc_header);

        const data_len: usize = @intCast(compressed_size - 12);
        const encrypted_data = try self.allocator.alloc(u8, data_len);
        errdefer self.allocator.free(encrypted_data);
        _ = try file.readAll(encrypted_data);

        var encryption_type = ZipEncryption.ZipCrypto;
        if (compression == 99) encryption_type = .AES256;

        const has_dd = (flags & 0x0008) != 0;

        return ZipFileInfo{
            .filename = filename,
            .compression_method = compression,
            .encryption_method = encryption_type,
            .crc32 = crc,
            .compressed_size = compressed_size,
            .uncompressed_size = uncompressed_size,
            .encryption_header = enc_header,
            .has_data_descriptor = has_dd,
            .modification_time = mod_time,
            .flags = flags,
            .encrypted_data = encrypted_data,
        };
    }

    /// Multithreaded password cracking with chunked loading for large wordlists
    pub fn crackPasswordMultithreaded(
        self: *ZipCracker,
        zip_info: *const ZipFileInfo,
        wordlist_path: []const u8,
        num_threads: usize,
    ) !?[]const u8 {
        std.debug.print("\n╔══════════════════════════════════════════════════════════╗\n", .{});
        std.debug.print("║          ZIP PASSWORD CRACKER                           ║\n", .{});
        std.debug.print("╚══════════════════════════════════════════════════════════╝\n\n", .{});

        std.debug.print("[*] Target File: {s}\n", .{zip_info.filename});
        std.debug.print("[*] Encryption: {s}\n", .{zip_info.encryption_method.getName()});
        std.debug.print("[*] Compression: {d}\n", .{zip_info.compression_method});
        std.debug.print("[*] CRC32: 0x{x:0>8}\n", .{zip_info.crc32});
        std.debug.print("[*] Threads: {d}\n", .{num_threads});

        if (zip_info.encryption_method != .ZipCrypto) {
            std.debug.print("\n[!] WARNING: Only ZipCrypto is currently supported\n", .{});
            return error.UnsupportedEncryption;
        }

        // First, count total passwords (fast scan)
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
            return try self.crackWithPreloadedWordlist(zip_info, wordlist_path, num_threads, total_passwords);
        } else {
            std.debug.print("[*] Using streaming mode for large wordlist...\n", .{});
            return try self.crackWithStreamingWordlist(zip_info, wordlist_path, num_threads, total_passwords);
        }
    }

    /// Original method: load entire wordlist into memory
    fn crackWithPreloadedWordlist(
        self: *ZipCracker,
        zip_info: *const ZipFileInfo,
        wordlist_path: []const u8,
        num_threads: usize,
        total_passwords: usize,
    ) !?[]const u8 {
        const passwords = try self.readWordlist(wordlist_path);
        defer {
            for (passwords) |pwd| self.allocator.free(pwd);
            self.allocator.free(passwords);
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

            const context = try self.allocator.create(ZipThreadContext);
            errdefer self.allocator.destroy(context);

            context.* = .{
                .allocator = self.allocator,
                .zip_info = zip_info,
                .passwords = passwords[start_idx..end_idx],
                .result_ptr = &result_ptr,
                .result_len = &result_len,
                .attempts = &total_attempts,
                .cancel_ptr = &cancel,
            };

            thread.* = std.Thread.spawn(.{}, zipWorkerThread, .{context}) catch |err| {
                self.allocator.destroy(context);
                cancel.store(true, .release);
                for (0..spawned) |j| threads[j].join();
                return err;
            };
            spawned += 1;
        }

        const monitor_thread = std.Thread.spawn(.{}, zipProgressMonitor, .{
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
        self: *ZipCracker,
        zip_info: *const ZipFileInfo,
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
                zip_info,
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
        self: *ZipCracker,
        zip_info: *const ZipFileInfo,
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

            const context = try self.allocator.create(ZipThreadContext);
            errdefer self.allocator.destroy(context);

            context.* = .{
                .allocator = self.allocator,
                .zip_info = zip_info,
                .passwords = passwords[start_idx..end_idx],
                .result_ptr = result_ptr,
                .result_len = result_len,
                .attempts = total_attempts,
                .cancel_ptr = cancel,
            };

            thread.* = std.Thread.spawn(.{}, zipWorkerThread, .{context}) catch |err| {
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
        self: *ZipCracker,
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

    pub fn crackPassword(
        self: *ZipCracker,
        zip_info: *const ZipFileInfo,
        wordlist_path: []const u8,
    ) !?[]const u8 {
        return self.crackPasswordMultithreaded(zip_info, wordlist_path, 1);
    }

    fn readWordlist(self: *ZipCracker, wordlist_path: []const u8) ![][]const u8 {
        const file = try std.fs.cwd().openFile(wordlist_path, .{});
        defer file.close();

        var passwords = std.ArrayList([]const u8).init(self.allocator);
        errdefer {
            for (passwords.items) |pwd| self.allocator.free(pwd);
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

    fn testZipPassword(zip_info: *const ZipFileInfo, password: []const u8) bool {
        var keys: [3]u32 = .{ 0x12345678, 0x23456789, 0x34567890 };

        for (password) |char| updateKeys(&keys, char);

        var decrypted_header: [12]u8 = undefined;
        for (zip_info.encryption_header, 0..) |byte, i| {
            const k = decryptByte(keys[2]);
            decrypted_header[i] = byte ^ k;
            updateKeys(&keys, decrypted_header[i]);
        }

        const check_byte = decrypted_header[11];
        const expected_check: u8 = if (zip_info.has_data_descriptor)
            @as(u8, @truncate(zip_info.modification_time >> 8))
        else
            @as(u8, @truncate(zip_info.crc32 >> 24));

        if (check_byte != expected_check) return false;

        if (zip_info.compression_method != 0) return true;

        var crc: u32 = 0xFFFF_FFFF;
        for (zip_info.encrypted_data) |cipher| {
            const k = decryptByte(keys[2]);
            const plain = cipher ^ k;
            updateKeys(&keys, plain);
            crc = crc32Update(crc, plain);
        }

        return ~crc == zip_info.crc32;
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

fn zipWorkerThread(context: *ZipThreadContext) void {
    defer context.allocator.destroy(context);

    for (context.passwords) |password| {
        if (context.cancel_ptr.load(.acquire)) break;
        if (context.result_ptr.load(.acquire) != null) break;

        _ = context.attempts.fetchAdd(1, .monotonic);

        if (ZipCracker.testZipPassword(context.zip_info, password)) {
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

fn zipProgressMonitor(
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
        const rate = @as(f64, @floatFromInt(current_attempts)) / elapsed;
        const progress = (@as(f64, @floatFromInt(current_attempts)) / @as(f64, @floatFromInt(total))) * 100.0;

        std.debug.print(
            "\r[*] Progress: {d:.1}% | Tried: {d}/{d} | Speed: {d:.2} pwd/sec     ",
            .{ progress, current_attempts, total, rate },
        );

        if (result.load(.acquire) != null or current_attempts >= total) break;
    }
}

fn updateKeys(keys: *[3]u32, char: u8) void {
    keys[0] = crc32Update(keys[0], char);
    keys[1] = keys[1] +% (keys[0] & 0xFF);
    keys[1] = keys[1] *% 134775813 +% 1;
    keys[2] = crc32Update(keys[2], @as(u8, @truncate(keys[1] >> 24)));
}

fn decryptByte(key2: u32) u8 {
    const temp = key2 | 2;
    return @truncate((temp *% (temp ^ 1)) >> 8);
}

const CRC32_TABLE: [256]u32 = blk: {
    @setEvalBranchQuota(10000);
    var table: [256]u32 = undefined;
    var i: usize = 0;
    while (i < 256) : (i += 1) {
        var crc: u32 = @intCast(i);
        var j: usize = 0;
        while (j < 8) : (j += 1) {
            if (crc & 1 != 0) {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc = crc >> 1;
            }
        }
        table[i] = crc;
    }
    break :blk table;
};

fn crc32Update(crc: u32, char: u8) u32 {
    return (crc >> 8) ^ CRC32_TABLE[@as(u8, @truncate(crc)) ^ char];
}

fn printHex(data: []const u8) void {
    for (data) |byte| {
        std.debug.print("{x:0>2}", .{byte});
    }
}
