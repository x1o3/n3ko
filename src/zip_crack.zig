// zip_crack.zig - ZIP password cracking implementation with multithreading
const std = @import("std");

pub const ZipEncryption = enum {
    ZipCrypto,    // Traditional PKWARE encryption
    AES128,       // WinZip AES-128
    AES192,       // WinZip AES-192
    AES256,       // WinZip AES-256
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
            .ZipCrypto => 17200,  // PKZIP (Compressed)
            .AES128 => 13600,     // WinZip AES
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
    // Encrypted file data AFTER the 12-byte encryption header
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
};

pub const ZipCracker = struct {
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) ZipCracker {
        return .{ .allocator = allocator };
    }

    /// Extract ZIP encryption info from file
    pub fn extractZipInfo(self: *ZipCracker, zip_path: []const u8) !ZipFileInfo {
        const file = try std.fs.cwd().openFile(zip_path, .{});
        defer file.close();

        // Read first local file header (30 bytes)
        var header_buf: [30]u8 = undefined;
        _ = try file.readAll(&header_buf);

        // Check signature: 0x04034b50
        const signature = std.mem.readInt(u32, header_buf[0..4], .little);
        if (signature != 0x04034b50) {
            return error.InvalidZipFile;
        }

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

        // Check if encrypted (bit 0 of flags)
        const is_encrypted = (flags & 0x0001) != 0;
        if (!is_encrypted) {
            return error.ZipNotEncrypted;
        }

        // Sanity: we expect compressed_size to be known and >= 12
        if (compressed_size < 12) {
            return error.UnsupportedZipLayout;
        }

        // Read filename
        const filename = try self.allocator.alloc(u8, filename_len);
        errdefer self.allocator.free(filename);
        _ = try file.readAll(filename);

        // Skip extra field
        if (extra_len > 0) {
            try file.seekBy(extra_len);
        }

        // Read 12-byte encryption header
        var enc_header: [12]u8 = undefined;
        _ = try file.readAll(&enc_header);

        // Remaining encrypted data (compressed_size includes enc header)
        const data_len: usize = @intCast(compressed_size - 12);
        const encrypted_data = try self.allocator.alloc(u8, data_len);
        errdefer self.allocator.free(encrypted_data);
        _ = try file.readAll(encrypted_data);

        // Determine encryption type
        var encryption_type = ZipEncryption.ZipCrypto;

        // Check for AES encryption in extra field (simplified: method=99)
        if (compression == 99) {
            encryption_type = .AES256; // Default to strongest
        }

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

    /// Multithreaded password cracking
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
        std.debug.print("[*] Compressed Size: {d}\n", .{zip_info.compressed_size});
        std.debug.print("[*] Uncompressed Size: {d}\n", .{zip_info.uncompressed_size});
        std.debug.print("[*] Modification Time: 0x{x:0>4}\n", .{zip_info.modification_time});
        std.debug.print("[*] Flags: 0x{x:0>4} (data descriptor: {s})\n",
            .{ zip_info.flags, if (zip_info.has_data_descriptor) "yes" else "no" });
        std.debug.print("[*] Hashcat Mode: {d}\n", .{zip_info.encryption_method.getHashcatMode()});
        std.debug.print("[*] Threads: {d}\n", .{num_threads});

        if (zip_info.encryption_method != .ZipCrypto) {
            std.debug.print("\n[!] WARNING: Only ZipCrypto is currently supported\n", .{});
            std.debug.print("[!] AES encryption requires additional implementation\n\n", .{});
            return error.UnsupportedEncryption;
        }

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

        std.debug.print("\n[*] Starting brute force attack...\n", .{});
        std.debug.print("[*] Encryption header: ", .{});
        printHex(&zip_info.encryption_header);
        std.debug.print("\n", .{});

        const expected_crc_check = @as(u8, @truncate(zip_info.crc32 >> 24));
        const expected_time_check = @as(u8, @truncate(zip_info.modification_time >> 8));
        const selected_expected: u8 = if (zip_info.has_data_descriptor) expected_time_check else expected_crc_check;

        std.debug.print("[*] Expected check byte (CRC-based):  0x{x:0>2}\n", .{expected_crc_check});
        std.debug.print("[*] Expected check byte (Time-based): 0x{x:0>2}\n", .{expected_time_check});
        std.debug.print("[*] Using check byte:                0x{x:0>2}\n", .{selected_expected});

        std.debug.print("[*] Loaded {d} passwords from wordlist\n\n", .{passwords.len});

        // Shared result storage
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

            if (start_idx >= passwords.len) continue;

            const context = try self.allocator.create(ZipThreadContext);
            context.* = .{
                .allocator = self.allocator,
                .zip_info = zip_info,
                .passwords = passwords[start_idx..end_idx],
                .result_ptr = &result_ptr,
                .result_len = &result_len,
                .attempts = &total_attempts,
            };

            thread.* = std.Thread.spawn(.{}, zipWorkerThread, .{ context }) catch {
                self.allocator.destroy(context);
                return error.ThreadSpawnFailed;
            };
        }

        // Progress monitor thread
        const monitor_thread = try std.Thread.spawn(
            .{},
            zipProgressMonitor,
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

        const elapsed = @as(f64, @floatFromInt(std.time.nanoTimestamp() - start_time)) / 1_000_000_000.0;
        const attempts = total_attempts.load(.acquire);

        if (result_ptr.load(.acquire)) |ptr| {
            const len = result_len.load(.acquire);
            const password_str = ptr[0..len];

            // erase progress line
            std.debug.print("\r                                                    \r", .{});

            std.debug.print("\n╔══════════════════════════════════════════════════════════╗\n", .{});
            std.debug.print("║                    SUCCESS!                             ║\n", .{});
            std.debug.print("╚══════════════════════════════════════════════════════════╝\n\n", .{});

            std.debug.print("[+] Password Found: \x1b[32m{s}\x1b[0m\n", .{password_str});
            std.debug.print("[+] Attempts: {d}\n", .{attempts});
            std.debug.print("[+] Time: {d:.2}s\n", .{elapsed});
            std.debug.print(
                "[+] Speed: {d:.2} passwords/sec\n\n",
                .{ @as(f64, @floatFromInt(attempts)) / elapsed },
            );

            // Make a safe copy first
            const result = try self.allocator.dupe(u8, password_str);
            self.allocator.free(password_str);
            return result;
        }

        std.debug.print("\r                                                    \r", .{});
        std.debug.print("\n╔══════════════════════════════════════════════════════════╗\n", .{});
        std.debug.print("║                    FAILED                               ║\n", .{});
        std.debug.print("╚══════════════════════════════════════════════════════════╝\n\n", .{});
        std.debug.print("[-] Password not found in wordlist\n", .{});
        std.debug.print("[-] Total attempts: {d}\n", .{attempts});
        std.debug.print("[-] Time: {d:.2}s\n\n", .{elapsed});
        return null;
    }

    /// Single-threaded cracking (legacy)
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

    /// Full ZipCrypto verification:
    /// 1) Check-byte matches
    /// 2) Decrypt stored data, compute CRC32, match file CRC
    fn testZipPassword(zip_info: *const ZipFileInfo, password: []const u8) bool {
        // Initialize ZipCrypto keys
        var keys: [3]u32 = .{ 0x12345678, 0x23456789, 0x34567890 };

        // Update keys with password
        for (password) |char| {
            updateKeys(&keys, char);
        }

        // Decrypt the 12-byte encryption header
        var decrypted_header: [12]u8 = undefined;
        for (zip_info.encryption_header, 0..) |byte, i| {
            const k = decryptByte(keys[2]);
            decrypted_header[i] = byte ^ k;
            updateKeys(&keys, decrypted_header[i]);
        }

        const check_byte = decrypted_header[11];

        // 1-byte quick check (spec):
        // - if data descriptor is used: high byte of mod time
        // - otherwise: high byte of CRC32
        const expected_check: u8 = if (zip_info.has_data_descriptor)
            @as(u8, @truncate(zip_info.modification_time >> 8))
        else
            @as(u8, @truncate(zip_info.crc32 >> 24));

        if (check_byte != expected_check) {
            return false;
        }

        // For compression method 0 (stored), we can do a STRONG check:
        // decrypt full data, compute CRC32, compare.
        if (zip_info.compression_method != 0) {
            // For now, only strong-verify stored files.
            return true; // already passed 1-byte check; best-effort
        }

        // Re-use current keys (already advanced by header) to decrypt data
        var crc: u32 = 0xFFFF_FFFF;

        for (zip_info.encrypted_data) |cipher| {
            const k = decryptByte(keys[2]);
            const plain = cipher ^ k;
            updateKeys(&keys, plain);

            crc = crc32Update(crc, plain);
        }

        crc = ~crc;

        return crc == zip_info.crc32;
    }
};

fn zipWorkerThread(context: *ZipThreadContext) void {
    defer context.allocator.destroy(context);

    for (context.passwords) |password| {
        // Check if another thread found the password
        if (context.result_ptr.load(.acquire) != null) {
            break;
        }

        _ = context.attempts.fetchAdd(1, .monotonic);

        if (ZipCracker.testZipPassword(context.zip_info, password)) {
            const password_copy = context.allocator.dupe(u8, password) catch continue;
            context.result_ptr.store(password_copy.ptr, .release);
            context.result_len.store(password_copy.len, .release);
            break;
        }
    }
}

fn zipProgressMonitor(
    attempts: *std.atomic.Value(usize),
    result: *std.atomic.Value(?[*]const u8),
    start_time: i128,
    total: usize,
) void {
    while (result.load(.acquire) == null) {
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

/// ZipCrypto key update function
fn updateKeys(keys: *[3]u32, char: u8) void {
    keys[0] = crc32Update(keys[0], char);
    keys[1] = keys[1] +% (keys[0] & 0xFF);
    keys[1] = keys[1] *% 134775813 +% 1;
    keys[2] = crc32Update(keys[2], @as(u8, @truncate(keys[1] >> 24)));
}

/// Decrypt single byte
fn decryptByte(key2: u32) u8 {
    const temp = key2 | 2;
    return @truncate((temp *% (temp ^ 1)) >> 8);
}

/// Precomputed CRC32 lookup table (standard polynomial 0xedb88320)
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

