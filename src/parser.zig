const std = @import("std");

pub const PdfParser = struct {};

pub fn parseDictionary(
    dict_slice: []const u8,
    allocator: std.mem.Allocator,
) !std.StringHashMap([]const u8) {
    // Create a mutable hash map on the stack
    var dict = std.StringHashMap([]const u8).init(allocator);
    var i: usize = 0;
    const len = dict_slice.len;
    
    while (i < len) : (i += 1) {
        if (dict_slice[i] == '/') {
            // Parse key
            i += 1;
            const key_start = i;
            while (i < len and !std.ascii.isWhitespace(dict_slice[i]) and dict_slice[i] != '>') : (i += 1) {}
            const key = dict_slice[key_start..i];
            
            // Skip whitespace
            while (i < len and std.ascii.isWhitespace(dict_slice[i])) : (i += 1) {}
            
            // Parse value
            if (i < len and dict_slice[i] == '<' and i + 1 < len and dict_slice[i+1] != '<') {
                // Hex string
                const val_start = i + 1;
                while (i < len and dict_slice[i] != '>') : (i += 1) {}
                const value = dict_slice[val_start..i];
                try dict.put(key, value);
                i += 1;
            } else if (i < len and dict_slice[i] == '/') {
                // Name
                i += 1;
                const val_start = i;
                while (i < len and !std.ascii.isWhitespace(dict_slice[i]) and dict_slice[i] != '>') : (i += 1) {}
                const value = dict_slice[val_start..i];
                try dict.put(key, value);
            } else if (i < len and (std.ascii.isDigit(dict_slice[i]) or dict_slice[i] == '-')) {
                // Number
                const val_start = i;
                while (i < len and (std.ascii.isDigit(dict_slice[i]) or dict_slice[i] == '-' or dict_slice[i] == '.')) : (i += 1) {}
                const value = dict_slice[val_start..i];
                try dict.put(key, value);
            }
        }
    }
    return dict; 
}
