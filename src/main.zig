const std = @import("std");

const Base64 = struct {
    _table: *const [64]u8,

    pub fn init() Base64 {
        const upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        const lower = "abcdefghijklmonpqrstuvwxyz";
        const numbers_symbol = "123456789+/";
        return .{ ._table = upper ++ lower ++ numbers_symbol };
    }

    pub fn _char_at(self: Base64, index: u8) u8 {
        return self._table[index];
    }

    pub fn encode(self: Base64, allocator: std.mem.Allocator, input: []const u8) ![]u8 {
        if (input.len == 0) {
            return "";
        }

        const out_n = _calc_encode_length(input);
        var out = try allocator.alloc(u8, out_n);
        var buf = [3]u8{ 0, 0, 0 };
        var count: u8 = 0;
        var iout: u64 = 0;

        for (input, 0..) |_, i| {
            buf[count] = input[i];
            count += 1;

            if (count == 3) {
                out[iout] = self._char_at(buf[0] >> 2);
                out[iout + 1] = self._char_at(((buf[0] & 0x03) << 4) + (buf[1] >> 4));
                out[iout + 2] = self._char_at(((buf[1] & 0x0f) << 2) + (buf[2] >> 6));
                out[iout + 3] = self._char_at(buf[2] & 0x3f);
                iout += 4;
                count = 0;
            }
        }

        if (count == 1) {
            out[iout] = self._char_at(buf[0] >> 2);
            out[iout + 1] = self._char_at(((buf[0] & 0x03) << 4) + (buf[1] >> 4));
            out[iout + 2] = '=';
            out[iout + 3] = '=';
            iout += 4;
        }

        if (count == 2) {
            out[iout] = self._char_at(buf[0] >> 2);
            out[iout + 1] = self._char_at(((buf[0] & 0x03) << 4) + (buf[1] >> 4));
            out[iout + 2] = self._char_at(((buf[1] & 0x0f) << 2) + (buf[2] >> 6));
            out[iout + 3] = '=';
            iout += 4;
        }

        return out;
    }

    fn _char_index(self: Base64, char: u8) u8 {
        if (char == '=') {
            return 64;
        }

        var index: u8 = 0;
        var i:u8 = 0;
        while(i < 63){
            if (self._char_at(i) == char) {
                index = i;
                break;
            }
            i += 1;
        }

        return index;
    }

    fn decode(self: Base64, allocator: std.mem.Allocator, input: []const u8) ![]u8 {
        if (input.len == 0) {
            return "";
        }

        const output_len = _calc_decode_length(input);
        var output = try allocator.alloc(u8, output_len);

        for (output, 0..) |_, i| {
            output[i] = 0;
        }

        var buff: [4]u8 = .{0,0,0,0};
        var count: u8 = 0;
        var iout: u64 = 0;

        for(input, 0..) |_, i|{
            buff[count] = self._char_index(input[i]);
            count += 1;

            if(count == 4){
                output[iout] = (buff[0] << 2) + (buff[1] >> 4);

                if (buff[2] != 64) {
                    output[iout + 1] = (buff[1] << 4) + (buff[2] >> 2);
                }

                if (buff[3] != 64) {
                    output[iout + 2] = (buff[2] << 6) + buff[3];
                }

                iout += 3;
                count = 0;
            }
        }

        return output;
    }
};

fn _calc_encode_length(input: []const u8) u64 {
    if (input.len < 3) {
        const n_output: u64 = 4;
        return n_output;
    }

    const len_as_float: f64 = @floatFromInt(input.len);
    const n_output: u64 = @intFromFloat(@ceil(len_as_float / 3.0) * 4.0);

    return n_output;
}

fn _calc_decode_length(input: []const u8) u64 {
    if (input.len < 4) {
        const n_output: u64 = 3;
        return n_output;
    }

    const len_as_float: f64 = @floatFromInt(input.len);
    const n_output: u64 = @intFromFloat(@floor(len_as_float / 4) * 3);
    return n_output;
}

pub fn main() !void {
    var memory_buffer: [1000]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&memory_buffer);
    const allocator = fba.allocator();

    const hello = "Testing some shit";

    const base64 = Base64.init();

    const encoded_text = try base64.encode(allocator, hello);
    const decoded_text = try base64.decode(allocator, encoded_text);

    std.debug.print("TEST TEXT {s}\n", .{hello});
    std.debug.print("ENCODE TEXT {s}\n", .{encoded_text});
    std.debug.print("DECODE TEXT {s}", .{decoded_text});
}
