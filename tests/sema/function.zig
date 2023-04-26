const fn_type0 = fn () void;
//    ^^^^^^^^ (type)(fn() void)

const fn_type1 = fn () u32;
//    ^^^^^^^^ (type)(fn() u32)

const fn_type2 = fn (u32) u32;
//    ^^^^^^^^ (type)(fn(u32) u32)

const fn_type3 = fn (a: u32, b: []const u8) ?bool;
//    ^^^^^^^^ (type)(fn(u32, []const u8) ?bool)

// zig fmt: off
fn foo() void {
// ^^^ (type)(fn() void)
// zig fmt: on
    // TODO
    // var some_variable = 3;
    // //  ^^^^^^^^^^^^^ (comptime_int)(3)
    // return some_variable;
}
