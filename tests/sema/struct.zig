pub const SomeStruct = struct {};
//        ^^^^^^^^^^ (type)(SomeStruct)

pub const OtherStruct = struct { alpha: u32 };
//        ^^^^^^^^^^^ (type)(OtherStruct)

const other_struct: OtherStruct = undefined;
//    ^^^^^^^^^^^^ (OtherStruct)()
const alpha = other_struct.alpha;
//    ^^^^^ (u32)()
