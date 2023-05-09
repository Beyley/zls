const ptr_to_u32 = *u32;
//    ^^^^^^^^^^ (type)(*u32)
const slice_of_u32 = []u32;
//    ^^^^^^^^^^^^ (type)([]u32)
// TODO
// const complicated_ptr = [*:3]align(4:2:1) u32;
// //^^^^^^^^^^^^^^^ (type)([*:3]align(4:2:1) u32)
