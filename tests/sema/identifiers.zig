const T: type = u32;
//    ^ (type)(u32);
const OptionalT = ?T;
//    ^^^^^^^^^ (type)(?u32);

// TODO
// const A = B;
// //    ^ (type)(u32);
// const B = u32;
// //    ^ (type)(u32);
