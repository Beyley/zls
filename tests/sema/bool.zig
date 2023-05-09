const True: bool = true;
//    ^^^^ (bool)(true)
const False: bool = false;
//    ^^^^^ (bool)(false)

const TrueEqTrue = true == true;
//    ^^^^^^^^^^ (bool)(true)
const FalseEqFalse = false == false;
//    ^^^^^^^^^^^^ (bool)(true)

const TrueEqFalse = true == false;
//    ^^^^^^^^^^^ (bool)(false)
const FalsEeqTrue = false == true;
//    ^^^^^^^^^^^ (bool)(false)

const TrueNeqTrue = true != true;
//    ^^^^^^^^^^^ (bool)(false)
const FalseNeqFalse = false != false;
//    ^^^^^^^^^^^^^ (bool)(false)

const TrueNeqFalse = true != false;
//    ^^^^^^^^^^^^ (bool)(true)
const FalsNeqTrue = false != true;
//    ^^^^^^^^^^^ (bool)(true)

const TrueToInt = @boolToInt(true);
//    ^^^^^^^^^ (comptime_int)(1)
const FalseToInt = @boolToInt(false);
//    ^^^^^^^^^^ (comptime_int)(0)

const NotTrue = !true;
//    ^^^^^^^ (bool)(false)
const NotFalse = !false;
//    ^^^^^^^^ (bool)(true)

const NotUndefined = !@as(bool, undefined);
//    ^^^^^^^^^^^^ (bool)(undefined)
