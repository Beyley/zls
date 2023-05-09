const foo = blk: {
    //^^^ (comptime_int)(3)
    break :blk 3;
};

const bar = blk: {
    //^^^ (bool)(false)
    if (true) {
        break :blk false;
    } else {
        break :blk true;
    }
};
