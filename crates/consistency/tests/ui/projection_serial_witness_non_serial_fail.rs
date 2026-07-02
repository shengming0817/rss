//! 非串行 source 不能 mint SerialInOrder witness。

use consistency::SerialInOrder;

struct NonSerialSource;

fn main() {
    let _witness = SerialInOrder::from_source(&NonSerialSource);
}
