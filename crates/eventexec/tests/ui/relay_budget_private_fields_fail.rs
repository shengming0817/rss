//! compile-fail：RelayBudget 字段私有，外部调用方只能经校验构造器创建。

use std::time::Duration;

use eventexec::RelayBudget;

fn main() {
    let _budget = RelayBudget {
        lease_ttl: Duration::from_secs(60),
        publish_timeout: Duration::from_secs(40),
        settle_timeout: Duration::from_secs(5),
        safety_margin: Duration::from_secs(5),
    };
}
