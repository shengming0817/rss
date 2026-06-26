// rss_projection_append_only UI fixture（dylint_testing::ui_test_example 消费）。
// golden 见 disallowed.stderr：RED 3 条触发（DELETE/TRUNCATE projection_events），GREEN 3 条不触发。
#![allow(unused, unknown_lints)]

// RED：触发——DELETE projection_events
const DELETE_PROJECTION: &str = "DELETE FROM projection_events WHERE id = $1";

// RED：触发——TRUNCATE projection_events
const TRUNCATE_PROJECTION: &str = "TRUNCATE projection_events";

// RED：触发——多条件 DELETE projection_events
const MULTILINE_DELETE: &str = "DELETE FROM projection_events WHERE created_at < now()";

// GREEN：不触发——INSERT projection_events（append-only 正常写路径）
const INSERT_PROJECTION: &str = "INSERT INTO projection_events (domain, payload) VALUES ($1, $2)";

// GREEN：不触发——SELECT projection_events（读路径）
const SELECT_PROJECTION: &str = "SELECT * FROM projection_events ORDER BY id ASC LIMIT 10";

// GREEN：不触发——DELETE 其他表（非 projection_events）
const DELETE_OTHER_TABLE: &str = "DELETE FROM outbox WHERE id = $1";

fn main() {}
