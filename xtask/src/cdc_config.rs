//! Debezium CDC connector config renderer for the append-only `outbox_log` table.
//!
//! This is a read-only helper: it prints a Kafka Connect JSON skeleton with RSS placeholders,
//! and does not participate in committed `generated/` drift gates.

use anyhow::Result;
use serde::Serialize;

const CONNECTOR_NAME: &str = "rss-outbox-log-cdc";
const TRANSFORM_ALIAS: &str = "outbox";

pub(crate) fn run_debezium() -> Result<()> {
    println!("{}", render_debezium_json()?);
    Ok(())
}

fn render_debezium_json() -> Result<String> {
    let doc = DebeziumConnector::new();
    Ok(serde_json::to_string_pretty(&doc)?)
}

#[derive(Debug, Serialize)]
struct DebeziumConnector {
    name: &'static str,
    config: DebeziumConnectorConfig,
}

impl DebeziumConnector {
    fn new() -> Self {
        Self {
            name: CONNECTOR_NAME,
            config: DebeziumConnectorConfig::new(),
        }
    }
}

#[derive(Debug, Serialize)]
struct DebeziumConnectorConfig {
    name: &'static str,
    #[serde(rename = "connector.class")]
    connector_class: &'static str,
    #[serde(rename = "plugin.name")]
    plugin_name: &'static str,
    #[serde(rename = "topic.prefix")]
    topic_prefix: &'static str,
    #[serde(rename = "database.hostname")]
    database_hostname: &'static str,
    #[serde(rename = "database.port")]
    database_port: &'static str,
    #[serde(rename = "database.user")]
    database_user: &'static str,
    #[serde(rename = "database.password")]
    database_password: &'static str,
    #[serde(rename = "database.dbname")]
    database_dbname: &'static str,
    #[serde(rename = "slot.name")]
    slot_name: &'static str,
    #[serde(rename = "publication.name")]
    publication_name: &'static str,
    #[serde(rename = "publication.autocreate.mode")]
    publication_autocreate_mode: &'static str,
    #[serde(rename = "snapshot.mode")]
    snapshot_mode: &'static str,
    #[serde(rename = "table.include.list")]
    table_include_list: &'static str,
    transforms: &'static str,
    #[serde(rename = "transforms.outbox.type")]
    transforms_outbox_type: &'static str,
    #[serde(rename = "transforms.outbox.table.field.event.id")]
    transforms_outbox_table_field_event_id: &'static str,
    #[serde(rename = "transforms.outbox.table.field.event.key")]
    transforms_outbox_table_field_event_key: &'static str,
    #[serde(rename = "transforms.outbox.table.field.event.payload")]
    transforms_outbox_table_field_event_payload: &'static str,
    #[serde(rename = "transforms.outbox.route.by.field")]
    transforms_outbox_route_by_field: &'static str,
    #[serde(rename = "transforms.outbox.route.topic.regex")]
    transforms_outbox_route_topic_regex: &'static str,
    #[serde(rename = "transforms.outbox.route.topic.replacement")]
    transforms_outbox_route_topic_replacement: &'static str,
    #[serde(rename = "transforms.outbox.table.op.invalid.behavior")]
    transforms_outbox_table_op_invalid_behavior: &'static str,
    #[serde(rename = "transforms.outbox.table.field.additional.missing")]
    transforms_outbox_table_field_additional_missing: &'static str,
    #[serde(rename = "transforms.outbox.table.fields.additional.placement")]
    transforms_outbox_table_fields_additional_placement: String,
}

impl DebeziumConnectorConfig {
    fn new() -> Self {
        Self {
            name: CONNECTOR_NAME,
            connector_class: "io.debezium.connector.postgresql.PostgresConnector",
            plugin_name: "pgoutput",
            topic_prefix: "rss",
            database_hostname: "${RSS_CDC_DB_HOST}",
            database_port: "${RSS_CDC_DB_PORT}",
            database_user: "${RSS_CDC_DB_USER}",
            database_password: "${RSS_CDC_DB_PASSWORD}",
            database_dbname: "${RSS_CDC_DB_NAME}",
            slot_name: "${RSS_CDC_SLOT_NAME}",
            publication_name: "${RSS_CDC_PUBLICATION_NAME}",
            publication_autocreate_mode: "disabled",
            snapshot_mode: "no_data",
            table_include_list: "public.outbox_log",
            transforms: TRANSFORM_ALIAS,
            transforms_outbox_type: "io.debezium.transforms.outbox.EventRouter",
            transforms_outbox_table_field_event_id: "event_id",
            transforms_outbox_table_field_event_key: "event_id",
            transforms_outbox_table_field_event_payload: "payload",
            transforms_outbox_route_by_field: "topic",
            transforms_outbox_route_topic_regex: "(.*)",
            transforms_outbox_route_topic_replacement: "$1",
            transforms_outbox_table_op_invalid_behavior: "fatal",
            transforms_outbox_table_field_additional_missing: "error",
            transforms_outbox_table_fields_additional_placement: additional_placement_config(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AdditionalHeaderPlacement {
    field: &'static str,
    alias: &'static str,
}

impl AdditionalHeaderPlacement {
    fn as_config(self) -> String {
        let Self { field, alias } = self;
        format!("{field}:header:{alias}")
    }
}

fn additional_placements() -> &'static [AdditionalHeaderPlacement] {
    &[
        AdditionalHeaderPlacement {
            field: "tenant_id",
            alias: "tenantId",
        },
        AdditionalHeaderPlacement {
            field: "contract_version",
            alias: "schemaVersion",
        },
        AdditionalHeaderPlacement {
            field: "schema_hash",
            alias: "schemaHash",
        },
    ]
}

fn additional_placement_config() -> String {
    additional_placements()
        .iter()
        .map(|placement| placement.as_config())
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rendered_config() -> anyhow::Result<(String, serde_json::Value)> {
        let json = render_debezium_json()?;
        let value = serde_json::from_str(&json)?;
        Ok((json, value))
    }

    fn config(
        value: &serde_json::Value,
    ) -> anyhow::Result<&serde_json::Map<String, serde_json::Value>> {
        value
            .get("config")
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| anyhow::anyhow!("connector config object missing"))
    }

    fn assert_config_values(
        config: &serde_json::Map<String, serde_json::Value>,
        expected: &[(&str, &str)],
    ) {
        for (key, value) in expected {
            assert_eq!(
                config.get(*key).and_then(serde_json::Value::as_str),
                Some(*value),
                "{key}"
            );
        }
    }

    #[test]
    fn debezium_config_has_connector_and_smt_prefix() -> anyhow::Result<()> {
        let (_json, value) = rendered_config()?;
        let config = config(&value)?;

        assert_eq!(
            value.get("name").and_then(serde_json::Value::as_str),
            Some(CONNECTOR_NAME)
        );
        assert_config_values(
            config,
            &[
                ("name", CONNECTOR_NAME),
                (
                    "connector.class",
                    "io.debezium.connector.postgresql.PostgresConnector",
                ),
                ("plugin.name", "pgoutput"),
                ("topic.prefix", "rss"),
                ("table.include.list", "public.outbox_log"),
                ("snapshot.mode", "no_data"),
                ("publication.autocreate.mode", "disabled"),
                ("transforms", TRANSFORM_ALIAS),
                (
                    "transforms.outbox.type",
                    "io.debezium.transforms.outbox.EventRouter",
                ),
                ("transforms.outbox.table.field.event.id", "event_id"),
                ("transforms.outbox.table.field.event.key", "event_id"),
                ("transforms.outbox.table.field.event.payload", "payload"),
                ("transforms.outbox.route.by.field", "topic"),
                ("transforms.outbox.route.topic.regex", "(.*)"),
                ("transforms.outbox.route.topic.replacement", "$1"),
                ("transforms.outbox.table.op.invalid.behavior", "fatal"),
            ],
        );

        Ok(())
    }

    #[test]
    fn debezium_config_keeps_database_values_as_placeholders() -> anyhow::Result<()> {
        let (json, value) = rendered_config()?;
        let config = config(&value)?;
        for key in [
            "database.hostname",
            "database.port",
            "database.user",
            "database.password",
            "database.dbname",
            "slot.name",
            "publication.name",
        ] {
            let value = config
                .get(key)
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            assert!(
                value.starts_with("${RSS_CDC_") && value.ends_with('}'),
                "{key} must be an RSS_CDC placeholder, got {value:?}"
            );
        }
        for forbidden in ["postgres://", "localhost", "127.0.0.1", "secret"] {
            assert!(
                !json.to_ascii_lowercase().contains(forbidden),
                "rendered config must not contain concrete secret-ish value {forbidden:?}"
            );
        }
        for token in json.match_indices("${").map(|(index, _)| index) {
            let tail = &json[token..];
            let placeholder_end = tail.find('}').map_or(tail.len(), |index| index + 1);
            let placeholder = &tail[..placeholder_end];
            assert!(
                placeholder.starts_with("${RSS_CDC_"),
                "non-deployment placeholder must not use ${{...}} syntax: {placeholder:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn debezium_config_excludes_unsupported_partition_and_private_headers() -> anyhow::Result<()> {
        let (json, value) = rendered_config()?;
        let config = config(&value)?;
        assert!(!config.contains_key("transforms.outbox.table.field.event.schema.version"));
        assert!(!config.contains_key("transforms.outbox.table.field.event.timestamp"));
        assert!(!json.contains(":partition"));
        assert!(!json.contains(":envelope"));
        assert!(!json.contains("aggregate_id"));
        assert!(!json.contains("contract_id:"));
        assert!(!json.contains("aggregate_type:"));
        assert!(!json.contains("metadata:header"));
        assert!(!json.contains("causation_id:header"));
        Ok(())
    }

    #[test]
    fn debezium_config_additional_placements_are_exact() -> anyhow::Result<()> {
        let (_json, value) = rendered_config()?;
        let config = config(&value)?;
        assert_eq!(
            config["transforms.outbox.table.fields.additional.placement"],
            "tenant_id:header:tenantId,contract_version:header:schemaVersion,schema_hash:header:schemaHash"
        );
        Ok(())
    }
}
