//! Always-on Medium ownership gate for the MQTT wire namespace.
//!
//! Kept outside `#![cfg(feature = "broker-tests")]` so ArchRules enrolls `exec = "test"`
//! against default-feature AST symbols.

use std::path::{Path, PathBuf};

/// INVARIANT: MQTT-RAW-NAMESPACE-01 { level = "Medium", exec = "test", source = "code", synthetic_red = "raw_mqtt_namespace_detects_rogue_concat", anti_vacuity = "raw_mqtt_namespace_anti_vacuity_ignores_comment_only_bait" }
/// Medium gate: `rss/v1/` concatenation is confined to policy/plugin/fixture owners.
const NAMESPACE_MARKER: &str = "rss/v1/";

fn mqtt_raw_namespace_sites(source: &str) -> Vec<String> {
    source
        .lines()
        .filter(|line| line.contains(NAMESPACE_MARKER) && !line.trim_start().starts_with("//"))
        .map(str::to_owned)
        .collect()
}

fn allowlisted_owner(path: &Path) -> bool {
    let normalized = path.to_string_lossy().replace('\\', "/");
    normalized.ends_with("adapters/mqtt/src/topic.rs")
        || normalized.ends_with("adapters/mqtt/mosquitto-plugin/plugin.c")
        || normalized.ends_with("crates/testkit/src/containers.rs")
        || normalized.ends_with("adapters/mqtt/tests/ownership_gate.rs")
}

fn walk_source_files(root: &Path, out: &mut Vec<PathBuf>) {
    let entries = match std::fs::read_dir(root) {
        Ok(entries) => entries,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk_source_files(&path, out);
            continue;
        }
        let Some(ext) = path.extension().and_then(|ext| ext.to_str()) else {
            continue;
        };
        if matches!(ext, "rs" | "c") {
            out.push(path);
        }
    }
}

fn workspace_roots() -> Vec<PathBuf> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace = manifest
        .join("../..")
        .canonicalize()
        .expect("workspace root");
    [
        "adapters",
        "assemblies",
        "bins",
        "composition",
        "crates",
        "examples",
        "journeys",
    ]
    .into_iter()
    .map(|directory| workspace.join(directory))
    .collect()
}

#[test]
fn raw_mqtt_namespace_owners_mint_prefix() {
    let policy = include_str!("../src/topic.rs");
    let plugin = include_str!("../mosquitto-plugin/plugin.c");
    let fixture = include_str!("../../../crates/testkit/src/containers.rs");
    assert!(
        !mqtt_raw_namespace_sites(policy).is_empty() || policy.contains("TOPIC_PREFIX"),
        "policy owner must mint the namespace"
    );
    assert!(
        !mqtt_raw_namespace_sites(plugin).is_empty(),
        "plugin owner must compare exact rss/v1 topics"
    );
    assert!(
        !mqtt_raw_namespace_sites(fixture).is_empty(),
        "fixture owner may render exact ACL topics"
    );
}

#[test]
fn broker_plugin_downlink_contract_set_is_exact() {
    let plugin = include_str!("../mosquitto-plugin/plugin.c");
    let downlink = plugin
        .split_once("static bool exact_downlink_topic")
        .and_then(|(_, tail)| tail.split_once("static bool device_topic_allowed"))
        .map(|(function, _)| function)
        .expect("exact plugin downlink authorization function");
    for contract in [
        "identity.commands.apply-device-certificate",
        "identity.device-ingress-receipted",
    ] {
        assert_eq!(
            downlink.matches(contract).count(),
            1,
            "plugin must authorize the exact downlink contract once: {contract}"
        );
    }
    assert_eq!(
        downlink.matches("identity.").count(),
        2,
        "plugin downlink authorization must remain a two-contract closed set"
    );
}

#[test]
fn raw_mqtt_namespace_anti_vacuity_ignores_comment_only_bait() {
    // Anti-vacuity / string bait: comments alone are not production sites; literal bait still is.
    let bait = "// rss/v1/ should not count\nlet _ = \"rss/v1/\";\n";
    let sites = mqtt_raw_namespace_sites(bait);
    assert!(
        sites.iter().all(|line| line.contains("let _")),
        "gate must still observe literal bait for anti-vacuity: {sites:?}"
    );
    assert!(
        mqtt_raw_namespace_sites("// rss/v1/ comment only\n").is_empty(),
        "comment-only bait must not count as a production site"
    );
}

#[test]
fn raw_mqtt_namespace_detects_rogue_concat() {
    // Synthetic red: a rogue concat outside owners must be detectable.
    let rogue = r#"fn bad() { let _ = format!("rss/v1/{}/uplink", "x"); }"#;
    assert!(!mqtt_raw_namespace_sites(rogue).is_empty());
}

#[test]
fn raw_mqtt_namespace_is_confined_to_allowlisted_owners() {
    let mut files = Vec::new();
    for root in workspace_roots() {
        walk_source_files(&root, &mut files);
    }
    assert!(
        !files.is_empty(),
        "ownership gate must discover mqtt/testkit sources"
    );

    let mut violations = Vec::new();
    for path in files {
        if allowlisted_owner(&path) {
            continue;
        }
        let source = std::fs::read_to_string(&path).expect("readable source");
        let sites = mqtt_raw_namespace_sites(&source);
        if !sites.is_empty() {
            violations.push(format!("{}: {sites:?}", path.display()));
        }
    }
    assert!(
        violations.is_empty(),
        "rss/v1/ must stay in allowlisted owners; violations: {violations:?}"
    );
}

/// INVARIANT: MQTT-INGRESS-ACK-CALLSITE-01 { level = "Medium", exec = "test", source = "code", synthetic_red = "mqtt_ingress_ack_gate_rejects_second_callsite_and_string_bait", anti_vacuity = "mqtt_ingress_ack_gate_finds_exact_postgres_proof_bridge" }
/// Medium gate: the public cross-crate terminal bridge has one exact composition callsite.
fn durable_ack_callsite(path: &Path, source: &str) -> Option<String> {
    #[derive(Default)]
    struct AckCalls {
        function: Option<String>,
        sites: Vec<String>,
    }

    impl<'ast> syn::visit::Visit<'ast> for AckCalls {
        fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
            let previous = self.function.replace(item.sig.ident.to_string());
            syn::visit::visit_item_fn(self, item);
            self.function = previous;
        }

        fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
            let previous = self.function.replace(item.sig.ident.to_string());
            syn::visit::visit_impl_item_fn(self, item);
            self.function = previous;
        }

        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            if call.method == "settle_terminal" && call.args.is_empty() {
                self.sites.push(
                    self.function
                        .clone()
                        .unwrap_or_else(|| "<outside-function>".to_owned()),
                );
            }
            syn::visit::visit_expr_method_call(self, call);
        }
    }

    let syntax = syn::parse_file(source).ok()?;
    let mut visitor = AckCalls::default();
    syn::visit::Visit::visit_file(&mut visitor, &syntax);
    let sites = visitor.sites;
    (!sites.is_empty()).then(|| format!("{}: {sites:?}", path.display()))
}

fn production_rust_source(path: &Path) -> bool {
    let normalized = path.to_string_lossy().replace('\\', "/");
    normalized.ends_with(".rs") && normalized.contains("/src/")
}

#[test]
fn mqtt_ingress_ack_gate_rejects_second_callsite_and_string_bait() {
    let rogue = "fn bypass(delivery: mqtt::AuthenticatedDeviceDelivery) { delivery.settle_terminal().unwrap(); }";
    assert!(durable_ack_callsite(Path::new("rogue.rs"), rogue).is_some());
    let bait = r#"const BAIT: &str = ".settle_terminal(";"#;
    assert!(durable_ack_callsite(Path::new("bait.rs"), bait).is_none());
}

#[test]
fn mqtt_ingress_ack_gate_finds_exact_postgres_proof_bridge() {
    let mut files = Vec::new();
    for root in workspace_roots() {
        walk_source_files(&root, &mut files);
    }
    let callsites: Vec<_> = files
        .iter()
        .filter(|path| production_rust_source(path))
        .filter_map(|path| {
            let source = std::fs::read_to_string(path).expect("readable source");
            durable_ack_callsite(path, &source)
        })
        .collect();
    assert_eq!(
        callsites.len(),
        1,
        "exactly one durable ACK callsite: {callsites:?}"
    );
    assert!(
        callsites[0]
            .replace('\\', "/")
            .contains("composition/identity/src/device_ingress.rs"),
        "durable ACK must be owned by the PostgreSQL proof bridge: {callsites:?}"
    );
    assert!(
        callsites[0].contains("settle_terminal_delivery"),
        "terminal ACK call must remain inside the closed proof-consuming function: {callsites:?}"
    );
    let bridge = include_str!("../../../composition/identity/src/device_ingress.rs");
    assert!(
        bridge.contains("postgres::PgDeviceIngressCommit<DraftEligibility>")
            && bridge
                .contains("pending: identity::ports::device_certificate::PendingDeviceIngress"),
        "real ACK bridge must consume authenticated delivery, pending verified outcome, and exact draft PostgreSQL commit proof"
    );
}

/// INVARIANT: MQTT-BROKER-ACCEPTANCE-MINT-01 · PG-DEVICE-PUBACK-CALLSITE-01 { level = "Medium", exec = "test", source = "code", synthetic_red = "device_puback_capability_gate_rejects_rogue_calls_and_string_bait", anti_vacuity = "device_puback_capability_has_one_mint_and_one_settlement_callsite" }
/// Medium gate: only the managed session may mint broker acceptance and only the pilot's
/// accepted-claim runner may invoke durable settlement.
fn named_callsite(path: &Path, source: &str, target: &str) -> Option<String> {
    #[derive(Default)]
    struct NamedCalls<'name> {
        target: &'name str,
        function: Option<String>,
        sites: Vec<String>,
    }

    impl<'ast> syn::visit::Visit<'ast> for NamedCalls<'_> {
        fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
            let previous = self.function.replace(item.sig.ident.to_string());
            syn::visit::visit_item_fn(self, item);
            self.function = previous;
        }

        fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
            let previous = self.function.replace(item.sig.ident.to_string());
            syn::visit::visit_impl_item_fn(self, item);
            self.function = previous;
        }

        fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
            if path
                .path
                .segments
                .last()
                .is_some_and(|segment| segment.ident == self.target)
            {
                self.record();
            }
            syn::visit::visit_expr_path(self, path);
        }

        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            if call.method == self.target {
                self.record();
            }
            syn::visit::visit_expr_method_call(self, call);
        }
    }

    impl NamedCalls<'_> {
        fn record(&mut self) {
            self.sites.push(
                self.function
                    .clone()
                    .unwrap_or_else(|| "<outside-function>".to_owned()),
            );
        }
    }

    let syntax = syn::parse_file(source).ok()?;
    let mut visitor = NamedCalls {
        target,
        ..NamedCalls::default()
    };
    syn::visit::Visit::visit_file(&mut visitor, &syntax);
    (!visitor.sites.is_empty()).then(|| format!("{}: {:?}", path.display(), visitor.sites))
}

#[test]
fn device_puback_capability_gate_rejects_rogue_calls_and_string_bait() {
    let rogue_mint = "fn bypass() { let _ = BrokerAcceptanceMint::mqtt_session_boundary(); }";
    assert!(named_callsite(Path::new("rogue.rs"), rogue_mint, "mqtt_session_boundary").is_some());
    let rogue_settle =
        "async fn bypass(outbox: &Outbox, raw: Raw) { outbox.settle_puback(raw).await; }";
    assert!(named_callsite(Path::new("rogue.rs"), rogue_settle, "settle_puback").is_some());
    let bait = r#"const BAIT: &str = "mqtt_session_boundary settle_puback";"#;
    assert!(named_callsite(Path::new("bait.rs"), bait, "mqtt_session_boundary").is_none());
    assert!(named_callsite(Path::new("bait.rs"), bait, "settle_puback").is_none());
}

#[test]
fn device_puback_capability_has_one_mint_and_one_settlement_callsite() {
    let mut files = Vec::new();
    for root in workspace_roots() {
        walk_source_files(&root, &mut files);
    }
    let production: Vec<_> = files
        .iter()
        .filter(|path| production_rust_source(path))
        .collect();

    let mint_sites: Vec<_> = production
        .iter()
        .filter_map(|path| {
            let source = std::fs::read_to_string(path).expect("readable source");
            named_callsite(path, &source, "mqtt_session_boundary")
        })
        .collect();
    assert_eq!(
        mint_sites.len(),
        1,
        "exactly one broker acceptance mint: {mint_sites:?}"
    );
    assert!(
        mint_sites[0]
            .replace('\\', "/")
            .contains("adapters/mqtt/src/session.rs")
            && mint_sites[0].contains("send_downlink"),
        "broker acceptance must be minted only after managed-session PUBACK: {mint_sites:?}"
    );

    let settlement_sites: Vec<_> = production
        .iter()
        .filter_map(|path| {
            let source = std::fs::read_to_string(path).expect("readable source");
            named_callsite(path, &source, "settle_puback")
        })
        .collect();
    assert_eq!(
        settlement_sites.len(),
        1,
        "exactly one accepted-claim settlement callsite: {settlement_sites:?}"
    );
    assert!(
        settlement_sites[0]
            .replace('\\', "/")
            .contains("composition/identity/src/pilot.rs")
            && settlement_sites[0].contains("settle_puback"),
        "durable settlement must stay in the accepted-claim pilot runner: {settlement_sites:?}"
    );
}

/// INVARIANT: DEVICE-MQTT-RAW-SURFACE-01 { level = "Medium", exec = "test", source = "code", synthetic_red = "device_mqtt_raw_surface_gate_recognizes_public_items", anti_vacuity = "device_mqtt_raw_surface_is_composition_private" }
fn public_device_mqtt_raw_items(source: &str) -> Vec<String> {
    let syntax = syn::parse_file(source).expect("valid Rust source");
    let mut public = Vec::new();
    for item in syntax.items {
        match item {
            syn::Item::Enum(item)
                if item.ident == "DeviceMqttPublishRequest"
                    && matches!(item.vis, syn::Visibility::Public(_)) =>
            {
                public.push(item.ident.to_string());
            }
            syn::Item::Struct(item)
                if item.ident == "DeviceMqttPublisher"
                    && matches!(item.vis, syn::Visibility::Public(_)) =>
            {
                public.push(item.ident.to_string());
            }
            syn::Item::Impl(item) if matches!(item.self_ty.as_ref(), syn::Type::Path(path) if path.path.segments.last().is_some_and(|segment| segment.ident == "DeviceMqttPublisher")) => {
                for member in item.items {
                    if let syn::ImplItem::Fn(method) = member
                        && method.sig.ident == "publish"
                        && matches!(method.vis, syn::Visibility::Public(_))
                    {
                        public.push("DeviceMqttPublisher::publish".to_owned());
                    }
                }
            }
            _ => {}
        }
    }
    public
}

#[test]
fn device_mqtt_raw_surface_gate_recognizes_public_items() {
    let rogue = "pub enum DeviceMqttPublishRequest {}\npub struct DeviceMqttPublisher;\nimpl DeviceMqttPublisher { pub async fn publish(&self) {} }";
    assert_eq!(public_device_mqtt_raw_items(rogue).len(), 3);
}

#[test]
fn device_mqtt_raw_surface_is_composition_private() {
    let boundary = include_str!("../../../composition/identity/src/device_mqtt.rs");
    assert!(
        public_device_mqtt_raw_items(boundary).is_empty(),
        "raw device MQTT request/publisher APIs must remain composition-private"
    );
    let root = include_str!("../../../composition/identity/src/lib.rs");
    assert!(
        !root.contains("DeviceMqttPublishRequest") && !root.contains("DeviceMqttPublisher"),
        "composition root must not re-export raw device MQTT routing APIs"
    );
}
