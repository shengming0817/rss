//! Closed provider-owned catalog for the generic outbox PostgreSQL routine surface.

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum OutboxRoutineRole {
    GeneratedColumnHelper,
    ServingAuthority,
    OperatorAuthority,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OutboxRoutineOwnerPolicy {
    NotServingRole,
    MaintenanceNoLogin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OutboxRoutinePolicy {
    pub(crate) owner: OutboxRoutineOwnerPolicy,
    pub(crate) security_definer: bool,
    pub(crate) fixed_search_path: bool,
    pub(crate) public_execute: bool,
    pub(crate) app_execute: bool,
    pub(crate) maintenance_execute: bool,
    pub(crate) recovery_execute: bool,
}

impl OutboxRoutineRole {
    pub(crate) const fn policy(self) -> OutboxRoutinePolicy {
        match self {
            Self::GeneratedColumnHelper => OutboxRoutinePolicy {
                owner: OutboxRoutineOwnerPolicy::NotServingRole,
                security_definer: false,
                fixed_search_path: false,
                public_execute: false,
                app_execute: true,
                maintenance_execute: true,
                recovery_execute: true,
            },
            Self::ServingAuthority => OutboxRoutinePolicy {
                owner: OutboxRoutineOwnerPolicy::MaintenanceNoLogin,
                security_definer: true,
                fixed_search_path: true,
                public_execute: false,
                app_execute: true,
                maintenance_execute: true,
                recovery_execute: false,
            },
            Self::OperatorAuthority => OutboxRoutinePolicy {
                owner: OutboxRoutineOwnerPolicy::MaintenanceNoLogin,
                security_definer: true,
                fixed_search_path: true,
                public_execute: false,
                app_execute: false,
                maintenance_execute: true,
                recovery_execute: false,
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OutboxRoutineSpec {
    pub(crate) id: OutboxRoutineId,
    pub(crate) function: &'static str,
    pub(crate) signature: &'static str,
    pub(crate) role: OutboxRoutineRole,
}

macro_rules! outbox_routine_catalog {
    (
        helpers { $( $helper:ident => { function: $helper_function:ident, arguments: $helper_arguments:literal } ),+ $(,)? }
        serving { $( $serving:ident => { function: $serving_function:ident, arguments: $serving_arguments:literal, sql: [$serving_prefix:literal, $serving_suffix:literal] } ),+ $(,)? }
        operator { $( $operator:ident => { function: $operator_function:ident, arguments: $operator_arguments:literal, sql: [$operator_prefix:literal, $operator_suffix:literal] } ),+ $(,)? }
    ) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
        pub(crate) enum OutboxRoutineId {
            $( $helper, )+
            $( $serving, )+
            $( $operator, )+
        }

        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub(crate) enum OutboxCallableRoutine {
            $( $serving, )+
        }

        impl OutboxCallableRoutine {
            pub(crate) const ALL: &'static [Self] = &[
                $( Self::$serving, )+
            ];

            pub(crate) const fn spec(self) -> OutboxRoutineSpec {
                match self {
                    $( Self::$serving => OutboxRoutineSpec {
                        id: OutboxRoutineId::$serving,
                        function: stringify!($serving_function),
                        signature: concat!(stringify!($serving_function), $serving_arguments),
                        role: OutboxRoutineRole::ServingAuthority,
                    }, )+
                }
            }

            pub(crate) const fn sql(self) -> &'static str {
                let _catalog = OUTBOX_ROUTINES;
                let _closed_callable_set = Self::ALL;
                let spec = self.spec();
                let _identity = (spec.id, spec.signature);
                let _policy = spec.role.policy();
                match self {
                    $( Self::$serving => concat!($serving_prefix, stringify!($serving_function), $serving_suffix), )+
                }
            }
        }

        // INVARIANT: POSTGRES-OUTBOX-ROUTINE-CATALOG-01 { level = "Hard", exec = "native-compile", source = "code", native = "one closed typed catalog derives routine identity, authority role, security policy, and production call SQL" }
        pub(crate) const OUTBOX_ROUTINES: &[OutboxRoutineSpec] = &[
            $( OutboxRoutineSpec {
                id: OutboxRoutineId::$helper,
                function: stringify!($helper_function),
                signature: concat!(stringify!($helper_function), $helper_arguments),
                role: OutboxRoutineRole::GeneratedColumnHelper,
            }, )+
            $( OutboxRoutineSpec {
                id: OutboxRoutineId::$serving,
                function: stringify!($serving_function),
                signature: concat!(stringify!($serving_function), $serving_arguments),
                role: OutboxRoutineRole::ServingAuthority,
            }, )+
            $( OutboxRoutineSpec {
                id: OutboxRoutineId::$operator,
                function: stringify!($operator_function),
                signature: concat!(stringify!($operator_function), $operator_arguments),
                role: OutboxRoutineRole::OperatorAuthority,
            }, )+
        ];
    };
}

outbox_routine_catalog! {
    helpers {
        FactFrame => { function: rss_outbox_fact_frame, arguments: "(integer,integer,bytea)" },
        CanonicalNumber => { function: rss_outbox_canonical_number, arguments: "(jsonb)" },
        CanonicalJson => { function: rss_outbox_canonical_json, arguments: "(jsonb,boolean)" },
        FactFingerprint => { function: rss_outbox_fact_fingerprint, arguments: "(text,text,text,text,text,text,text,bytea,text,text,jsonb)" },
    }
    serving {
        ClaimBatch => {
            function: rss_outbox_claim_batch,
            arguments: "(text,bigint,bigint,bigint)",
            sql: [r#"
                SELECT tenant_id, contract_id, topic, event_id, payload, retry_count, metadata,
                       domain, contract_version, schema_hash, claimed_at_epoch_seconds,
                       lease_token, deadline_epoch_micros
                FROM "#, "($1, $2, $3, $4)"]
        },
        PublishPreflight => {
            function: rss_outbox_publish_preflight,
            arguments: "(text,uuid,bigint,bigint,bigint)",
            sql: ["SELECT ", "($1, $2::uuid, $3, $4, $5)"]
        },
        SettlePublished => {
            function: rss_outbox_settle_published,
            arguments: "(text,uuid,bigint)",
            sql: ["SELECT ", "($1, $2::uuid, $3)::text"]
        },
        SettleRetry => {
            function: rss_outbox_settle_retry,
            arguments: "(text,uuid,bigint)",
            sql: ["SELECT ", "($1, $2::uuid, $3)::text"]
        },
        MarkDlx => {
            function: rss_outbox_mark_dlx,
            arguments: "(text,uuid,bigint)",
            sql: [r#"
                SELECT settlement_outcome::text, tenant_id, domain, contract_id, topic,
                       payload, metadata AS metadata_json, contract_version, schema_hash,
                       retry_count
                FROM "#, "($1, $2::uuid, $3)"]
        },
        SweepPublished => {
            function: rss_sweep_outbox_published,
            arguments: "(bigint)",
            sql: ["SELECT ", "($1) AS deleted_rows"]
        },
        SampleBacklog => {
            function: rss_outbox_sample_backlog,
            arguments: "(text)",
            sql: [r#"
                SELECT tenant_id, contract_id, depth, oldest_age_seconds,
                       partition_blocked_depth
                FROM "#, "($1)"]
        },
    }
    operator {
        Redrive => {
            function: rss_outbox_redrive,
            arguments: "(text,uuid)",
            sql: ["SELECT ", "($1, $2::uuid)"]
        },
        ResolveExpired => {
            function: rss_outbox_resolve_expired,
            arguments: "(text,uuid,text,text,text,text)",
            sql: ["SELECT ", "($1, $2::uuid, $3, $4, $5, $6)"]
        },
    }
}

#[cfg(test)]
mod tests {
    use super::{OUTBOX_ROUTINES, OutboxCallableRoutine, OutboxRoutineRole};

    fn called_routine_functions(sql: &str) -> Vec<&str> {
        sql.split_ascii_whitespace()
            .filter_map(|token| token.split_once('(').map(|(function, _)| function))
            .filter(|function| function.starts_with("rss_"))
            .collect()
    }

    #[test]
    fn catalog_is_closed_unique_and_covers_every_authority_role() {
        let signatures = OUTBOX_ROUTINES
            .iter()
            .map(|spec| spec.signature)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(signatures.len(), OUTBOX_ROUTINES.len());
        for role in [
            OutboxRoutineRole::GeneratedColumnHelper,
            OutboxRoutineRole::ServingAuthority,
            OutboxRoutineRole::OperatorAuthority,
        ] {
            assert!(OUTBOX_ROUTINES.iter().any(|spec| spec.role == role));
        }
    }

    #[test]
    fn callable_sql_names_the_catalog_identity() {
        for callable in OutboxCallableRoutine::ALL {
            let routine_name = callable.spec().function;
            let called_functions = called_routine_functions(callable.sql());
            assert_eq!(
                called_functions,
                [routine_name],
                "call SQL must execute exactly its catalog identity"
            );
        }
    }

    #[test]
    fn exact_callee_projection_rejects_prefix_and_comment_bait() {
        assert_ne!(
            called_routine_functions("SELECT rss_outbox_redrive_prefix($1)"),
            ["rss_outbox_redrive"]
        );
        assert_ne!(
            called_routine_functions(
                "SELECT rss_outbox_redrive_wrong($1) /* rss_outbox_redrive($1) */"
            ),
            ["rss_outbox_redrive"]
        );
    }
}
