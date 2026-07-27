//! Production provider construction for the closed settingsonly runtime plan.

use std::sync::Arc;

use anyhow::Context as _;
use diport::DynManagedResource;

use crate::config;
use crate::runtime::SharedManagedResource;

pub(crate) struct ProviderBundle {
    pub(crate) pg: postgres::PgRuntimeHandle,
    pub(crate) vault: vault::VaultRuntimeDeps,
    pub(crate) settings_key: diport::KeyName,
    pub(crate) verifier: crate::auth_bridge::FederatedVerifier,
    pub(crate) audit_sink: httpserve::AuditSinkHandle,
    pub(crate) metrics: Arc<dyn diport::MetricsExporter>,
    pub(crate) limiter: Arc<ratelimit::GovernorLimiter>,
    pub(crate) vault_readiness: settings_composition::KeyProviderReadinessInterval,
}

pub(crate) struct CompletedProviderBuild {
    providers: ProviderBundle,
    listeners: config::ListenersConfig,
    support_probe: JwksSupportProbe,
    provider_roles: crate::providers_gen::CompletedProviderRoles,
}

impl CompletedProviderBuild {
    pub(crate) fn into_parts(
        self,
    ) -> (
        ProviderBundle,
        config::ListenersConfig,
        JwksSupportProbe,
        crate::providers_gen::CompletedProviderRoles,
    ) {
        (
            self.providers,
            self.listeners,
            self.support_probe,
            self.provider_roles,
        )
    }
}

struct BuildProducts {
    providers: ProviderBundle,
    listeners: config::ListenersConfig,
    support_probe: JwksSupportProbe,
    auth_audit_sink: crate::providers_gen::AuthAuditSinkReceipt,
    listener_pdp: crate::providers_gen::ListenerPdpReceipt,
    listener_rate_limiter: crate::providers_gen::ListenerRateLimiterReceipt,
    settings_key_provider: crate::providers_gen::SettingsKeyProviderReceipt,
    settings_secret_resolver: crate::providers_gen::SettingsSecretResolverReceipt,
}

pub(crate) async fn build(
    mut roles: crate::providers_gen::ProviderRoleBatches,
    config: config::SettingsOnlyConfig,
    secrets: config::ResolvedSecrets,
    transaction: &mut runtimeexec::StartupTransaction<'_>,
) -> anyhow::Result<CompletedProviderBuild> {
    let (listeners, federated, postgres, vault_config) = config.into_sections();
    let (writer_password, reader_password, migrator_password, vault_token) =
        secrets.into_secret_material();
    let auth_audit_sink = roles.auth_audit_sink()?;
    let listener_pdp = roles.listener_pdp()?;
    let listener_rate_limiter = roles.listener_rate_limiter()?;
    let settings_key_provider = roles.settings_key_provider()?;
    let settings_secret_resolver = roles.settings_secret_resolver()?;

    let (pg, pg_readiness) = build_postgres(
        postgres,
        writer_password,
        reader_password,
        migrator_password,
    )
    .await?;
    let pg_handle = pg.handle();
    let (pg_resources, pg_sampler) = pg.into_runtime_parts(pg_readiness);
    let mut pg_output = bootstrap::DomainModuleResult::default();
    pg_output.resources.extend(pg_resources);
    pg_output.workers.push(Box::new(move |token| {
        DynManagedResource::new_box(pg_sampler.spawn(token))
    }));
    let auth_audit_sink = auth_audit_sink
        .finish(pg_output)?
        .transfer(transaction.provider_output_mut());
    let audit_sink = httpserve::AuditSinkHandle::new(pg_handle.auth_audit_sink());

    let vault = build_vault(
        vault_config,
        vault_token,
        settings_key_provider,
        settings_secret_resolver,
    )?;
    let settings_key_provider = vault
        .settings_key_provider
        .transfer(transaction.provider_output_mut());
    let settings_secret_resolver = vault
        .settings_secret_resolver
        .transfer(transaction.provider_output_mut());

    let federated = build_federated(federated, listener_pdp)?;
    let listener_pdp = federated
        .provider_batch
        .transfer(transaction.provider_output_mut());

    let metrics = Arc::new(
        prometheus_adapter::PromExporter::install()
            .context("install settingsonly metrics exporter")?,
    );
    transaction
        .provider_output_mut()
        .resources
        .push(SharedManagedResource::boxed(
            Arc::clone(&metrics),
            "settingsonly-prometheus",
        ));
    let metrics_port: Arc<dyn diport::MetricsExporter> = metrics;
    let limiter = crate::listeners::rate_limiter();
    let listener_rate_limiter = listener_rate_limiter
        .finish(bootstrap::DomainModuleResult::default())?
        .transfer(transaction.provider_output_mut());

    // The Vault composition owns both samplers. Validating this interval here keeps the provider
    // construction and Settings worker configuration tied to one captured generation.
    let vault_readiness =
        settings_composition::KeyProviderReadinessInterval::try_new(vault.readiness)?;
    let products = BuildProducts {
        providers: ProviderBundle {
            pg: pg_handle,
            vault: vault.deps,
            settings_key: vault.settings_key,
            verifier: federated.verifier,
            audit_sink,
            metrics: metrics_port,
            limiter,
            vault_readiness,
        },
        listeners,
        support_probe: federated.support_probe,
        auth_audit_sink,
        listener_pdp,
        listener_rate_limiter,
        settings_key_provider,
        settings_secret_resolver,
    };
    let provider_roles = roles.finish(
        transaction.provider_output_mut(),
        products.auth_audit_sink,
        products.listener_pdp,
        products.listener_rate_limiter,
        products.settings_key_provider,
        products.settings_secret_resolver,
    )?;
    Ok(CompletedProviderBuild {
        providers: products.providers,
        listeners: products.listeners,
        support_probe: products.support_probe,
        provider_roles,
    })
}

async fn build_postgres(
    config: config::PostgresConfig,
    writer_password: zeroize::Zeroizing<String>,
    reader_password: zeroize::Zeroizing<String>,
    migrator_password: zeroize::Zeroizing<String>,
) -> anyhow::Result<(postgres::PgRuntimeDeps, std::time::Duration)> {
    let (connection, writer, reader, migrator, readiness) = config.into_postgres_inputs();
    let (host, port, database, ssl_mode, root_cert) = connection.into_connect_options();
    let (writer_name, writer_max) = writer.into_writer_pool();
    let (reader_name, reader_max) = reader.into_reader_pool();
    let migrator_name = migrator.into_username();
    let make = |username: String, password: String, max_connections: u32| {
        let mut value = postgres::PgConfig::new(
            host.clone(),
            port,
            database.clone(),
            username,
            postgres::PgPassword::new(password),
        )
        .with_ssl_mode(pg_ssl_mode(ssl_mode))
        .with_max_connections(max_connections);
        if let Some(path) = root_cert.clone() {
            value = value.with_ssl_root_cert(path);
        }
        value
    };
    let serving = make(writer_name, writer_password.to_string(), writer_max);
    let reader = postgres::PgTenantReadConfig::new(make(
        reader_name,
        reader_password.to_string(),
        reader_max,
    ));
    let migrator = make(migrator_name, migrator_password.to_string(), 1);
    let owner = postgres::PgRuntimeDeps::setup(
        &migrator,
        &serving,
        &reader,
        generated::event::PROJECTION_INPUT_GENERATION,
        generated::event::PROJECTION_INPUTS,
    )
    .await
    .context("setup settingsonly postgres")?;
    Ok((owner, readiness))
}

const fn pg_ssl_mode(mode: config::PgSslMode) -> postgres::PgSslMode {
    match mode {
        config::PgSslMode::Disable => postgres::PgSslMode::Disable,
        config::PgSslMode::Prefer => postgres::PgSslMode::Prefer,
        config::PgSslMode::Require => postgres::PgSslMode::Require,
        config::PgSslMode::VerifyCa => postgres::PgSslMode::VerifyCa,
        config::PgSslMode::VerifyFull => postgres::PgSslMode::VerifyFull,
    }
}

struct VaultProvider {
    deps: vault::VaultRuntimeDeps,
    settings_key: diport::KeyName,
    readiness: std::time::Duration,
    settings_key_provider: crate::providers_gen::SettingsKeyProviderBatch,
    settings_secret_resolver: crate::providers_gen::SettingsSecretResolverBatch,
}

fn build_vault(
    config: config::VaultConfig,
    token: zeroize::Zeroizing<String>,
    settings_key_provider: crate::providers_gen::SettingsKeyProviderConstructor,
    settings_secret_resolver: crate::providers_gen::SettingsSecretResolverConstructor,
) -> anyhow::Result<VaultProvider> {
    let (addr, ca_path, transit_mount, key_name, stores, readiness) = config.into_vault_inputs();
    let mut client = reqwest::Client::builder().https_only(true);
    if let Some(path) = ca_path {
        let pem = std::fs::read(path).context("read settingsonly Vault CA")?;
        let certificate =
            reqwest::Certificate::from_pem(&pem).context("parse settingsonly Vault CA")?;
        client = client.add_root_certificate(certificate);
    }
    let client = client.build().context("build settingsonly Vault client")?;
    let stores = stores
        .into_iter()
        .map(|binding| {
            let (tenant, store, mount, kv_path_prefix) = binding.into_store_binding();
            Ok((
                (vocab::TenantId::parse(&tenant)?, store),
                vault::StoreBinding {
                    mount,
                    kv_path_prefix,
                },
            ))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let stores = vault::TenantStoreAllowlist::new(stores)
        .context("build settingsonly Vault store allowlist")?;
    let resolver = vault::VaultSecretResolver::new(
        client.clone(),
        addr.clone(),
        token.to_string(),
        readiness,
        stores,
    )
    .context("build settingsonly Vault secret resolver")?;
    let key_provider =
        vault::VaultKeyProvider::new(client, addr, token.to_string(), transit_mount, readiness)
            .context("build settingsonly Vault key provider")?;
    let key_name =
        diport::KeyName::try_new(key_name).context("build settingsonly Vault settings key")?;
    let deps = vault::VaultRuntimeDeps::new(resolver, key_provider);
    let mut resources = deps.runtime_resources().into_iter();
    let resolver = resources
        .next()
        .context("settingsonly Vault bundle omitted secret-resolver resource")?;
    let key_provider = resources
        .next()
        .context("settingsonly Vault bundle omitted key-provider resource")?;
    anyhow::ensure!(
        resources.next().is_none(),
        "settingsonly Vault bundle produced an undeclared resource"
    );
    let mut key_output = bootstrap::DomainModuleResult::default();
    key_output.resources.push(key_provider);
    let mut resolver_output = bootstrap::DomainModuleResult::default();
    resolver_output.resources.push(resolver);
    Ok(VaultProvider {
        deps,
        settings_key: key_name,
        readiness,
        settings_key_provider: settings_key_provider.finish(key_output)?,
        settings_secret_resolver: settings_secret_resolver.finish(resolver_output)?,
    })
}

struct FederatedProvider {
    verifier: crate::auth_bridge::FederatedVerifier,
    provider_batch: crate::providers_gen::ListenerPdpBatch,
    support_probe: JwksSupportProbe,
}

fn build_federated(
    config: config::FederatedConfig,
    listener_pdp: crate::providers_gen::ListenerPdpConstructor,
) -> anyhow::Result<FederatedProvider> {
    let (issuer, audience, path, refresh, kinds) = config.into_oidc_inputs();
    let source = oidc::JwksKeySource::load_and_watch(
        "settingsonly-federated-access",
        path,
        refresh,
        tokio_util::sync::CancellationToken::new(),
    )
    .context("load settingsonly federated JWKS")?;
    let readiness = source.readiness_handle();
    let mut builder =
        oidc::VerifierConfigBuilder::<diport::FederatedAccessProfile>::new(issuer, audience)
            .keys_jwks(source);
    for kind in kinds {
        builder = builder.trust_kind(kind.as_str());
    }
    let provider = Arc::new(oidc::OidcProvider::new(
        builder
            .build()
            .context("build settingsonly federated verifier")?,
        Box::new(crate::SystemClock),
    ));
    let resource =
        SharedManagedResource::boxed(Arc::clone(&provider), "settingsonly-federated-verifier");
    let name = primitives::ProbeName::parse("federated_access_token_jwks_ready")
        .context("build settingsonly federated JWKS probe name")?;
    let probe = JwksProbe {
        name: name.clone(),
        readiness,
    };
    let mut provider_output = bootstrap::DomainModuleResult::default();
    provider_output.resources.push(resource);
    Ok(FederatedProvider {
        verifier: crate::auth_bridge::FederatedVerifier::production(provider),
        provider_batch: listener_pdp.finish(provider_output)?,
        support_probe: JwksSupportProbe {
            name,
            probe: Box::new(probe),
        },
    })
}

pub(crate) struct JwksSupportProbe {
    name: primitives::ProbeName,
    probe: Box<dyn bootstrap::HealthProbe>,
}

impl JwksSupportProbe {
    pub(crate) fn into_parts(self) -> (primitives::ProbeName, Box<dyn bootstrap::HealthProbe>) {
        (self.name, self.probe)
    }
}

struct JwksProbe {
    name: primitives::ProbeName,
    readiness: oidc::JwksReadinessHandle,
}

impl bootstrap::HealthProbe for JwksProbe {
    fn check(&self) -> primitives::HealthCheck {
        let (status, detail) = if self.readiness.is_ready() {
            (primitives::HealthStatus::Healthy, "ready")
        } else {
            (primitives::HealthStatus::Unhealthy, "degraded")
        };
        primitives::HealthCheck::new(self.name.clone(), status, detail)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    struct TestResource;

    impl diport::ManagedResource for TestResource {
        fn name(&self) -> &str {
            "settingsonly-provider-test"
        }

        async fn shutdown(&self) -> Result<(), diport::ShutdownError> {
            Ok(())
        }
    }

    struct TestProbe(primitives::ProbeName);

    impl bootstrap::HealthProbe for TestProbe {
        fn check(&self) -> primitives::HealthCheck {
            primitives::HealthCheck::new(self.0.clone(), primitives::HealthStatus::Healthy, "ready")
        }
    }

    fn resource_output() -> bootstrap::DomainModuleResult {
        let mut output = bootstrap::DomainModuleResult::default();
        output
            .resources
            .push(DynManagedResource::new_box(TestResource));
        output
    }

    #[test]
    fn generated_provider_roles_reject_jwks_probe_as_listener_pdp_output() {
        let mut roles = crate::plan::SettingsOnlyPlan::bundled()
            .expect("bundled plan")
            .provider_build()
            .expect("exact provider join");
        let listener_pdp = roles.listener_pdp().expect("listener PDP constructor");
        let probe_name = primitives::ProbeName::parse("federated_access_token_jwks_ready")
            .expect("valid probe name");
        let mut output = resource_output();
        output
            .probes
            .push((probe_name.clone(), Box::new(TestProbe(probe_name))));

        assert!(listener_pdp.finish(output).is_err());
    }

    #[test]
    fn generated_provider_finish_proves_role_inventory_and_support_probe_stays_separate() {
        let mut roles = crate::plan::SettingsOnlyPlan::bundled()
            .expect("bundled plan")
            .provider_build()
            .expect("exact provider join");
        let auth_audit_sink = roles
            .auth_audit_sink()
            .expect("auth audit constructor")
            .finish(auth_audit_output())
            .expect("auth audit batch");
        let listener_pdp = roles
            .listener_pdp()
            .expect("listener PDP constructor")
            .finish(resource_output())
            .expect("listener PDP batch");
        let listener_rate_limiter = roles
            .listener_rate_limiter()
            .expect("rate-limiter constructor")
            .finish(bootstrap::DomainModuleResult::default())
            .expect("rate-limiter batch");
        let settings_key_provider = roles
            .settings_key_provider()
            .expect("key-provider constructor")
            .finish(resource_output())
            .expect("key-provider batch");
        let settings_secret_resolver = roles
            .settings_secret_resolver()
            .expect("secret-resolver constructor")
            .finish(resource_output())
            .expect("secret-resolver batch");

        let mut inventory = bootstrap::DomainModuleResult::default();
        let auth_audit_sink = auth_audit_sink.transfer(&mut inventory);
        let listener_pdp = listener_pdp.transfer(&mut inventory);
        let listener_rate_limiter = listener_rate_limiter.transfer(&mut inventory);
        let settings_key_provider = settings_key_provider.transfer(&mut inventory);
        let settings_secret_resolver = settings_secret_resolver.transfer(&mut inventory);
        let _completed = roles
            .finish(
                &inventory,
                auth_audit_sink,
                listener_pdp,
                listener_rate_limiter,
                settings_key_provider,
                settings_secret_resolver,
            )
            .expect("complete role inventory");

        assert_eq!(inventory.resources.len(), 4);
        assert!(inventory.probes.is_empty());
        assert_eq!(inventory.workers.len(), 1);

        let name = primitives::ProbeName::parse("federated_access_token_jwks_ready")
            .expect("valid probe name");
        let support_probe = JwksSupportProbe {
            name: name.clone(),
            probe: Box::new(TestProbe(name.clone())),
        };
        let (staged_name, _probe) = support_probe.into_parts();
        assert_eq!(staged_name, name);
    }

    fn auth_audit_output() -> bootstrap::DomainModuleResult {
        let mut output = resource_output();
        output
            .workers
            .push(Box::new(|_token| DynManagedResource::new_box(TestResource)));
        output
    }
}
