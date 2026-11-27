//! Replay signed continuations through the public directory and its normal RLS role.
use crate::{federation_support as oidc, support::*};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rss_identity_core::{
    department::{DepartmentSnapshot, DepartmentSnapshotClaim, UpstreamDepartmentSnapshot},
    directory::AccountQuery,
};
use rss_identity_postgres::{AccountPage, AuthenticatedSession, AuthorityError};

async fn read(f: &Fixture, q: &AccountQuery, cursor: Option<&str>) -> Result<AccountPage> {
    Ok(f.store
        .list_accounts(
            f.actor().await?,
            q.clone(),
            cursor.map(str::to_owned),
            deadline(),
        )
        .await?)
}

async fn first(f: &Fixture, q: &AccountQuery) -> Result<String> {
    read(f, q, None)
        .await?
        .next_cursor
        .context("expected a continuation")
}

async fn rejects(
    f: &Fixture,
    actor: AuthenticatedSession,
    q: &AccountQuery,
    cursor: &str,
) -> Result<()> {
    ensure!(matches!(
        f.store
            .list_accounts(actor, q.clone(), Some(cursor.into()), deadline())
            .await,
        Err(AuthorityError::CursorInvalidated)
    ));
    Ok(())
}

pub async fn run(f: &Fixture) -> Result<()> {
    let reader = f
        .store
        .create_local_account(f.actor().await?, login("reader"), password(), deadline())
        .await?
        .key();
    let tree: DepartmentSnapshot = serde_json::from_value(serde_json::json!({
        "version":1,"sourceRevision":"revision","memberships":["leaf"],
        "nodes":[{"id":"root","parentId":null,"displayName":"Root"},
                 {"id":"leaf","parentId":"root","displayName":"Leaf"}]
    }))?;
    *f.oidc
        .department
        .lock()
        .map_err(|_| anyhow::anyhow!("department fixture"))? =
        UpstreamDepartmentSnapshot::Present(tree.clone());
    let federation = oidc::service(f);
    let mut settings = oidc::settings().input();
    settings.claims.department_snapshot = Some(DepartmentSnapshotClaim::new("org".into(), 300)?);
    let selected = oidc::enabled_settings(f, &federation, settings.try_into()?).await?;
    let other = oidc::enabled(f, &federation).await?;
    let source = selected.id.to_string();
    let mut accepted = Vec::new();
    for subject in ["alice", "bob"] {
        accepted.push(oidc::issued(
            oidc::finish(
                &federation,
                oidc::begin(f, &federation, &selected).await?,
                subject,
            )
            .await?,
        ));
    }
    profile_projection(f).await?;
    projection(f, &source, &tree).await?;
    off_page_window(f, &source, accepted[0].view().id.as_uuid()).await?;
    let queries = [
        AccountQuery::parse(None, None, Some("principalId"), None, 1)?,
        AccountQuery::parse(
            Some("departmentSubtree==root"),
            None,
            Some("principalId"),
            Some(&source),
            1,
        )?,
        AccountQuery::parse(
            None,
            Some("-departmentStatus"),
            Some("principalId"),
            Some(&source),
            1,
        )?,
        AccountQuery::parse(None, None, Some("departmentSnapshot"), Some(&source), 1)?,
    ];
    let mut pages = Vec::new();
    for q in &queries {
        let cursor = first(f, q).await?;
        let id = read(f, q, Some(&cursor))
            .await?
            .accounts
            .remove(0)
            .principal_id;
        pages.push((cursor, id));
    }
    federation
        .enable_provider(f.actor().await?, other.id, other.version, false, deadline())
        .await?;
    let mut rollback = f.owner.begin().await?;
    sqlx::query("UPDATE identity_authority.providers SET enabled=false WHERE tenant_id=$1::uuid AND provider_id=$2::uuid")
        .bind(A).bind(&source).execute(&mut *rollback).await?;
    rollback.rollback().await?;
    for (q, (cursor, id)) in queries.iter().zip(&pages) {
        assert_eq!(
            read(f, q, Some(cursor)).await?.accounts[0].principal_id,
            *id
        );
    }
    actor_binding(f, &queries[0], &pages[0].0, reader).await?;
    *f.oidc
        .department
        .lock()
        .map_err(|_| anyhow::anyhow!("department fixture"))? = UpstreamDepartmentSnapshot::Missing;
    oidc::issued(
        oidc::finish(
            &federation,
            oidc::begin(f, &federation, &selected).await?,
            "alice",
        )
        .await?,
    );
    for (q, (cursor, _)) in queries[1..].iter().zip(&pages[1..]) {
        rejects(f, f.actor().await?, q, cursor).await?;
    }
    assert_eq!(
        read(f, &queries[0], Some(&pages[0].0)).await?.accounts[0].principal_id,
        pages[0].1
    );
    let missing = AccountQuery::parse(
        Some("departmentStatus==claim_missing"),
        None,
        Some("departmentSnapshot"),
        Some(&source),
        8,
    )?;
    let rows = read(f, &missing, None).await?.accounts;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].department_snapshot, None);
    let match_leaf = AccountQuery::parse(Some("department==leaf"), None, None, Some(&source), 8)?;
    assert_eq!(read(f, &match_leaf, None).await?.accounts.len(), 1);
    deadline_during_page(
        f,
        reader.principal.as_uuid(),
        &source,
        accepted[1].view().id.as_uuid(),
    )
    .await
}

async fn profile_projection(f: &Fixture) -> Result<()> {
    use rss_identity_core::profile::{Extensions, LocalProfile};
    use rss_identity_postgres::{ProfileChange, ProfileOperationId};
    f.store
        .update_local_profile(
            f.actor().await?,
            f.key,
            ProfileChange {
                operation_id: ProfileOperationId::now(),
                expected_revision: 0,
                value: Some(LocalProfile {
                    display_name: Some("Alice 林".into()),
                    username: None,
                    email: Some("alice@example.test".into()),
                    extensions: Extensions::try_from(serde_json::json!({}))?,
                    max_age_seconds: 3600,
                }),
            },
            deadline(),
        )
        .await?;
    f.login().await?;
    let q = AccountQuery::parse(
        Some("email=icontains=EXAMPLE"),
        Some("-displayName"),
        Some("displayName,email,profileStatus,enabled,memberActive,hasLocalPassword"),
        Some("local"),
        1,
    )?;
    let page = read(f, &q, None).await?;
    let row = page.accounts.first().context("local profile")?;
    assert_eq!(row.principal_id, f.key.principal.as_uuid().to_string());
    assert_eq!(row.display_name.as_deref(), Some("Alice 林"));
    assert_eq!(row.email.as_deref(), Some("alice@example.test"));
    assert_eq!(row.profile_status, "available");
    assert!(row.enabled && row.member_active && row.has_local_password);
    Ok(())
}

async fn projection(f: &Fixture, source: &str, tree: &DepartmentSnapshot) -> Result<()> {
    for (filter, count) in [
        ("department==root", 0),
        ("department==leaf", 2),
        ("departmentSubtree==root", 2),
        ("departmentSubtree==root;departmentSubtree==absent", 0),
        ("departmentSubtree==absent,departmentSubtree==leaf", 2),
        (
            "login==admin,(departmentSubtree==leaf;departmentSubtree==absent)",
            1,
        ),
    ] {
        let q = AccountQuery::parse(
            Some(filter),
            None,
            Some("departmentStatus"),
            Some(source),
            8,
        )?;
        let page = read(f, &q, None).await?;
        assert_eq!(page.fields, q.fields());
        assert_eq!(page.accounts.len(), count, "{filter}");
        assert!(
            page.accounts
                .iter()
                .all(|r| r.department_snapshot.is_none())
        );
    }
    let q = AccountQuery::parse(
        Some("department==leaf"),
        None,
        Some("departmentSnapshot"),
        Some(source),
        1,
    )?;
    let page = read(f, &q, None).await?;
    assert_eq!(page.accounts[0].department_snapshot.as_ref(), Some(tree));
    let second = read(f, &q, Some(&page.next_cursor.context("second snapshot")?)).await?;
    assert_eq!(second.accounts[0].department_snapshot.as_ref(), Some(tree));
    assert!(second.next_cursor.is_none());

    // Hidden boolean and nullable text sort keys, including two NULL logins.
    let q = AccountQuery::parse(None, Some("-enabled,login"), Some("memberActive"), None, 1)?;
    let mut seen = Vec::new();
    let mut cursor = None;
    loop {
        let page = read(f, &q, cursor.as_deref()).await?;
        assert_eq!(page.accounts.len(), 1);
        seen.push((
            page.accounts[0].principal_id.clone(),
            page.accounts[0].login.clone(),
        ));
        cursor = page.next_cursor;
        if cursor.is_none() {
            break;
        }
        ensure!(seen.len() < 5, "pagination did not advance");
    }
    assert_eq!(seen.len(), 4);
    assert_eq!(seen[0].1.as_deref(), Some("admin"));
    assert_eq!(seen[1].1.as_deref(), Some("reader"));
    assert!(seen[2].1.is_none() && seen[3].1.is_none() && seen[2].0 < seen[3].0);
    Ok(())
}

async fn actor_binding(
    f: &Fixture,
    q: &AccountQuery,
    cursor: &str,
    reader: rss_identity_core::account::AccountKey,
) -> Result<()> {
    f.policy
        .managers
        .write()
        .map_err(|_| anyhow::anyhow!("policy fixture"))?
        .push(reader);
    for (who, name) in [
        (reader, "reader"),
        (f.key, "admin"),
        (f.system_key, "platform"),
    ] {
        f.reset_attempts().await?;
        let binding = binding(who.tenant);
        let login = f
            .store
            .login_local(binding, login(name), password(), source(), None, deadline())
            .await?;
        let actor = f
            .store
            .inspect_session(binding, oidc::secret(&login), deadline())
            .await?;
        rejects(f, actor, q, cursor).await?;
    }
    for changed in [
        AccountQuery::parse(Some("enabled==true"), None, Some("principalId"), None, 1)?,
        AccountQuery::parse(None, Some("login"), Some("principalId"), None, 1)?,
        AccountQuery::parse(None, None, Some("memberActive"), None, 1)?,
    ] {
        rejects(f, f.actor().await?, &changed, cursor).await?;
    }
    let mut bytes = URL_SAFE_NO_PAD.decode(cursor)?;
    bytes[0] ^= 1;
    rejects(f, f.actor().await?, q, &URL_SAFE_NO_PAD.encode(bytes)).await?;
    Ok(())
}

async fn off_page_window(f: &Fixture, source: &str, session: uuid::Uuid) -> Result<()> {
    let q = AccountQuery::parse(
        Some("login=isnotnull=true"),
        Some("login"),
        Some("departmentStatus"),
        Some(source),
        1,
    )?;
    let original: serde_json::Value = sqlx::query_scalar(
        "SELECT auth_facts FROM identity_authority.sessions WHERE session_id=$1",
    )
    .bind(session)
    .fetch_one(&f.owner)
    .await?;
    for future in [true, false] {
        let now: i64 =
            sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
                .fetch_one(&f.owner)
                .await?;
        let (start, end) = if future {
            (now + 25, now + 80)
        } else {
            (now - 25, now + 30)
        };
        sqlx::query("UPDATE identity_authority.sessions SET auth_facts=jsonb_set(jsonb_set(auth_facts,'{department_snapshot,observed_at}',to_jsonb($2::bigint)),'{department_snapshot,expires_at}',to_jsonb($3::bigint)) WHERE session_id=$1")
            .bind(session).bind(start).bind(end).execute(&f.owner).await?;
        let page = read(f, &q, None).await?;
        assert_eq!(page.accounts[0].login.as_deref(), Some("admin"));
        let bytes = URL_SAFE_NO_PAD.decode(page.next_cursor.context("expected next account")?)?;
        let payload: serde_json::Value = serde_json::from_slice(&bytes[32..])?;
        assert_eq!(payload["expires"], if future { start } else { end });
    }
    sqlx::query("UPDATE identity_authority.sessions SET auth_facts=$2 WHERE session_id=$1")
        .bind(session)
        .bind(original)
        .execute(&f.owner)
        .await?;
    Ok(())
}

async fn deadline_during_page(
    f: &Fixture,
    target: uuid::Uuid,
    source: &str,
    off_page: uuid::Uuid,
) -> Result<()> {
    let session = f.login().await?;
    let end:i64=sqlx::query_scalar("UPDATE identity_authority.sessions SET idle_expires_at=floor(extract(epoch FROM clock_timestamp()))::bigint+5 WHERE session_id=$1 RETURNING idle_expires_at")
        .bind(session.view().id.as_uuid()).fetch_one(&f.owner).await?;
    let binding = binding(f.key.tenant);
    let actor = f
        .store
        .inspect_session(binding, oidc::secret(&session), deadline())
        .await?;
    let q = AccountQuery::parse(
        Some("login=isnotnull=true"),
        Some("login"),
        Some("principalId,departmentStatus"),
        Some(source),
        1,
    )?;
    let cursor = f
        .store
        .list_accounts(actor, q.clone(), None, deadline())
        .await?
        .next_cursor
        .context("second page")?;
    let renewed = f
        .store
        .authenticate_session(binding, oidc::secret(&session), deadline())
        .await?;
    ensure!(renewed.view().idle_expires_at > end);
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE FUNCTION public.wait_page() RETURNS boolean LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock_shared(3374); RETURN true; END $$;
        CREATE POLICY wait_page ON identity_authority.local_credentials AS RESTRICTIVE FOR SELECT USING (CASE WHEN principal_id='{target}'::uuid THEN public.wait_page() ELSE true END)"))).execute(&f.owner).await?;
    cross_page_boundary(f, renewed, q.clone(), Some(cursor), end).await?;

    // The filtered-out Bob is the only clock transition. Force a fresh, unsigned
    // first page to cross it after authorization and the database time sample.
    let end:i64=sqlx::query_scalar("UPDATE identity_authority.sessions SET auth_facts=jsonb_set(auth_facts,'{department_snapshot,expires_at}',to_jsonb(floor(extract(epoch FROM clock_timestamp()))::bigint+5)) WHERE session_id=$1 RETURNING (auth_facts #>> '{department_snapshot,expires_at}')::bigint")
        .bind(off_page).fetch_one(&f.owner).await?;
    let cursor = first(f, &q).await?;
    cross_page_boundary(f, f.actor().await?, q.clone(), None, end).await?;
    rejects(f, f.actor().await?, &q, &cursor).await
}

async fn cross_page_boundary(
    f: &Fixture,
    actor: AuthenticatedSession,
    q: AccountQuery,
    cursor: Option<String>,
    end: i64,
) -> Result<()> {
    let mut gate = f.owner.begin().await?;
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid() FROM pg_advisory_xact_lock(3374)")
        .fetch_one(&mut *gate)
        .await?;
    let store = f.store.clone();
    let continued =
        tokio::spawn(async move { store.list_accounts(actor, q, cursor, deadline()).await });
    wait_for_blocked_backend(f, pid).await?;
    sqlx::query("SELECT pg_sleep(greatest(0,$1::bigint-extract(epoch FROM clock_timestamp()))::double precision)").bind(end).execute(&f.owner).await?;
    gate.commit().await?;
    ensure!(matches!(
        continued.await?,
        Err(AuthorityError::CursorInvalidated)
    ));
    Ok(())
}
