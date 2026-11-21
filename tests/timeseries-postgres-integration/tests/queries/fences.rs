use super::*;
use crate::aggregation::{complete, plan, window};

async fn latest_ids(f: &Fixture, selection: Selection) -> anyhow::Result<Vec<String>> {
    let q = Query::new(
        selection,
        window(0, 30)?,
        QueryBudget {
            max_points: NonZeroU32::MIN,
            max_series: NonZeroU32::MIN,
        },
        QueryMode::Latest,
    )?;
    let authorized = Authorized::<Query>::verify(&authority(TENANT)?, q)?;
    let mut cursor = None;
    let mut ids = Vec::new();
    loop {
        let page = f
            .store
            .query(&authorized, cursor.as_ref(), deadline()?)
            .await?;
        ids.extend(
            page.rows
                .into_iter()
                .map(|r| r.sample.input().id.as_str().to_owned()),
        );
        cursor = page.next;
        if cursor.is_none() {
            break;
        }
        anyhow::ensure!(ids.len() < 4, "expected at most three groups");
    }
    ids.sort();
    Ok(ids)
}

#[tokio::test]
async fn visible_window_winners_follow_exact_and_keyed_resource_fences() -> anyhow::Result<()> {
    let f = Fixture::new("ts-fenced-pages").await?;
    let temp = definition(TENANT)?;
    let mut spec = temp.spec().clone();
    spec.key = id("pressure")?;
    let pressure = Definition::new(spec)?;
    f.register(&temp).await?;
    f.register(&pressure).await?;
    let latest = sample(&temp, "latest", 20, 7)?;
    let exact = Selection::Exact {
        stream: latest.input().stream.clone(),
        series: latest.input().series.clone(),
    };
    let mut other = latest.input().clone();
    other.id = id("other-generation")?;
    other.stream = Stream::new(temp.spec().scope.clone(), id("sensor")?, id("other")?);
    confirmed(f.write(&batch("other", vec![Sample::new(other)?])?).await?)?;
    confirmed(
        f.write(&batch(
            "window",
            vec![
                sample(&temp, "earlier", 10, 1)?,
                latest,
                sample(&temp, "outside", 30, 8)?,
                sample(&pressure, "pressure-old", 8, 1)?,
                sample(&pressure, "pressure-new", 21, 4)?,
            ],
        )?)
        .await?,
    )?;
    let resource = |keys| -> anyhow::Result<Selection> {
        Ok(Selection::Resource {
            scope: temp.spec().scope.clone(),
            subject: id("device")?,
            resource: id("resource")?,
            keys,
        })
    };
    let both = resource([temp.spec().key.clone(), pressure.spec().key.clone()].into())?;
    let keyed = resource([pressure.spec().key.clone()].into())?;
    let until = Timestamp::new(i64::MAX)?;
    for (name, selection) in [("exact", exact.clone()), ("keyed", keyed)] {
        complete(
            &f.store,
            plan(
                name,
                MaintenanceAction::Delete {
                    selection,
                    window: window(20, 30)?,
                    restore_until: until,
                },
                1,
            )?,
        )
        .await?;
    }
    assert_eq!(latest_ids(&f, exact.clone()).await?, ["earlier"]);
    let winners = ["earlier", "other-generation", "pressure-old"];
    assert_eq!(latest_ids(&f, both.clone()).await?, winners);
    assert_eq!(
        latest_ids(&f, resource(Default::default())?).await?,
        winners
    );
    complete(
        &f.store,
        plan(
            "restore-exact",
            MaintenanceAction::Restore {
                selection: exact,
                window: window(20, 30)?,
                deletion_fence: id("exact")?,
            },
            1,
        )?,
    )
    .await?;
    assert_eq!(
        latest_ids(&f, both).await?,
        ["latest", "other-generation", "pressure-old"]
    );
    Ok(())
}
