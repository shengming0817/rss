SELECT count(*) FROM (SELECT FROM rss_ts_ch.fences WHERE tenant_id=$1::text::uuid AND namespace=$2 LIMIT $3) bounded
