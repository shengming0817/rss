WITH selected AS (
 SELECT DISTINCT ON (series_digest,source,generation) s.* FROM rss_timeseries.samples s
 WHERE tenant_id=$1::text::uuid AND namespace=$2 AND observed_at >= $3 AND observed_at < $4
 AND rss_timeseries.visible(convert_from(s.raw,'UTF8')::jsonb,s.observed_at)
 AND ($5::bytea IS NULL OR series_digest=$5) AND ($6::text IS NULL OR source=$6)
 AND ($7::text IS NULL OR generation=$7) AND ($8::text IS NULL OR subject=$8)
 AND ($9::text IS NULL OR resource=$9) AND (cardinality($10::text[])=0 OR key=ANY($10))
 ORDER BY series_digest,source,generation,observed_at DESC,sequence DESC,sample_id DESC
)
SELECT s.*,s.sequence::text AS sequence_text,s.version::text AS version_text,i.digest,i.received_at AS original_received FROM selected s JOIN rss_timeseries.sample_identities i
 USING(tenant_id,namespace,source,generation,sample_id,observed_at)
WHERE ($11::bytea IS NULL OR (series_digest,source,generation)>($11,$12::text COLLATE "C",$13::text COLLATE "C") AND ($14::bigint IS NULL OR true) AND ($15::text IS NULL OR true) AND ($16::text IS NULL OR true))
ORDER BY series_digest,source,generation,observed_at,sequence,sample_id LIMIT $17
