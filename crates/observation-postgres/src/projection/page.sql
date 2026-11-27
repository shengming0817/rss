-- Keep the body lookup correlated to each admitted position even in a generic plan.
SELECT j.expired_through, b.scope,b.batch_id,b.raw,b.fingerprint,b.received_at,
 b.policy,b.decision,b.sequence::text AS sequence,b.applicable,b.log_position
 FROM rss_observation.journals j LEFT JOIN LATERAL (
   SELECT log_position,sum(n) OVER (ORDER BY log_position ROWS UNBOUNDED PRECEDING) AS bytes
   FROM (SELECT log_position,coalesce(octet_length(raw),0) AS n FROM rss_observation.batches
     WHERE tenant_id=j.tenant_id AND applicable AND log_position>$2 AND $2>=j.expired_through
     ORDER BY log_position LIMIT $3) candidates
 ) p ON p.bytes<=$4::bigint LEFT JOIN LATERAL (
   SELECT scope,batch_id,raw,fingerprint,received_at,policy,decision,sequence,applicable,log_position
   FROM rss_observation.batches WHERE tenant_id=j.tenant_id AND applicable AND log_position=p.log_position
   LIMIT 1
 ) b ON true
 WHERE j.tenant_id=$1::uuid ORDER BY b.log_position
