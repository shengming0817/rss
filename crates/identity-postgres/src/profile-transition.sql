-- Only transitions within the remaining signed window matter. Each arm can seek to
-- the first eligible row by observed_at or expires_at, including in generic plans.
SELECT min(at) FROM (
 (SELECT observed_at AS at FROM scoped
  WHERE observed_at>$2 AND observed_at<=$4 ORDER BY observed_at LIMIT 1)
 UNION ALL
 (SELECT expires_at FROM scoped WHERE expires_at>$2 AND expires_at<=$4
  AND observed_at<=$2 AND observed_at>$2-$3 ORDER BY expires_at LIMIT 1)
 UNION ALL
 (SELECT observed_at+$3 FROM scoped WHERE observed_at>$2-$3
  AND observed_at<=least($2,$4-$3) AND expires_at>$2 ORDER BY observed_at LIMIT 1)
) transitions
