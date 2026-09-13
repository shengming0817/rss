-- One statement snapshot; assessment materializes only bounded scalar metadata, never payload.
-- ref: postgres/postgres src/backend/utils/adt/varlena.c@3af37ef3482b7d207e7eccfe8987bb8f011ee227
-- bytea octet_length reads the raw TOAST length without detoasting the payload.
-- Parameters: tenant, chain, inclusive start/end, byte budget, key, V1 overhead, payload bound.
WITH assessment AS MATERIALIZED (
    SELECT observed_tail, actual_records, expected_records, required_bytes::bigint,
        CASE
            WHEN wrong_key THEN 1
            WHEN wrong_version THEN 2
            WHEN malformed THEN 3
            WHEN actual_records <> expected_records THEN 4
            WHEN required_bytes > $5::bigint THEN 5
            ELSE 0
        END AS status
    FROM (
        SELECT h.seq AS observed_tail,
            count(e.seq) AS actual_records,
            CASE WHEN h.seq >= $3::bigint
                THEN least(h.seq - $3::bigint, $4::bigint - $3::bigint) + 1
                ELSE 0 END + ($3::bigint > 0)::int AS expected_records,
            coalesce(sum($7::bigint
                + octet_length(convert_to(e.chain_id, 'UTF8'))::bigint
                + octet_length(convert_to(e.record_id, 'UTF8'))::bigint
                + octet_length(convert_to(e.key_id, 'UTF8'))::bigint
                + octet_length(e.payload)::bigint), 0) AS required_bytes,
            coalesce(h.key_id <> $6 OR bool_or(e.key_id <> $6), false) AS wrong_key,
            coalesce(h.encoding_version <> 1 OR bool_or(e.encoding_version <> 1), false) AS wrong_version,
            -- NULL is corruption for an existing head/entry, not an absent LEFT JOIN row.
            -- Only a non-malformed assessment may use the aggregate charge to admit payloads.
            coalesce(h.tenant_id IS NOT NULL AND (
                h.key_id IS NULL OR h.encoding_version IS NULL
                OR h.seq < 0 OR octet_length(h.tag) IS DISTINCT FROM 32
            ), false)
                OR coalesce(bool_or(e.seq IS NOT NULL AND ((
                    e.encoding_version IS NOT NULL AND
                    octet_length(convert_to(e.chain_id, 'UTF8')) BETWEEN 1 AND 255
                    AND octet_length(convert_to(e.record_id, 'UTF8')) BETWEEN 1 AND 255
                    AND octet_length(convert_to(e.key_id, 'UTF8')) BETWEEN 1 AND 255
                    AND octet_length(e.payload) <= $8::bigint
                    AND octet_length(e.previous_tag) = 32
                    AND octet_length(e.tag) = 32
                ) IS NOT TRUE)), false) AS malformed
        FROM (VALUES (1)) AS seed(value)
        LEFT JOIN rss_ledger.heads h ON h.tenant_id = $1::uuid AND h.chain_id = $2
        LEFT JOIN rss_ledger.entries e ON e.tenant_id = h.tenant_id AND e.chain_id = h.chain_id
            AND e.seq BETWEEN greatest($3::bigint - 1, 0) AND $4::bigint
        GROUP BY h.tenant_id, h.seq, h.key_id, h.encoding_version, octet_length(h.tag)
    ) AS facts
)
SELECT true AS header, a.status, a.observed_tail, a.expected_records, a.required_bytes,
    NULL::text AS tenant_text, NULL::text AS chain_id, NULL::text AS record_id,
    NULL::bigint AS seq, NULL::bytea AS previous_tag, NULL::bytea AS tag,
    NULL::bytea AS payload, NULL::smallint AS encoding_version, NULL::text AS key_id
FROM assessment a
UNION ALL
SELECT false, 0, NULL::bigint, NULL::bigint, NULL::bigint,
    e.tenant_id::text, e.chain_id, e.record_id, e.seq, e.previous_tag, e.tag,
    e.payload, e.encoding_version, e.key_id
FROM assessment a
JOIN rss_ledger.entries e ON e.tenant_id = $1::uuid AND e.chain_id = $2
    AND e.seq BETWEEN greatest($3::bigint - 1, 0) AND $4::bigint
WHERE a.status = 0 AND a.actual_records > 0
