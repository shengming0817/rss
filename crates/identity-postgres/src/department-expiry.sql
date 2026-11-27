SELECT least(min((fact->>'observed_at')::bigint) FILTER (WHERE (fact->>'observed_at')::bigint>$3),
             min((fact->>'expires_at')::bigint) FILTER (WHERE (fact->>'expires_at')::bigint>$3))
FROM department_facts
WHERE eligible AND fact->>'status'='available'
