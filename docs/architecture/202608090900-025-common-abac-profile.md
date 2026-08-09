# ADR-025: RSS Common ABAC Profile

- Status: Accepted
- Date: 2026-08-09
- Tracking: #1238

## Context

The route authorizer already consumes tenant-scoped durable policies and typed PIP keys, but the
operator boundary was a flat string-valued enum. Numeric comparisons parsed both sides as `f64`,
membership required repeated rules, and every extension invented another unrelated payload field.
The active policy HTTP contract and PostgreSQL document therefore exposed invalid combinations that
could only be rejected late.

## Decision

RSS owns a closed Common ABAC Profile. It adopts the applicable XACML equality, ordering,
membership, and string-function semantics and the bounded glob/regex matcher concepts used by
Casbin, without implementing either policy language or runtime.

The value set is `string | boolean | integer | decimal`. Strings are bounded to 256 UTF-8 bytes;
integers are `i64`; decimals use a canonical, exact, non-exponent representation. The operator set
has four families:

| Family | Predicates | Operand |
|---|---|---|
| equality | `eq`, `ne` | typed literal or typed PIP attribute |
| ordering | `gt`, `ge`, `lt`, `le` | integer/decimal literal |
| membership | `in`, `notIn` | homogeneous, unique, canonical set of 1–32 values |
| string | `startsWith`, `endsWith`, `contains`, `glob`, `regex` | non-empty pattern ≤256 bytes |

There is no implicit coercion. Missing LHS/RHS, a declared/runtime type mismatch, malformed data, or
an unknown family is a no-match and therefore fail-closed. Negated predicates are evaluated only
after presence and type validation. Regex is compiled at authoring/hydration, never in the request
evaluation loop.

The supported operand shapes are deliberately explicit:

```json
{"family":"equality","predicate":"eq","operand":{"kind":"literal","valueType":"boolean","value":true}}
{"family":"equality","predicate":"eq","operand":{"kind":"attribute","valueType":"string","attribute":"principal.id"}}
{"family":"membership","predicate":"in","operand":{"kind":"set","valueType":"string","values":["eng","ops"]}}
{"family":"string","predicate":"regex","operand":{"kind":"pattern","valueType":"string","value":"^team-[0-9]+$"}}
```

All currently registered PIP keys are intrinsically strings. Attribute RHS is therefore available
only to equality and must declare `valueType=string`; ordering remains literal-only until a real
numeric PIP key is introduced. A caller cannot declare a different type for an existing key.

Extension is code-first and exhaustive. A change must: (1) establish a real consumer and intrinsic
PIP type; (2) add a closed domain predicate/operand whose private fields preserve its bounds; (3)
update the canonical `rss://component/identity/v1/common-abac-operator` schema once; (4) extend the
unique fallible `OperatorInput` hydration funnel and borrowed `OperatorRef` projection; (5) update
every exhaustive HTTP and PostgreSQL boundary match and regenerate code; and (6) add domain, wire,
persistence and production-authorizer evidence. Arbitrary function names, scripts, plugins,
implicit coercion, compatibility aliases, and wildcard decoder arms are forbidden.

## Four-principle check

- **Thorough**: domain, PIP, HTTP, storage, migration, generated code, and documentation use one model.
- **Breaking**: active v1 is replaced in place; there are no aliases, dual readers, v2, or rolling window.
- **Simple**: four families and four operand shapes replace a function registry or policy DSL.
- **AI-HARD**: the exact component ref governance rule, opaque operator representation, one
  hydration funnel, borrowed exhaustive projection, strict serde DTOs, and JSONB constraints make
  bypasses and invalid combinations unrepresentable or unhydratable.

## Migration

Migration `0102` maps legacy `eq`, `ne`, `like`, and `eqAttr` losslessly. Legacy `gt`/`lt` cannot be
typed without inferring the LHS and are rejected with policy identifiers. Resource values become
tagged JSONB. Deployment is non-rolling: stop old binaries, run the migration, then start the new
binary.

MDM/fleet operations, a general policy management platform, full XACML/Casbin compatibility, bag
algebra, datetime/IP/URI values, and dynamic function registration remain out of scope.
