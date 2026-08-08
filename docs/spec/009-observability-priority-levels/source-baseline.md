# Source baseline

At #2035 start:

- `tracewire` captured/restored only an outbox `traceparent`;
- HTTP middleware emitted a local `http.request` span with custom fields;
- the trace layer sat inside budget, body-limit, and authentication bridge work;
- Health already disabled request tracing through listener policy.

#2035 replaces the old API and span contract in place and moves the policy to the unique bindable
router funnel.
