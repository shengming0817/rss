# Consistency / Effect Posture

Status: **failed** · Active HTTP contracts: **2** · Findings: **2**

| Contract | Owner | Method | Path | Consistency | Effects | Mount | LocalOnly Proof | Findings |
|---|---|---|---|---|---|---|---|---|
| <code>a.local</code> | <code>demo</code> | <code>GET</code> | <code>/v1/a</code> | <code>LocalOnly</code> | <code>read, cross-tenant-audit</code> | <code>mounted: crates/demo/src/lib.rs:7</code> | <code>localOnlyStatic/failed; state=classified; effect=ReadEffect; privilege=LocalPrivilege</code> | <code>forbiddenStateEffect @ crates/demo/src/lib.rs:7: escaped &#124; cell&#92;path<br>line &#91;link&#93;&#40;https://example.invalid&#41; &#33;&#91;img&#93;&#40;x&#41; &lt;em&gt;raw&lt;/em&gt; &#96;tick&#96; &#42;strong&#42; &amp; amp</code> |
| <code>z.remote</code> | <code>demo</code> | <code>POST</code> | <code>/v1/z</code> | <code>LocalTx</code> | <code>auth, transaction</code> | <code>missing</code> | <code>declarationOnly/notApplicable</code> | <code>missingRouteBinding @ z.remote: canonical production Domain::init mount is missing</code> |
