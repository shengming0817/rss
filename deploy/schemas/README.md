# Deployment schemas

This directory is the complete local kubeconform inventory for the chart's Kubernetes 1.30 core
resources and extension resources. `cargo xtask deployment policy check` verifies the exact file
set and every SHA-256 digest before invoking kubeconform. Network lookup, kubeconform's `default`
schema source, and `-ignore-missing-schemas` are forbidden.

| Schema | Upstream release source | SHA-256 |
| --- | --- | --- |
| `apps/deployment_v1.json` | `yannh/kubernetes-json-schema` commit `05eeed51991935dd1f47cd3b3682de4e8af233f3`, `v1.30.0-standalone-strict/deployment-apps-v1.json` | `eec9281764590b81aae81f0571790a1733e886585093e389f6bc03e233809763` |
| `autoscaling/horizontalpodautoscaler_v2.json` | same commit, `v1.30.0-standalone-strict/horizontalpodautoscaler-autoscaling-v2.json` | `75e74b614d909e1d0140f6a286d6d58876c9591917ebd3f8456f7c7646cb921f` |
| `batch/job_v1.json` | same commit, `v1.30.0-standalone-strict/job-batch-v1.json` | `10a36c2ac43f955296a8f311bc950eab81f9285ae99a12c79e059f1bb91c10c9` |
| `configmap_v1.json` | same commit, `v1.30.0-standalone-strict/configmap-v1.json` | `e0eaddebd677c08aa092b2da2264d86ac4fc34eed112b9fac2945b3f00c1e9b1` |
| `monitoring.coreos.com/servicemonitor_v1.json` | `prometheus-operator/prometheus-operator` `v0.92.1`, `example/prometheus-operator-crd/monitoring.coreos.com_servicemonitors.yaml`, version `v1` | `e27d2c90afaf0950fe99f822072d9db7882a7fb134c2781583b0ea0cfcdf0bbd` |
| `networking.k8s.io/networkpolicy_v1.json` | same Kubernetes schema commit, `v1.30.0-standalone-strict/networkpolicy-networking-v1.json` | `68f66caa6cb28841e7ab6b2b1cf5ac56085d50730a3813e538dd9204529b5b04` |
| `policy/poddisruptionbudget_v1.json` | same Kubernetes schema commit, `v1.30.0-standalone-strict/poddisruptionbudget-policy-v1.json` | `9f72ca6ac7baa59ce19de22e9817b0ec91ae3f061343acd212c70c511a40e10b` |
| `secrets-store.csi.x-k8s.io/secretproviderclass_v1.json` | `kubernetes-sigs/secrets-store-csi-driver` `v1.6.0`, `config/crd/bases/secrets-store.csi.x-k8s.io_secretproviderclasses.yaml`, version `v1` | `fdba4a9fd8cf4073d7bf1f67d8ffac86073486431cc529f3be407b35d58d001f` |
| `service_v1.json` | same Kubernetes schema commit, `v1.30.0-standalone-strict/service-v1.json` | `4de9eaf03191038e5b82edaed358d91abc474dd375c582d216b951c12934fbed` |
| `serviceaccount_v1.json` | same Kubernetes schema commit, `v1.30.0-standalone-strict/serviceaccount-v1.json` | `30f37eecc08c8793b1b96f954986e48320a7d5c265bf3a00cefd8595c2c63b44` |

Core filenames follow
`deploy/schemas/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json`; grouped Kubernetes APIs and CRDs
follow `deploy/schemas/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json`.
