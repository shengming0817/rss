{{/* RSS chart-local names. Values expose only the closed profile and phase selectors. */}}
{{- define "rss.name" -}}
{{- .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "rss.phase" -}}
{{- $phase := required "values.phase is required" .Values.phase -}}
{{- if not (has $phase (list "migration" "serving")) -}}
{{- fail "values.phase must be migration or serving" -}}
{{- end -}}
{{- $phase -}}
{{- end -}}

{{- define "rss.fullname" -}}
{{- $name := include "rss.name" . -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "rss.profile" -}}
{{- $profile := required "values.profile is required" .Values.profile -}}
{{- if not (regexMatch "^[a-z][a-z0-9]*$" $profile) -}}
{{- fail "values.profile must select a bundled DeploymentPlan" -}}
{{- end -}}
{{- $profile -}}
{{- end -}}

{{- define "rss.planPath" -}}
{{- printf "plans/%s.deployment-plan.json" (include "rss.profile" .) -}}
{{- end -}}

{{- define "rss.planSource" -}}
{{- $path := include "rss.planPath" . -}}
{{- required (printf "bundled DeploymentPlan is missing: %s" $path) (.Files.Get $path) -}}
{{- end -}}

{{- define "rss.resourceName" -}}
{{- $suffix := required "resource semantic suffix is required" .name -}}
{{- if gt (len $suffix) 63 -}}{{- fail "resource semantic suffix exceeds DNS label budget" -}}{{- end -}}
{{- if ge (len $suffix) 62 -}}
{{- $suffix -}}
{{- else -}}
{{- $budget := sub 62 (len $suffix) | int -}}
{{- $prefix := include "rss.fullname" .root | trunc $budget | trimSuffix "-" -}}
{{- printf "%s-%s" $prefix $suffix -}}
{{- end -}}
{{- end -}}

{{- define "rss.serviceAccountName" -}}
{{- $identity := required "DeploymentPlan workload identity serviceAccount is required" .identity -}}
{{- if or (gt (len $identity) 253) (not (regexMatch "^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$" $identity)) -}}
{{- fail "DeploymentPlan workload identity serviceAccount must be a DNS subdomain of at most 253 characters" -}}
{{- end -}}

{{- $scope := include "rss.fullname" .root | trunc 20 | trimSuffix "-" -}}
{{- $identityBudget := sub 49 (len $scope) | int -}}
{{- $identityPart := $identity | replace "." "-" | trunc $identityBudget | trimSuffix "-" -}}
{{- $digestSource := printf "%s/%s/%s/%s" .root.Release.Namespace .root.Release.Name .root.Chart.Name $identity -}}
{{- $digest := $digestSource | sha256sum | trunc 12 -}}
{{- printf "%s-%s-%s" $scope $identityPart $digest -}}
{{- end -}}

{{- define "rss.phaseServiceAccountName" -}}
{{- $identity := .identity -}}
{{- if eq .phase "migration" -}}
{{- $identity = printf "%s-migration" $identity -}}
{{- end -}}
{{- include "rss.serviceAccountName" (dict "root" .root "identity" $identity) -}}
{{- end -}}

{{- define "rss.secretProviderClassName" -}}
{{- $suffix := printf "%s-%s-%s-secrets" .profile .workload .phase -}}
{{- include "rss.resourceName" (dict "root" .root "name" $suffix) -}}
{{- end -}}

{{- define "rss.secretFileName" -}}
{{- if or (eq . "migrationDatabaseUrl") (eq . "servingDatabaseUrl") -}}database-url
{{- else if eq . "servingSecretBundle" -}}serving-secret-bundle
{{- else -}}{{- fail "DeploymentPlan contains an unsupported SecretPurpose" -}}
{{- end -}}
{{- end -}}

{{- define "rss.applicationConfigPath" -}}
{{- if eq . "settingsOnlyV1" -}}configs/settings-only-v1.toml
{{- else if eq . "identityAuditV1" -}}configs/identity-audit-v1.toml
{{- else -}}{{- fail "DeploymentPlan contains an unsupported applicationConfig" -}}
{{- end -}}
{{- end -}}

{{- define "rss.dependencyPort" -}}
{{- if eq . "vault" -}}8200
{{- else if eq . "postgresql" -}}5432
{{- else if eq . "amqp" -}}5671
{{- else if eq . "redis" -}}6379
{{- else if eq . "objectStorage" -}}443
{{- else if eq . "oidc" -}}443
{{- else -}}{{- fail "DeploymentPlan contains an unsupported dependency peer role" -}}
{{- end -}}
{{- end -}}

{{- define "rss.deploymentFingerprint" -}}
{{- required "DeploymentPlan deploymentFingerprint is required" .deploymentFingerprint | trimPrefix "sha256:" -}}
{{- end -}}

{{- define "rss.migrationHeadFingerprint" -}}
{{- required "DeploymentPlan migrationHeadFingerprint is required for migration phase" .migrationHeadFingerprint | trimPrefix "sha256:" -}}
{{- end -}}

{{- define "rss.planConfigMapName" -}}
{{- $digest := include "rss.deploymentFingerprint" .plan | trunc 12 -}}
{{- $suffix := printf "%s-plan-%s" .profile $digest -}}
{{- include "rss.resourceName" (dict "root" .root "name" $suffix) -}}
{{- end -}}

{{- define "rss.selectorLabels" -}}
app.kubernetes.io/name: {{ include "rss.name" .root }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .workload }}
{{- end -}}

{{- define "rss.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .root.Chart.Name .root.Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "rss.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .root.Release.Service }}
rss.gocell.io/profile: {{ .profile }}
{{- end -}}

{{- define "rss.fingerprintAnnotations" -}}
rss.gocell.io/assembly-fingerprint: {{ .assemblyFingerprint | quote }}
rss.gocell.io/runtime-plan-fingerprint: {{ .runtimePlanFingerprint | quote }}
rss.gocell.io/deployment-fingerprint: {{ .deploymentFingerprint | quote }}
{{- end -}}
