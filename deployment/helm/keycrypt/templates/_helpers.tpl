{{/*
Expand chart base name.
*/}}
{{- define "keycrypt.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Chart label value.
*/}}
{{- define "keycrypt.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
keycrypt.fullname: Generate full resource name.
*/}}
{{- define "keycrypt.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
keycrypt.selectorLabels: Pod selector labels.
*/}}
{{- define "keycrypt.selectorLabels" -}}
app.kubernetes.io/name: {{ include "keycrypt.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
keycrypt.labels: Standard Kubernetes labels.
*/}}
{{- define "keycrypt.labels" -}}
helm.sh/chart: {{ include "keycrypt.chart" . }}
{{ include "keycrypt.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
{{- with .Values.commonLabels }}
{{- toYaml . }}
{{- end }}
{{- end -}}

{{/*
keycrypt.serviceAccountName: Service account name.
*/}}
{{- define "keycrypt.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "keycrypt.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
keycrypt.image: Container image reference with tag/digest.
Supports optional image.registry and digest pinning.
*/}}
{{- define "keycrypt.image" -}}
{{- $repository := required "Values.image.repository is required" .Values.image.repository -}}
{{- $prefix := "" -}}
{{- if .Values.image.registry -}}
{{- $prefix = printf "%s/" (trimSuffix "/" .Values.image.registry) -}}
{{- end -}}
{{- if .Values.image.digest -}}
{{- printf "%s%s@%s" $prefix $repository .Values.image.digest -}}
{{- else -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag -}}
{{- printf "%s%s:%s" $prefix $repository $tag -}}
{{- end -}}
{{- end -}}

{{/*
Autoscaling helper: true when HPA should own replica management.
*/}}
{{- define "keycrypt.autoscalingEnabled" -}}
{{- if .Values.autoscaling.enabled -}}true{{- else -}}false{{- end -}}
{{- end -}}

{{/*
Replica helper used when autoscaling is disabled.
*/}}
{{- define "keycrypt.replicaCount" -}}
{{- if .Values.autoscaling.enabled -}}
{{- default 2 .Values.autoscaling.minReplicas | int -}}
{{- else -}}
{{- default 2 .Values.replicaCount | int -}}
{{- end -}}
{{- end -}}

{{/*
Resource requests/limits helper.
*/}}
{{- define "keycrypt.resources" -}}
{{- toYaml (default (dict) .Values.resources) -}}
{{- end -}}

{{/*
Pod security context helper.
*/}}
{{- define "keycrypt.podSecurityContext" -}}
runAsNonRoot: {{ default true .Values.podSecurityContext.runAsNonRoot }}
{{- if hasKey .Values.podSecurityContext "runAsUser" }}
runAsUser: {{ .Values.podSecurityContext.runAsUser }}
{{- end }}
{{- if hasKey .Values.podSecurityContext "runAsGroup" }}
runAsGroup: {{ .Values.podSecurityContext.runAsGroup }}
{{- end }}
{{- if hasKey .Values.podSecurityContext "fsGroup" }}
fsGroup: {{ .Values.podSecurityContext.fsGroup }}
{{- end }}
{{- end -}}

{{/*
Container security context helper.
*/}}
{{- define "keycrypt.securityContext" -}}
runAsNonRoot: {{ default true .Values.securityContext.runAsNonRoot }}
allowPrivilegeEscalation: {{ default false .Values.securityContext.allowPrivilegeEscalation }}
readOnlyRootFilesystem: {{ default true .Values.securityContext.readOnlyRootFilesystem }}
{{- if hasKey .Values.securityContext "runAsUser" }}
runAsUser: {{ .Values.securityContext.runAsUser }}
{{- end }}
{{- if hasKey .Values.securityContext "runAsGroup" }}
runAsGroup: {{ .Values.securityContext.runAsGroup }}
{{- end }}
capabilities:
  drop:
{{- range $cap := default (list "ALL") .Values.securityContext.capabilities.drop }}
  - {{ $cap | quote }}
{{- end }}
{{- end -}}

{{/*
Ingress API version helper based on cluster version.
*/}}
{{- define "keycrypt.ingress.apiVersion" -}}
{{- if semverCompare ">=1.19-0" .Capabilities.KubeVersion.Version -}}
networking.k8s.io/v1
{{- else -}}
networking.k8s.io/v1beta1
{{- end -}}
{{- end -}}

{{/*
Ingress enabled helper.
*/}}
{{- define "keycrypt.ingress.enabled" -}}
{{- if .Values.ingress.enabled -}}true{{- else -}}false{{- end -}}
{{- end -}}

{{/*
Persistent volume claim name for key storage.
*/}}
{{- define "keycrypt.keyStoragePvcName" -}}
{{- if .Values.persistence.existingClaim -}}
{{- .Values.persistence.existingClaim -}}
{{- else -}}
{{- printf "%s-key-storage" (include "keycrypt.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{/*
ConfigMap name for policy/configuration payloads.
*/}}
{{- define "keycrypt.configMapName" -}}
{{- printf "%s-config" (include "keycrypt.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
