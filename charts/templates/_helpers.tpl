{{/*
Expand the name of the chart.
*/}}
{{- define "tokenx.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "tokenx.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "tokenx.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}

{{- define "tokenx.tokendings.labels" -}}
helm.sh/chart: {{ include "tokenx.chart" . }}
{{ include "tokenx.tokendings.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "tokenx.jwker.selectorLabels" -}}
app.kubernetes.io/name: {{ include "tokenx.name" . }}-jwker
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "tokenx.tokendings.selectorLabels" -}}
app.kubernetes.io/name: {{ include "tokenx.name" . }}-tokendings
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "tokenx.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "tokenx.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Tokendings host.
*/}}
{{- define "tokenx.tokendings.URL" -}}
{{- if .Values.tokendings.host }}
{{- printf "https://%s" .Values.tokendings.host }}
{{- else }}
{{- fail ".Values.tokendings.host is required." }}
{{- end }}
{{- end }}
