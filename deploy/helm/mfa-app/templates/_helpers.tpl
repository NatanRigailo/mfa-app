{{- define "mfa-app.name" -}}
{{- .Chart.Name }}
{{- end }}

{{- define "mfa-app.fullname" -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "mfa-app.labels" -}}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
app.kubernetes.io/name: {{ include "mfa-app.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "mfa-app.selectorLabels" -}}
app.kubernetes.io/name: {{ include "mfa-app.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "mfa-app.imageTag" -}}
{{- .Values.image.tag | default .Chart.AppVersion }}
{{- end }}
