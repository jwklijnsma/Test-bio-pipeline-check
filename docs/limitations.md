# Limitations

- Helm/OpenShift templates are checked via targeted regex on raw text (Go template
  syntax like `{{ .Values.x }}` isn't valid YAML, so a text-based approach is more
  robust than parsing), not a full Helm render — deeply nested or unusually
  formatted manifests may be missed.
- This is a heuristic linter, not a substitute for `kube-linter`, `checkov`,
  `ansible-lint`, or an official BIO2 audit.
- Control-category labels are illustrative, not authoritative BIO2 clause numbers.
