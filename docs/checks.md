# Checks reference

## Ansible (`ANS0xx`)

| ID | Severity | Category | Description |
|---|---|---|---|
| `ANS000` | Low | Configuratiebeheer | File could not be parsed as YAML |
| `ANS001` | Critical | Cryptografie / Sleutelbeheer | Possible hardcoded secret in `vars` (not vault/lookup/Jinja) |
| `ANS002` | High | Cryptografie | TLS certificate validation disabled (`validate_certs: false`) |
| `ANS003` | High | Logging en monitoring | Task handles a sensitive field without `no_log: true` |
| `ANS004` | Medium | Toegangsbeveiliging | `become: true` without an explicit `become_user` |
| `ANS005` | High | Netwerkbeveiliging | SSH `StrictHostKeyChecking` disabled |

## Helm (`HLM0xx`)

| ID | Severity | Category | Description |
|---|---|---|---|
| `HLM000` | Low | Configuratiebeheer | `values.yaml` could not be parsed |
| `HLM001` | Medium | Wijzigingsbeheer | `image.tag` in `values.yaml` is `latest` or missing |
| `HLM002` | Medium | Wijzigingsbeheer | Container image uses the `latest` tag |
| `HLM003` | Critical | Hardening | Container runs `privileged: true` |
| `HLM004` | Medium/High | Toegangsbeveiliging | `runAsNonRoot` missing or explicitly `false` |
| `HLM005` | High | Toegangsbeveiliging | Container explicitly runs as UID 0 (root) |
| `HLM006` | High | Netwerkbeveiliging | Pod uses `hostNetwork: true` |
| `HLM007` | High | Hardening | Pod shares host PID or IPC namespace |
| `HLM008` | High | Hardening | `allowPrivilegeEscalation: true` |
| `HLM009` | Critical | Hardening | All Linux capabilities added (`capabilities.add: ALL`) |
| `HLM010` | Low | Hardening | `readOnlyRootFilesystem: false` |
| `HLM011` | Medium | Continuïteit / Capaciteitsbeheer | No resource requests/limits defined |
| `HLM012` | Low | Continuïteit | No `livenessProbe` defined |
| `HLM013` | Low | Continuïteit | No `readinessProbe` defined |

## OpenShift (`OCP0xx`)

| ID | Severity | Category | Description |
|---|---|---|---|
| `OCP001` | High | Cryptografie / Transportbeveiliging | `Route` has no `tls:` block |
| `OCP002` | Medium | Cryptografie / Transportbeveiliging | `Route` allows `insecureEdgeTerminationPolicy: Allow` |
| `OCP003` | Critical | Hardening | `SecurityContextConstraints` allows `allowPrivilegedContainer: true` |
| `OCP004` | High | Netwerkbeveiliging | SCC allows host network, host PID, or host ports |
| `OCP005` | Medium | Toegangsbeveiliging | SCC uses `runAsUser.type: RunAsAny` |
| `OCP006` | High | Hardening | SCC allows `allowPrivilegeEscalation: true` |
| `OCP007` | Medium | Continuïteit / Capaciteitsbeheer | KubeVirt `VirtualMachine` has no `spec.domain.resources` |
| `OCP008` | Critical | Cryptografie / Sleutelbeheer | Plaintext password in cloud-init `userData` |
| `OCP009` | High | Toegangsbeveiliging | VM access configured via cloud-init instead of `accessCredentials` |
| `OCP010` | Low | Continuïteit | `runStrategy: Always` without an `evictionStrategy` |
