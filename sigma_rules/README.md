# Sigma examples

Sigma is a portable YAML format describing detection intent. SIEM-specific conversion maps
fields and selections to a backend query language. These examples complement, but do not drive,
the Python rules. Validate with a Sigma converter and your backend before deployment.

PowerShell and privileged-login examples are event filters. Authentication is a base filter
with a Sigma correlation rule counting events per source in five minutes. Success-after-failure,
multi-account distinct counting and privileged-to-network joins need backend-specific correlation
and normalized identity fields; the Python engine demonstrates those semantics directly.
No EventID filter is required here: this lab's event_id is a unique record identifier, not the
Windows numeric event code. Native Windows deployments should map event types to 4624/4625.
