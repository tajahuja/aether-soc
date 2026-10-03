# Security policy and operating boundaries

Run only as a local educational lab using synthetic data. All generated IPs use documentation
networks (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24); domains use example.test.
Commands are strings, never executed. The generator does not contact any destination.

Bind dashboard/API to 127.0.0.1. They have no authentication, authorization or multi-user isolation.
Do not expose them publicly or upload real organizational telemetry. Reports retain raw command
lines; adding external inputs requires sanitization, size limits, retention and access policies.

Keep secrets in environment variables. `.env` and virtual environments are ignored.
`.env.example` contains no key; the current offline module reads no key and sends no data.
Any future LLM integration needs explicit redaction and data-transfer controls.

Generated snapshots are replaced by each analysis run. This is not evidence-preserving production
storage, durable incident lifecycle management or automated remediation. No containment is executed.
Dependency pins reproduce a tested environment; they are not a guarantee of vulnerability absence.
Review dependency advisories and update/test before any broader deployment.

For a discovered issue, contact the repository owner privately using their chosen channel.
No fabricated security contact address is provided. Avoid including secrets or real telemetry in issues.
