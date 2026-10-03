# Dashboard appearance and profile links

The dashboard uses a local dark terminal-inspired palette: near-black surfaces, green accents,
light text and colored severity bars. It downloads no fonts, images or theme assets.

KPI counts use thousands separators and responsive font sizing. Metric labels wrap.
Charts use explicit padding, whole-number count axes, hover tooltips and visible count labels.
Long IP addresses, account names and detection names appear horizontally instead of rotated.
The time chart uses a UTC scale, rather than allowing browser timezone conversion.

Public connection links are in `dashboard/profile.toml`. The sidebar renders LinkedIn and GitHub
buttons only for HTTPS URLs on their respective domains. These are ordinary external links;
there is no sign-in, account integration, tracking or automatic message sending.

Streamlit normally reloads source changes. For theme configuration changes, stop the server with
Ctrl+C and restart using the README dashboard command, then refresh the browser.
