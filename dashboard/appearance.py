"""Local theme assets; no fonts, trackers or imagery fetched from the internet."""
from pathlib import Path
import tomllib
from urllib.parse import urlparse

import streamlit as st


def apply_theme():
    st.markdown('''
<style>
.stApp {
    background: radial-gradient(ellipse at top right, #12362a55, transparent 55%), #08110f;
    color: #effff7;
}
.block-container {padding-top: 3rem; padding-bottom: 3rem; max-width: 1600px;}
h1, h2, h3 {letter-spacing: -.025em;}
h1 {color: #42f5ad !important; font-family: Consolas, monospace !important;}
[data-testid="stHeader"] {background: #08110fe8;}
[data-testid="stSidebar"] {background: #0d1918; border-right: 1px solid #284438;}
[data-testid="stMetric"] {
    background: #0d1918; border: 1px solid #284438; border-top: 3px solid #42f5ad;
    border-radius: 10px; padding: 18px 16px; min-height: 112px;
}
[data-testid="stMetricValue"] {
    color: #effff7; font-family: Consolas, monospace; font-variant-numeric: tabular-nums;
    font-size: clamp(1.4rem, 2.4vw, 2.3rem); line-height: 1.4;
    overflow: visible !important; white-space: normal !important;
}
[data-testid="stMetricLabel"] {color: #c3d8d0;}
[data-testid="stMetricLabel"] p {white-space: normal !important;}
.stButton button, .stDownloadButton button, .stLinkButton a {
    border: 1px solid #42f5ad88; border-radius: 7px; background: #10281d; color: #effff7;
}
.stButton button:hover, .stDownloadButton button:hover, .stLinkButton a:hover {
    border-color: #42f5ad; background: #193f2e; color: #42f5ad;
}
.soc-tag {font-family: Consolas, monospace; font-size: .8rem; color: #91b8a4;
          letter-spacing: .12em; margin-bottom: .5rem;}
@media(max-width: 850px) {
    [data-testid="stHorizontalBlock"] {flex-wrap: wrap; gap: 1rem;}
    [data-testid="stHorizontalBlock"] > [data-testid="stColumn"] {
        min-width: min(100%, 220px); flex: 1 1 220px;
    }
}
</style>
''', unsafe_allow_html=True)


def connection_panel():
    profile_path = Path(__file__).with_name('profile.toml')
    profiles = tomllib.loads(profile_path.read_text(encoding='utf-8'))
    with st.sidebar:
        st.markdown('### AETHER / SOC')
        st.caption('DEFENSIVE OPERATIONS LAB')
        st.divider()
        st.markdown('### Connect with the builder')
        st.write('Explore the project or connect about cybersecurity opportunities.')
        for key, label, domain in [('linkedin', 'Connect on LinkedIn', 'linkedin.com'),
                                   ('github', 'View GitHub', 'github.com')]:
            url = profiles.get(key, '').strip()
            parsed = urlparse(url)
            if parsed.scheme == 'https' and parsed.hostname in {domain, 'www.' + domain}:
                st.link_button(label, url, use_container_width=True)
            else:
                st.caption(f'{label}: profile link awaiting configuration.')
        st.divider()
        st.caption('Synthetic telemetry only. Local analysis. Human-reviewed response.')
