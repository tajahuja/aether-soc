import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pandas as pd
import streamlit as st
from app.storage import read
from app.models.security import Incident
from app.reporting.markdown import report
from app.ai.analyst import OfflineAnalyst
from dashboard.appearance import apply_theme, connection_panel
from dashboard.charts import counts, over_time

st.set_page_config(page_title='AetherSOC', page_icon='🛡️', layout='wide')
apply_theme()
connection_panel()
st.markdown('<div class="soc-tag">// SECURITY OPERATIONS · SYNTHETIC LAB</div>',
            unsafe_allow_html=True)
st.title('AetherSOC')
st.caption('AI-ready mini SOC • Synthetic telemetry • Local defensive analysis')
if st.button('Refresh analysis snapshot'):
    st.rerun()
events, alerts, incidents = read('events'), read('alerts'), read('incidents')
for column, label, value in zip(st.columns(5),
        ['Total Events','Alerts Generated','Open Incidents','Critical Alerts','High Alerts'],
        [len(events), len(alerts), sum(i['status']=='OPEN' for i in incidents),
         sum(a['severity']=='CRITICAL' for a in alerts), sum(a['severity']=='HIGH' for a in alerts)]):
    column.metric(label, f'{value:,}')
if not alerts:
    st.info('Generate the demo first: python -m app.cli demo')
    st.stop()
frame = pd.DataFrame(alerts)
left, right = st.columns(2)
with left:
    st.subheader('Alerts by severity')
    st.altair_chart(counts(frame['severity'].value_counts(), 'Severity', severity=True),
                    use_container_width=True)
    st.subheader('Top source IPs')
    st.altair_chart(counts(frame['source'].replace('', 'unknown').value_counts().head(8),
                           'Source IP'), use_container_width=True)
    st.subheader('Detections by rule')
    st.altair_chart(counts(frame['rule_name'].value_counts(), 'Detection rule'),
                    use_container_width=True)
with right:
    st.subheader('Alerts over time (UTC)')
    st.altair_chart(over_time(frame['timestamp']), use_container_width=True)
    st.subheader('Top affected users')
    st.altair_chart(counts(frame['affected_user'].value_counts().head(8), 'User'),
                    use_container_width=True)
    st.subheader('ATT&CK techniques observed')
    st.altair_chart(counts(frame.explode('mitre')['mitre'].dropna().value_counts(),
                           'Technique'), use_container_width=True)
st.subheader('Incident queue')
st.dataframe(pd.DataFrame(incidents)[['incident_id','severity','risk_score','start_time','status','title']],
             hide_index=True, use_container_width=True)
options = {f"{item['incident_id']} • {item['risk_score']}/100 • {', '.join(item['users'])}": item
           for item in incidents}
selected = st.selectbox('Investigate incident', list(options))
incident = Incident.model_validate(options[selected])
st.subheader(incident.title)
st.write(f'**{incident.severity} · Risk {incident.risk_score}/100**')
st.write('Users:', ', '.join(incident.users), ' | Hosts:', ', '.join(incident.hosts))
st.write('ATT&CK:', ', '.join(incident.attack_techniques) or 'No supported mapping')
for reason in incident.risk_reasons:
    st.write(reason)
st.dataframe(pd.DataFrame([e.model_dump(mode='json', exclude={'raw_event'}) for e in incident.timeline]),
             hide_index=True, use_container_width=True)
with st.expander('Raw evidence and associated alerts'):
    st.json([a for a in alerts if a['alert_id'] in incident.associated_alerts])
    st.json([e.raw_event for e in incident.timeline])
st.subheader('Analyst recommendations')
for action in incident.recommended_actions:
    st.write('• ' + action)
st.info(OfflineAnalyst().summarize(incident))
st.download_button('Download investigation report', report(incident),
                   file_name=f'{incident.incident_id}.md', mime='text/markdown')
