"""Explicit chart sizing and integer axes keep security counts readable."""
import altair as alt
import pandas as pd

GREEN = '#42f5ad'
SEVERITY_COLORS = ['#42f5ad', '#f4ce68', '#ff986a', '#ff5975']


def finish(chart: alt.Chart, height: int = 270) -> alt.Chart:
    return (chart.properties(height=height, padding={'left': 24, 'right': 36,
                                                    'top': 16, 'bottom': 24})
            .configure(background='#0d1918')
            .configure_view(strokeOpacity=0)
            .configure_axis(labelColor='#c3d8d0', titleColor='#c3d8d0',
                            gridColor='#243b33', domainColor='#385347',
                            labelFontSize=12, titleFontSize=12, labelPadding=10,
                            labelLimit=300)
            .configure_title(color='#effff7'))


def counts(series: pd.Series, category: str, severity: bool = False) -> alt.Chart:
    """Horizontal labels and text counts avoid truncation and rotated IP addresses."""
    data = series.rename_axis(category).reset_index(name='Alerts')
    bars = alt.Chart(data).mark_bar(cornerRadiusEnd=4, size=22).encode(
        y=alt.Y(f'{category}:N', sort='-x', title=None,
                axis=alt.Axis(labelLimit=300)),
        x=alt.X('Alerts:Q', title='Alert count', scale=alt.Scale(zero=True),
                axis=alt.Axis(format='d', tickMinStep=1)),
        color=(alt.Color(f'{category}:N', legend=None,
                         scale=alt.Scale(domain=['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
                                         range=SEVERITY_COLORS)) if severity else alt.value(GREEN)),
        tooltip=[alt.Tooltip(f'{category}:N'), alt.Tooltip('Alerts:Q', format='d')])
    values = bars.mark_text(align='left', dx=7, color='#effff7', fontSize=13).encode(
        text=alt.Text('Alerts:Q', format='d'), color=alt.value('#effff7'))
    return finish(bars + values, max(220, len(data) * 43))


def over_time(timestamps: pd.Series) -> alt.Chart:
    # A literal UTC label avoids browser-local timezone changes in the plotted axis.
    times = pd.to_datetime(timestamps, utc=True)
    data = pd.Series(1, index=times).resample('15min').sum().rename('Alerts').reset_index()
    data.columns = ['Timestamp', 'Alerts']
    chart = alt.Chart(data).mark_line(color=GREEN, point=True).encode(
        x=alt.X('Timestamp:T', title='UTC time',
                scale=alt.Scale(type='utc'),
                axis=alt.Axis(format='%H:%M', labelAngle=0, tickCount=6)),
        y=alt.Y('Alerts:Q', title='Alert count', scale=alt.Scale(zero=True),
                axis=alt.Axis(format='d', tickMinStep=1)),
        tooltip=[alt.Tooltip('Timestamp:T', title='UTC time', format='%Y-%m-%d %H:%M'),
                 alt.Tooltip('Alerts:Q', format='d')])
    return finish(chart)
