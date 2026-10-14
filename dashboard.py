
import json
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st


ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "data"
ALERTS_FILE = ROOT / "reports" / "alerts.json"
SUMMARY_FILE = ROOT / "reports" / "summary.json"

st.set_page_config(
    page_title="MINI SOC LAB // MATRIX",
    page_icon="🟢",
    layout="wide",
)

st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&display=swap');

    .stApp {
        background: #050907;
        color: #d7ffe3;
        font-family: 'JetBrains Mono', monospace;
    }

    [data-testid="stSidebar"] {
        background: #08110b;
        border-right: 1px solid #174d2d;
    }

    h1, h2, h3 {
        color: #00ff66 !important;
        font-family: 'JetBrains Mono', monospace !important;
    }

    p, label, span {
        font-family: 'JetBrains Mono', monospace;
    }

    [data-testid="stMetric"] {
        background: #0a140d;
        border: 1px solid #174d2d;
        border-radius: 8px;
        padding: 16px;
    }

    [data-testid="stMetricLabel"] {
        color: #75b98b !important;
    }

    [data-testid="stMetricValue"] {
        color: #00ff66 !important;
    }

    [data-testid="stDataFrame"] {
        border: 1px solid #174d2d;
        border-radius: 8px;
        box-shadow: 0 0 8px rgba(0, 255, 102, 0.04);
    }

    div.stButton > button {
        background: #0b1b10;
        color: #00ff66;
        border: 1px solid #00a844;
        border-radius: 5px;
    }

    div.stButton > button:hover {
        background: #12351e;
        color: #baffce;
        border-color: #00ff66;
    }

    hr {
        border-color: #174d2d;
    }

    code {
        color: #00ff66 !important;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


def read_json(path):
    if not path.exists():
        return None

    try:
        with path.open("r", encoding="utf-8") as file:
            return json.load(file)
    except (json.JSONDecodeError, OSError):
        return None


def read_all_logs():
    frames = []

    columns = [
        "znacznik_czasu",
        "adres_ip",
        "uzytkownik",
        "zdarzenie",
        "scenariusz",
    ]

    if not DATA_DIR.exists():
        return pd.DataFrame(columns=columns)

    required_columns = {
        "znacznik_czasu",
        "adres_ip",
        "uzytkownik",
        "zdarzenie",
    }

    for path in sorted(DATA_DIR.glob("*.csv")):
        try:
            df = pd.read_csv(path, encoding="utf-8-sig")

            if not required_columns.issubset(df.columns):
                continue

            df = df.copy()
            df["scenariusz"] = path.stem
            frames.append(df)

        except (OSError, pd.errors.ParserError, UnicodeDecodeError):
            continue

    if not frames:
        return pd.DataFrame(columns=columns)

    logs = pd.concat(frames, ignore_index=True)

    logs["znacznik_czasu"] = pd.to_datetime(
        logs["znacznik_czasu"],
        errors="coerce",
    )

    return logs.sort_values(
        "znacznik_czasu",
        ascending=False,
        na_position="last",
    )


def mitre_id(alert):
    mitre = alert.get("mitre_attack")

    if isinstance(mitre, dict):
        return mitre.get("id", "-")

    return alert.get("mitre_id", "-")


def styl_poziomu(value):
    styles = {
        "Krytyczny": (
            "background-color: #5c1018; "
            "color: #ff6675; font-weight: bold;"
        ),
        "Wysoki": (
            "background-color: #401016; "
            "color: #ff626e; font-weight: bold;"
        ),
        "Średni": (
            "background-color: #33280a; "
            "color: #ffd166; font-weight: bold;"
        ),
        "Niski": (
            "background-color: #0b3020; "
            "color: #00ff88; font-weight: bold;"
        ),
    }

    return styles.get(value, "")


def styl_zdarzenia(row):
    if row["ZDARZENIE"] == "LOGOWANIE_UDANE":
        return [
            "background-color: #0b3020; color: #00ff88;"
        ] * len(row)

    if row["ZDARZENIE"] == "LOGOWANIE_NIEUDANE":
        return [
            "background-color: #351218; color: #ff6675;"
        ] * len(row)

    return [""] * len(row)


nazwy_poziomow = {
    "KRYTYCZNY": "Krytyczny",
    "WYSOKI": "Wysoki",
    "SREDNI": "Średni",
    "NISKI": "Niski",
}

nazwy_typow = {
    "BRUTE_FORCE": "Brute-force — zgadywanie haseł",
    "PASSWORD_SPRAYING": "Password spraying — wiele kont",
    "DISTRIBUTED_BRUTE_FORCE": (
        "Rozproszony brute-force — wiele adresów IP"
    ),
}

summary = read_json(SUMMARY_FILE)
alerts = read_json(ALERTS_FILE)
logs = read_all_logs()

if not isinstance(summary, dict):
    summary = {}

if not isinstance(alerts, list):
    alerts = []

by_level = summary.get("alerty_wedlug_poziomu", {})
by_type = summary.get("alerty_wedlug_typu", {})

if not isinstance(by_level, dict):
    by_level = {}

if not isinstance(by_type, dict):
    by_type = {}


st.markdown("# 🟢 MINI SOC LAB")

st.markdown(
    """
    <span style="color:#4d9b6a">
        CENTRUM OPERACJI BEZPIECZEŃSTWA //
        MONITOROWANIE UWIERZYTELNIANIA
    </span>
    """,
    unsafe_allow_html=True,
)

st.divider()

with st.sidebar:
    st.markdown("## // PANEL STEROWANIA")
    st.markdown("`STATUS SYSTEMU: AKTYWNY`")
    st.markdown("`TRYB: ANALIZA LOKALNA`")

    st.divider()

    st.markdown("### ŹRÓDŁA DANYCH")
    st.code("data/*.csv")
    st.code("reports/alerts.json")
    st.code("reports/summary.json")
    st.caption("Dane pochodzą z lokalnego analizatora.")

    if st.button("↻ ODŚWIEŻ DANE", width="stretch"):
        st.rerun()


st.markdown("### // DZIENNIK ZDARZEŃ")

if logs.empty:
    st.warning(
        "Nie znaleziono prawidłowych plików CSV w folderze data."
    )
else:
    successful_events = int(
        (logs["zdarzenie"] == "LOGOWANIE_UDANE").sum()
    )
    failed_events = int(
        (logs["zdarzenie"] == "LOGOWANIE_NIEUDANE").sum()
    )

    m1, m2, m3 = st.columns(3)
    m1.metric("WSZYSTKIE ZDARZENIA", len(logs))
    m2.metric("UDANE LOGOWANIA", successful_events)
    m3.metric("NIEUDANE LOGOWANIA", failed_events)

    f1, f2, f3 = st.columns(3)

    scenarios = ["Wszystkie"] + sorted(
        logs["scenariusz"].dropna().unique().tolist()
    )

    selected_scenario = f1.selectbox(
        "Scenariusz",
        scenarios,
        key="log_scenario",
    )

    event_types = ["Wszystkie"] + sorted(
        logs["zdarzenie"].dropna().unique().tolist()
    )

    selected_event = f2.selectbox(
        "Rodzaj zdarzenia",
        event_types,
        key="log_event",
    )

    search_text = f3.text_input(
        "Szukaj IP lub użytkownika",
        key="log_search",
    )

    filtered_logs = logs.copy()

    if selected_scenario != "Wszystkie":
        filtered_logs = filtered_logs[
            filtered_logs["scenariusz"] == selected_scenario
        ]

    if selected_event != "Wszystkie":
        filtered_logs = filtered_logs[
            filtered_logs["zdarzenie"] == selected_event
        ]

    if search_text:
        search_mask = (
            filtered_logs["adres_ip"].astype(str).str.contains(
                search_text,
                case=False,
                na=False,
                regex=False,
            )
            | filtered_logs["uzytkownik"].astype(str).str.contains(
                search_text,
                case=False,
                na=False,
                regex=False,
            )
        )

        filtered_logs = filtered_logs[search_mask]

    display_logs = filtered_logs.rename(
        columns={
            "znacznik_czasu": "CZAS",
            "adres_ip": "ADRES IP",
            "uzytkownik": "UŻYTKOWNIK",
            "zdarzenie": "ZDARZENIE",
            "scenariusz": "SCENARIUSZ",
        }
    )

    st.caption(
        f"Liczba wyświetlanych zdarzeń: {len(display_logs)}"
    )

    styled_logs = display_logs.style.apply(
        styl_zdarzenia,
        axis=1,
    )

    st.dataframe(
        styled_logs,
        width="stretch",
        hide_index=True,
    )

st.divider()


alert_count = summary.get("liczba_alertow", len(alerts))
event_count = summary.get("liczba_zdarzen", 0)
high_count = by_level.get("WYSOKI", 0)
critical_count = by_level.get("KRYTYCZNY", 0)

ip_data = summary.get("adresy_ip_w_alertach", {})
ip_count = len(ip_data) if isinstance(ip_data, dict) else 0

c1, c2, c3, c4 = st.columns(4)
c1.metric("PRZEANALIZOWANE ZDARZENIA", event_count)
c2.metric("WYKRYTE ALERTY", alert_count)
c3.metric("WYSOKIE / KRYTYCZNE", high_count + critical_count)
c4.metric("PODEJRZANE ADRESY IP", ip_count)

st.divider()


chart1, chart2 = st.columns(2, gap="large")

with chart1:
    st.markdown("### // ALERTY WEDŁUG POZIOMU")

    dane_poziomow = pd.DataFrame(
        {
            "Poziom": [
                nazwy_poziomow[kod]
                for kod in ["KRYTYCZNY", "WYSOKI", "SREDNI", "NISKI"]
            ],
            "Liczba alertów": [
                by_level.get(kod, 0)
                for kod in ["KRYTYCZNY", "WYSOKI", "SREDNI", "NISKI"]
            ],
        }
    )

    sort_poziomow = [
        "Krytyczny",
        "Wysoki",
        "Średni",
        "Niski",
    ]

    wykres_poziomow = (
        alt.Chart(dane_poziomow)
        .mark_bar(
            color="#00ff66",
            cornerRadiusEnd=3,
        )
        .encode(
            x=alt.X(
                "Liczba alertów:Q",
                title=None,
                scale=alt.Scale(domainMin=0),
                axis=alt.Axis(format="d", tickMinStep=1),
            ),
            y=alt.Y(
                "Poziom:N",
                sort=sort_poziomow,
                title=None,
                axis=alt.Axis(labelAngle=0),
            ),
            tooltip=[
                alt.Tooltip("Poziom:N", title="Poziom"),
                alt.Tooltip(
                    "Liczba alertów:Q",
                    title="Liczba alertów",
                ),
            ],
        )
    )

    etykiety_poziomow = (
        alt.Chart(dane_poziomow)
        .mark_text(
            align="left",
            dx=5,
            color="#d7ffe3",
            fontSize=11,
        )
        .encode(
            x=alt.X(
                "Liczba alertów:Q",
                scale=alt.Scale(domainMin=0),
            ),
            y=alt.Y(
                "Poziom:N",
                sort=sort_poziomow,
            ),
            text=alt.Text(
                "Liczba alertów:Q",
                format="d",
            ),
        )
    )

    wykres_poziomow_polaczony = (
        wykres_poziomow + etykiety_poziomow
    ).configure_view(
        stroke=None
    ).configure_axis(
        labelColor="#b8eac7",
        titleColor="#00ff66",
        gridColor="#173322",
        labelFontSize=11,
    ).configure(
        background="#050907"
    )

    st.altair_chart(
        wykres_poziomow_polaczony,
        width="stretch",
    )


with chart2:
    st.markdown("### // TYPY WYKRYTYCH ATAKÓW")

    if by_type:
        dane_typow = pd.DataFrame(
            [
                {
                    "Typ wykrycia": nazwy_typow.get(typ, typ),
                    "Liczba alertów": liczba,
                }
                for typ, liczba in by_type.items()
            ]
        )

        wykres_typow = (
            alt.Chart(dane_typow)
            .mark_bar(
                color="#00cc55",
                cornerRadiusEnd=3,
            )
            .encode(
                x=alt.X(
                    "Liczba alertów:Q",
                    title=None,
                    scale=alt.Scale(domainMin=0),
                    axis=alt.Axis(format="d", tickMinStep=1),
                ),
                y=alt.Y(
                    "Typ wykrycia:N",
                    sort="-x",
                    title=None,
                    axis=alt.Axis(
                        labelAngle=0,
                        labelLimit=250,
                        labelPadding=6,
                    ),
                ),
                tooltip=[
                    alt.Tooltip(
                        "Typ wykrycia:N",
                        title="Typ wykrycia",
                    ),
                    alt.Tooltip(
                        "Liczba alertów:Q",
                        title="Liczba alertów",
                    ),
                ],
            )
        )

        etykiety_typow = (
            alt.Chart(dane_typow)
            .mark_text(
                align="left",
                dx=5,
                color="#d7ffe3",
                fontSize=11,
            )
            .encode(
                x=alt.X(
                    "Liczba alertów:Q",
                    scale=alt.Scale(domainMin=0),
                ),
                y=alt.Y(
                    "Typ wykrycia:N",
                    sort="-x",
                ),
                text=alt.Text(
                    "Liczba alertów:Q",
                    format="d",
                ),
            )
        )

        wykres_typow_polaczony = (
            wykres_typow + etykiety_typow
        ).properties(
            height=max(100, len(dane_typow) * 38)
        ).configure_view(
            stroke=None
        ).configure_axis(
            labelColor="#b8eac7",
            titleColor="#00ff66",
            gridColor="#173322",
            labelFontSize=11,
        ).configure(
            background="#050907"
        )

        st.altair_chart(
            wykres_typow_polaczony,
            width="stretch",
        )
    else:
        st.info("Brak danych o wykrytych typach ataków.")

st.divider()


st.markdown("### // STRUMIEŃ WYKRYTYCH ZAGROŻEŃ")

if alerts:
    rows = []

    for alert in alerts:
        addresses = alert.get("adresy_ip", [])

        if not isinstance(addresses, list):
            addresses = []

        address_text = (
            ", ".join(str(ip) for ip in addresses)
            or alert.get("adres_ip", "-")
        )

        detection_type = alert.get("typ_wykrycia", "-")
        level = alert.get("poziom", "-")

        rows.append(
            {
                "ID ALERTU": alert.get("id_alertu", "-"),
                "TYP WYKRYCIA": nazwy_typow.get(
                    detection_type,
                    detection_type,
                ),
                "POZIOM": nazwy_poziomow.get(level, level),
                "ADRESY IP": address_text,
                "KONTO": alert.get("uzytkownik", "-"),
                "MITRE ATT&CK": mitre_id(alert),
            }
        )

    df = pd.DataFrame(rows)

    f1, f2, f3 = st.columns(3)

    severity_options = ["Wszystkie"] + sorted(
        df["POZIOM"].dropna().unique().tolist()
    )

    type_options = ["Wszystkie"] + sorted(
        df["TYP WYKRYCIA"].dropna().unique().tolist()
    )

    selected_severity = f1.selectbox(
        "Filtruj poziom alertu",
        severity_options,
        key="alert_severity",
    )

    selected_type = f2.selectbox(
        "Filtruj typ wykrycia",
        type_options,
        key="alert_type",
    )

    search_ip = f3.text_input(
        "Szukaj adresu IP",
        key="alert_ip",
    )

    filtered = df.copy()

    if selected_severity != "Wszystkie":
        filtered = filtered[
            filtered["POZIOM"] == selected_severity
        ]

    if selected_type != "Wszystkie":
        filtered = filtered[
            filtered["TYP WYKRYCIA"] == selected_type
        ]

    if search_ip:
        filtered = filtered[
            filtered["ADRESY IP"].str.contains(
                search_ip,
                case=False,
                na=False,
                regex=False,
            )
        ]

    styled_df = filtered.style.map(
        styl_poziomu,
        subset=["POZIOM"],
    )

    st.dataframe(
        styled_df,
        width="stretch",
        hide_index=True,
    )

    with st.expander("⌕ SZCZEGÓŁY ALERTU"):
        selected_index = st.selectbox(
            "Wybierz alert do podglądu",
            range(len(alerts)),
            format_func=lambda i: (
                f"{nazwy_typow.get(alerts[i].get('typ_wykrycia', ''), alerts[i].get('typ_wykrycia', 'ALERT'))} "
                f"— {alerts[i].get('id_alertu', i)}"
            ),
            key="alert_details",
        )

        alert_detail = alerts[selected_index]
        level = alert_detail.get("poziom", "")

        if level in ("WYSOKI", "KRYTYCZNY"):
            st.error(
                f"⚠ ALERT {nazwy_poziomow.get(level, level)} "
                "— wymaga weryfikacji"
            )
        elif level == "SREDNI":
            st.warning("Alert o średnim poziomie ryzyka.")
        else:
            st.success("Alert o niskim poziomie ryzyka.")

        st.json(alert_detail)
else:
    st.success("Brak alertów w aktualnym raporcie.")

st.divider()

st.markdown(
    """
    <span style="color:#4d9b6a">
        MINI SOC LAB // BEZPIECZEŃSTWO DEFENSYWNE // TRYB MATRIX
    </span>
    """,
    unsafe_allow_html=True,
)
