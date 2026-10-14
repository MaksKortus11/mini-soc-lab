import json
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st


ROOT = Path(__file__).resolve().parent
ALERTS_FILE = ROOT / "reports" / "alerts.json"
SUMMARY_FILE = ROOT / "reports" / "summary.json"

st.set_page_config(
    page_title="MINI SOC LAB // MATRIX",
    page_icon="🟢",
    layout="wide",
)


# =========================================================
# STYL: STABILNY MOTYW MATRIX (BEZ WARSTWY ZASŁANIAJĄCEJ UI)
# =========================================================

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

    /* Kolory alertów w tabeli */
    [data-testid="stDataFrame"] {
        box-shadow: 0 0 8px rgba(0, 255, 102, 0.04);
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# =========================================================
# ODCZYT RAPORTÓW
# =========================================================

def read_json(path):
    if not path.exists():
        return None

    try:
        with path.open("r", encoding="utf-8") as file:
            return json.load(file)
    except (json.JSONDecodeError, OSError):
        return None


summary = read_json(SUMMARY_FILE)
alerts = read_json(ALERTS_FILE)

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


# =========================================================
# POLSKIE NAZWY I POMOCNICZE FUNKCJE
# =========================================================

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


def mitre_id(alert):
    """Pobiera identyfikator techniki MITRE ATT&CK z alertu."""
    mitre = alert.get("mitre_attack")

    if isinstance(mitre, dict):
        return mitre.get("id", "-")

    return alert.get("mitre_id", "-")


def styl_poziomu(value):
    """Zwraca styl komórki dla poziomu alertu."""
    if value == "Krytyczny":
        return (
            "background-color: #5c1018; "
            "color: #ff6675; font-weight: bold;"
        )

    if value == "Wysoki":
        return (
            "background-color: #401016; "
            "color: #ff626e; font-weight: bold;"
        )

    if value == "Średni":
        return (
            "background-color: #33280a; "
            "color: #ffd166; font-weight: bold;"
        )

    if value == "Niski":
        return (
            "background-color: #0b3020; "
            "color: #00ff88; font-weight: bold;"
        )

    return ""


# =========================================================
# NAGŁÓWEK
# =========================================================

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


# =========================================================
# PANEL BOCZNY
# =========================================================

with st.sidebar:
    st.markdown("## // PANEL STEROWANIA")
    st.markdown("`STATUS SYSTEMU: AKTYWNY`")
    st.markdown("`TRYB: ANALIZA LOKALNA`")

    st.divider()

    st.markdown("### ŹRÓDŁA DANYCH")
    st.code("reports/alerts.json")
    st.code("reports/summary.json")
    st.caption("Dane pochodzą z lokalnego analizatora.")

    if st.button("↻ ODŚWIEŻ DANE", use_container_width=True):
        st.rerun()


# =========================================================
# KARTY STATYSTYK
# =========================================================

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


# =========================================================
# WYKRES: ALERTY WEDŁUG POZIOMU
# =========================================================

st.markdown("### // ALERTY WEDŁUG POZIOMU")

kolejnosc_kodow = ["KRYTYCZNY", "WYSOKI", "SREDNI", "NISKI"]
kolejnosc_poziomow = [nazwy_poziomow[kod] for kod in kolejnosc_kodow]

dane_poziomow = pd.DataFrame({
    "Poziom": kolejnosc_poziomow,
    "Liczba alertów": [
        by_level.get(kod, 0) for kod in kolejnosc_kodow
    ],
})

wykres_poziomow = (
    alt.Chart(dane_poziomow)
    .mark_bar(color="#00ff66", cornerRadiusEnd=3)
    .encode(
        x=alt.X(
            "Liczba alertów:Q",
            title="Liczba alertów",
            axis=alt.Axis(format="d", tickMinStep=1),
        ),
        y=alt.Y(
            "Poziom:N",
            sort=kolejnosc_poziomow,
            title=None,
            axis=alt.Axis(labelAngle=0),
        ),
        tooltip=[
            alt.Tooltip("Poziom:N", title="Poziom"),
            alt.Tooltip("Liczba alertów:Q", title="Liczba alertów"),
        ],
    )
    .properties(height=180)
    .configure_view(stroke=None)
    .configure_axis(
        labelColor="#b8eac7",
        titleColor="#00ff66",
        gridColor="#173322",
    )
    .configure(background="#050907")
)

st.altair_chart(wykres_poziomow, use_container_width=True)

st.divider()


# =========================================================
# WYKRES: TYPY WYKRYTYCH ATAKÓW
# =========================================================

st.markdown("### // TYPY WYKRYTYCH ATAKÓW")

if by_type:
    dane_typow = pd.DataFrame([
        {
            "Typ wykrycia": nazwy_typow.get(typ, typ),
            "Liczba alertów": liczba,
        }
        for typ, liczba in by_type.items()
    ])

    wykres_typow = (
        alt.Chart(dane_typow)
        .mark_bar(color="#00cc55", cornerRadiusEnd=3)
        .encode(
            x=alt.X(
                "Liczba alertów:Q",
                title="Liczba alertów",
                axis=alt.Axis(format="d", tickMinStep=1),
            ),
            y=alt.Y(
                "Typ wykrycia:N",
                sort="-x",
                title=None,
                axis=alt.Axis(
                    labelAngle=0,
                    labelLimit=600,
                    labelPadding=8,
                ),
            ),
            tooltip=[
                alt.Tooltip("Typ wykrycia:N", title="Typ wykrycia"),
                alt.Tooltip(
                    "Liczba alertów:Q",
                    title="Liczba alertów",
                ),
            ],
        )
        .properties(height=max(120, len(dane_typow) * 55))
        .configure_view(stroke=None)
        .configure_axis(
            labelColor="#b8eac7",
            titleColor="#00ff66",
            gridColor="#173322",
        )
        .configure(background="#050907")
    )

    st.altair_chart(wykres_typow, use_container_width=True)
else:
    st.info("Brak danych o wykrytych typach ataków.")


st.divider()


# =========================================================
# TABELA ALERTÓW
# =========================================================

st.markdown("### // STRUMIEŃ WYKRYTYCH ZAGROŻEŃ")

if alerts:
    rows = []

    for alert in alerts:
        adresy = alert.get("adresy_ip", [])
        if not isinstance(adresy, list):
            adresy = []

        adres_ip = (
            ", ".join(str(ip) for ip in adresy)
            or alert.get("adres_ip", "-")
        )

        rows.append({
            "ID ALERTU": alert.get("id_alertu", "-"),
            "TYP WYKRYCIA": nazwy_typow.get(
                alert.get("typ_wykrycia", ""),
                alert.get("typ_wykrycia", "-"),
            ),
            "POZIOM": nazwy_poziomow.get(
                alert.get("poziom", ""),
                alert.get("poziom", "-"),
            ),
            "ADRESY IP": adres_ip,
            "KONTO": alert.get("uzytkownik", "-"),
            "MITRE ATT&CK": mitre_id(alert),
        })

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
    )
    selected_type = f2.selectbox(
        "Filtruj typ wykrycia",
        type_options,
    )
    search_ip = f3.text_input("Szukaj adresu IP")

    filtered = df.copy()

    if selected_severity != "Wszystkie":
        filtered = filtered[filtered["POZIOM"] == selected_severity]

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
        use_container_width=True,
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


# =========================================================
# STOPKA
# =========================================================

st.divider()

st.markdown(
    """
    <span style="color:#4d9b6a">
        MINI SOC LAB // BEZPIECZEŃSTWO DEFENSYWNE // TRYB MATRIX
    </span>
    """,
    unsafe_allow_html=True,
)
