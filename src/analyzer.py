
import csv
import argparse
import json
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path

OKNO_MINUTY = 5
PROG_NIEUDANYCH_LOGOWAN = 5
PROG_ROZNYCH_KONT = 3

KATALOG_PROJEKTU = Path(__file__).resolve().parent.parent
PLIK_LOGOW = KATALOG_PROJEKTU / "data" / "auth_logs.csv"
PLIK_ALERTOW = KATALOG_PROJEKTU / "reports" / "alerts.json"

WYMAGANE_KOLUMNY = {
    "znacznik_czasu",
    "adres_ip",
    "uzytkownik",
    "zdarzenie",
}

ZDARZENIA = {"LOGOWANIE_UDANE", "LOGOWANIE_NIEUDANE"}


def wczytaj_logi(sciezka=PLIK_LOGOW):
    """Wczytuje, sprawdza i sortuje zdarzenia logowania."""

    if not sciezka.exists():
        raise FileNotFoundError(
            f"Nie znaleziono pliku z logami: {sciezka}"
        )

    with sciezka.open(
        "r",
        encoding="utf-8-sig",
        newline="",
    ) as plik:
        probka = plik.read(4096)
        plik.seek(0)

        try:
            format_csv = csv.Sniffer().sniff(
                probka,
                delimiters=",;",
            )
        except csv.Error:
            format_csv = csv.excel

        czytnik = csv.DictReader(plik, dialect=format_csv)

        if not czytnik.fieldnames:
            raise ValueError("Plik CSV jest pusty lub nie ma nagłówka.")

        czytnik.fieldnames = [
            nazwa.strip().lstrip("\ufeff").lower()
            for nazwa in czytnik.fieldnames
        ]

        brakujace = WYMAGANE_KOLUMNY - set(czytnik.fieldnames)

        if brakujace:
            raise ValueError(
                f"Brak wymaganych kolumn w CSV: {sorted(brakujace)}"
            )

        logi = []

        for numer_linii, wiersz in enumerate(czytnik, start=2):
            if not wiersz or all(
                wartosc is None or not wartosc.strip()
                for wartosc in wiersz.values()
            ):
                continue

            try:
                czas = datetime.fromisoformat(
                    wiersz["znacznik_czasu"].strip()
                )
            except (ValueError, AttributeError):
                raise ValueError(
                    f"Nieprawidłowy znacznik czasu w linii {numer_linii}."
                )

            adres_ip = (wiersz.get("adres_ip") or "").strip()
            uzytkownik = (wiersz.get("uzytkownik") or "").strip()
            zdarzenie = (wiersz.get("zdarzenie") or "").strip().upper()

            if not adres_ip or not uzytkownik:
                raise ValueError(
                    f"Brak adresu IP lub użytkownika w linii {numer_linii}."
                )

            if zdarzenie not in ZDARZENIA:
                raise ValueError(
                    f"Nieznany rodzaj zdarzenia w linii "
                    f"{numer_linii}: {zdarzenie}"
                )

            logi.append({
                "czas": czas,
                "adres_ip": adres_ip,
                "uzytkownik": uzytkownik,
                "zdarzenie": zdarzenie,
            })

    logi.sort(key=lambda wpis: wpis["czas"])
    return logi


def analizuj_logi(logi):
    """
    Wykrywa brute-force na pojedyncze konto i password spraying
    obejmujący wiele kont w ruchomym oknie czasowym.
    """

    okno = timedelta(minutes=OKNO_MINUTY)

    # Dotychczasowa detekcja: adres IP + konkretne konto.
    nieudane_logowania = defaultdict(deque)
    podejrzane_serie = []

    # Nowa detekcja: wszystkie nieudane próby z danego adresu IP.
    nieudane_na_ip = defaultdict(deque)
    podejrzane_spraying = []
    ostatni_alert_spraying = {}

    for wpis in logi:
        czas = wpis["czas"]
        adres_ip = wpis["adres_ip"]
        uzytkownik = wpis["uzytkownik"]
        zdarzenie = wpis["zdarzenie"]

        klucz = (adres_ip, uzytkownik)
        proby = nieudane_logowania[klucz]
        granica_czasu = czas - okno

        # Usuń stare próby dla konkretnego konta.
        while proby and proby[0]["czas"] < granica_czasu:
            proby.popleft()

        # Usuń stare próby dla adresu IP.
        proby_ip = nieudane_na_ip[adres_ip]

        while proby_ip and proby_ip[0]["czas"] < granica_czasu:
            proby_ip.popleft()

        if zdarzenie == "LOGOWANIE_NIEUDANE":
            nowa_proba = {
                "czas": czas,
                "uzytkownik": uzytkownik,
            }

            proby.append(nowa_proba)
            proby_ip.append(nowa_proba)

            # Reguła 1: pięć błędów dla jednego konta.
            if len(proby) == PROG_NIEUDANYCH_LOGOWAN:
                podejrzane_serie.append({
                    "adres_ip": adres_ip,
                    "uzytkownik": uzytkownik,
                    "pierwsza_proba": proby[0]["czas"],
                    "ostatnia_proba": czas,
                    "liczba_prob": len(proby),
                    "logowanie_udane_po_serii": False,
                    "czas_udanego_logowania": None,
                })

            # Reguła 2: password spraying z jednego adresu IP.
            rozne_konta = {
                proba["uzytkownik"] for proba in proby_ip
            }

            poprzedni_alert = ostatni_alert_spraying.get(adres_ip)

            mozna_zglosic = (
                poprzedni_alert is None
                or czas - poprzedni_alert > okno
            )

            if (
                len(proby_ip) >= PROG_NIEUDANYCH_LOGOWAN
                and len(rozne_konta) >= PROG_ROZNYCH_KONT
                and mozna_zglosic
            ):
                podejrzane_spraying.append({
                    "adres_ip": adres_ip,
                    "konta": sorted(rozne_konta),
                    "pierwsza_proba": proby_ip[0]["czas"],
                    "ostatnia_proba": czas,
                    "liczba_prob": len(proby_ip),
                })

                ostatni_alert_spraying[adres_ip] = czas

        elif zdarzenie == "LOGOWANIE_UDANE":
            # Korelacja sukcesu z wcześniejszą serią brute-force.
            for seria in reversed(podejrzane_serie):
                if seria["adres_ip"] != adres_ip:
                    continue

                if seria["uzytkownik"] != uzytkownik:
                    continue

                if seria["logowanie_udane_po_serii"]:
                    continue

                if czas < seria["ostatnia_proba"]:
                    continue

                if czas - seria["ostatnia_proba"] > okno:
                    continue

                seria["logowanie_udane_po_serii"] = True
                seria["czas_udanego_logowania"] = czas.isoformat()
                break

    alerty = []

    for seria in podejrzane_serie:
        sukces_po_serii = seria["logowanie_udane_po_serii"]

        alerty.append({
            "typ_wykrycia": "BRUTE_FORCE",
            "adres_ip": seria["adres_ip"],
            "uzytkownik": seria["uzytkownik"],
            "liczba_nieudanych_prob": seria["liczba_prob"],
            "okno_minuty": OKNO_MINUTY,
            "pierwsza_proba": seria["pierwsza_proba"].isoformat(),
            "ostatnia_proba": seria["ostatnia_proba"].isoformat(),
            "logowanie_udane_po_serii": sukces_po_serii,
            "czas_udanego_logowania": seria["czas_udanego_logowania"],
            "poziom": "WYSOKI" if sukces_po_serii else "SREDNI",
            "opis": (
                "Wykryto serię nieudanych logowań, po której "
                "nastąpiło udane logowanie z tego samego adresu IP "
                "i na to samo konto."
                if sukces_po_serii
                else "Wykryto wiele nieudanych prób logowania."
            ),
            "zalecane_dzialanie": (
                "Sprawdź udane logowanie, potwierdź aktywność "
                "użytkownika i przeanalizuj powiązane zdarzenia."
                if sukces_po_serii
                else "Sprawdź adres IP i poszukaj powiązanych zdarzeń."
            ),
        })

    for seria in podejrzane_spraying:
        alerty.append({
            "typ_wykrycia": "PASSWORD_SPRAYING",
            "adres_ip": seria["adres_ip"],
            "uzytkownik": ", ".join(seria["konta"]),
            "konta_objete": seria["konta"],
            "liczba_nieudanych_prob": seria["liczba_prob"],
            "okno_minuty": OKNO_MINUTY,
            "pierwsza_proba": seria["pierwsza_proba"].isoformat(),
            "ostatnia_proba": seria["ostatnia_proba"].isoformat(),
            "logowanie_udane_po_serii": False,
            "czas_udanego_logowania": None,
            "poziom": "SREDNI",
            "opis": (
                "Wykryto nieudane próby logowania z jednego adresu IP "
                "na wiele różnych kont."
            ),
            "zalecane_dzialanie": (
                "Sprawdź źródłowy adres IP, konta objęte próbami "
                "i powiązane zdarzenia uwierzytelniania."
            ),
        })

    return alerty


def zapisz_alerty(alerty):
    """Zapisuje wykryte alerty do pliku JSON."""

    PLIK_ALERTOW.parent.mkdir(parents=True, exist_ok=True)

    with PLIK_ALERTOW.open("w", encoding="utf-8") as plik:
        json.dump(
            alerty,
            plik,
            indent=4,
            ensure_ascii=False,
        )


def main():
    parser = argparse.ArgumentParser(
        description="Analizator logów uwierzytelniania Mini SOC Lab."
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=PLIK_LOGOW,
        help="Ścieżka do pliku CSV z logami.",
    )
    args = parser.parse_args()

    try:
        logi = wczytaj_logi(args.input)
        alerty = analizuj_logi(logi)
        zapisz_alerty(alerty)

        print("Analiza zakonczona pomyslnie.")
        print(f"Przeanalizowane zdarzenia: {len(logi)}")
        print(f"Liczba wygenerowanych alertow: {len(alerty)}")
        print(f"Raport zapisano w: {PLIK_ALERTOW}")

        for numer, alert in enumerate(alerty, start=1):
            print(f"\nAlert nr {numer}")
            print(f"  Typ wykrycia: {alert['typ_wykrycia']}")
            print(f"  Adres IP: {alert['adres_ip']}")
            print(f"  Uzytkownik: {alert['uzytkownik']}")
            print(
                f"  Nieudane logowania: "
                f"{alert['liczba_nieudanych_prob']}"
            )
            print(
                "  Udane logowanie po serii: "
                f"{alert['logowanie_udane_po_serii']}"
            )
            print(f"  Poziom: {alert['poziom']}")
            print(f"  Opis: {alert['opis']}")

    except (OSError, ValueError, csv.Error) as blad:
        print(f"BLAD: {blad}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
