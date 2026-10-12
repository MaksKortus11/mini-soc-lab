import argparse
import csv
import hashlib
import json
from collections import defaultdict, deque
from datetime import timedelta
from pathlib import Path

OKNO_MINUTY = 5
PROG_NIEUDANYCH_LOGOWAN = 5
PROG_ROZNYCH_KONT = 3
PROG_ROZNYCH_IP = 3

KATALOG_PROJEKTU = Path(__file__).resolve().parent.parent
PLIK_LOGOW = KATALOG_PROJEKTU / "data" / "auth_logs.csv"
PLIK_ALERTOW = KATALOG_PROJEKTU / "reports" / "alerts.json"
PLIK_PODSUMOWANIA = KATALOG_PROJEKTU / "reports" / "summary.json"

WYMAGANE_KOLUMNY = {
    "znacznik_czasu",
    "adres_ip",
    "uzytkownik",
    "zdarzenie",
}

ZDARZENIA = {"LOGOWANIE_UDANE", "LOGOWANIE_NIEUDANE"}

MITRE_ATTACK = {
    "BRUTE_FORCE": {
        "id": "T1110.001",
        "nazwa": "Password Guessing",
        "taktyka": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1110/001/",
    },
    "PASSWORD_SPRAYING": {
        "id": "T1110.003",
        "nazwa": "Password Spraying",
        "taktyka": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1110/003/",
    },
    "DISTRIBUTED_BRUTE_FORCE": {
        "id": "T1110",
        "nazwa": "Brute Force",
        "taktyka": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1110/",
    },
}


def wczytaj_logi(sciezka=PLIK_LOGOW):
    if not sciezka.exists():
        raise FileNotFoundError(f"Nie znaleziono pliku z logami: {sciezka}")

    with sciezka.open("r", encoding="utf-8-sig", newline="") as plik:
        probka = plik.read(4096)
        plik.seek(0)

        try:
            format_csv = csv.Sniffer().sniff(probka, delimiters=",;")
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
                czas = __import__("datetime").datetime.fromisoformat(
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
                    f"Nieznany rodzaj zdarzenia w linii {numer_linii}: {zdarzenie}"
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
    okno = timedelta(minutes=OKNO_MINUTY)
    nieudane_logowania = defaultdict(deque)
    nieudane_na_ip = defaultdict(deque)
    nieudane_na_uzytkownika = defaultdict(deque)
    podejrzane_serie = []
    podejrzane_spraying = []
    rozproszone_alerty = []
    ostatni_alert_spraying = {}

    for wpis in sorted(logi, key=lambda element: element["czas"]):
        czas = wpis["czas"]
        adres_ip = wpis["adres_ip"]
        uzytkownik = wpis["uzytkownik"]
        zdarzenie = wpis["zdarzenie"]
        granica_czasu = czas - okno
        klucz = (adres_ip, uzytkownik)
        proby = nieudane_logowania[klucz]
        proby_ip = nieudane_na_ip[adres_ip]
        proby_uzytkownika = nieudane_na_uzytkownika[uzytkownik]

        while proby and proby[0]["czas"] < granica_czasu:
            proby.popleft()
        while proby_ip and proby_ip[0]["czas"] < granica_czasu:
            proby_ip.popleft()
        while (
            proby_uzytkownika
            and proby_uzytkownika[0]["czas"] < granica_czasu
        ):
            proby_uzytkownika.popleft()

        if zdarzenie == "LOGOWANIE_NIEUDANE":
            nowa_proba = {
                "czas": czas,
                "adres_ip": adres_ip,
                "uzytkownik": uzytkownik,
            }
            proby.append(nowa_proba)
            proby_ip.append(nowa_proba)
            proby_uzytkownika.append(nowa_proba)

            if len(proby) >= PROG_NIEUDANYCH_LOGOWAN:
                istniejąca_seria = next(
                    (
                        seria
                        for seria in reversed(podejrzane_serie)
                        if seria["adres_ip"] == adres_ip
                        and seria["uzytkownik"] == uzytkownik
                        and not seria["logowanie_udane_po_serii"]
                        and czas >= seria["ostatnia_proba"]
                        and czas - seria["ostatnia_proba"] <= okno
                    ),
                    None,
                )

                if istniejąca_seria is None:
                    podejrzane_serie.append({
                        "adres_ip": adres_ip,
                        "uzytkownik": uzytkownik,
                        "pierwsza_proba": proby[0]["czas"],
                        "ostatnia_proba": czas,
                        "liczba_prob": len(proby),
                        "logowanie_udane_po_serii": False,
                        "czas_udanego_logowania": None,
                    })
                else:
                    istniejąca_seria["ostatnia_proba"] = czas
                    istniejąca_seria["liczba_prob"] = len(proby)

            rozne_konta = {proba["uzytkownik"] for proba in proby_ip}
            poprzedni_alert = ostatni_alert_spraying.get(adres_ip)
            mozna_zglosic = (
                poprzedni_alert is None or czas - poprzedni_alert > okno
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

            rozne_ip = {
                proba["adres_ip"] for proba in proby_uzytkownika
            }
            if (
                len(proby_uzytkownika) >= PROG_NIEUDANYCH_LOGOWAN
                and len(rozne_ip) >= PROG_ROZNYCH_IP
            ):
                rozproszone_alerty.append({
                    "typ_wykrycia": "DISTRIBUTED_BRUTE_FORCE",
                    "mitre_attack": MITRE_ATTACK["DISTRIBUTED_BRUTE_FORCE"].copy(),
                    "adres_ip": adres_ip,
                    "adresy_ip": sorted(rozne_ip),
                    "uzytkownik": uzytkownik,
                    "liczba_nieudanych_prob": len(proby_uzytkownika),
                    "okno_minuty": OKNO_MINUTY,
                    "pierwsza_proba": proby_uzytkownika[0]["czas"].isoformat(),
                    "ostatnia_proba": proby_uzytkownika[-1]["czas"].isoformat(),
                    "logowanie_udane_po_serii": True,
                    "czas_udanego_logowania": czas.isoformat(),
                    "poziom": "WYSOKI",
                    "opis": (
                        "Wykryto nieudane próby logowania na to samo konto z wielu "
                        "adresów IP, po których nastąpiło udane logowanie."
                    ),
                    "zalecane_dzialanie": (
                        "Zweryfikuj udane logowanie, adresy źródłowe, aktywność "
                        "użytkownika i powiązane zdarzenia."
                    ),
                })
                proby_uzytkownika.clear()

    alerty = []
    for seria in podejrzane_serie:
        sukces_po_serii = seria["logowanie_udane_po_serii"]
        alerty.append({
            "typ_wykrycia": "BRUTE_FORCE",
            "mitre_attack": MITRE_ATTACK["BRUTE_FORCE"].copy(),
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
                "Wykryto serię nieudanych logowań, po której nastąpiło udane "
                "logowanie z tego samego adresu IP i na to samo konto."
                if sukces_po_serii
                else "Wykryto wiele nieudanych prób logowania."
            ),
            "zalecane_dzialanie": (
                "Sprawdź udane logowanie, potwierdź aktywność użytkownika i "
                "przeanalizuj powiązane zdarzenia."
                if sukces_po_serii
                else "Sprawdź adres IP i poszukaj powiązanych zdarzeń."
            ),
        })

    for seria in podejrzane_spraying:
        alerty.append({
            "typ_wykrycia": "PASSWORD_SPRAYING",
            "mitre_attack": MITRE_ATTACK["PASSWORD_SPRAYING"].copy(),
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
                "Wykryto nieudane próby logowania z jednego adresu IP na wiele "
                "różnych kont."
            ),
            "zalecane_dzialanie": (
                "Sprawdź źródłowy adres IP, konta objęte próbami i powiązane "
                "zdarzenia uwierzytelniania."
            ),
        })

    alerty.extend(rozproszone_alerty)
    return alerty


def zapisz_alerty(alerty):
    PLIK_ALERTOW.parent.mkdir(parents=True, exist_ok=True)
    for alert in alerty:
        dane_id = "|".join([
            alert["typ_wykrycia"],
            alert["adres_ip"],
            alert["uzytkownik"],
            alert["pierwsza_proba"],
            alert["ostatnia_proba"],
        ])
        alert["id_alertu"] = hashlib.sha256(
            dane_id.encode("utf-8")
        ).hexdigest()[:12].upper()

    with PLIK_ALERTOW.open("w", encoding="utf-8") as plik:
        json.dump(alerty, plik, indent=4, ensure_ascii=False)


def wyswietl_podsumowanie(logi, alerty):
    print("\n" + "=" * 45)
    print("           PODSUMOWANIE SOC")
    print("=" * 45)
    print(f"Przeanalizowane zdarzenia: {len(logi)}")
    print(f"Wygenerowane alerty:      {len(alerty)}")

    poziomy = {"KRYTYCZNY": 0, "WYSOKI": 0, "SREDNI": 0, "NISKI": 0}
    typy = {}
    for alert in alerty:
        poziom = alert.get("poziom", "NIEZNANY")
        poziomy[poziom] = poziomy.get(poziom, 0) + 1
        typ = alert.get("typ_wykrycia", "NIEZNANY")
        typy[typ] = typy.get(typ, 0) + 1

    print("\nAlerty według poziomu:")
    for poziom, liczba in poziomy.items():
        print(f"  {poziom:<12} {liczba}")

    print("\nAlerty według typu:")
    if typy:
        for typ, liczba in sorted(typy.items()):
            print(f"  {typ:<25} {liczba}")
    else:
        print("  Brak wykrytych zagrożeń.")

    adresy_ip = {}
    konta = {}
    for alert in alerty:
        adresy_alertu = set()
        ip = alert.get("adres_ip")
        if ip:
            adresy_alertu.add(ip)
        adresy_alertu.update(alert.get("adresy_ip", []))
        for ip in adresy_alertu:
            adresy_ip[ip] = adresy_ip.get(ip, 0) + 1
        for konto in alert.get("konta_objete", []):
            konta[konto] = konta.get(konto, 0) + 1
        uzytkownik = alert.get("uzytkownik")
        if uzytkownik and not alert.get("konta_objete"):
            konta[uzytkownik] = konta.get(uzytkownik, 0) + 1

    print("\nAdresy IP występujące w alertach:")
    if adresy_ip:
        for ip, liczba in sorted(
            adresy_ip.items(), key=lambda element: element[1], reverse=True
        ):
            print(f"  {ip:<20} {liczba} alert(y)")
    else:
        print("  Brak.")

    print("\nKonta występujące w alertach:")
    if konta:
        for konto, liczba in sorted(
            konta.items(), key=lambda element: element[1], reverse=True
        ):
            print(f"  {konto:<20} {liczba} alert(y)")
    else:
        print("  Brak.")
    print("=" * 45)


def zapisz_podsumowanie(logi, alerty):
    poziomy = {}
    typy = {}
    adresy_ip = {}
    konta = {}

    for alert in alerty:
        poziom = alert.get("poziom", "NIEZNANY")
        poziomy[poziom] = poziomy.get(poziom, 0) + 1
        typ = alert.get("typ_wykrycia", "NIEZNANY")
        typy[typ] = typy.get(typ, 0) + 1

        adresy_alertu = set()
        ip = alert.get("adres_ip")
        if ip:
            adresy_alertu.add(ip)
        adresy_alertu.update(alert.get("adresy_ip", []))
        for adres in adresy_alertu:
            adresy_ip[adres] = adresy_ip.get(adres, 0) + 1

        for konto in alert.get("konta_objete", []):
            konta[konto] = konta.get(konto, 0) + 1
        uzytkownik = alert.get("uzytkownik")
        if uzytkownik and not alert.get("konta_objete"):
            konta[uzytkownik] = konta.get(uzytkownik, 0) + 1

    podsumowanie = {
        "liczba_zdarzen": len(logi),
        "liczba_alertow": len(alerty),
        "alerty_wedlug_poziomu": poziomy,
        "alerty_wedlug_typu": typy,
        "adresy_ip_w_alertach": adresy_ip,
        "konta_w_alertach": konta,
    }

    PLIK_PODSUMOWANIA.parent.mkdir(parents=True, exist_ok=True)
    with PLIK_PODSUMOWANIA.open("w", encoding="utf-8") as plik:
        json.dump(podsumowanie, plik, indent=4, ensure_ascii=False)


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
        zapisz_podsumowanie(logi, alerty)
        wyswietl_podsumowanie(logi, alerty)

        print("Analiza zakonczona pomyslnie.")
        print(f"Przeanalizowane zdarzenia: {len(logi)}")
        print(f"Liczba wygenerowanych alertow: {len(alerty)}")
        print(f"Raport zapisano w: {PLIK_ALERTOW}")

        for numer, alert in enumerate(alerty, start=1):
            print(f"\nAlert nr {numer}")
            print(f"  Typ wykrycia: {alert['typ_wykrycia']}")
            mitre = alert["mitre_attack"]
            print(f"  MITRE ATT&CK: {mitre['id']} - {mitre['nazwa']}")
            print(f"  Taktyka: {mitre['taktyka']}")
            print(f"  Dokumentacja: {mitre['url']}")
            print(f"  Adres IP: {alert['adres_ip']}")
            if "adresy_ip" in alert:
                print(f"  Adresy IP objęte serią: {', '.join(alert['adresy_ip'])}")
            print(f"  Uzytkownik: {alert['uzytkownik']}")
            print(f"  Nieudane logowania: {alert['liczba_nieudanych_prob']}")
            print(f"  Udane logowanie po serii: {alert['logowanie_udane_po_serii']}")
            print(f"  Poziom: {alert['poziom']}")
            print(f"  Opis: {alert['opis']}")

    except (OSError, ValueError, csv.Error) as blad:
        print(f"BLAD: {blad}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
