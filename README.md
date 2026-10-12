# Mini SOC Lab — analizator logów uwierzytelniania

Projekt edukacyjny z zakresu cyberbezpieczeństwa. Narzędzie napisane w Pythonie analizuje logi uwierzytelniania, wykrywa podejrzane wzorce logowania i generuje alerty oraz raporty JSON.

## Cel projektu

Celem projektu jest praktyczne przećwiczenie podstaw analizy logów, tworzenia reguł detekcji, korelacji zdarzeń i testowania mechanizmów bezpieczeństwa — z perspektywy analityka SOC.

## Funkcjonalności

- Wczytywanie i walidacja danych z plików CSV.
- Wykrywanie brute-force — powtarzających się nieudanych prób logowania na jedno konto z jednego adresu IP.
- Wykrywanie password spraying — prób logowania na wiele kont z jednego adresu IP.
- Wykrywanie distributed brute-force — prób logowania na to samo konto z wielu adresów IP.
- Korelacja nieudanych prób z późniejszym udanym logowaniem.
- Klasyfikacja alertów według poziomu ryzyka.
- Mapowanie wykryć na techniki MITRE ATT&CK.
- Generowanie raportów `alerts.json` i `summary.json`.
- Stabilne identyfikatory alertów.
- Automatyczne testy jednostkowe, w tym przypadki brzegowe i błędne dane wejściowe.

## Technologie

- Python 3
- CSV i JSON
- `unittest`
- Git i GitHub

Projekt nie wymaga instalowania dodatkowych bibliotek.

## Reguły detekcji

Analizator wykorzystuje okno czasowe o długości pięciu minut.

| Reguła | Opis |
|---|---|
| Brute-force | Co najmniej 5 nieudanych prób logowania na to samo konto z jednego IP w oknie czasowym |
| Password spraying | Co najmniej 5 nieudanych prób z jednego IP obejmujących co najmniej 3 różne konta w oknie czasowym |
| Distributed brute-force | Co najmniej 5 nieudanych prób na to samo konto z co najmniej 3 adresów IP w oknie czasowym |

Udane logowanie skorelowane z podejrzaną serią może podnieść poziom alertu do `WYSOKI`, zgodnie z regułami zaimplementowanymi w analizatorze.

Poziomy alertów są uproszczoną klasyfikacją edukacyjną. Alert nie stanowi sam w sobie dowodu włamania.

## MITRE ATT&CK

| Wykrycie | Technika | Taktyka |
|---|---|---|
| Brute-force — zgadywanie haseł | [T1110.001 — Password Guessing](https://attack.mitre.org/techniques/T1110/001/) | Credential Access |
| Password spraying | [T1110.003 — Password Spraying](https://attack.mitre.org/techniques/T1110/003/) | Credential Access |
| Distributed brute-force | [T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/) | Credential Access |

Mapowanie służy uporządkowaniu wykryć według frameworka MITRE ATT&CK. Nie oznacza, że sam alert potwierdza wystąpienie danej techniki.

## Struktura projektu

```text
mini-soc-lab/
├── data/
│   ├── auth_logs.csv
│   ├── spraying_logs.csv
│   └── distributed_bruteforce_logs.csv
├── src/
│   └── analyzer.py
├── tests/
│   └── test_analyzer.py
├── reports/
│   ├── alerts.json
│   └── summary.json
├── docs/
├── screenshots/
├── README.md
└── .gitignore
```

## Wymagania

- Python 3.10 lub nowszy.
- Git — jeśli chcesz pobrać projekt z repozytorium.
- Brak dodatkowych zależności zewnętrznych.

## Uruchomienie

Uruchom terminal w głównym katalogu projektu.

Domyślny scenariusz:

```powershell
py src/analyzer.py
```

Scenariusz password spraying:

```powershell
py src/analyzer.py --input data/spraying_logs.csv
```

Scenariusz distributed brute-force:

```powershell
py src/analyzer.py --input data/distributed_bruteforce_logs.csv
```

Program wyświetla podsumowanie w terminalu i zapisuje wyniki w katalogu `reports/`. Kolejne uruchomienia nadpisują generowane raporty.

## Raporty

- `reports/alerts.json` — szczegółowe informacje o wykrytych alertach, m.in. typ wykrycia, adresy IP, konto, liczba prób, poziom alertu, identyfikator i zalecane działanie.
- `reports/summary.json` — podsumowanie analizy, liczba zdarzeń i alertów, zestawienie według poziomu i typu oraz adresów IP i kont występujących w alertach.

## Testy

Uruchom testy jednostkowe:

```powershell
py -m unittest discover -s tests -v
```

Zestaw testów obejmuje m.in.:

- wykrywanie trzech typów podejrzanych wzorców logowania;
- przypadki poniżej progu detekcji;
- korelację nieudanego i udanego logowania;
- granice okna czasowego;
- dłuższe i rozdzielone serie prób;
- stabilność identyfikatorów alertów;
- generowanie raportów;
- brakujące kolumny, nieprawidłowe znaczniki czasu, pusty plik i brakujący plik CSV.

## Ograniczenia

- Projekt wykorzystuje syntetyczne logi, a nie dane z produkcyjnych systemów.
- Analiza odbywa się lokalnie, na podstawie plików CSV.
- Narzędzie nie blokuje adresów IP ani kont użytkowników.
- Nie jest zintegrowane z produkcyjną platformą SIEM.
- Reguły detekcji są uproszczone i mogą generować fałszywe alarmy lub nie wykrywać bardziej złożonych ataków.
- Wykryte zdarzenia wymagają kontekstu i dalszej analizy.

## Możliwe rozszerzenia

- Integracja z Wazuh lub inną platformą SIEM.
- Dodanie nowych reguł detekcji.
- Obsługa kolejnych formatów logów.
- Rozbudowa raportowania i prezentacji alertów.
- Dodanie logowania działania samego analizatora i konfiguracji progów detekcji.

## Przeznaczenie

Projekt ma charakter edukacyjny i służy nauce defensywnego cyberbezpieczeństwa. Wszystkie dołączone logi są fikcyjne.