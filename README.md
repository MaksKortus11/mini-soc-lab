# Mini SOC Lab — analizator logów uwierzytelniania

Projekt edukacyjny symulujący wybrane zadania analityka SOC (Security Operations Center). Aplikacja analizuje logi uwierzytelniania, wykrywa podejrzane wzorce logowania, generuje alerty i prezentuje wyniki w interaktywnym dashboardzie.

Projekt powstał w celu praktycznej nauki analizy logów, wykrywania zagrożeń, korelacji zdarzeń oraz mapowania wykryć na framework MITRE ATT&CK.

## Funkcjonalności

- Analiza logów uwierzytelniania z plików CSV.
- Walidacja danych wejściowych.
- Wykrywanie ataków brute force.
- Wykrywanie password spraying.
- Wykrywanie rozproszonego brute force.
- Korelacja nieudanych prób logowania z późniejszym udanym logowaniem.
- Klasyfikacja alertów według poziomu ryzyka.
- Mapowanie wykryć na MITRE ATT&CK.
- Generowanie raportów JSON.
- Interaktywny dashboard w Streamlit.
- Filtrowanie i przeglądanie logów według scenariusza, rodzaju zdarzenia, adresu IP i użytkownika.
- Wizualizacja alertów i poziomów ryzyka.
- Testy jednostkowe z wykorzystaniem `unittest`.

## Wykrywane zagrożenia

| Typ wykrycia | Warunek | MITRE ATT&CK |
|---|---|---|
| Brute force | Co najmniej 5 nieudanych prób logowania na to samo konto z jednego IP w ciągu 5 minut | T1110.001 — Password Guessing |
| Password spraying | Co najmniej 5 nieudanych prób z jednego IP na co najmniej 3 różne konta w analizowanym oknie czasowym | T1110.003 — Password Spraying |
| Distributed brute force | Co najmniej 5 nieudanych prób na to samo konto z co najmniej 3 różnych adresów IP w analizowanym oknie czasowym | T1110 — Brute Force |

Wykrycia dotyczą taktyki **Credential Access**.

Jeśli po serii nieudanych prób nastąpi udane logowanie z tego samego adresu IP na to samo konto, analizator może podnieść poziom alertu do `WYSOKI`.

Poziom alertu jest oceną heurystyczną. Udane logowanie po serii niepowodzeń nie stanowi samo w sobie dowodu przejęcia konta.

## Dashboard

Dashboard został zbudowany w Pythonie z wykorzystaniem Streamlit, Pandas i Altair.

Udostępnia:

- dziennik zdarzeń z plików CSV;
- statystyki udanych i nieudanych logowań;
- filtrowanie logów;
- kolorystyczne oznaczenie udanych i nieudanych logowań;
- wykresy alertów według poziomu i typu;
- tabelę wykrytych zagrożeń;
- filtrowanie alertów;
- szczegóły alertów i identyfikatory MITRE ATT&CK.

Interfejs wykorzystuje ciemny motyw inspirowany estetyką Matrix.

## Technologie

- Python
- Pandas
- Streamlit
- Altair
- JSON
- CSV
- `unittest`
- MITRE ATT&CK
- Git i GitHub

## Struktura projektu

```text
mini-soc-lab/
├── data/
│   ├── auth_logs.csv
│   ├── spraying_logs.csv
│   ├── distributed_bruteforce_logs.csv
│   ├── password_spraying_logs.csv
│   ├── slow_bruteforce_logs.csv
│   ├── normal_activity_logs.csv
│   └── successful_compromise_logs.csv
├── docs/
├── reports/
│   ├── alerts.json
│   └── summary.json
├── screenshots/
├── src/
│   └── analyzer.py
├── tests/
│   └── test_analyzer.py
├── dashboard.py
├── README.md
└── .gitignore
```

Pliki CSV zawierają przykładowe scenariusze testowe. Folder `reports/` przechowuje raporty generowane przez analizator.

## Uruchomienie

### 1. Wymagania

Zainstalowany Python oraz Git. Do uruchomienia dashboardu potrzebne są również biblioteki Streamlit, Pandas i Altair.

### 2. Instalacja zależności

W terminalu, w katalogu projektu, wykonaj:

```powershell
py -m pip install streamlit pandas altair
```

### 3. Uruchomienie analizatora

Analiza domyślnego pliku:

```powershell
py src/analyzer.py
```

Analiza wybranego scenariusza:

```powershell
py src/analyzer.py --input data/password_spraying_logs.csv
```

Przykładowe dodatkowe scenariusze:

```powershell
py src/analyzer.py --input data/slow_bruteforce_logs.csv
py src/analyzer.py --input data/normal_activity_logs.csv
py src/analyzer.py --input data/successful_compromise_logs.csv
```

Analizator zapisuje raporty w folderze `reports/`. Kolejne uruchomienie może zastąpić poprzednie wyniki.

### 4. Uruchomienie dashboardu

```powershell
py -m streamlit run dashboard.py
```

Następnie otwórz lokalny adres wyświetlony w terminalu, zwykle `http://localhost:8501`.

Dashboard wczytuje pliki CSV z folderu `data/` oraz raporty JSON z folderu `reports/`.

### 5. Uruchomienie testów

```powershell
py -m unittest discover -s tests -v
```

**Wynik testów:** 26/26 testów zaliczonych.

## Przykładowe scenariusze

| Scenariusz | Oczekiwany rezultat |
|---|---|
| Password spraying | Alert `PASSWORD_SPRAYING` |
| Slow brute force | Brak alertu, jeśli próby nie spełniają progu czasowego |
| Normalna aktywność | Brak alertu brute force |
| Brute force zakończony udanym logowaniem | Alert `BRUTE_FORCE` z podwyższonym poziomem ryzyka |
| Rozproszony brute force | Alert po spełnieniu warunków dotyczących konta, liczby prób i adresów IP |

## Ograniczenia

- Projekt jest edukacyjną symulacją analizatora SOC.
- Dane wejściowe są przykładowymi logami, a nie strumieniem zdarzeń z produkcyjnej infrastruktury.
- Reguły wykrywania opierają się na ustalonych progach i oknach czasowych.
- Wykrycie podejrzanego wzorca nie przesądza o faktycznym włamaniu.
- Raporty JSON przedstawiają wyniki ostatniej analizy, a dashboard prezentuje logi ze wszystkich prawidłowych plików CSV w folderze `data/`.

## Możliwe dalsze rozszerzenia

- Integracja z rzeczywistymi logami systemowymi.
- Dodanie obsługi logów Windows i Linux.
- Rozszerzenie reguł wykrywania i korelacji zdarzeń.
- Eksport raportów do dodatkowych formatów.
- Dodanie testów integracyjnych.
- Automatyczne odświeżanie danych i historii alertów.

## Cel projektu

Celem projektu jest rozwijanie praktycznych umiejętności z zakresu cyberbezpieczeństwa, analizy logów, wykrywania zagrożeń, testowania kodu oraz prezentowania wyników analizy w czytelnym interfejsie.

Projekt stanowi element portfolio rozwijanego w kierunku stanowisk juniorskich i stażowych związanych z cyberbezpieczeństwem oraz analizą bezpieczeństwa.
