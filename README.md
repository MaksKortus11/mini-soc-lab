# Mini SOC Lab — analizator logów uwierzytelniania

Projekt edukacyjny z zakresu cyberbezpieczeństwa, którego celem jest wykrywanie podejrzanych wzorców logowania przy użyciu języka Python.

## Opis projektu

Mini SOC Lab to prosty analizator logów uwierzytelniania. Wczytuje zdarzenia z pliku CSV, wykrywa powtarzające się nieudane próby logowania i sprawdza, czy po podejrzanej serii nastąpiło udane logowanie.

Program zapisuje wykryte zdarzenia w raporcie JSON.

### Funkcjonalności

- Wczytywanie i walidacja logów CSV.
- Wykrywanie co najmniej pięciu nieudanych logowań w ciągu pięciu minut.
- Łączenie zdarzeń na podstawie adresu IP i nazwy użytkownika.
- Podwyższanie poziomu alertu, gdy po podejrzanej serii nastąpi udane logowanie.
- Generowanie raportów JSON.
- Automatyczne testy sprawdzające reguły detekcji.

## Technologie

- Python 3
- CSV i JSON
- unittest
- Git i GitHub

## Reguły wykrywania

Analizator korzysta z ruchomego okna czasowego o długości pięciu minut.

| Warunek | Wynik |
|---|---|
| Mniej niż pięć nieudanych prób | Brak alertu |
| Pięć nieudanych prób w oknie czasowym | Alert o średnim poziomie |
| Udane logowanie po podejrzanej serii, w ciągu kolejnych pięciu minut | Alert o wysokim poziomie |

Poziomy alertów są uproszczoną klasyfikacją na potrzeby projektu edukacyjnego. Alert nie stanowi dowodu włamania.

## Struktura projektu

```text
mini-soc-lab/
├── data/
│   └── auth_logs.csv
├── src/
│   └── analyzer.py
├── tests/
│   └── test_analyzer.py
├── reports/
│   └── alerts.json
├── docs/
├── screenshots/
├── README.md
└── .gitignore
```

## Wymagania

- Python 3.10 lub nowszy.
- Brak konieczności instalowania dodatkowych bibliotek.

## Uruchomienie

W terminalu, w głównym katalogu projektu, wykonaj:

```powershell
py src/analyzer.py
```

Program odczyta dane z `data/auth_logs.csv` i zapisze alerty w `reports/alerts.json`.

## Uruchamianie testów

```powershell
py -m unittest discover -s tests -v
```

Testy sprawdzają:
- wykrywanie pięciu nieudanych logowań;
- brak alertu przy czterech próbach;
- udane logowanie po podejrzanej serii;
- brak korelacji zbyt późnego sukcesu;
- brak korelacji zdarzeń z innego adresu IP;
- brak korelacji zdarzeń dotyczących innego użytkownika.

## Ograniczenia

- Projekt korzysta z syntetycznych danych testowych, a nie z bieżących logów systemowych.
- Program nie blokuje adresów IP ani kont użytkowników.
- Wykryte zdarzenie może mieć uzasadnioną przyczynę i wymaga dalszej analizy.
- Korelacja opiera się na adresie IP, użytkowniku i znacznikach czasu.
- Reguły detekcji są uproszczone i służą celom edukacyjnym.

## Możliwe rozszerzenia

- Dodanie kolejnych reguł detekcji.
- Rozbudowa testów o dodatkowe przypadki brzegowe.
- Integracja z platformą SIEM, np. Wazuh.
- Obsługa dodatkowych rodzajów zdarzeń uwierzytelniania.

## Informacja o przeznaczeniu

Projekt ma charakter edukacyjny i służy nauce defensywnego cyberbezpieczeństwa. Wszystkie zawarte w nim logi są fikcyjne.