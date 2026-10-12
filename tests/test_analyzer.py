import json
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch
from src.analyzer import (
    analizuj_logi,
    zapisz_alerty,
    wyswietl_podsumowanie,
    zapisz_podsumowanie,
    wczytaj_logi,
)


class TestAnalizatoraSOC(unittest.TestCase):

    def setUp(self):
        self.poczatek = datetime(2026, 10, 12, 10, 0, 0)

    def utworz_zdarzenie(
        self,
        minuty,
        zdarzenie,
        adres_ip="192.168.1.25",
        uzytkownik="admin",
    ):
        return {
            "czas": self.poczatek + timedelta(minutes=minuty),
            "adres_ip": adres_ip,
            "uzytkownik": uzytkownik,
            "zdarzenie": zdarzenie,
        }

    # BRUTE FORCE

    def test_wykrywa_brute_force(self):
        logi = [
            self.utworz_zdarzenie(i, "LOGOWANIE_NIEUDANE")
            for i in range(5)
        ]

        alerty = analizuj_logi(logi)

        brute_force = [
            a for a in alerty
            if a["typ_wykrycia"] == "BRUTE_FORCE"
        ]

        self.assertEqual(len(brute_force), 1)
        self.assertEqual(brute_force[0]["liczba_nieudanych_prob"], 5)
        self.assertEqual(brute_force[0]["poziom"], "SREDNI")

    def test_brute_force_zakonczony_sukcesem(self):
        logi = [
            self.utworz_zdarzenie(i, "LOGOWANIE_NIEUDANE")
            for i in range(5)
        ]
        logi.append(
            self.utworz_zdarzenie(5, "LOGOWANIE_UDANE")
        )

        alerty = analizuj_logi(logi)
        brute_force = [
            a for a in alerty
            if a["typ_wykrycia"] == "BRUTE_FORCE"
        ]

        self.assertEqual(len(brute_force), 1)
        self.assertTrue(
            brute_force[0]["logowanie_udane_po_serii"]
        )
        self.assertEqual(brute_force[0]["poziom"], "WYSOKI")

    def test_brak_brute_force_dla_roznych_adresow_i_kont(self):
        logi = [
            self.utworz_zdarzenie(
                i,
                "LOGOWANIE_NIEUDANE",
                adres_ip=f"192.168.1.{i + 1}",
                uzytkownik=f"user{i}",
            )
            for i in range(5)
        ]

        alerty = analizuj_logi(logi)

        self.assertFalse(
            any(
                a["typ_wykrycia"] == "BRUTE_FORCE"
                for a in alerty
            )
        )


    def test_wykrywa_password_spraying(self):
        logi = [
            self.utworz_zdarzenie(
                0, "LOGOWANIE_NIEUDANE",
                uzytkownik="user1",
            ),
            self.utworz_zdarzenie(
                1, "LOGOWANIE_NIEUDANE",
                uzytkownik="user2",
            ),
            self.utworz_zdarzenie(
                2, "LOGOWANIE_NIEUDANE",
                uzytkownik="user3",
            ),
            self.utworz_zdarzenie(
                3, "LOGOWANIE_NIEUDANE",
                uzytkownik="user1",
            ),
            self.utworz_zdarzenie(
                4, "LOGOWANIE_NIEUDANE",
                uzytkownik="user2",
            ),
        ]

        alerty = analizuj_logi(logi)
        spraying = [
            a for a in alerty
            if a["typ_wykrycia"] == "PASSWORD_SPRAYING"
        ]

        self.assertEqual(len(spraying), 1)
        self.assertGreaterEqual(
            len(spraying[0]["konta_objete"]), 3
        )

    def test_brak_spraying_dla_jednego_konta(self):
        logi = [
            self.utworz_zdarzenie(i, "LOGOWANIE_NIEUDANE")
            for i in range(5)
        ]

        alerty = analizuj_logi(logi)

        self.assertFalse(
            any(
                a["typ_wykrycia"] == "PASSWORD_SPRAYING"
                for a in alerty
            )
        )


    def test_wykrywa_distributed_brute_force(self):
        adresy = [
            "192.0.2.10",
            "192.0.2.20",
            "192.0.2.30",
            "192.0.2.10",
            "192.0.2.20",
        ]

        logi = [
            self.utworz_zdarzenie(
                i,
                "LOGOWANIE_NIEUDANE",
                adres_ip=adres,
                uzytkownik="admin",
            )
            for i, adres in enumerate(adresy)
        ]

        logi.append(
            self.utworz_zdarzenie(
                5,
                "LOGOWANIE_UDANE",
                adres_ip="192.0.2.30",
                uzytkownik="admin",
            )
        )

        alerty = analizuj_logi(logi)

        rozproszone = [
            a for a in alerty
            if a["typ_wykrycia"] == "DISTRIBUTED_BRUTE_FORCE"
        ]

        self.assertEqual(len(rozproszone), 1)

        alert = rozproszone[0]
        self.assertEqual(alert["uzytkownik"], "admin")
        self.assertEqual(alert["liczba_nieudanych_prob"], 5)
        self.assertEqual(len(alert["adresy_ip"]), 3)
        self.assertTrue(alert["logowanie_udane_po_serii"])
        self.assertEqual(alert["poziom"], "WYSOKI")

    def test_brak_distributed_brute_force_bez_sukcesu(self):
        adresy = [
            "192.0.2.10",
            "192.0.2.20",
            "192.0.2.30",
            "192.0.2.10",
            "192.0.2.20",
        ]

        logi = [
            self.utworz_zdarzenie(
                i,
                "LOGOWANIE_NIEUDANE",
                adres_ip=adres,
                uzytkownik="admin",
            )
            for i, adres in enumerate(adresy)
        ]

        alerty = analizuj_logi(logi)

        self.assertFalse(
            any(
                a["typ_wykrycia"] == "DISTRIBUTED_BRUTE_FORCE"
                for a in alerty
            )
        )


    def utworz_alert_testowy(self):
        return {
            "typ_wykrycia": "BRUTE_FORCE",
            "adres_ip": "192.0.2.10",
            "uzytkownik": "admin",
            "pierwsza_proba": "2026-10-12T10:00:00",
            "ostatnia_proba": "2026-10-12T10:04:00",
            "poziom": "SREDNI",
            "zalecane_dzialanie": "Sprawdź adres IP i powiązane zdarzenia.",
        }

    def test_alert_otrzymuje_id(self):
        alert = self.utworz_alert_testowy()

        with tempfile.TemporaryDirectory() as katalog:
            sciezka = Path(katalog) / "alerts.json"

            with patch("src.analyzer.PLIK_ALERTOW", sciezka):
                zapisz_alerty([alert.copy()])

            with sciezka.open(encoding="utf-8") as plik:
                wynik = json.load(plik)

        self.assertEqual(len(wynik), 1)
        self.assertIn("id_alertu", wynik[0])
        self.assertEqual(len(wynik[0]["id_alertu"]), 12)

    def test_id_alertu_jest_stabilny(self):
        alert = self.utworz_alert_testowy()

        with tempfile.TemporaryDirectory() as katalog:
            sciezka = Path(katalog) / "alerts.json"

            with patch("src.analyzer.PLIK_ALERTOW", sciezka):
                zapisz_alerty([alert.copy()])
                with sciezka.open(encoding="utf-8") as plik:
                    pierwszy_id = json.load(plik)[0]["id_alertu"]

                zapisz_alerty([alert.copy()])
                with sciezka.open(encoding="utf-8") as plik:
                    drugi_id = json.load(plik)[0]["id_alertu"]

        self.assertEqual(pierwszy_id, drugi_id)

    def test_alert_zawiera_zalecane_dzialanie(self):
        alert = self.utworz_alert_testowy()

        with tempfile.TemporaryDirectory() as katalog:
            sciezka = Path(katalog) / "alerts.json"

            with patch("src.analyzer.PLIK_ALERTOW", sciezka):
                zapisz_alerty([alert.copy()])

            with sciezka.open(encoding="utf-8") as plik:
                wynik = json.load(plik)

        self.assertIn("zalecane_dzialanie", wynik[0])
        self.assertTrue(wynik[0]["zalecane_dzialanie"])

    def test_podsumowanie_pokazuje_liczbe_zdarzen_i_alertow(self):
        from io import StringIO
        from contextlib import redirect_stdout

        logi = [
            self.utworz_zdarzenie(0, "LOGOWANIE_NIEUDANE"),
            self.utworz_zdarzenie(1, "LOGOWANIE_UDANE"),
        ]

        alerty = [
            {
                "typ_wykrycia": "BRUTE_FORCE",
                "adres_ip": "192.0.2.10",
                "uzytkownik": "admin",
                "poziom": "WYSOKI",
            }
        ]

        wyjscie = StringIO()
        with redirect_stdout(wyjscie):
            wyswietl_podsumowanie(logi, alerty)

        tekst = wyjscie.getvalue()

        self.assertIn("Przeanalizowane zdarzenia: 2", tekst)
        self.assertIn("Wygenerowane alerty:      1", tekst)
        self.assertIn("WYSOKI", tekst)
        self.assertIn("BRUTE_FORCE", tekst)


    def test_podsumowanie_obsluguje_brak_alertow(self):
        from io import StringIO
        from contextlib import redirect_stdout

        logi = [
            self.utworz_zdarzenie(0, "LOGOWANIE_UDANE"),
        ]

        wyjscie = StringIO()
        with redirect_stdout(wyjscie):
            wyswietl_podsumowanie(logi, [])

        tekst = wyjscie.getvalue()

        self.assertIn("Przeanalizowane zdarzenia: 1", tekst)
        self.assertIn("Wygenerowane alerty:      0", tekst)
        self.assertIn("Brak wykrytych zagrożeń.", tekst)

    
    def test_zapisuje_podsumowanie_do_json(self):
        from tempfile import TemporaryDirectory
        from unittest.mock import patch

        logi = [
            self.utworz_zdarzenie(0, "LOGOWANIE_NIEUDANE"),
            self.utworz_zdarzenie(1, "LOGOWANIE_UDANE"),
        ]

        alerty = [
            {
                "typ_wykrycia": "BRUTE_FORCE",
                "adres_ip": "192.0.2.10",
                "uzytkownik": "admin",
                "poziom": "WYSOKI",
                "konta_objete": [],
            }
        ]

        with TemporaryDirectory() as katalog:
            sciezka = Path(katalog) / "summary.json"

            with patch("src.analyzer.PLIK_PODSUMOWANIA", sciezka):
                zapisz_podsumowanie(logi, alerty)

            with sciezka.open(encoding="utf-8") as plik:
                wynik = json.load(plik)

        self.assertEqual(wynik["liczba_zdarzen"], 2)
        self.assertEqual(wynik["liczba_alertow"], 1)
        self.assertEqual(wynik["alerty_wedlug_poziomu"]["WYSOKI"], 1)
        self.assertEqual(wynik["alerty_wedlug_typu"]["BRUTE_FORCE"], 1)
        self.assertEqual(wynik["adresy_ip_w_alertach"]["192.0.2.10"], 1)
        self.assertEqual(wynik["konta_w_alertach"]["admin"], 1)


    def test_brak_alertu_przy_czterech_nieudanych_logowaniach(self):
        logi = [
            self.utworz_zdarzenie(i, "LOGOWANIE_NIEUDANE")
            for i in range(4)
        ]

        alerty = analizuj_logi(logi)

        self.assertFalse(
            any(
                alert["typ_wykrycia"] == "BRUTE_FORCE"
                for alert in alerty
            )
        )

    def test_brute_force_poza_oknem_czasowym(self):
        logi = [
            self.utworz_zdarzenie(i * 2, "LOGOWANIE_NIEUDANE")
            for i in range(5)
        ]

        alerty = analizuj_logi(logi)

        self.assertFalse(
            any(
                alert["typ_wykrycia"] == "BRUTE_FORCE"
                for alert in alerty
            )
        )

    def test_sukces_po_uplywie_okna_nie_podnosi_poziomu(self):
        logi = [
            self.utworz_zdarzenie(i, "LOGOWANIE_NIEUDANE")
            for i in range(5)
        ]
        logi.append(
            self.utworz_zdarzenie(10, "LOGOWANIE_UDANE")
        )

        alerty = analizuj_logi(logi)
        brute_force = [
            alert for alert in alerty
            if alert["typ_wykrycia"] == "BRUTE_FORCE"
        ]

        self.assertEqual(len(brute_force), 1)
        self.assertFalse(
            brute_force[0]["logowanie_udane_po_serii"]
        )
        self.assertEqual(brute_force[0]["poziom"], "SREDNI")

    def test_analiza_tych_samych_logow_jest_powtarzalna(self):
        logi = [
            self.utworz_zdarzenie(i, "LOGOWANIE_NIEUDANE")
            for i in range(5)
        ]

        pierwsza_analiza = analizuj_logi(logi)
        druga_analiza = analizuj_logi(logi)

        self.assertEqual(pierwsza_analiza, druga_analiza)


    def test_sukces_dokladnie_na_granicy_okna(self):
        logi = [
            self.utworz_zdarzenie(i, "LOGOWANIE_NIEUDANE")
            for i in range(5)
        ]
        logi.append(
            self.utworz_zdarzenie(9, "LOGOWANIE_UDANE")
        )

        alerty = analizuj_logi(logi)
        brute_force = [
            alert for alert in alerty
            if alert["typ_wykrycia"] == "BRUTE_FORCE"
        ]

        self.assertEqual(len(brute_force), 1)
        self.assertTrue(
            brute_force[0]["logowanie_udane_po_serii"]
        )
        self.assertEqual(brute_force[0]["poziom"], "WYSOKI")


    def test_dluzsza_seria_brute_force_nie_generuje_duplikatow(self):
        logi = [
            self.utworz_zdarzenie(i, "LOGOWANIE_NIEUDANE")
            for i in range(7)
        ]

        alerty = analizuj_logi(logi)
        brute_force = [
            alert for alert in alerty
            if alert["typ_wykrycia"] == "BRUTE_FORCE"
        ]

        self.assertEqual(len(brute_force), 1)
        self.assertEqual(
            brute_force[0]["liczba_nieudanych_prob"], 6
        )


    def test_dluzsza_seria_aktualizuje_liczbe_prob(self):
        minuty = [0, 1, 2, 3, 4, 4.5, 5]
        logi = [
            self.utworz_zdarzenie(
                minuta, "LOGOWANIE_NIEUDANE"
            )
            for minuta in minuty
        ]

        alerty = analizuj_logi(logi)
        brute_force = [
            alert for alert in alerty
            if alert["typ_wykrycia"] == "BRUTE_FORCE"
        ]

        self.assertEqual(len(brute_force), 1)
        self.assertEqual(
            brute_force[0]["liczba_nieudanych_prob"], 7
        )
        self.assertEqual(
            brute_force[0]["ostatnia_proba"],
            logi[-1]["czas"].isoformat(),
        )

    def test_sukces_po_dluzszej_serii_podnosi_poziom_alertu(self):
        minuty = [0, 1, 2, 3, 4, 4.5, 5]
        logi = [
            self.utworz_zdarzenie(
                minuta, "LOGOWANIE_NIEUDANE"
            )
            for minuta in minuty
        ]
        logi.append(
            self.utworz_zdarzenie(6, "LOGOWANIE_UDANE")
        )

        alerty = analizuj_logi(logi)
        brute_force = [
            alert for alert in alerty
            if alert["typ_wykrycia"] == "BRUTE_FORCE"
        ]

        self.assertEqual(len(brute_force), 1)
        self.assertEqual(
            brute_force[0]["liczba_nieudanych_prob"], 7
        )
        self.assertTrue(
            brute_force[0]["logowanie_udane_po_serii"]
        )
        self.assertEqual(brute_force[0]["poziom"], "WYSOKI")



    def test_dwie_osobne_serie_brute_force_generuja_dwa_alerty(self):
        pierwsza_seria = [
            self.utworz_zdarzenie(i, "LOGOWANIE_NIEUDANE")
            for i in range(5)
        ]

        druga_seria = [
            self.utworz_zdarzenie(i, "LOGOWANIE_NIEUDANE")
            for i in range(11, 16)
        ]

        logi = pierwsza_seria + druga_seria

        alerty = analizuj_logi(logi)
        brute_force = [
            alert for alert in alerty
            if alert["typ_wykrycia"] == "BRUTE_FORCE"
        ]

        self.assertEqual(len(brute_force), 2)
        self.assertEqual(
            [alert["liczba_nieudanych_prob"] for alert in brute_force],
            [5, 5],
        )
        

    def test_brak_wymaganych_kolumn_w_csv(self):
        with tempfile.TemporaryDirectory() as katalog:
            sciezka = Path(katalog) / "bledne_logi.csv"
            sciezka.write_text(
                "czas,adres_ip,zdarzenie\n"
                "2026-10-12T10:00:00,192.168.1.25,"
                "LOGOWANIE_NIEUDANE\n",
                encoding="utf-8",
            )

            with self.assertRaises((ValueError, KeyError)):
                wczytaj_logi(sciezka)



    def test_nieprawidlowy_format_czasu_w_csv(self):
        with tempfile.TemporaryDirectory() as katalog:
            sciezka = Path(katalog) / "bledny_czas.csv"
            sciezka.write_text(
                "czas,adres_ip,uzytkownik,zdarzenie\n"
                "to-nie-jest-data,192.168.1.25,admin,"
                "LOGOWANIE_NIEUDANE\n",
                encoding="utf-8",
            )

            with self.assertRaises(ValueError):
                wczytaj_logi(sciezka)


    def test_pusty_plik_csv(self):
        with tempfile.TemporaryDirectory() as katalog:
            sciezka = Path(katalog) / "pusty.csv"
            sciezka.write_text("", encoding="utf-8")

            with self.assertRaises(ValueError):
                wczytaj_logi(sciezka)


    def test_brak_pliku_csv(self):
        with tempfile.TemporaryDirectory() as katalog:
            sciezka = Path(katalog) / "nie_istnieje.csv"

            with self.assertRaises(FileNotFoundError):
                wczytaj_logi(sciezka)


if __name__ == "__main__":
    unittest.main()
