
import json
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from src.analyzer import analizuj_logi, zapisz_alerty


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

    # PASSWORD SPRAYING

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

    # DISTRIBUTED BRUTE FORCE

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

    # ZALECENIA I IDENTYFIKATORY ALERTOW

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


if __name__ == "__main__":
    unittest.main()
