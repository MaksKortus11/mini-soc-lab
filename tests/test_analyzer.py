
import sys
import unittest
from datetime import datetime, timedelta
from pathlib import Path


KATALOG_PROJEKTU = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(KATALOG_PROJEKTU / "src"))

from analyzer import analizuj_logi


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

    def test_piec_bledow_generuje_alert(self):
        logi = [
            self.utworz_zdarzenie(i, "LOGOWANIE_NIEUDANE")
            for i in range(5)
        ]

        alerty = analizuj_logi(logi)

        self.assertEqual(len(alerty), 1)
        self.assertEqual(alerty[0]["poziom"], "SREDNI")
        self.assertFalse(alerty[0]["logowanie_udane_po_serii"])

    def test_cztery_bledy_nie_generuja_alertu(self):
        logi = [
            self.utworz_zdarzenie(i, "LOGOWANIE_NIEUDANE")
            for i in range(4)
        ]

        alerty = analizuj_logi(logi)

        self.assertEqual(len(alerty), 0)

    def test_sukces_po_serii_podnosi_poziom_alertu(self):
        logi = [
            self.utworz_zdarzenie(i, "LOGOWANIE_NIEUDANE")
            for i in range(5)
        ]
        logi.append(
            self.utworz_zdarzenie(6, "LOGOWANIE_UDANE")
        )

        alerty = analizuj_logi(logi)

        self.assertEqual(len(alerty), 1)
        self.assertTrue(alerty[0]["logowanie_udane_po_serii"])
        self.assertEqual(alerty[0]["poziom"], "WYSOKI")

    def test_zbyt_pozny_sukces_nie_jest_powiazany(self):
        logi = [
            self.utworz_zdarzenie(i, "LOGOWANIE_NIEUDANE")
            for i in range(5)
        ]
        logi.append(
            self.utworz_zdarzenie(11, "LOGOWANIE_UDANE")
        )

        alerty = analizuj_logi(logi)

        self.assertEqual(len(alerty), 1)
        self.assertFalse(alerty[0]["logowanie_udane_po_serii"])
        self.assertEqual(alerty[0]["poziom"], "SREDNI")

    def test_inny_adres_ip_nie_jest_powiazany(self):
        logi = [
            self.utworz_zdarzenie(i, "LOGOWANIE_NIEUDANE")
            for i in range(5)
        ]
        logi.append(
            self.utworz_zdarzenie(
                6,
                "LOGOWANIE_UDANE",
                adres_ip="192.168.1.99",
            )
        )

        alerty = analizuj_logi(logi)

        self.assertEqual(len(alerty), 1)
        self.assertFalse(alerty[0]["logowanie_udane_po_serii"])

    def test_inny_uzytkownik_nie_jest_powiazany(self):
        logi = [
            self.utworz_zdarzenie(i, "LOGOWANIE_NIEUDANE")
            for i in range(5)
        ]
        logi.append(
            self.utworz_zdarzenie(
                6,
                "LOGOWANIE_UDANE",
                uzytkownik="student",
            )
        )

        alerty = analizuj_logi(logi)

        self.assertEqual(len(alerty), 1)
        self.assertFalse(alerty[0]["logowanie_udane_po_serii"])
        self.assertEqual(alerty[0]["poziom"], "SREDNI")


if __name__ == "__main__":
    unittest.main()
