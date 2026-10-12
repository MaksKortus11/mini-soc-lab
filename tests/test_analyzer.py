
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


    def test_wykrywa_proby_na_wiele_kont_z_jednego_ip(self):
        logi = [
            self.utworz_zdarzenie(
                0, "LOGOWANIE_NIEUDANE", uzytkownik="user1"
            ),
            self.utworz_zdarzenie(
                1, "LOGOWANIE_NIEUDANE", uzytkownik="user2"
            ),
            self.utworz_zdarzenie(
                2, "LOGOWANIE_NIEUDANE", uzytkownik="user3"
            ),
            self.utworz_zdarzenie(
                3, "LOGOWANIE_NIEUDANE", uzytkownik="user1"
            ),
            self.utworz_zdarzenie(
                4, "LOGOWANIE_NIEUDANE", uzytkownik="user2"
            ),
        ]

        alerty = analizuj_logi(logi)

        alerty_spraying = [
            alert for alert in alerty
            if alert.get("typ_wykrycia") == "PASSWORD_SPRAYING"
        ]

        self.assertEqual(len(alerty_spraying), 1)
        self.assertEqual(
            alerty_spraying[0]["liczba_nieudanych_prob"], 5
        )
        self.assertEqual(
            alerty_spraying[0]["adres_ip"], "192.168.1.25"
        )

    def test_spraying_na_dwa_konta_nie_generuje_alertu(self):
        logi = [
            self.utworz_zdarzenie(
                0, "LOGOWANIE_NIEUDANE", uzytkownik="user1"
            ),
            self.utworz_zdarzenie(
                1, "LOGOWANIE_NIEUDANE", uzytkownik="user2"
            ),
            self.utworz_zdarzenie(
                2, "LOGOWANIE_NIEUDANE", uzytkownik="user1"
            ),
            self.utworz_zdarzenie(
                3, "LOGOWANIE_NIEUDANE", uzytkownik="user2"
            ),
            self.utworz_zdarzenie(
                4, "LOGOWANIE_NIEUDANE", uzytkownik="user1"
            ),
        ]

        alerty = analizuj_logi(logi)

        self.assertFalse(
            any(
                alert.get("typ_wykrycia") == "PASSWORD_SPRAYING"
                for alert in alerty
            )
        )

    def test_cztery_proby_na_trzy_konta_nie_generuja_spraying(self):
        logi = [
            self.utworz_zdarzenie(
                0, "LOGOWANIE_NIEUDANE", uzytkownik="user1"
            ),
            self.utworz_zdarzenie(
                1, "LOGOWANIE_NIEUDANE", uzytkownik="user2"
            ),
            self.utworz_zdarzenie(
                2, "LOGOWANIE_NIEUDANE", uzytkownik="user3"
            ),
            self.utworz_zdarzenie(
                3, "LOGOWANIE_NIEUDANE", uzytkownik="user1"
            ),
        ]

        alerty = analizuj_logi(logi)

        self.assertFalse(
            any(
                alert.get("typ_wykrycia") == "PASSWORD_SPRAYING"
                for alert in alerty
            )
        )

    def test_proby_poza_oknem_czasowym_nie_generuja_spraying(self):
        logi = [
            self.utworz_zdarzenie(
                0, "LOGOWANIE_NIEUDANE", uzytkownik="user1"
            ),
            self.utworz_zdarzenie(
                1, "LOGOWANIE_NIEUDANE", uzytkownik="user2"
            ),
            self.utworz_zdarzenie(
                2, "LOGOWANIE_NIEUDANE", uzytkownik="user3"
            ),
            self.utworz_zdarzenie(
                6, "LOGOWANIE_NIEUDANE", uzytkownik="user1"
            ),
            self.utworz_zdarzenie(
                7, "LOGOWANIE_NIEUDANE", uzytkownik="user2"
            ),
        ]

        alerty = analizuj_logi(logi)

        self.assertFalse(
            any(
                alert.get("typ_wykrycia") == "PASSWORD_SPRAYING"
                for alert in alerty
            )
        )

    
    def test_brute_force_ma_poprawne_mapowanie_mitre(self):
        logi = [
            self.utworz_zdarzenie(
                minuta,
                "LOGOWANIE_NIEUDANE",
                uzytkownik="admin",
            )
            for minuta in range(5)
        ]

        alerty = analizuj_logi(logi)
        alert = next(
            alert for alert in alerty
            if alert.get("typ_wykrycia") == "BRUTE_FORCE"
        )

        self.assertEqual(
            alert["mitre_attack"]["id"], "T1110.001"
        )
        self.assertEqual(
            alert["mitre_attack"]["nazwa"], "Password Guessing"
        )

    def test_password_spraying_ma_poprawne_mapowanie_mitre(self):
        logi = [
            self.utworz_zdarzenie(
                0, "LOGOWANIE_NIEUDANE", uzytkownik="user1"
            ),
            self.utworz_zdarzenie(
                1, "LOGOWANIE_NIEUDANE", uzytkownik="user2"
            ),
            self.utworz_zdarzenie(
                2, "LOGOWANIE_NIEUDANE", uzytkownik="user3"
            ),
            self.utworz_zdarzenie(
                3, "LOGOWANIE_NIEUDANE", uzytkownik="user1"
            ),
            self.utworz_zdarzenie(
                4, "LOGOWANIE_NIEUDANE", uzytkownik="user2"
            ),
        ]

        alerty = analizuj_logi(logi)
        alert = next(
            alert for alert in alerty
            if alert.get("typ_wykrycia") == "PASSWORD_SPRAYING"
        )

        self.assertEqual(
            alert["mitre_attack"]["id"], "T1110.003"
        )
        self.assertEqual(
            alert["mitre_attack"]["nazwa"], "Password Spraying"
        )



if __name__ == "__main__":
    unittest.main()
