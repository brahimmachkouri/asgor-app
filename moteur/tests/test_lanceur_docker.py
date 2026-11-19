"""LanceurDocker : déroulement d'une étape avec un faux filtre."""

import os
import tempfile
import time
import unittest

from asgor_moteur import etapes

ANALYSE = "0123456789abcdef0123456789abcdef"
CONTENEUR = "c" * 64


class FauxFiltre:
    def __init__(self, code=0, tours=2, memoire_depassee=False, refus_lancer=False):
        self.code, self.tours, self.memoire_depassee = code, tours, memoire_depassee
        self.refus_lancer = refus_lancer
        self.demandes = []

    def __call__(self, demande):
        self.demandes.append(demande)
        action = demande["action"]
        if action == "lancer":
            if self.refus_lancer:
                raise etapes.FiltreInjoignable("profil refusé")
            return {"ok": True, "conteneur": CONTENEUR}, b""
        if action == "attendre":
            self.tours -= 1
            fini = self.tours <= 0
            return {"ok": True, "termine": fini, "code": self.code if fini else None,
                    "memoire_depassee": self.memoire_depassee}, b""
        if action == "journaux":
            return {"ok": True, "taille": 5}, b"sortie"
        return {"ok": True}, b""

    def actions(self):
        return [d["action"] for d in self.demandes]


class TestLanceurDocker(unittest.TestCase):
    def setUp(self):
        self.dossier = tempfile.mkdtemp()
        self.journaux = os.path.join(self.dossier, "logs")
        os.makedirs(self.journaux)
        self.intervalle = etapes.INTERVALLE_SURVEILLANCE
        etapes.INTERVALLE_SURVEILLANCE = 0.01

    def tearDown(self):
        etapes.INTERVALLE_SURVEILLANCE = self.intervalle

    def lanceur(self, filtre, arret=None, echeance=60):
        return etapes.LanceurDocker(ANALYSE, self.journaux, time.monotonic() + echeance,
                                    arret=arret, dossier_analyses=self.dossier, demander=filtre)

    def test_etape_reussie(self):
        filtre = FauxFiltre()
        etape = self.lanceur(filtre).lancer("gitleaks", "scan", ["gitleaks", "version"])
        self.assertEqual(etape.statut, etapes.OK)
        self.assertEqual(etape.code_retour, 0)
        self.assertEqual(filtre.actions(), ["lancer", "attendre", "attendre", "journaux", "supprimer"])
        self.assertEqual(filtre.demandes[0], {"action": "lancer", "profil": "scan", "analyse": ANALYSE,
                                              "commande": ["gitleaks", "version"], "memoire_haute": False})
        with open(etape.journal, "rb") as f:
            self.assertEqual(f.read(), b"sortie")
        for sous in ("src", "out", "home"):
            self.assertTrue(os.path.isdir(os.path.join(self.dossier, ANALYSE, sous)))

    def test_echec_et_memoire(self):
        etape = self.lanceur(FauxFiltre(code=137, memoire_depassee=True)).lancer("psalm", "scan", ["psalm"])
        self.assertEqual(etape.statut, etapes.ECHEC)
        self.assertIn("mémoire maximale dépassée", etape.detail)

    def test_code_accepte(self):
        etape = self.lanceur(FauxFiltre(code=1)).lancer("opengrep", "scan", ["opengrep"], codes_ok=(0, 1))
        self.assertEqual(etape.statut, etapes.OK)

    def test_annulation(self):
        filtre = FauxFiltre(tours=1000)
        etape = self.lanceur(filtre, arret=lambda: True).lancer("trivy", "fetch", ["trivy"])
        # Annulée avant même d'être lancée.
        self.assertEqual(etape.statut, etapes.ANNULEE)
        self.assertEqual(filtre.actions(), [])

    def test_annulation_pendant_l_etape(self):
        filtre = FauxFiltre(tours=1000)
        appels = []
        lanceur = self.lanceur(filtre, arret=lambda: len(appels) > 1 or appels.append(1) and False)
        etape = lanceur.lancer("trivy", "fetch", ["trivy"])
        self.assertEqual(etape.statut, etapes.ANNULEE)
        self.assertIn("tuer", filtre.actions())
        self.assertEqual(filtre.actions()[-1], "supprimer")

    def test_delai(self):
        filtre = FauxFiltre(tours=1000)
        etape = self.lanceur(filtre).lancer("trivy", "fetch", ["trivy"], duree_max=0.05)
        self.assertEqual(etape.statut, etapes.DELAI)
        self.assertIn("tuer", filtre.actions())

    def test_refus_du_filtre(self):
        etape = self.lanceur(FauxFiltre(refus_lancer=True)).lancer("x", "scan", ["x"])
        self.assertEqual(etape.statut, etapes.ECHEC)
        self.assertIn("profil refusé", etape.detail)


if __name__ == "__main__":
    unittest.main()
