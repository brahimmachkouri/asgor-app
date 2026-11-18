"""Tests de simuler_bareme.py.

Le point essentiel : le barème « actuel » de l'outil donne exactement les scores du
moteur (asgor_moteur.notation), sinon les comparaisons ne valent rien.
"""

import json
import os
import random
import sys
import tempfile
import unittest

ICI = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [ICI, os.path.join(ICI, "..", "moteur")]

import simuler_bareme as sb  # noqa: E402
from asgor_moteur import notation  # noqa: E402
from asgor_moteur.modele import Probleme  # noqa: E402


def p(domaine, gravite, paquet=None, fichier="composer.lock"):
    d = {"domaine": domaine, "gravite": gravite, "titre": "t", "fichier": fichier}
    if paquet:
        d["paquet"] = paquet
    return d


class MemeCalculQueLeMoteur(unittest.TestCase):
    def test_tirages_au_hasard_barème_v2(self):
        hasard = random.Random(20261116)
        paquets = ["a/a", "b/b", "c/c", "django", None]
        for _ in range(300):
            problemes = []
            for _ in range(hasard.randint(0, 60)):
                domaine = hasard.choice(("secrets", "dependances", "code"))
                d = {"domaine": domaine, "gravite": hasard.choice(sb.GRAVITES), "titre": "t",
                     "fichier": hasard.choice(("composer.lock", "back/composer.lock", "tests/x.php")),
                     "a_verifier": domaine == "secrets" and hasard.random() < 0.5,
                     "ecarte": hasard.random() < 0.1}
                if domaine == "dependances" and hasard.choice(paquets):
                    d["paquet"] = hasard.choice(paquets[:-1])
                problemes.append(d)
            objets = [Probleme(domaine=d["domaine"], gravite=d["gravite"], titre="t", fichier=d["fichier"],
                               paquet=d.get("paquet", ""), a_verifier=d["a_verifier"], ecarte=d["ecarte"])
                      for d in problemes]
            moteur = notation.noter(objets)
            outil = sb.noter({"problemes": problemes}, sb.VERSION_2)
            for dom in sb.DOMAINES:
                self.assertEqual(outil["domaines"][dom]["score"], moteur["domaines"][dom]["score"], (dom, problemes))

    def test_lettres(self):
        for s in range(0, 101):
            self.assertEqual(sb.lettre(s, sb.VERSION_2), notation.lettre_depuis_score(s), s)


class Bareme(unittest.TestCase):
    def test_dependance_comptee_une_fois(self):
        problemes = [p("dependances", "Élevée", "django", "requirements.txt")] * 51 + \
                    [p("dependances", "Critique", "django", "requirements.txt")] + \
                    [p("dependances", "Moyenne", "symfony/yaml")]
        b = sb.Bareme(nom="x", poids=dict(sb.VERSION_1.poids), dependance_une_fois=True)
        self.assertEqual(sorted(sb.problemes_comptes(problemes, "dependances", b)), ["Critique", "Moyenne"])
        self.assertEqual(len(sb.problemes_comptes(problemes, "dependances", sb.VERSION_1)), 53)

    def test_degressivite(self):
        b = sb.Bareme(nom="x", poids={"Critique": 50, "Élevée": 20, "Moyenne": 5, "Faible": 1},
                      degressivite=0.5)
        # 20 + 10 + 5 + 2,5 = 37,5 -> score 62 (arrondi)
        self.assertEqual(sb.score(["Élevée"] * 4, b), 62)
        # jamais plus que poids / (1 - r) = 40 points, même avec 100 problèmes
        self.assertEqual(sb.score(["Élevée"] * 100, b), 60)

    def test_plafonnements_repris_du_rapport(self):
        rapport = {"problemes": [], "note": {"tous_les_plafonnements": [{"note_max": "F", "raison": "secret"}]}}
        self.assertEqual(sb.noter(rapport, sb.VERSION_2)["globale"], "F")

    def test_fichier_de_baremes(self):
        with tempfile.TemporaryDirectory() as d:
            chemin = os.path.join(d, "b.json")
            with open(chemin, "w", encoding="utf-8") as f:
                json.dump([{"nom": "essai", "poids": {"Critique": 40, "Élevée": 15, "Moyenne": 5, "Faible": 1},
                            "degressivite": 0.8, "dependance_une_fois": True}], f)
            b, = sb.lire_baremes(chemin)
            self.assertEqual((b.nom, b.degressivite, b.dependance_une_fois), ("essai", 0.8, True))
            for mauvais in ([{"nom": "x", "poids": {"Critique": 1}}],
                            [{"nom": "x", "poids": dict(sb.VERSION_1.poids), "degressivite": 0}],
                            [{"nom": "x", "poids": dict(sb.VERSION_1.poids), "inconnu": 1}],
                            [{"nom": "x", "poids": dict(sb.VERSION_1.poids),
                              "seuils": {"A": 50, "B": 75, "C": 60, "D": 45, "E": 30}}]):
                with open(chemin, "w", encoding="utf-8") as f:
                    json.dump(mauvais, f)
                with self.assertRaises(ValueError):
                    sb.lire_baremes(chemin)


if __name__ == "__main__":
    unittest.main()
