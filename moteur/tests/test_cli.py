"""Résumé affiché par asgor-scan (cli._resume), avec le format de rapport du barème 3."""

import unittest

from asgor_moteur.cli import _resume


def _domaine(score, lettre, etat, raison="", problemes=0):
    return {"score": score, "lettre": lettre, "etat": etat, "raison": raison,
            "problemes": problemes}


def _rapport(domaines, globale="C", portee=""):
    return {
        "note": {"globale": globale, "portee": portee, "plafonnements": [], "domaines": domaines},
        "problemes": [], "avertissements": [], "analyse": {"duree_s": 12.0},
    }


class TestResume(unittest.TestCase):
    def test_domaines_non_notes(self):
        texte = _resume(_rapport({
            "secrets": _domaine(None, None, "non évalué", "Gitleaks : délai dépassé"),
            "dependances": _domaine(80, "B", "partiel", "Trivy en échec", 2),
            "code": _domaine(None, None, "hors périmètre", "aucun fichier PHP ou Python"),
        }, portee="note calculée sur Dépendances"), "/tmp/r.json")
        self.assertIn("Note globale : C", texte)
        self.assertIn("note calculée sur Dépendances", texte)
        self.assertIn("  —/100  —", texte)
        self.assertIn("(non évalué : Gitleaks : délai dépassé)", texte)
        self.assertIn("(partiel : Trivy en échec)", texte)
        self.assertIn("(hors périmètre : aucun fichier PHP ou Python)", texte)

    def test_domaines_complets(self):
        texte = _resume(_rapport({
            d: _domaine(100, "A", "complet") for d in ("secrets", "dependances", "code")
        }, globale="A"), "/tmp/r.json")
        self.assertIn("100/100  A  0 problème(s)\n", texte)
        for etat in ("partiel", "non évalué", "hors périmètre"):
            self.assertNotIn(etat, texte)

    def test_aucune_note_globale(self):
        texte = _resume(_rapport({
            d: _domaine(None, None, "non évalué", "échec") for d in ("secrets", "dependances", "code")
        }, globale=None), "/tmp/r.json")
        self.assertIn("Note globale : —", texte)


if __name__ == "__main__":
    unittest.main()
