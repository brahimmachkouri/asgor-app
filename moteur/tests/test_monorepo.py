"""Tests ajoutés après le scan d'un monorepo Symfony réel."""

import os
import tempfile
import unittest

from asgor_moteur.modele import DEPENDANCES, MOYENNE
from asgor_moteur.moteur import lock_perime, probleme_lock_perime
from asgor_moteur.notation import noter

# Extrait réel du journal de composer install (packages/intranet-bundle)
JOURNAL_PERIME = """Installing dependencies from lock file (including require-dev)
Verifying lock file contents can be installed on current platform.
Warning: The lock file is not up to date with the latest changes in composer.json. You may be getting outdated dependencies.
- Required package "symfony/framework-bundle" is in the lock file as "v7.4.8" but that does not satisfy your constraint "^8.1".
"""


class LockPerime(unittest.TestCase):
    def _journal(self, texte):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        chemin = os.path.join(d.name, "14-composer-install-3.log")
        with open(chemin, "w", encoding="utf-8") as f:
            f.write(texte)
        return chemin

    def test_detection(self):
        self.assertTrue(lock_perime(self._journal(JOURNAL_PERIME)))
        self.assertFalse(lock_perime(self._journal("Could not download package\n")))
        self.assertFalse(lock_perime(""))
        self.assertFalse(lock_perime("/chemin/inexistant.log"))

    def test_probleme_moyen(self):
        p = probleme_lock_perime("packages/intranet-bundle/composer.lock")
        self.assertEqual((p.domaine, p.gravite), (DEPENDANCES, MOYENNE))
        self.assertEqual(p.fichier, "packages/intranet-bundle/composer.lock")
        note = noter([p])
        self.assertEqual(note["domaines"][DEPENDANCES]["score"], 94)   # total 0,3
        self.assertEqual(note["globale"], "B")  # un problème moyen interdit le A


class Phpstan(unittest.TestCase):
    def test_lecture(self):
        from asgor_moteur import analyseurs
        from tests.test_deroulement import PHPSTAN
        q = analyseurs.lire_phpstan(PHPSTAN, racine_analyse="/var/lib/asgor/jobs/x", niveau=5)
        self.assertEqual((q["nb_erreurs"], q["nb_fichiers"], q["niveau"]), (2, 1, 5))
        self.assertEqual(q["erreurs"][0], {"fichier": "index.php", "ligne": 3,
                                           "type": "variable.undefined",
                                           "message": "Variable $x might not be defined."})
        self.assertEqual(analyseurs.lire_phpstan({"totals": {}, "files": []})["nb_erreurs"], 0)
        with self.assertRaises(analyseurs.FormatInattendu):
            analyseurs.lire_phpstan({"erreur": 1})

    def test_chemin_dangereux_refuse_dans_la_configuration(self):
        from asgor_moteur.depot import Inventaire
        from asgor_moteur.moteur import AnalyseImpossible, _phpstan_neon
        with self.assertRaises(AnalyseImpossible):
            _phpstan_neon(Inventaire(dossiers_tiers=["a\n    bootstrapFiles: [x]/vendor"]))


if __name__ == "__main__":
    unittest.main()
