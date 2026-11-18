"""Lanceur réel (etapes.Lanceur) avec un faux asgor-sandbox : annulation et délai.

Le faux asgor-sandbox lance directement la commande, sans isolation.
"""

import os
import stat
import tempfile
import time
import unittest

from asgor_moteur.etapes import ANNULEE, DELAI, OK, Lanceur

FAUX_SANDBOX = """#!/bin/sh
# usage : faux-sandbox profil id -- commande...
shift 3
exec "$@"
"""


class LanceurReel(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = tmp.name
        self.sandbox = os.path.join(self.tmp, "faux-sandbox")
        with open(self.sandbox, "w") as f:
            f.write(FAUX_SANDBOX)
        os.chmod(self.sandbox, stat.S_IRWXU)

    def _lanceur(self, arret=None, duree=60):
        return Lanceur("0" * 32, self.tmp, time.monotonic() + duree,
                       sandbox=self.sandbox, arret=arret)

    def test_etape_normale(self):
        etape = self._lanceur().lancer("essai", "scan", ["true"])
        self.assertEqual(etape.statut, OK)

    def test_annulation_en_moins_de_deux_secondes(self):
        debut = time.monotonic()
        lanceur = self._lanceur(arret=lambda: time.monotonic() - debut > 0.6)
        etape = lanceur.lancer("long", "scan", ["sleep", "30"])
        self.assertEqual(etape.statut, ANNULEE)
        self.assertLess(time.monotonic() - debut, 2.5)
        # Les étapes suivantes ne sont plus lancées.
        self.assertEqual(lanceur.lancer("suivante", "scan", ["true"]).statut, ANNULEE)

    def test_delai(self):
        etape = self._lanceur().lancer("long", "scan", ["sleep", "30"], duree_max=1)
        self.assertEqual(etape.statut, DELAI)


if __name__ == "__main__":
    unittest.main()
