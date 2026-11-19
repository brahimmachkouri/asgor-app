"""L'inventaire ne dépend pas de l'ordre rendu par le système de fichiers."""

import os
import tempfile
import unittest
from unittest import mock

from asgor_moteur import depot


class TestOrdre(unittest.TestCase):
    def test_meme_inventaire_quel_que_soit_l_ordre(self):
        racine = tempfile.mkdtemp()
        # 25 fichiers requirements.txt : plus que NB_MAX_MANIFESTES (20), comme pygoat.
        for i in range(25):
            dossier = os.path.join(racine, "labs", f"lab{i:02d}")
            os.makedirs(dossier)
            with open(os.path.join(dossier, "requirements.txt"), "w") as f:
                f.write("flask==2.0.0\n")
        with open(os.path.join(racine, "requirements.txt"), "w") as f:
            f.write("django==4.0\n")

        vrai_walk = os.walk

        def walk_inverse(*args, **kwargs):
            # Comme un système qui rendrait les entrées dans l'ordre inverse.
            for dossier, sous, noms in vrai_walk(*args, **kwargs):
                sous.reverse()
                noms.reverse()
                yield dossier, sous, noms

        normal = depot.inventorier(racine)
        with mock.patch.object(depot.os, "walk", walk_inverse):
            inverse = depot.inventorier(racine)
        self.assertEqual(len(normal.requirements), depot.NB_MAX_MANIFESTES)
        self.assertEqual(normal.requirements, inverse.requirements)
        self.assertEqual(normal.requirements[0], "requirements.txt")
        self.assertIn("labs/lab00/requirements.txt", normal.requirements)
        self.assertNotIn("labs/lab24/requirements.txt", normal.requirements)


if __name__ == "__main__":
    unittest.main()
