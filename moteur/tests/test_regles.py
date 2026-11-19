"""Installation des règles Semgrep (image Docker) et clé d'empreinte au premier démarrage."""

import hashlib
import io
import os
import tarfile
import tempfile
import unittest

from asgor_moteur import demarrage_docker, regles

COMMIT = "a" * 40


def archive(membres: dict, liens: dict = None) -> bytes:
    tampon = io.BytesIO()
    with tarfile.open(fileobj=tampon, mode="w:gz") as tar:
        for nom, contenu in membres.items():
            info = tarfile.TarInfo(nom)
            info.size = len(contenu)
            tar.addfile(info, io.BytesIO(contenu))
        for nom, cible in (liens or {}).items():
            info = tarfile.TarInfo(nom)
            info.type = tarfile.SYMTYPE
            info.linkname = cible
            tar.addfile(info)
    return tampon.getvalue()


def ouvreur(donnees: bytes):
    def ouvrir(url, timeout=None):
        assert url == f"https://github.com/semgrep/semgrep-rules/archive/{COMMIT}.tar.gz"
        return io.BytesIO(donnees)
    return ouvrir


class TestRegles(unittest.TestCase):
    def setUp(self):
        self.dossier = tempfile.mkdtemp()

    def test_installation(self):
        donnees = archive({f"semgrep-rules-{COMMIT}/LICENSE": b"licence",
                           f"semgrep-rules-{COMMIT}/php/regle.yaml": b"rules: []"})
        regles.installer(COMMIT, hashlib.sha256(donnees).hexdigest(), self.dossier, ouvreur(donnees))
        actuel = os.path.join(self.dossier, "actuel")
        self.assertEqual(os.readlink(actuel), COMMIT)
        with open(os.path.join(actuel, "php", "regle.yaml"), "rb") as f:
            self.assertEqual(f.read(), b"rules: []")
        self.assertEqual(sorted(os.listdir(self.dossier)), sorted(["actuel", COMMIT]))

    def test_somme_fausse(self):
        donnees = archive({f"semgrep-rules-{COMMIT}/LICENSE": b"licence"})
        with self.assertRaises(ValueError):
            regles.installer(COMMIT, "0" * 64, self.dossier, ouvreur(donnees))
        self.assertFalse(os.path.exists(os.path.join(self.dossier, "actuel")))
        self.assertFalse(os.path.exists(os.path.join(self.dossier, COMMIT)))

    def test_archive_piegee(self):
        dehors = os.path.join(self.dossier, "..", "piege-regles")
        for membres, liens in (({f"x/../../piege-regles": b"!"}, {}),
                               ({"x/LICENSE": b"l"}, {"x/lien": "/etc/passwd"})):
            with self.subTest(membres=list(membres), liens=liens):
                donnees = archive(membres, liens)
                with self.assertRaises(tarfile.TarError):
                    regles.installer(COMMIT, hashlib.sha256(donnees).hexdigest(), self.dossier,
                                     ouvreur(donnees))
                self.assertFalse(os.path.exists(dehors))
                self.assertFalse(os.path.exists(os.path.join(self.dossier, COMMIT)))

    def test_arguments_invalides(self):
        with self.assertRaises(ValueError):
            regles.installer("../x", "0" * 64, self.dossier, ouvreur(b""))


class TestCle(unittest.TestCase):
    def test_creee_une_fois_puis_gardee(self):
        dossier = tempfile.mkdtemp()
        chemin = os.path.join(dossier, "secrets", "empreintes.key")
        demarrage_docker.creer_cle(chemin)
        with open(chemin, "rb") as f:
            cle = f.read()
        self.assertEqual(len(cle), 32)
        self.assertEqual(os.stat(chemin).st_mode & 0o777, 0o600)
        demarrage_docker.creer_cle(chemin)
        with open(chemin, "rb") as f:
            self.assertEqual(f.read(), cle)

    def test_cle_trop_courte_refusee(self):
        dossier = tempfile.mkdtemp()
        chemin = os.path.join(dossier, "empreintes.key")
        with open(chemin, "wb") as f:
            f.write(b"court")
        with self.assertRaises(demarrage_docker.DemarrageImpossible):
            demarrage_docker.creer_cle(chemin)


if __name__ == "__main__":
    unittest.main()
