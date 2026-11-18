"""File des demandes (lot 3 de l'étape 4) : dépôt par le service web, relevé par le worker.

Le worker ne doit faire confiance à rien de ce que contient le dossier.
"""

import json
import os
import tempfile
import time
import unittest

from asgor_moteur import file
from asgor_moteur.url import UrlInvalide

ID = "0123456789abcdef" * 2


class Depot(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dossier = tmp.name

    def _ecrire(self, nom, contenu):
        with open(os.path.join(self.dossier, nom), "w", encoding="utf-8") as f:
            f.write(contenu if isinstance(contenu, str) else json.dumps(contenu))

    def _demande(self, **champs):
        d = {"id": ID, "url": "https://github.com/a/b", "historique_complet": True,
             "masquee": False, "forcee": False}
        d.update(champs)
        return d

    # --------------------------------------------------------- service web
    def test_aller_retour(self):
        identifiant = file.deposer_demande("https://github.com/Organisation/monDepot.git",
                                           historique_complet=False, masquee=True,
                                           dossier=self.dossier)
        self.assertRegex(identifiant, r"^[0-9a-f]{32}$")
        self.assertTrue(file.demande_en_file(identifiant, self.dossier))
        self.assertEqual(os.listdir(self.dossier), [f"{identifiant}.json"])  # pas de .tmp restant
        demandes, annulations, rejets = file.relever(self.dossier)
        self.assertEqual(rejets, [])
        self.assertEqual(annulations, [])
        d, = demandes
        self.assertEqual((d.id, d.url, d.proprietaire, d.nom), (
            identifiant, "https://github.com/Organisation/monDepot", "Organisation", "monDepot"))
        self.assertEqual((d.historique_complet, d.masquee, d.forcee), (False, True, False))
        self.assertEqual(os.listdir(self.dossier), [])  # fichier supprimé après lecture
        self.assertFalse(file.demande_en_file(identifiant, self.dossier))

    def test_url_refusee_au_depot(self):
        with self.assertRaises(UrlInvalide):
            file.deposer_demande("https://gitlab.com/a/b", dossier=self.dossier)
        self.assertEqual(os.listdir(self.dossier), [])

    def test_file_pleine(self):
        for _ in range(file.NB_MAX_EN_FILE):
            file.deposer_demande("https://github.com/a/b", dossier=self.dossier)
        with self.assertRaises(file.FilePleine):
            file.deposer_demande("https://github.com/a/b", dossier=self.dossier)

    def test_annulation(self):
        file.deposer_annulation(ID, self.dossier)
        file.deposer_annulation(ID, self.dossier)  # deux fois : sans erreur
        demandes, annulations, rejets = file.relever(self.dossier)
        self.assertEqual((demandes, annulations, rejets), ([], [ID], []))
        with self.assertRaises(ValueError):
            file.deposer_annulation("../../etc/passwd", self.dossier)

    def test_ordre_des_demandes(self):
        premiere = file.deposer_demande("https://github.com/a/premier", dossier=self.dossier)
        os.utime(os.path.join(self.dossier, f"{premiere}.json"), (1000, 1000))
        seconde = file.deposer_demande("https://github.com/a/second", dossier=self.dossier)
        demandes, _, _ = file.relever(self.dossier)
        self.assertEqual([d.id for d in demandes], [premiere, seconde])

    # ----------------------------------------------- fichiers piégés (worker)
    def _refuse(self, nom, raison_attendue):
        demandes, annulations, rejets = file.relever(self.dossier)
        self.assertEqual((demandes, annulations), ([], []))
        self.assertEqual(len(rejets), 1, rejets)
        self.assertIn(raison_attendue, rejets[0])
        self.assertFalse(os.path.lexists(os.path.join(self.dossier, nom)),
                         "le fichier refusé doit être supprimé")

    def test_lien_symbolique(self):
        cible = os.path.join(self.dossier, "..", "cible-secrete")
        cible = os.path.abspath(cible)
        with open(cible, "w") as f:
            json.dump(self._demande(), f)
        self.addCleanup(os.remove, cible)
        os.symlink(cible, os.path.join(self.dossier, f"{ID}.json"))
        self._refuse(f"{ID}.json", "pas un fichier ordinaire")
        self.assertTrue(os.path.exists(cible), "la cible du lien ne doit pas être supprimée")

    def test_lien_physique(self):
        cible = os.path.join(self.dossier, "..", f"cible-physique-{os.getpid()}")
        cible = os.path.abspath(cible)
        with open(cible, "w") as f:
            json.dump(self._demande(), f)
        self.addCleanup(os.remove, cible)
        os.link(cible, os.path.join(self.dossier, f"{ID}.json"))
        self._refuse(f"{ID}.json", "plusieurs liens physiques")

    def test_trop_gros(self):
        self._ecrire(f"{ID}.json", self._demande(url="https://github.com/a/" + "b" * 3000))
        self._refuse(f"{ID}.json", "trop gros")

    def test_champ_inconnu(self):
        self._ecrire(f"{ID}.json", {**self._demande(), "commande": "rm -rf /"})
        self._refuse(f"{ID}.json", "champs inattendus")

    def test_champ_manquant(self):
        d = self._demande()
        del d["forcee"]
        self._ecrire(f"{ID}.json", d)
        self._refuse(f"{ID}.json", "champs inattendus")

    def test_identifiant_different_du_nom(self):
        self._ecrire(f"{ID}.json", self._demande(id="f" * 32))
        self._refuse(f"{ID}.json", "identifiant différent")

    def test_option_qui_n_est_pas_un_booleen(self):
        self._ecrire(f"{ID}.json", self._demande(masquee="non"))
        self._refuse(f"{ID}.json", "n'est pas un booléen")
        self._ecrire(f"{ID}.json", self._demande(forcee=1))
        self._refuse(f"{ID}.json", "n'est pas un booléen")

    def test_url_invalide_dans_le_fichier(self):
        for url in ("https://gitlab.com/a/b", "https://jeton@github.com/a/b", 12, None):
            with self.subTest(url=url):
                self._ecrire(f"{ID}.json", self._demande(url=url))
                self._refuse(f"{ID}.json", "URL refusée")

    def test_json_invalide(self):
        self._ecrire(f"{ID}.json", "{pas du json")
        self._refuse(f"{ID}.json", "JSON invalide")
        self._ecrire(f"{ID}.json", "[]")
        self._refuse(f"{ID}.json", "champs inattendus")

    def test_nom_inattendu(self):
        for nom in ("autre.txt", f"{ID.upper()}.json", f"{ID}.json.bak", "..json", f"x{ID}.json"):
            with self.subTest(nom=nom):
                self._ecrire(nom, self._demande())
                self._refuse(nom, "nom de fichier inattendu")

    def test_dossier_au_nom_valide(self):
        os.mkdir(os.path.join(self.dossier, f"{ID}.json"))
        self._refuse(f"{ID}.json", "pas un fichier ordinaire")

    def test_annulation_non_vide(self):
        self._ecrire(f"{ID}.annuler", "contenu")
        self._refuse(f"{ID}.annuler", "doit être vide")

    def test_fichier_temporaire(self):
        self._ecrire(f".{ID}.tmp", "{")
        # Récent : laissé en place (le service web est en train de l'écrire).
        self.assertEqual(file.relever(self.dossier), ([], [], []))
        self.assertTrue(os.path.exists(os.path.join(self.dossier, f".{ID}.tmp")))
        # Abandonné depuis plus d'une minute : supprimé.
        _, _, rejets = file.relever(self.dossier, maintenant=time.time() + 120)
        self.assertIn("abandonné", rejets[0])
        self.assertEqual(os.listdir(self.dossier), [])

    def test_le_rejet_ne_contient_pas_le_contenu(self):
        self._ecrire(f"{ID}.json", {**self._demande(), "SECRET": "valeur-confidentielle"})
        _, _, rejets = file.relever(self.dossier)
        self.assertNotIn("valeur-confidentielle", rejets[0])

    def test_dossier_absent(self):
        self.assertEqual(file.relever(os.path.join(self.dossier, "absent")), ([], [], []))


if __name__ == "__main__":
    unittest.main()
