"""Résultats écartés comme faux positifs (BAREME.md § 6 c) : file, base, worker, note."""

import copy
import json
import os
import tempfile
import unittest

from asgor_moteur import base, ecartes, file
from asgor_moteur.modele import CODE, CRITIQUE, MOYENNE, SECRETS, Probleme
from asgor_moteur.notation import Contexte, noter
from asgor_moteur.worker import Worker


def rapport_exemple(sans_verrouillage=()):
    problemes = [Probleme(domaine=SECRETS, gravite=CRITIQUE, titre="Secret", fichier="test/v.js",
                          ligne=3, regle="generic-api-key", occurrences=905),
                 Probleme(domaine=CODE, gravite=MOYENNE, titre="Faille", fichier="src/a.php", ligne=9,
                          regle="r")]
    return {
        "version_format": 2,
        "analyse": {"duree_s": 1.0, "version_moteur": "0.3", "historique_complet": True},
        "depot": {"proprietaire": "Exemple", "nom": "Depot", "commit": "c" * 40,
                  "branche": "main", "nb_commits": 3},
        "note": noter(problemes, Contexte(sans_verrouillage=list(sans_verrouillage))),
        "problemes": [p.en_dict() for p in problemes],
    }


class FauxMoteur:
    rapport = None
    rapports = None

    def __init__(self, depot, id_analyse, historique_complet, observateur, arret, doublon, afficher):
        self.id = id_analyse

    def lancer(self):
        r = copy.deepcopy(FauxMoteur.rapport)
        with open(os.path.join(FauxMoteur.rapports, f"{self.id}.json"), "w", encoding="utf-8") as f:
            json.dump(r, f)
        return r


class Ecartes(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.file = os.path.join(tmp.name, "file")
        self.rapports = os.path.join(tmp.name, "reports")
        for d in (self.file, self.rapports, os.path.join(tmp.name, "jobs")):
            os.makedirs(d)
        FauxMoteur.rapport, FauxMoteur.rapports = rapport_exemple(), self.rapports
        self.journal = []
        self.worker = Worker(chemin_base=os.path.join(tmp.name, "asgor.db"), dossier_file=self.file,
                             dossier_analyses=os.path.join(tmp.name, "jobs"), dossier_rapports=self.rapports,
                             fabrique_analyse=FauxMoteur, journal=self.journal.append)
        self.addCleanup(self.worker.cnx.close)
        self.secret = FauxMoteur.rapport["problemes"][0]["id"]
        self.code = FauxMoteur.rapport["problemes"][1]["id"]

    def _analyse(self, forcee=False):
        ident = file.deposer_demande("https://github.com/Exemple/Depot", forcee=forcee, dossier=self.file)
        self.assertTrue(self.worker.un_tour())
        return ident

    def _marquer(self, ident, action, empreintes, motif="vecteurs de test", ip="10.0.0.7"):
        file.deposer_marquage(ident, action, empreintes, motif, ip, dossier=self.file)
        self.worker.entretien(force=True)

    def _rapport(self, ident):
        with open(os.path.join(self.rapports, f"{ident}.json"), encoding="utf-8") as f:
            return json.load(f)

    def test_ecarter_puis_retablir(self):
        ident = self._analyse()
        self.assertEqual(base.analyse(self.worker.cnx, ident)["note"], "F")
        self._marquer(ident, file.ECARTER, [self.secret])
        ligne = base.analyse(self.worker.cnx, ident)
        self.assertEqual((ligne["note"], ligne["score_secrets"], ligne["nb_problemes"]), ("B", 100, 1))
        r = self._rapport(ident)
        self.assertTrue(r["problemes"][0]["ecarte"])
        with open(os.path.join(self.rapports, f"{ident}.sarif"), encoding="utf-8") as f:
            sarif = json.load(f)
        supprimes = [x for x in sarif["runs"][0]["results"] if x.get("suppressions")]
        self.assertEqual(len(supprimes), 1)
        # trace en base, motif et IP hors du rapport
        e = base.ecartes_du_depot(self.worker.cnx, "exemple", "depot")[self.secret]
        self.assertEqual((e["motif"], e["ip"]), ("vecteurs de test", "10.0.0.7"))
        self.assertNotIn("10.0.0.7", json.dumps(r))
        # nouvelle analyse du même dépôt : l'écart s'applique d'emblée
        suivante = self._analyse(forcee=True)
        self.assertEqual(base.analyse(self.worker.cnx, suivante)["note"], "B")
        self.assertTrue(self._rapport(suivante)["problemes"][0]["ecarte"])
        # rétablir : la note redescend
        self._marquer(ident, file.RETABLIR, [self.secret], motif="")
        self.assertEqual(base.analyse(self.worker.cnx, ident)["note"], "F")
        self.assertNotIn("ecarte", self._rapport(ident)["problemes"][0])
        actions = [x["action"] for x in self.worker.cnx.execute("SELECT action FROM ecartes_journal")]
        self.assertEqual(actions, ["ecarter", "retablir"])

    def test_plafonnement_sans_verrouillage_conserve(self):
        FauxMoteur.rapport = rapport_exemple(sans_verrouillage=["composer.json n'a pas de composer.lock"])
        ident = self._analyse()
        self._marquer(ident, file.ECARTER, [self.secret, self.code])
        self.assertEqual(base.analyse(self.worker.cnx, ident)["note"], "B")   # pas A : verrouillage

    def test_identifiants_inconnus_et_analyse_absente(self):
        ident = self._analyse()
        self._marquer(ident, file.ECARTER, ["0" * 16])
        self.assertEqual(base.analyse(self.worker.cnx, ident)["note"], "F")
        self.assertTrue(any("absent(s) du rapport" in j for j in self.journal))
        self._marquer("f" * 32, file.ECARTER, [self.secret])
        self.assertTrue(any("absente ou non terminée" in j for j in self.journal))

    def test_controles_au_depot(self):
        ident = "a" * 32
        for args in ((ident, file.ECARTER, [self.secret], "", "10.0.0.1"),          # motif obligatoire
                     (ident, file.ECARTER, [], "motif", "10.0.0.1"),
                     (ident, file.ECARTER, ["xyz"], "motif", "10.0.0.1"),
                     (ident, file.ECARTER, ["0" * 16] * 501, "motif", "10.0.0.1"),
                     (ident, "supprimer", [self.secret], "motif", "10.0.0.1"),
                     ("../x", file.ECARTER, [self.secret], "motif", "10.0.0.1"),
                     (ident, file.ECARTER, [self.secret], "m" * 301, "10.0.0.1"),
                     (ident, file.ECARTER, [self.secret], "motif", "pas une ip")):
            with self.assertRaises(file.MarquageInvalide, msg=args):
                file.deposer_marquage(*args, dossier=self.file)
        self.assertEqual(os.listdir(self.file), [])

    def test_fichier_de_marquage_trafique(self):
        ident = self._analyse()
        chemin = os.path.join(self.file, "b" * 32 + ".marquage")
        with open(chemin, "w") as f:
            json.dump({"id": "b" * 32, "analyse": ident, "action": "ecarter", "empreintes": [self.secret],
                       "motif": "ok ok", "ip": "", "en_plus": 1}, f)
        self.worker.entretien(force=True)
        self.assertEqual(base.analyse(self.worker.cnx, ident)["note"], "F")
        self.assertFalse(os.path.exists(chemin))
        self.assertTrue(any("champs inattendus" in j for j in self.journal))

    def test_motif_nettoye(self):
        empreintes, motif, ip = file._verifier_marquage("a" * 32, file.ECARTER, ["1" * 16, "1" * 16],
                                                         "  clé\nde\x07 test  ", "::1")
        self.assertEqual((empreintes, motif, ip), (("1" * 16,), "clé de test", "::1"))

    def test_contexte_relu(self):
        r = rapport_exemple(sans_verrouillage=["x/composer.json n'a pas de composer.lock"])
        r["analyse"]["historique_complet"] = False
        c = ecartes.contexte_depuis_rapport(r)
        self.assertEqual(c.sans_verrouillage, ["x/composer.json n'a pas de composer.lock"])
        self.assertTrue(c.historique_non_analyse)


if __name__ == "__main__":
    unittest.main()
