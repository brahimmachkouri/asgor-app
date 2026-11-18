"""Déroulement complet d'une analyse, sans la VM.

L'isolation (asgor-sandbox) est remplacée par un faux lanceur qui écrit,
pour chaque étape, une sortie d'outil d'exemple. Ce test vérifie que le
moteur enchaîne toutes les étapes, lit chaque résultat et écrit le rapport.
Il ne vérifie pas les vraies commandes des outils : cela se fait sur la VM.
"""

import json
import os
import tempfile
import unittest
from unittest import mock

from asgor_moteur import avancement, moteur
from asgor_moteur.etapes import ANNULEE, ECHEC, IGNOREE, OK, Etape
from asgor_moteur.url import valider_url
from tests import test_moteur as exemples

PHPSTAN = {"totals": {"errors": 0, "file_errors": 2}, "errors": [],
           "files": {"/var/lib/asgor/jobs/x/src/index.php": {"errors": 2, "messages": [
               {"message": "Call to an undefined method A::b().", "line": 12,
                "ignorable": True, "identifier": "method.notFound"},
               {"message": "Variable $x might not be defined.", "line": 3,
                "ignorable": True, "identifier": "variable.undefined"}]}}}


def _faux_lanceur(racine_analyses, en_echec=()):
    class FauxLanceur:
        def __init__(self, id_analyse, dossier_journaux, echeance, arret=None):
            self.etapes = []
            self.arret = arret or (lambda: False)
            self.commandes = {}
            self.dossier = os.path.join(racine_analyses, id_analyse)
            for sous_dossier in ("src", "out", "home"):
                os.makedirs(os.path.join(self.dossier, sous_dossier))

        def _ecrire(self, chemin, contenu):
            complet = os.path.join(self.dossier, chemin)
            os.makedirs(os.path.dirname(complet), exist_ok=True)
            with open(complet, "w", encoding="utf-8") as f:
                f.write(contenu if isinstance(contenu, str) else json.dumps(contenu))

        def ignorer(self, nom, profil, raison):
            etape = Etape(nom=nom, profil=profil, statut=IGNOREE, detail=raison)
            self.etapes.append(etape)
            return etape

        def lancer(self, nom, profil, commande, duree_max=1800, codes_ok=(0,),
                   memoire_haute=False):
            self.memoire_haute = getattr(self, "memoire_haute", {})
            self.memoire_haute[nom] = memoire_haute
            assert all(isinstance(argument, str) for argument in commande), commande
            self.commandes[nom] = commande
            if nom == "gitleaks":
                # Le .gitleaksignore du dépôt doit avoir disparu de la copie à ce moment-là.
                self.gitleaksignore_present = os.path.lexists(
                    os.path.join(self.dossier, "src", ".gitleaksignore"))
            if self.arret():
                etape = Etape(nom=nom, profil=profil, statut=ANNULEE, detail="analyse annulée")
                self.etapes.append(etape)
                return etape
            statut = ECHEC if nom in en_echec else OK
            if statut == OK:
                self._simuler(nom)
                if nom.startswith("composer-install-"):
                    # comme le vrai composer install : un dossier vendor dans le dossier -d
                    self._ecrire(os.path.join(commande[-1], "vendor/a/b/B.php"), "<?php")
            etape = Etape(nom=nom, profil=profil, statut=statut, code_retour=0,
                          duree_s=1.0, memoire_max_octets=1024,
                          detail="échec simulé" if statut == ECHEC else "")
            self.etapes.append(etape)
            return etape

        def _simuler(self, nom):
            sorties = {
                "verification-depot": ("out/depot.json", {"private": False, "size": 10}),
                "composer-audit-1": ("out/composer-audit-1.json", exemples.Dependances.COMPOSER),
                "pip-audit-1": ("out/pip-audit-1.json", exemples.Dependances.PIP),
                "gitleaks": ("out/gitleaks.json", exemples.Gitleaks.SORTIE),
                # Comme le vrai OSV-Scanner : chemin absolu dans le dossier de l'analyse.
                "osv-scanner": ("out/osv.json", json.loads(json.dumps(exemples.Dependances.OSV)
                                .replace("/var/lib/asgor/jobs/x", self.dossier))),
                "trivy": ("out/trivy.json", exemples.Dependances.TRIVY),
                "psalm": ("out/psalm.json", exemples.Code.PSALM),
                "opengrep": ("out/opengrep.json", exemples.Code.SEMGREP),
                "bandit": ("out/bandit.json", exemples.Code.BANDIT),
                "phpstan": ("out/phpstan.json", PHPSTAN),
            }
            if nom == "commit-distant":
                # Même commit que celui du clone (informations-git) : comme dans la réalité.
                self._ecrire("out/ls-remote.txt", "a" * 40 + "\tHEAD\n")
            elif nom == "clonage":
                self._ecrire("src/index.php", "<?php")
                self._ecrire("src/app/vues.py", "")
                self._ecrire("src/composer.json", {"require": {"symfony/http-kernel": "^6.4"}})
                self._ecrire("src/composer.lock", {})
                self._ecrire("src/requirements.txt", "django==4.2.0\n")
                # Monorepo : une application dans back/, un bundle sans composer.lock
                self._ecrire("src/back/composer.json", {"require": {"a/b": "^1"}})
                self._ecrire("src/back/composer.lock", {})
                self._ecrire("src/packages/x-bundle/composer.json",
                             {"type": "symfony-bundle", "require": {"a/b": "^1"}})
            elif nom == "informations-git":
                self._ecrire("out/commit.txt", "a" * 40 + "\n")
                self._ecrire("out/nb-commits.txt", "412\n")
                self._ecrire("out/branche.txt", "main\n")
            elif nom.startswith("composer-audit-"):
                self._ecrire(f"out/{nom}.json", exemples.Dependances.COMPOSER)
            elif nom in sorties:
                self._ecrire(*sorties[nom])

    return FauxLanceur


class Deroulement(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = tmp.name
        self.analyses = os.path.join(self.tmp, "jobs")
        os.makedirs(self.analyses)

    def _analyser(self, en_echec=(), lanceur=None, **options):
        correctifs = [
            mock.patch.object(moteur, "ANALYSES", self.analyses),
            mock.patch.object(moteur, "RAPPORTS", os.path.join(self.tmp, "reports")),
            mock.patch.object(moteur, "JOURNAUX", os.path.join(self.tmp, "logs")),
            mock.patch.object(moteur, "VERROU", os.path.join(self.tmp, "verrou")),
            mock.patch.object(moteur, "Lanceur", lanceur or _faux_lanceur(self.analyses, en_echec)),
            mock.patch.object(moteur.os, "geteuid", lambda: 0),
            mock.patch.object(moteur.os.path, "ismount", lambda chemin: True),
        ]
        for correctif in correctifs:
            correctif.start()
            self.addCleanup(correctif.stop)
        analyse = moteur.Analyse(valider_url("https://github.com/exemple/depot"),
                                 afficher=lambda *a: None, **options)
        return analyse, analyse.lancer()

    def test_analyse_complete(self):
        analyse, rapport = self._analyser()

        noms = [e["nom"] for e in rapport["etapes"]]
        for attendu in ("verification-depot", "clonage", "base-trivy", "base-osv",
                        "composer-audit-1", "pip-audit-1", "gitleaks", "osv-scanner", "trivy",
                        "composer-install-1", "composer-install-2", "psalm", "phpstan",
                        "opengrep", "bandit"):
            self.assertIn(attendu, noms)
        self.assertTrue(all(e["statut"] == OK for e in rapport["etapes"]))
        self.assertNotIn("semgrep", noms)  # décision : Opengrep seul
        # Qualité du code : présente dans le rapport, sans effet sur la note.
        self.assertEqual(rapport["qualite"]["nb_erreurs"], 2)
        self.assertEqual(rapport["qualite"]["effet_sur_la_note"], "aucun")
        self.assertFalse(any(p["outils"] == ["PHPStan"] for p in rapport["problemes"]))
        with open(os.path.join(analyse.dossier, "phpstan.neon"), encoding="utf-8") as f:
            neon = f.read()
        self.assertIn("level: 5", neon)
        self.assertIn("- src/back/vendor", neon)
        self.assertTrue(analyse.lanceur.memoire_haute["psalm"])
        self.assertFalse(analyse.lanceur.memoire_haute["opengrep"])
        # Le bundle sans composer.lock est une bibliothèque : avertissement, pas plafonnement.
        self.assertTrue(any("x-bundle" in a for a in rapport["avertissements"]))
        self.assertFalse(any("x-bundle" in p["raison"]
                             for p in rapport["note"]["tous_les_plafonnements"]))

        self.assertEqual(rapport["depot"]["commit"], "a" * 40)
        self.assertEqual(rapport["depot"]["nb_commits"], 412)
        self.assertEqual(rapport["depot"]["langages"], ["PHP", "Python"])

        # Un secret : note F, et le secret n'apparaît nulle part en clair.
        self.assertEqual(rapport["note"]["globale"], "F")
        domaines = {p["domaine"] for p in rapport["problemes"]}
        self.assertEqual(domaines, {"secrets", "dependances", "code"})
        with open(analyse.chemin_rapport, encoding="utf-8") as f:
            texte = f.read()
        self.assertEqual(json.loads(texte), rapport)
        self.assertNotIn("SECRETSECRET", texte)
        self.assertIn("ghp_****", texte)

        # Le rapport brut de Gitleaks et le clone sont supprimés.
        self.assertFalse(os.path.exists(os.path.join(analyse.out, "gitleaks.json")))
        self.assertFalse(os.path.exists(analyse.src))
        self.assertTrue(os.path.exists(os.path.join(analyse.out, "rapport.json")))
        # Le SARIF est écrit à côté du rapport, sans secret en clair.
        with open(analyse.chemin_sarif, encoding="utf-8") as f:
            sarif_texte = f.read()
        self.assertEqual(json.loads(sarif_texte)["version"], "2.1.0")
        self.assertNotIn("SECRETSECRET", sarif_texte)

        # La même faille vue par trois outils ne compte qu'une fois par fichier de
        # verrouillage. Composer Audit la voit aussi dans back/composer.lock : c'est
        # un second problème, corrigé à part (cas réel d'un monorepo Symfony).
        kernel = {p["fichier"]: p for p in rapport["problemes"]
                  if p.get("paquet") == "symfony/http-kernel"}
        self.assertEqual(sorted(kernel), ["back/composer.lock", "composer.lock"])
        self.assertEqual(kernel["composer.lock"]["outils"], ["Composer Audit", "OSV-Scanner", "Trivy"])
        self.assertEqual(kernel["back/composer.lock"]["outils"], ["Composer Audit"])

    def test_outil_en_echec(self):
        _, rapport = self._analyser(en_echec=("psalm", "gitleaks"))
        note = rapport["note"]
        self.assertEqual(note["domaines"]["code"]["outils_en_echec"], ["Psalm"])
        self.assertEqual(note["domaines"]["secrets"]["outils_en_echec"], ["Gitleaks"])
        self.assertEqual(note["domaines"]["secrets"]["evaluation"], "incomplète")
        self.assertTrue(any("Psalm" in a for a in rapport["avertissements"]))

    def test_phpstan_en_echec_sans_effet_sur_la_note(self):
        _, normal = self._analyser()
        self.setUp()
        _, echec = self._analyser(en_echec=("phpstan",))
        self.assertIsNone(echec["qualite"])
        self.assertEqual(echec["note"], normal["note"])
        self.assertTrue(any("PHPStan" in a for a in echec["avertissements"]))

    def test_depot_refuse(self):
        with self.assertRaises(moteur.AnalyseImpossible):
            self._analyser(en_echec=("verification-depot",))

    def test_garder_les_sources(self):
        analyse, _ = self._analyser(garder_sources=True)
        self.assertTrue(os.path.exists(os.path.join(analyse.src, "index.php")))


class Enregistreur(avancement.Observateur):
    def __init__(self):
        self.evenements = []

    def groupe_commence(self, cle):
        self.evenements.append(("commence", cle))

    def groupe_termine(self, cle, statut, detail, duree_s):
        self.evenements.append(("termine", cle, statut, detail))

    def depot_connu(self, commit, branche, nb_commits):
        self.evenements.append(("depot", commit, branche, nb_commits))


class Lot1(Deroulement):
    """Groupes d'avancement, historique Git facultatif, export SARIF."""

    def test_groupes_dans_l_ordre(self):
        obs = Enregistreur()
        self._analyser(observateur=obs)
        termines = [e for e in obs.evenements if e[0] == "termine"]
        self.assertEqual([e[1] for e in termines], list(avancement.CLES))
        self.assertTrue(all(e[2] == avancement.TERMINEE for e in termines), termines)
        details = {e[1]: e[3] for e in termines}
        self.assertEqual(details["clonage"], "412 commits, 1 Mo")
        self.assertEqual(details["langages"], "PHP, Python")
        self.assertEqual(details["secrets"], "Gitleaks, tout l'historique — 1 secret détecté")
        self.assertEqual(details["dependances"], "Composer Audit, pip-audit, OSV-Scanner, Trivy")
        self.assertEqual(details["note"], "note F")
        self.assertIn(("depot", "a" * 40, "main", 412), obs.evenements)

    def test_composer_audit_sur_une_copie(self):
        analyse, _ = self._analyser()
        commande = analyse.lanceur.commandes["composer-audit-1"]
        self.assertIn("out/composer-audit-1", commande)
        self.assertNotIn("src", commande)
        with open(os.path.join(analyse.dossier, "out/composer-audit-1/composer.json")) as f:
            self.assertEqual(f.read(), "{}\n")
        self.assertTrue(os.path.exists(os.path.join(analyse.dossier, "out/composer-audit-1/composer.lock")))

    def test_gitleaksignore_du_depot_supprime_avant_gitleaks(self):
        lanceur = _faux_lanceur(self.analyses)
        simuler = lanceur._simuler

        def avec_gitleaksignore(self_, nom):
            simuler(self_, nom)
            if nom == "clonage":
                self_._ecrire("src/.gitleaksignore", "abc:config/app.php:generic-api-key:3\n")
        lanceur._simuler = avec_gitleaksignore
        analyse, rapport = self._analyser(lanceur=lanceur, garder_sources=True)
        self.assertFalse(analyse.lanceur.gitleaksignore_present)
        self.assertTrue(any(".gitleaksignore" in a for a in rapport["avertissements"]))

    def test_regle_gitleaks_php(self):
        conf = os.path.join(os.path.dirname(moteur.__file__), "..", "conf", "gitleaks.toml")
        with open(conf, encoding="utf-8") as f:
            texte = f.read()
        self.assertIn('id = "asgor-secret-tableau-php"', texte)
        self.assertIn("useDefault = true", texte)

    def test_secrets_avant_dependances(self):
        _, rapport = self._analyser()
        noms = [e["nom"] for e in rapport["etapes"]]
        self.assertLess(noms.index("gitleaks"), noms.index("base-trivy"))
        self.assertLess(noms.index("commit-distant"), noms.index("clonage"))

    def test_groupes_ignores_sans_php(self):
        obs = Enregistreur()
        lanceur = _faux_lanceur(self.analyses)
        simuler = lanceur._simuler

        def sans_php(self_, nom):
            simuler(self_, nom)
            if nom == "clonage":
                for chemin in ("src/index.php", "src/composer.json", "src/composer.lock",
                               "src/back/composer.json", "src/back/composer.lock",
                               "src/packages/x-bundle/composer.json"):
                    os.remove(os.path.join(self_.dossier, chemin))
        lanceur._simuler = sans_php
        self._analyser(observateur=obs, lanceur=lanceur)
        termines = {e[1]: e[2:] for e in obs.evenements if e[0] == "termine"}
        self.assertEqual(termines["flux"], (avancement.IGNOREE, "aucun fichier PHP"))
        self.assertEqual(termines["qualite"], (avancement.IGNOREE, "aucun fichier PHP"))
        self.assertEqual(termines["python"][0], avancement.TERMINEE)

    def test_annulation(self):
        obs = Enregistreur()
        etat = {"annuler": False}

        class Annuleur(Enregistreur):
            def groupe_termine(self_, cle, statut, detail, duree_s):
                super().groupe_termine(cle, statut, detail, duree_s)
                if cle == "secrets":
                    etat["annuler"] = True
        obs = Annuleur()
        with self.assertRaises(moteur.AnalyseAnnulee):
            self._analyser(observateur=obs, arret=lambda: etat["annuler"])
        termines = [e for e in obs.evenements if e[0] == "termine"]
        self.assertEqual(termines[-1][1:3], ("dependances", avancement.ANNULEE))
        self.assertEqual(os.listdir(os.path.join(self.tmp, "reports")) if os.path.isdir(
            os.path.join(self.tmp, "reports")) else [], [])
        dossiers = os.listdir(self.analyses)
        self.assertFalse(os.path.exists(os.path.join(self.analyses, dossiers[0], "src")))

    def test_doublon_arrete_avant_le_clonage(self):
        vus = []

        def doublon(commit):
            vus.append(commit)
            return True
        with self.assertRaises(moteur.AnalyseExistante) as contexte:
            self._analyser(doublon=doublon)
        self.assertEqual(contexte.exception.commit, "a" * 40)
        self.assertEqual(vus, ["a" * 40])
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "reports")))

    def test_pas_de_doublon(self):
        _, rapport = self._analyser(doublon=lambda commit: False)
        self.assertEqual(rapport["depot"]["commit_distant"], "a" * 40)

    def test_sans_historique(self):
        analyse, rapport = self._analyser(historique_complet=False)
        self.assertIn("--depth", analyse.lanceur.commandes["clonage"])
        self.assertFalse(rapport["analyse"]["historique_complet"])
        raisons = [p["raison"] for p in rapport["note"]["tous_les_plafonnements"]]
        self.assertTrue(any(r.startswith("historique Git non analysé") for r in raisons))

    def test_avec_historique(self):
        analyse, rapport = self._analyser()
        self.assertNotIn("--depth", analyse.lanceur.commandes["clonage"])
        self.assertTrue(rapport["analyse"]["historique_complet"])

    def test_identifiant(self):
        analyse, rapport = self._analyser(id_analyse="0123456789abcdef" * 2)
        self.assertEqual(rapport["analyse"]["id"], "0123456789abcdef" * 2)
        self.assertTrue(analyse.chemin_rapport.endswith("0123456789abcdef" * 2 + ".json"))
        for mauvais in ("../x", "A" * 32, "abc", "0" * 33):
            with self.assertRaises(moteur.AnalyseImpossible):
                moteur.Analyse(valider_url("https://github.com/a/b"), id_analyse=mauvais)
        self.assertRegex(moteur.nouvel_identifiant(), r"^[0-9a-f]{32}$")

    def test_versions_des_outils(self):
        chemin = os.path.join(self.tmp, "outils.json")
        with open(chemin, "w") as f:
            json.dump({"Gitleaks": "8.30.1", "Psalm": "7.5.0", "x": 3}, f)
        with mock.patch.object(moteur, "OUTILS", chemin):
            _, rapport = self._analyser()
        self.assertEqual(rapport["outils"], {"Gitleaks": "8.30.1", "Psalm": "7.5.0"})
        self.assertEqual(rapport["outils_non_lances"], [])

    def test_outils_non_lances(self):
        # Dépôt sans Python : Bandit ne tourne pas, il est listé à part.
        chemin = os.path.join(self.tmp, "outils.json")
        with open(chemin, "w") as f:
            json.dump({"Gitleaks": "8.30.1", "Bandit": "1.9.4", "pip-audit": "2.10.1"}, f)
        lanceur = _faux_lanceur(self.analyses)
        simuler = lanceur._simuler

        def sans_python(self_, nom):
            simuler(self_, nom)
            if nom == "clonage":
                os.remove(os.path.join(self_.dossier, "src/app/vues.py"))
                os.remove(os.path.join(self_.dossier, "src/requirements.txt"))
        lanceur._simuler = sans_python
        with mock.patch.object(moteur, "OUTILS", chemin):
            _, rapport = self._analyser(lanceur=lanceur)
        self.assertEqual(rapport["outils"], {"Gitleaks": "8.30.1"})
        self.assertEqual(rapport["outils_non_lances"], ["Bandit", "pip-audit"])


class FormatDuRapport(Deroulement):
    """Clés et types du rapport (test demandé à l'étape de l'application web)."""

    def test_cles_et_types(self):
        _, r = self._analyser()
        self.assertEqual(r["version_format"], 2)
        attendu = {"version_format": int, "analyse": dict, "depot": dict, "note": dict,
                   "problemes": list, "qualite": dict, "avertissements": list,
                   "outils": dict, "outils_non_lances": list, "etapes": list}
        self.assertEqual(set(r), set(attendu))
        for cle, type_ in attendu.items():
            self.assertIsInstance(r[cle], type_, cle)
        for cle, type_ in {"id": str, "debut": str, "fin": str, "duree_s": float,
                           "version_moteur": str, "historique_complet": bool}.items():
            self.assertIsInstance(r["analyse"][cle], type_, cle)
        for cle, type_ in {"url": str, "proprietaire": str, "nom": str, "langages": list,
                           "commit": str, "branche": str, "nb_commits": int}.items():
            self.assertIsInstance(r["depot"][cle], type_, cle)
        self.assertIn(r["note"]["globale"], "ABCDEF")
        for domaine in ("secrets", "dependances", "code"):
            d = r["note"]["domaines"][domaine]
            self.assertIsInstance(d["score"], int)
            self.assertIn(d["lettre"], "ABCDEF")
        for p in r["problemes"]:
            for cle, type_ in {"id": str, "domaine": str, "gravite": str, "titre": str,
                               "ligne": int, "outils": list}.items():
                self.assertIsInstance(p[cle], type_, (cle, p))
            self.assertRegex(p["id"], r"^[0-9a-f]{16}$")
            self.assertIn(p["domaine"], ("secrets", "dependances", "code"))
        for e in r["etapes"]:
            self.assertEqual(set(e), {"nom", "profil", "statut", "code_retour", "duree_s",
                                      "memoire_max_octets", "detail"})


if __name__ == "__main__":
    unittest.main()
