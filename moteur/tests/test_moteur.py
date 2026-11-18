"""Tests du moteur qui tournent sans la VM : lecture des résultats des outils,
doublons, notation, inventaire du dépôt.

Les exemples de sorties d'outils sont écrits à la main d'après leur format
connu. Ils devront être confrontés à de vraies sorties (étape 3).
"""

import os
import tempfile
import unittest

from asgor_moteur import analyseurs, fichiers
from asgor_moteur.depot import inventorier, requirements_epingle, verifier_verrouillage
from asgor_moteur.etapes import memoire_max
from asgor_moteur.fusion import supprimer_doublons
from asgor_moteur.modele import (
    CODE, CRITIQUE, DEPENDANCES, ELEVEE, FAIBLE, MOYENNE, SECRETS, Probleme, masquer_secret,
)
from asgor_moteur.notation import Contexte, lettre_depuis_score, noter


class Masquage(unittest.TestCase):
    def test_quatre_caracteres_puis_etoiles(self):
        self.assertEqual(masquer_secret("ghp_abcdefghijklmnop"), "ghp_****")

    def test_secret_court_entierement_masque(self):
        self.assertEqual(masquer_secret("abcd1234"), "****")
        self.assertEqual(masquer_secret(""), "****")
        self.assertEqual(masquer_secret(None), "****")


class Gitleaks(unittest.TestCase):
    SORTIE = [
        {"RuleID": "github-pat", "Description": "GitHub Personal Access Token",
         "File": "config/prod.php", "StartLine": 12, "Commit": "a" * 40,
         "Secret": "ghp_SECRETSECRETSECRETSECRET", "Match": "token = ghp_SECRETSECRETSECRETSECRET",
         "Author": "x", "Email": "x@example.org"},
        {"RuleID": "github-pat", "Description": "GitHub Personal Access Token",
         "File": "config/prod.php", "StartLine": 14, "Commit": "b" * 40,
         "Secret": "ghp_SECRETSECRETSECRETSECRET"},
    ]

    def test_secret_jamais_en_clair(self):
        problemes = analyseurs.lire_gitleaks(self.SORTIE)
        self.assertEqual(len(problemes), 1)  # même secret dans deux commits
        p = problemes[0]
        self.assertEqual(p.occurrences, 2)
        self.assertEqual(p.secret_masque, "ghp_****")
        self.assertEqual(p.gravite, CRITIQUE)
        self.assertEqual(p.domaine, SECRETS)
        self.assertNotIn("SECRETSECRET", repr(p.en_dict()))
        self.assertNotIn("example.org", repr(p.en_dict()))

    def test_regroupement_par_fichier(self):
        # 905 vecteurs de test dans un fichier, 95 dans un autre (cas de PrivateBin)
        sortie = [{"RuleID": "generic-api-key", "File": "test/ccm_vectors.js", "StartLine": i,
                   "Commit": "c" * 40, "Secret": f"vecteur{i:06d}abcdef"} for i in range(905, 0, -1)]
        sortie += [{"RuleID": "generic-api-key", "File": "test/cbc_vectors.js", "StartLine": i,
                    "Commit": "c" * 40, "Secret": f"autre{i:06d}abcdef"} for i in range(1, 96)]
        problemes = analyseurs.lire_gitleaks(sortie)
        self.assertEqual(sorted(p.occurrences for p in problemes), [95, 905])
        ccm, = [p for p in problemes if p.fichier == "test/ccm_vectors.js"]
        self.assertEqual(ccm.ligne, 1)            # première occurrence, ordre fixe
        # Même identifiant quel que soit l'ordre de sortie de Gitleaks
        inverse = analyseurs.lire_gitleaks(list(reversed(sortie)))
        self.assertEqual(sorted(p.empreinte for p in problemes), sorted(p.empreinte for p in inverse))

    def test_secret_a_verifier(self):
        for chemin, attendu in (("tests/Unit/a.php", True), ("docs/install.md", True),
                                ("README.md", True), ("config/.env.example", True),
                                ("config.inc.php.dist", True), ("public/js/app.min.js", True),
                                ("Test/data/a.eml", True), ("config/prod.php", False),
                                ("src/Latest/x.php", False), ("contest/x.php", False),
                                ("testing.php", False), ("", False),
                                ("js/test.js", True), ("src/app.test.js", True), ("a/b.spec.js", True),
                                ("src/UserTest.php", True), ("test_api.py", True), ("api_test.py", True),
                                ("pkg/db_test.go", True), ("src/Test.php", False), ("latest.js", False),
                                ("src/usertest.php", False), ("contest_x.py", False), ("Test.js", False)):
            self.assertEqual(analyseurs.chemin_a_verifier(chemin), attendu, chemin)
        p, = analyseurs.lire_gitleaks([{"RuleID": "jwt", "File": "tests/Oauth.php", "StartLine": 3,
                                        "Secret": "eyJhbGciOiJIUzI1NiJ9.abc.def"}])
        self.assertTrue(p.a_verifier)
        self.assertEqual(p.gravite, ELEVEE)
        self.assertNotIn("eyJhbGciOiJIUzI1NiJ9.abc", repr(p.en_dict()))

    def test_rapport_vide(self):
        self.assertEqual(analyseurs.lire_gitleaks([]), [])
        self.assertEqual(analyseurs.lire_gitleaks(None), [])

    def test_forme_inattendue(self):
        with self.assertRaises(analyseurs.FormatInattendu):
            analyseurs.lire_gitleaks({"erreur": 1})


class Dependances(unittest.TestCase):
    COMPOSER = {"advisories": {"symfony/http-kernel": [
        {"advisoryId": "PKSA-1", "packageName": "symfony/http-kernel",
         "affectedVersions": ">=6.0,<6.4.5", "title": "Faille X", "cve": "CVE-2026-0001",
         "link": "https://example.org/a", "severity": "high",
         "sources": [{"name": "GitHub", "remoteId": "GHSA-aaaa-bbbb-cccc"}]}]}}
    OSV = {"results": [{"source": {"path": "/var/lib/asgor/jobs/x/src/composer.lock"},
                        "packages": [{
                            "package": {"name": "symfony/http-kernel", "version": "6.4.1",
                                        "ecosystem": "Packagist"},
                            "vulnerabilities": [{
                                "id": "GHSA-aaaa-bbbb-cccc", "aliases": ["CVE-2026-0001"],
                                "summary": "Faille X (OSV)",
                                "affected": [{"package": {"name": "symfony/http-kernel"},
                                              "ranges": [{"events": [{"introduced": "6.0"},
                                                                      {"fixed": "6.4.5"}]}]}]}],
                            "groups": [{"ids": ["GHSA-aaaa-bbbb-cccc"],
                                        "aliases": ["CVE-2026-0001"], "max_severity": "9.1"}]}]}]}
    TRIVY = {"SchemaVersion": 2, "Results": [{"Target": "composer.lock", "Vulnerabilities": [
        {"VulnerabilityID": "CVE-2026-0001", "PkgName": "symfony/http-kernel",
         "InstalledVersion": "6.4.1", "FixedVersion": "6.4.5, 7.0.3", "Severity": "HIGH",
         "Title": "Faille X"}]}]}
    PIP = {"dependencies": [{"name": "django", "version": "4.2.0", "vulns": [
        {"id": "PYSEC-2026-1", "fix_versions": ["4.2.9"], "aliases": ["CVE-2026-0002"],
         "description": "…"}]}, {"name": "requests", "version": "2.32.0", "vulns": []}]}

    def test_composer_audit(self):
        p, = analyseurs.lire_composer_audit(self.COMPOSER)
        self.assertEqual((p.paquet, p.gravite), ("symfony/http-kernel", ELEVEE))
        self.assertIn("CVE-2026-0001", p.identifiants)
        self.assertIn("GHSA-aaaa-bbbb-cccc", p.identifiants)

    def test_composer_audit_sans_avis(self):
        self.assertEqual(analyseurs.lire_composer_audit({"advisories": []}), [])

    def test_osv(self):
        p, = analyseurs.lire_osv(self.OSV, racine_analyse="/var/lib/asgor/jobs/x")
        self.assertEqual(p.fichier, "composer.lock")
        self.assertEqual(p.gravite, CRITIQUE)  # score 9,1
        self.assertEqual(p.version_corrigee, "6.4.5")

    def test_trivy(self):
        p, = analyseurs.lire_trivy(self.TRIVY)
        self.assertEqual((p.gravite, p.version_corrigee), (ELEVEE, "6.4.5"))

    def test_pip_audit(self):
        p, = analyseurs.lire_pip_audit(self.PIP)
        self.assertEqual((p.paquet, p.version_corrigee), ("django", "4.2.9"))

    def test_trois_outils_un_seul_probleme(self):
        problemes = (analyseurs.lire_composer_audit(self.COMPOSER)
                     + analyseurs.lire_osv(self.OSV, racine_analyse="/var/lib/asgor/jobs/x")
                     + analyseurs.lire_trivy(self.TRIVY))
        fusion = supprimer_doublons(problemes)
        self.assertEqual(len(fusion), 1)
        p = fusion[0]
        self.assertEqual(p.outils, ["Composer Audit", "OSV-Scanner", "Trivy"])
        self.assertEqual(p.gravite, CRITIQUE)       # la plus grave des trois
        self.assertEqual(p.version_corrigee, "6.4.5")

    def test_gravite_par_defaut_de_pip_audit_ne_l_emporte_pas(self):
        faible = Probleme(domaine=DEPENDANCES, gravite=FAIBLE, titre="t", paquet="django",
                          outils=["OSV-Scanner"], identifiants=["CVE-2026-0002"])
        fusion = supprimer_doublons(analyseurs.lire_pip_audit(self.PIP) + [faible])
        self.assertEqual(len(fusion), 1)
        self.assertEqual(fusion[0].gravite, FAIBLE)

    def test_paquets_differents_non_fusionnes(self):
        a = Probleme(domaine=DEPENDANCES, gravite=ELEVEE, titre="t", paquet="a/a",
                     identifiants=["CVE-1-1"])
        b = Probleme(domaine=DEPENDANCES, gravite=ELEVEE, titre="t", paquet="b/b",
                     identifiants=["CVE-1-1"])
        self.assertEqual(len(supprimer_doublons([a, b])), 2)

    def test_meme_faille_dans_deux_verrous_non_fusionnee(self):
        """Monorepo : la même faille Symfony dans composer.lock et back/composer.lock."""
        racine = Probleme(domaine=DEPENDANCES, gravite=ELEVEE, titre="t", paquet="symfony/config",
                          fichier="composer.lock", version="v8.1.5",
                          outils=["Composer Audit"], identifiants=["CVE-1-1"])
        back = Probleme(domaine=DEPENDANCES, gravite=ELEVEE, titre="t", paquet="symfony/config",
                        fichier="back/composer.lock", version="v8.1.10",
                        outils=["Composer Audit"], identifiants=["CVE-1-1"])
        trivy = Probleme(domaine=DEPENDANCES, gravite=ELEVEE, titre="t", paquet="symfony/config",
                         fichier="back/composer.lock", outils=["Trivy"], identifiants=["CVE-1-1"])
        fusion = supprimer_doublons([racine, back, trivy])
        self.assertEqual(sorted(p.fichier for p in fusion), ["back/composer.lock", "composer.lock"])
        p_back, = [p for p in fusion if p.fichier == "back/composer.lock"]
        self.assertEqual(p_back.outils, ["Composer Audit", "Trivy"])
        self.assertEqual(p_back.version, "v8.1.10")

    def test_fichier_inconnu_ne_bloque_pas_la_fusion(self):
        a = Probleme(domaine=DEPENDANCES, gravite=ELEVEE, titre="t", paquet="a/a",
                     fichier="composer.lock", identifiants=["CVE-1-1"])
        b = Probleme(domaine=DEPENDANCES, gravite=ELEVEE, titre="t", paquet="a/a",
                     identifiants=["CVE-1-1"])
        self.assertEqual(len(supprimer_doublons([a, b])), 1)


class Code(unittest.TestCase):
    PSALM = [
        {"type": "TaintedSql", "severity": "error", "line_from": 87, "message": "Detected tainted SQL",
         "file_name": "src/Controller/StageController.php", "link": "https://psalm.dev/244"},
        {"type": "UndefinedClass", "severity": "error", "line_from": 3, "message": "x",
         "file_name": "src/a.php"},
    ]
    SEMGREP = {"results": [
        {"check_id": "opt.asgor.regles.semgrep-rules.actuel.php.lang.security.injection.tainted-sql-string",
         "path": "src/Controller/StageController.php", "start": {"line": 87},
         "extra": {"message": "SQL injection", "severity": "ERROR",
                   "metadata": {"category": "security", "cwe": ["CWE-89: SQL Injection"],
                                "confidence": "MEDIUM"}}},
        {"check_id": "php.lang.best-practice.x", "path": "src/a.php", "start": {"line": 1},
         "extra": {"message": "style", "severity": "WARNING",
                   "metadata": {"category": "best-practice"}}},
    ], "errors": []}
    BANDIT = {"results": [
        {"filename": "src/app/vues.py", "line_number": 10, "test_id": "B608",
         "test_name": "hardcoded_sql_expressions", "issue_severity": "MEDIUM",
         "issue_confidence": "LOW", "issue_text": "Possible SQL injection",
         "issue_cwe": {"id": 89}}]}

    def test_psalm_garde_seulement_le_flux(self):
        p, = analyseurs.lire_psalm(self.PSALM)
        self.assertEqual((p.categorie, p.gravite, p.flux), ("injection-sql", ELEVEE, True))
        self.assertEqual(p.fichier, "Controller/StageController.php")

    def test_semgrep_garde_seulement_la_securite(self):
        p, = analyseurs.lire_semgrep(self.SEMGREP)
        self.assertEqual(p.regle, "php.lang.security.injection.tainted-sql-string")
        self.assertEqual(p.categorie, "injection-sql")

    def test_bandit_confiance_faible(self):
        p, = analyseurs.lire_bandit(self.BANDIT)
        self.assertEqual((p.gravite, p.fichier), (FAIBLE, "app/vues.py"))

    def test_psalm_semgrep_opengrep_un_seul_probleme(self):
        problemes = (analyseurs.lire_psalm(self.PSALM)
                     + analyseurs.lire_semgrep(self.SEMGREP)
                     + analyseurs.lire_semgrep(self.SEMGREP, outil="Opengrep"))
        fusion = supprimer_doublons(problemes)
        self.assertEqual(len(fusion), 1)
        self.assertEqual(fusion[0].outils, ["Opengrep", "Psalm", "Semgrep"])
        self.assertTrue(fusion[0].flux)

    def test_empreinte_stable(self):
        a, = analyseurs.lire_psalm(self.PSALM)
        b, = analyseurs.lire_psalm(self.PSALM)
        self.assertEqual(a.empreinte, b.empreinte)
        self.assertRegex(a.empreinte, r"^[0-9a-f]{16}$")


class Notation(unittest.TestCase):
    def _p(self, domaine, gravite, **champs):
        return Probleme(domaine=domaine, gravite=gravite, titre="t", **champs)

    def test_echelle(self):
        attendu = {100: "A", 90: "A", 89: "B", 75: "B", 74: "C", 60: "C",
                   59: "D", 45: "D", 44: "E", 30: "E", 29: "F", 0: "F"}
        for score, lettre in attendu.items():
            self.assertEqual(lettre_depuis_score(score), lettre, score)

    def test_aucun_probleme(self):
        note = noter([])
        self.assertEqual(note["globale"], "A")
        self.assertEqual(note["plafonnements"], [])

    def test_exemple_1_de_notation_md(self):
        problemes = [
            self._p(DEPENDANCES, ELEVEE, version_corrigee="1.2.3"),
            self._p(CODE, MOYENNE, ligne=1), self._p(CODE, MOYENNE, ligne=2),
        ]
        note = noter(problemes)
        self.assertEqual(note["domaines"][SECRETS]["score"], 100)
        self.assertEqual(note["domaines"][DEPENDANCES]["score"], 85)   # total 1
        self.assertEqual(note["domaines"][CODE]["score"], 90)          # total 0,6
        self.assertEqual(note["globale"], "B")
        self.assertEqual(note["version_bareme"], 2)

    def test_exemple_2_secret_dans_l_historique(self):
        note = noter([self._p(SECRETS, CRITIQUE, commit="a" * 40)])
        self.assertLessEqual(note["domaines"][SECRETS]["score"], 29)   # zone F
        self.assertEqual(note["globale"], "F")
        self.assertEqual(note["plafonnements"][0]["note_max"], "F")

    def test_exemple_3_sans_verrouillage(self):
        note = noter([], Contexte(sans_verrouillage=["composer.json n'a pas de composer.lock"]))
        self.assertEqual(note["avant_plafonnement"], "A")
        self.assertEqual(note["globale"], "B")
        self.assertIn("analyse des dépendances incomplète", note["plafonnements"][0]["raison"])

    def test_la_plus_basse_des_trois_lettres(self):
        # Code : 15 problèmes élevés -> score 40 (E). Les deux autres domaines sont à A.
        problemes = [self._p(CODE, ELEVEE, ligne=i) for i in range(15)]
        note = noter(problemes)
        self.assertEqual(note["domaines"][CODE]["score"], 40)
        self.assertEqual(note["globale"], "E")

    def test_flux_plafonne_a_c(self):
        note = noter([self._p(CODE, ELEVEE, flux=True, categorie="injection-sql")])
        self.assertEqual(note["domaines"][CODE]["lettre"], "B")
        self.assertEqual(note["globale"], "C")

    def test_faille_critique(self):
        self.assertEqual(noter([self._p(DEPENDANCES, CRITIQUE)])["globale"], "F")

    def test_table_du_doublement(self):
        for n, attendu in ((0, 100), (1, 85), (3, 70), (7, 55), (15, 40), (31, 25), (127, 0)):
            note = noter([self._p(CODE, ELEVEE, ligne=i) for i in range(n)])
            self.assertEqual(note["domaines"][CODE]["score"], attendu, n)

    def test_vingt_problemes_faibles(self):
        # 20 × 0,05 = 1 problème élevé : score 85 (B), note globale A possible
        note = noter([self._p(CODE, FAIBLE, ligne=i) for i in range(20)])
        self.assertEqual(note["domaines"][CODE]["score"], 85)
        self.assertEqual(note["globale"], "B")

    def test_dependance_comptee_une_fois(self):
        # Django : 51 avis élevés + 1 critique -> une seule dépendance critique (total 4)
        problemes = [self._p(DEPENDANCES, ELEVEE, paquet="django", fichier="requirements.txt",
                             identifiants=[f"CVE-{i}"]) for i in range(51)]
        problemes.append(self._p(DEPENDANCES, CRITIQUE, paquet="Django", fichier="requirements.txt"))
        note = noter(problemes)
        self.assertEqual(note["domaines"][DEPENDANCES]["score"], 65)
        self.assertEqual(note["globale"], "F")        # faille critique
        # Même paquet dans deux fichiers de verrouillage : deux dépendances
        autre = self._p(DEPENDANCES, ELEVEE, paquet="django", fichier="back/requirements.txt")
        self.assertEqual(noter(problemes + [autre])["domaines"][DEPENDANCES]["score"], 61)  # total 5

    def test_secret_a_verifier(self):
        note = noter([self._p(SECRETS, ELEVEE, a_verifier=True, fichier="tests/a.php")])
        self.assertEqual(note["domaines"][SECRETS]["score"], 59)       # zone D
        self.assertEqual(note["globale"], "D")
        self.assertIn("à vérifier", note["plafonnements"][0]["raison"])
        # Un vrai secret en plus : F
        note = noter([self._p(SECRETS, ELEVEE, a_verifier=True, fichier="tests/a.php"),
                      self._p(SECRETS, CRITIQUE, fichier="config/b.php")])
        self.assertEqual(note["globale"], "F")
        self.assertLessEqual(note["domaines"][SECRETS]["score"], 29)

    def test_faux_positif_ecarte(self):
        note = noter([self._p(SECRETS, CRITIQUE, ecarte=True)])
        self.assertEqual(note["globale"], "A")
        self.assertEqual(note["domaines"][SECRETS]["problemes"], 0)

    def test_un_probleme_moyen_interdit_le_a(self):
        note = noter([self._p(CODE, MOYENNE)])
        self.assertEqual(note["domaines"][CODE]["lettre"], "A")
        self.assertEqual(note["globale"], "B")

    def test_outil_en_echec(self):
        note = noter([], Contexte(outils_en_echec={CODE: ["Psalm"]}))
        self.assertEqual(note["globale"], "B")
        self.assertEqual(note["domaines"][CODE]["evaluation"], "incomplète")


class Inventaire(unittest.TestCase):
    def _depot(self, contenus: dict) -> str:
        racine = tempfile.mkdtemp(dir=self._tmp.name)
        for chemin, texte in contenus.items():
            complet = os.path.join(racine, chemin)
            os.makedirs(os.path.dirname(complet), exist_ok=True)
            with open(complet, "w", encoding="utf-8") as f:
                f.write(texte)
        return racine

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)

    def test_langages_et_dossiers_ignores(self):
        racine = self._depot({"index.php": "", "outil.py": "", "vendor/x/y.php": "",
                              "node_modules/a/b.py": ""})
        inv = inventorier(racine)
        self.assertEqual((inv.nb_php, inv.nb_python), (1, 1))
        self.assertEqual(inv.langages, ["PHP", "Python"])
        self.assertEqual(inv.dossiers_tiers, ["node_modules", "vendor"])

    def test_application_sans_composer_lock(self):
        racine = self._depot({"composer.json": '{"require": {"symfony/console": "^7.0"}}'})
        plafonds, avertissements = verifier_verrouillage(racine, inventorier(racine))
        self.assertEqual(len(plafonds), 1)
        self.assertEqual(avertissements, [])

    def test_bibliotheque_sans_composer_lock(self):
        racine = self._depot({"composer.json":
                              '{"type": "library", "require": {"symfony/console": "^7.0"}}'})
        plafonds, avertissements = verifier_verrouillage(racine, inventorier(racine))
        self.assertEqual(plafonds, [])
        self.assertEqual(len(avertissements), 1)

    def test_bundle_symfony_sans_composer_lock(self):
        racine = self._depot({"packages/auth-bundle/composer.json":
                              '{"type": "symfony-bundle", "require": {"symfony/console": "^7.0"}}'})
        plafonds, avertissements = verifier_verrouillage(racine, inventorier(racine))
        self.assertEqual(plafonds, [])
        self.assertEqual(len(avertissements), 1)

    def test_psalm_xml_monorepo(self):
        from asgor_moteur.depot import Inventaire
        from asgor_moteur.moteur import _psalm_xml
        xml = _psalm_xml(Inventaire(dossiers_tiers=["vendor", "back/vendor", "front/node_modules"]))
        self.assertIn('<directory name="src/back/vendor"/>\n  </extraFiles>', xml)
        self.assertEqual(xml.count("src/back/vendor"), 2)  # ignoré ET lu pour les classes
        self.assertNotIn("<extraFiles>\n    <directory name=\"src/front", xml)

    def test_composer_avec_verrou_ou_sans_dependance(self):
        racine = self._depot({"composer.json": '{"require": {"a/b": "^1"}}', "composer.lock": "{}",
                              "outils/composer.json": '{"require": {"php": ">=8.2"}}'})
        self.assertEqual(verifier_verrouillage(racine, inventorier(racine)), ([], []))

    def test_requirements(self):
        self.assertTrue(requirements_epingle("django==5.2.1\nrequests==2.32.0  # commentaire\n"))
        self.assertTrue(requirements_epingle("# vide\n"))
        self.assertTrue(requirements_epingle("django==5.2.1 \\\n  --hash=sha256:abc\n"))
        self.assertFalse(requirements_epingle("django>=5.0\n"))
        self.assertFalse(requirements_epingle("django\n"))
        self.assertFalse(requirements_epingle("django~=5.2\n"))
        self.assertFalse(requirements_epingle("django==5.*\n"))
        self.assertFalse(requirements_epingle("-e .\n"))
        self.assertFalse(requirements_epingle("git+https://github.com/a/b.git\n"))

    def test_requirements_non_epingle_plafonne(self):
        racine = self._depot({"requirements.txt": "django>=5.0\n", "app.py": ""})
        plafonds, _ = verifier_verrouillage(racine, inventorier(racine))
        self.assertEqual(len(plafonds), 1)

    def test_pyproject_seul_est_une_bibliotheque(self):
        racine = self._depot({"pyproject.toml": '[project]\nname = "x"\ndependencies = ["attrs"]\n'})
        plafonds, avertissements = verifier_verrouillage(racine, inventorier(racine))
        self.assertEqual(plafonds, [])
        self.assertEqual(len(avertissements), 1)


class Fichiers(unittest.TestCase):
    def test_lien_symbolique_refuse(self):
        with tempfile.TemporaryDirectory() as d:
            cible = os.path.join(d, "cible.json")
            with open(cible, "w") as f:
                f.write("{}")
            lien = os.path.join(d, "lien.json")
            os.symlink(cible, lien)
            self.assertEqual(fichiers.lire_json(cible), {})
            with self.assertRaises(fichiers.LectureRefusee):
                fichiers.lire_json(lien)

    def test_fichier_trop_gros_refuse(self):
        with tempfile.TemporaryDirectory() as d:
            chemin = os.path.join(d, "gros.json")
            with open(chemin, "w") as f:
                f.write("[" + "1," * 1000 + "1]")
            with self.assertRaises(fichiers.LectureRefusee):
                fichiers.lire_json(chemin, taille_max=100)


class Memoire(unittest.TestCase):
    def test_lecture_du_bilan_systemd(self):
        self.assertEqual(memoire_max("CPU time consumed: 2s\nMemory peak: 12.5M (swap: 0B)\n"),
                         int(12.5 * 1024 * 1024))
        self.assertIsNone(memoire_max("rien"))


if __name__ == "__main__":
    unittest.main()
