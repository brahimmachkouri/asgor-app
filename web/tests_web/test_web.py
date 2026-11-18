"""Service web (lot 5 de l'étape 4), avec le client de test de FastAPI.

Lancer depuis ~/sys/asgor avec l'environnement qui contient web/requirements.txt
et web/requirements-tests.txt :
    PYTHONPATH=moteur:web python -m unittest discover -s web/tests_web -t web
"""

import datetime
import json
import os
import re
import tempfile
import unittest

from fastapi.testclient import TestClient

from asgor_moteur import avancement, base, file
from asgor_moteur.file import Demande
from asgor_web.app import Chemins, creer_app

ICI = os.path.dirname(os.path.abspath(__file__))
GABARITS = os.path.join(ICI, "..", "asgor_web", "templates")
HOTE = "testserver"
PIEGE = '<script>alert("x")</script>"onmouseover="alert(1)'


def demande(n, nom="depot", masquee=False, historique=True):
    return Demande(id=f"{n:032x}", url=f"https://github.com/exemple/{nom}", proprietaire="exemple",
                   nom=nom, historique_complet=historique, masquee=masquee, forcee=False)


def rapport(nb_problemes=2, **remplacements):
    problemes = [{
        "id": f"{i:016x}", "domaine": "code", "gravite": "Élevée", "titre": f"Faille {i}",
        "fichier": "src/a.php", "ligne": i + 1, "outils": ["Psalm"], "regle": "TaintedSql",
        "explication": "Explication.", "correction": "Corriger."} for i in range(nb_problemes)]
    r = {
        "version_format": 2,
        "analyse": {"id": "x", "duree_s": 25.0, "version_moteur": "0.2", "historique_complet": True},
        "depot": {"url": "https://github.com/exemple/depot", "commit": "a" * 40,
                  "branche": "main", "nb_commits": 845},
        "note": {"globale": "C", "avant_plafonnement": "B",
                 "plafonnements": [{"note_max": "C", "raison": "injection SQL détectée"}],
                 "domaines": {d: {"score": s, "lettre": l, "problemes": n,
                                  "evaluation": "complète", "outils_en_echec": []}
                              for d, s, l, n in (("secrets", 100, "A", 0),
                                                 ("dependances", 75, "B", 0),
                                                 ("code", 50, "D", nb_problemes))}},
        "problemes": problemes,
        "qualite": {"outil": "PHPStan", "niveau": 5, "nb_erreurs": 1, "nb_fichiers": 1,
                    "par_type": [{"nom": "method.notFound", "nombre": 1}],
                    "par_fichier": [{"nom": "a.php", "nombre": 1}],
                    "erreurs": [{"fichier": "a.php", "ligne": 3, "type": "method.notFound",
                                 "message": "Call to an undefined method."}],
                    "erreurs_tronquees": False, "effet_sur_la_note": "aucun"},
        "avertissements": [],
        "outils": {"Gitleaks": "8.30.1", "Psalm": "7.5.0"},
        "etapes": [],
    }
    r.update(remplacements)
    return r


class Web(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        racine = tmp.name
        self.chemins = Chemins(base=os.path.join(racine, "asgor.db"),
                               file=os.path.join(racine, "file"),
                               rapports=os.path.join(racine, "reports"),
                               outils=os.path.join(racine, "outils.json"))
        os.makedirs(self.chemins.file)
        os.makedirs(self.chemins.rapports)
        with open(self.chemins.outils, "w") as f:
            json.dump({"Gitleaks": "8.30.1", "Opengrep": "2.0.0"}, f)
        self.cnx = base.ouvrir_ecriture(self.chemins.base)
        self.addCleanup(self.cnx.close)
        base.signe_de_vie(self.cnx)
        self.client = TestClient(creer_app(self.chemins), raise_server_exceptions=False)

    # ------------------------------------------------------------ utilitaires
    def _jeton(self):
        reponse = self.client.get("/")
        return self.client.cookies.get("csrf") or reponse.cookies.get("csrf")

    def _poster(self, chemin, donnees, jeton=True, origine=f"http://{HOTE}", **en_tetes):
        corps = dict(donnees)
        if jeton:
            corps["csrf"] = self._jeton()
        if origine is not None:
            en_tetes["Origin"] = origine
        return self.client.post(chemin, data=corps, headers=en_tetes, follow_redirects=False)

    def _terminee(self, n=1, contenu=None, **options):
        d = demande(n, **options)
        base.creer_analyse(self.cnx, d)
        base.demarrer(self.cnx, d.id, "0.2")
        r = contenu or rapport()
        base.terminer(self.cnx, d.id, r)
        with open(os.path.join(self.chemins.rapports, f"{d.id}.json"), "w", encoding="utf-8") as f:
            json.dump(r, f, ensure_ascii=False)
        with open(os.path.join(self.chemins.rapports, f"{d.id}.sarif"), "w") as f:
            json.dump({"version": "2.1.0", "runs": []}, f)
        return d.id

    # ------------------------------------------------------------- en-têtes
    def test_entetes_de_securite(self):
        r = self.client.get("/")
        self.assertEqual(r.status_code, 200)
        csp = r.headers["content-security-policy"]
        self.assertIn("default-src 'none'", csp)
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertEqual(r.headers["x-content-type-options"], "nosniff")
        # Pas « no-referrer » : le navigateur enverrait « Origin: null » sur les POST.
        self.assertEqual(r.headers["referrer-policy"], "same-origin")
        self.assertEqual(r.headers["cache-control"], "no-store")
        self.assertNotIn("server", {k.lower() for k in r.headers})
        cookie = r.headers["set-cookie"].lower()
        self.assertIn("httponly", cookie)
        self.assertIn("samesite=strict", cookie)

    def test_https_derriere_caddy(self):
        # En HTTP (tunnel SSH) : cookie sans Secure, pas de HSTS.
        r = self.client.get("/")
        self.assertNotIn("secure", r.headers["set-cookie"].lower())
        self.assertNotIn("strict-transport-security", r.headers)
        # En HTTPS (schéma donné par Caddy via X-Forwarded-Proto) : Secure et HSTS.
        client = TestClient(creer_app(self.chemins), base_url="https://asgor.exemple.fr")
        r = client.get("/")
        self.assertIn("secure", r.headers["set-cookie"].lower())
        self.assertEqual(r.headers["strict-transport-security"], "max-age=31536000")
        # Formulaire en HTTPS : l'origine https://asgor.exemple.fr correspond à l'hôte.
        jeton = client.cookies.get("csrf")
        r = client.post("/analyses", data={"url": "https://github.com/a/b", "csrf": jeton},
                        headers={"Origin": "https://asgor.exemple.fr"}, follow_redirects=False)
        self.assertEqual(r.status_code, 303)

    def test_aucune_ressource_externe_ni_style_en_ligne(self):
        html = self.client.get("/").text
        self.assertNotIn("<script", html)
        self.assertIsNone(re.search(r"\sstyle\s*=", html))
        self.assertNotIn("googleapis", html)
        self.assertNotIn("http://", html.replace('http://www.w3.org', ''))

    def test_gabarits_sans_safe_ni_style(self):
        for nom in os.listdir(GABARITS):
            with open(os.path.join(GABARITS, nom), encoding="utf-8") as f:
                texte = f.read()
            with self.subTest(gabarit=nom):
                self.assertNotIn("|safe", texte.replace(" ", ""))
                self.assertNotIn("autoescape false", texte)
                self.assertIsNone(re.search(r"\sstyle\s*=", texte))
                self.assertNotIn("<script", texte)

    def test_documentation_automatique_desactivee(self):
        for chemin in ("/docs", "/redoc", "/openapi.json"):
            self.assertEqual(self.client.get(chemin).status_code, 404, chemin)

    def test_fichiers_statiques(self):
        r = self.client.get("/static/style.css")
        self.assertEqual(r.status_code, 200)
        self.assertIn(".largeur-100", r.text)
        r = self.client.get("/static/polices/ibm-plex-sans-latin-400-normal.woff2")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.headers["x-content-type-options"], "nosniff")

    # --------------------------------------------------------------- accueil
    def test_accueil(self):
        self._terminee(1)
        self._terminee(2, masquee=True, nom="cache")
        html = self.client.get("/").text
        self.assertIn("github.com/exemple/depot", html)
        self.assertNotIn("exemple/cache", html)              # analyse masquée
        self.assertIn("Opengrep", html)                       # outils.json
        self.assertIn('name="historique" value="oui" checked', html)
        self.assertNotIn("ne donne plus signe de vie", html)

    def test_bandeau_worker_arrete(self):
        base.signe_de_vie(self.cnx, base.maintenant() - datetime.timedelta(minutes=5))
        self.assertIn("ne donne plus signe de vie", self.client.get("/").text)

    # ------------------------------------------------------ nouvelle analyse
    def test_nouvelle_analyse(self):
        r = self._poster("/analyses", {"url": "https://github.com/Organisation/monDepot",
                                       "historique": "oui"})
        self.assertEqual(r.status_code, 303)
        identifiant = r.headers["location"].rsplit("/", 1)[-1]
        self.assertRegex(identifiant, r"^[0-9a-f]{32}$")
        demandes, _, _ = file.relever(self.chemins.file)
        d, = demandes
        self.assertEqual((d.id, d.nom, d.historique_complet, d.masquee, d.forcee),
                         (identifiant, "monDepot", True, False, False))

    def test_case_historique_decochee(self):
        self._poster("/analyses", {"url": "https://github.com/a/b"})
        d, = file.relever(self.chemins.file)[0]
        self.assertFalse(d.historique_complet)

    def test_page_en_file_avant_le_worker(self):
        r = self._poster("/analyses", {"url": "https://github.com/a/b", "historique": "oui"})
        page = self.client.get(r.headers["location"])
        self.assertEqual(page.status_code, 200)
        self.assertIn("En attente du service d'analyse", page.text)
        self.assertIn('http-equiv="refresh" content="3"', page.text)

    def test_url_refusee_reaffichee_et_echappee(self):
        r = self._poster("/analyses", {"url": f"https://gitlab.com/{PIEGE}"})
        self.assertEqual(r.status_code, 400)
        self.assertIn("Adresse refusée", r.text)
        self.assertNotIn("<script>alert", r.text)
        self.assertIn("&lt;script&gt;", r.text)
        self.assertEqual(os.listdir(self.chemins.file), [])

    def test_csrf_absent_ou_faux(self):
        r = self._poster("/analyses", {"url": "https://github.com/a/b"}, jeton=False)
        self.assertEqual(r.status_code, 403)
        r = self._poster("/analyses", {"url": "https://github.com/a/b", "csrf": "x" * 40},
                         jeton=False)
        self.assertEqual(r.status_code, 403)
        self.assertEqual(os.listdir(self.chemins.file), [])

    def test_autre_origine_refusee(self):
        r = self._poster("/analyses", {"url": "https://github.com/a/b"},
                         origine="https://site-pirate.example")
        self.assertEqual(r.status_code, 403)
        r = self._poster("/analyses", {"url": "https://github.com/a/b"}, origine="null")
        self.assertEqual(r.status_code, 403)
        self.assertEqual(os.listdir(self.chemins.file), [])

    def test_corps_trop_gros_et_mauvais_type(self):
        r = self._poster("/analyses", {"url": "https://github.com/a/b", "x": "y" * 5000})
        self.assertEqual(r.status_code, 413)
        r = self.client.post("/analyses", json={"url": "https://github.com/a/b"},
                             headers={"Origin": f"http://{HOTE}"})
        self.assertEqual(r.status_code, 415)

    def test_file_pleine(self):
        for _ in range(file.NB_MAX_EN_FILE):
            file.deposer_demande("https://github.com/a/b", dossier=self.chemins.file)
        r = self._poster("/analyses", {"url": "https://github.com/a/b"})
        self.assertEqual(r.status_code, 503)
        self.assertIn("Trop d&#39;analyses", r.text)  # apostrophe échappée

    # ------------------------------------------------------------- analyses
    def test_identifiant_invalide_ou_inconnu(self):
        for chemin in ("/analyses/../../etc/passwd", "/analyses/abc", "/analyses/" + "A" * 32,
                       "/analyses/" + "0" * 32, "/analyses/" + "0" * 32 + "/rapport.json"):
            with self.subTest(chemin=chemin):
                r = self.client.get(chemin)
                self.assertEqual(r.status_code, 404)

    def test_avancement(self):
        d = demande(1)
        base.creer_analyse(self.cnx, d)
        base.demarrer(self.cnx, d.id, "0.2")
        base.groupe_termine(self.cnx, d.id, "clonage", avancement.TERMINEE, PIEGE, 3.0)
        base.groupe_commence(self.cnx, d.id, "langages")
        html = self.client.get(f"/analyses/{d.id}").text
        self.assertIn("Analyse en cours", html)
        self.assertIn("Étape 2 sur 9", html)
        self.assertIn("largeur-11", html)                     # 1 groupe sur 9
        self.assertIn("Clonage du dépôt", html)
        self.assertNotIn("<script>alert", html)
        self.assertIn('content="3"', html)
        self.assertIn("Annuler l'analyse", html)

    def test_position_en_attente(self):
        base.creer_analyse(self.cnx, demande(1))
        base.demarrer(self.cnx, demande(1).id, "0.2")
        base.creer_analyse(self.cnx, demande(2))
        self.assertIn("1 analyse avant la vôtre", self.client.get(f"/analyses/{demande(2).id}").text)

    def test_rapport_et_echappement(self):
        r = rapport(nb_problemes=1)
        r["problemes"][0].update(titre=PIEGE, fichier=f"src/{PIEGE}.php", explication=PIEGE,
                                 references=["javascript:alert(1)", "https://exemple.org/avis"])
        r["avertissements"] = [PIEGE]
        identifiant = self._terminee(1, r)
        html = self.client.get(f"/analyses/{identifiant}").text
        self.assertIn("Note globale", html)
        self.assertIn("note-c", html)
        self.assertIn("injection SQL détectée", html)
        self.assertIn("Qualité du code", html)
        self.assertIn("sans effet sur la note", html)
        self.assertNotIn("<script>alert", html)
        self.assertNotIn('"onmouseover="', html)
        self.assertNotIn("javascript:", html)
        self.assertIn('href="https://exemple.org/avis" target="_blank" rel="noopener noreferrer nofollow"', html)
        self.assertIsNone(re.search(r"\sstyle\s*=", html))

    def test_lien_voir_sur_github(self):
        r = rapport(nb_problemes=0)
        r["depot"].update(proprietaire="exemple", nom="depot")
        r["problemes"] = [
            {"id": "1" * 16, "domaine": "secrets", "gravite": "Élevée", "titre": "Secret",
             "fichier": "test/données vecteurs.js", "ligne": 7, "commit": "b" * 40,
             "outils": ["Gitleaks"], "secret_masque": "abcd****", "occurrences": 905, "a_verifier": True},
            {"id": "2" * 16, "domaine": "secrets", "gravite": "Critique", "titre": "Secret",
             "fichier": "config/prod.php", "ligne": 3, "outils": ["Gitleaks"], "secret_masque": "ghp_****"},
            {"id": "3" * 16, "domaine": "secrets", "gravite": "Critique", "titre": "Piège",
             "fichier": "../../etc/passwd", "ligne": 1, "outils": ["Gitleaks"], "secret_masque": "****"},
        ]
        html = self.client.get(f"/analyses/{self._terminee(1, r)}").text
        self.assertIn('href="https://github.com/exemple/depot/blob/' + "b" * 40
                      + '/test/donn%C3%A9es%20vecteurs.js#L7"', html)
        # sans commit propre au secret : commit de l'analyse
        self.assertIn('href="https://github.com/exemple/depot/blob/' + "a" * 40 + '/config/prod.php#L3" target="_blank"', html)  # nouvel onglet
        self.assertNotIn("etc/passwd#L1", html)
        self.assertIn("905 occurrences dans ce fichier", html)
        self.assertIn("Secret à vérifier", html)

    def test_lien_github_refuse_les_valeurs_douteuses(self):
        from asgor_web.securite import lien_github
        depot = {"proprietaire": "exemple", "nom": "depot", "commit": "a" * 40}
        bon = {"fichier": "src/a.php", "ligne": 2}
        self.assertEqual(lien_github(depot, bon),
                         "https://github.com/exemple/depot/blob/" + "a" * 40 + "/src/a.php#L2")
        for d, p in (({**depot, "proprietaire": "ex/../x"}, bon), ({**depot, "nom": ".."}, bon),
                     ({**depot, "commit": "main"}, bon), (depot, {"fichier": "/etc/passwd"}),
                     (depot, {"fichier": "a/./b"}), (depot, {"fichier": "a\nb"}), (depot, {"fichier": ""}),
                     (depot, {"fichier": "a.php", "commit": "javascript:alert(1)"})):
            self.assertIsNone(lien_github(d, p), (d, p))
        self.assertEqual(lien_github(depot, {"fichier": "a#b?.php"}),
                         "https://github.com/exemple/depot/blob/" + "a" * 40 + "/a%23b%3F.php")

    def _marquages(self):
        sortie = []
        for nom in sorted(os.listdir(self.chemins.file)):
            if nom.endswith(".marquage"):
                with open(os.path.join(self.chemins.file, nom), encoding="utf-8") as f:
                    sortie.append(json.load(f))
        return sortie

    def test_ecarter_selection_et_groupe(self):
        identifiant = self._terminee(1, rapport(nb_problemes=3))
        html = self.client.get(f"/analyses/{identifiant}").text
        self.assertIn('name="ids" value="' + f"{0:016x}" + '"', html)
        self.assertIn("Écarter tout ce groupe", html)      # 3 résultats dans src/a.php
        cle = re.search(r'name="groupe" value="([0-9a-f]{16})"', html).group(1)
        # sélection
        r = self.client.post(f"/analyses/{identifiant}/ecarter",
                             data={"csrf": self._jeton(), "motif": "faux positif connu",
                                   "ids": [f"{0:016x}", f"{2:016x}"]},
                             headers={"Origin": f"http://{HOTE}"}, follow_redirects=False)
        self.assertEqual((r.status_code, r.headers["location"]), (303, f"/analyses/{identifiant}?transmis=1"))
        m, = self._marquages()
        self.assertEqual((m["action"], m["empreintes"], m["motif"], m["analyse"]),
                         ("ecarter", [f"{0:016x}", f"{2:016x}"], "faux positif connu", identifiant))
        self.assertEqual(m["ip"], "")          # « testclient » n'est pas une adresse IP
        self.assertIn("Demande transmise", self.client.get(f"/analyses/{identifiant}?transmis=1").text)
        # groupe : tous les résultats du fichier
        self._poster(f"/analyses/{identifiant}/ecarter", {"motif": "dossier de test", "groupe": cle})
        groupe, = [m for m in self._marquages() if m["motif"] == "dossier de test"]
        self.assertEqual(sorted(groupe["empreintes"]), [f"{i:016x}" for i in range(3)])

    def test_ecarter_refus(self):
        identifiant = self._terminee(1, rapport(nb_problemes=2))
        for donnees in ({"motif": "", "ids": f"{0:016x}"}, {"motif": "ok ok"},
                        {"motif": "ok ok", "ids": "pas-un-id"}, {"motif": "ok ok", "groupe": "f" * 16}):
            r = self._poster(f"/analyses/{identifiant}/ecarter", donnees)
            self.assertEqual(r.status_code, 400, donnees)
        trop = self.client.post(f"/analyses/{identifiant}/ecarter",
                                data={"csrf": self._jeton(), "motif": "ok ok",
                                      "ids": [f"{i:016x}" for i in range(501)]},
                                headers={"Origin": f"http://{HOTE}"}, follow_redirects=False)
        self.assertIn(trop.status_code, (400, 413))
        r = self._poster(f"/analyses/{identifiant}/ecarter", {"motif": "ok ok", "ids": f"{0:016x}"}, jeton=False)
        self.assertEqual(r.status_code, 403)
        self.assertEqual(self._marquages(), [])

    def test_resultats_ecartes_affiches(self):
        r = rapport(nb_problemes=2)
        r["problemes"][1]["ecarte"] = True
        identifiant = self._terminee(1, r)
        base.marquer(self.cnx, "ecarter", "exemple", "depot", [f"{1:016x}"], PIEGE, "10.1.2.3", identifiant)
        html = self.client.get(f"/analyses/{identifiant}").text
        self.assertIn("Résultats écartés (1)", html)
        self.assertIn("10.1.2.3", html)
        self.assertNotIn("<script>alert", html)
        self.assertIn('action="/analyses/' + identifiant + '/retablir"', html)
        principal = html.split("Résultats écartés")[0]
        self.assertNotIn("Faille 1<", principal)            # absent de la liste principale
        self._poster(f"/analyses/{identifiant}/retablir", {"ids": f"{1:016x}", "motif": ""})
        self.assertEqual(self._marquages()[0]["action"], "retablir")

    def test_page_aide(self):
        r = self.client.get("/aide")
        self.assertEqual(r.status_code, 200)
        html = r.text
        self.assertIn('href="/aide"', html)                      # lien dans la barre du haut
        self.assertRegex(html, r'href="/static/style\.css\?v=[0-9a-f]{12}"')   # cache renouvelé
        self.assertIn("Designed by BM", html)                    # pied de page
        self.assertIn("Écarter un faux positif", html)
        self.assertIn('id="écarter-un-faux-positif"', html)
        self.assertIn("<table", html)
        self.assertIn("<code>https://github.com/organisation/depot</code>", html)   # pas un lien
        self.assertIsNone(re.search(r"(?<!\*)\*\*(?!\*)", html))   # gras converti (sauf « **** »)
        self.assertIsNone(re.search(r"<script|\sstyle\s*=|javascript:", html))

    def test_convertisseur_du_guide_echappe_tout(self):
        from asgor_web.guide_html import convertir
        corps, sommaire = convertir("# T\n\n## 1. Partie <b>\n\n" + PIEGE + "\n\n"
                                    "- [clic](javascript:alert(1)) et `<i>x</i>`\n"
                                    "| a | <img src=x> |\n|---|---|\n| **g** | https://exemple.org/p |\n\n"
                                    "Adresse : **https://exemple.org/site/**.\n")
        self.assertNotIn("<script>", corps)
        self.assertNotIn("<img", corps)
        self.assertNotIn("<b>", corps)
        self.assertNotIn('href="javascript', corps)
        self.assertIn("<code>&lt;i&gt;x&lt;/i&gt;</code>", corps)
        self.assertIn('<a href="https://exemple.org/p" rel="noopener noreferrer">', corps)
        self.assertIn('<strong><a href="https://exemple.org/site/" rel="noopener noreferrer">', corps)
        self.assertEqual(sommaire, [("partie-b", "1. Partie <b>")])

    def test_convertisseur_liens_internes(self):
        from asgor_web.guide_html import convertir
        corps, _ = convertir("[a](/outils/x.py) [b](//autre.org/x) [c](/a\"onclick=x)")
        self.assertIn('<a href="/outils/x.py" rel="noopener noreferrer">a</a>', corps)
        self.assertNotIn('href="//', corps)               # « // » = autre hôte : refusé
        self.assertIn("[c](/a&quot;onclick=x)", corps)    # guillemet : pas un lien, texte échappé

    def test_corriger_dependances_sur_github(self):
        # Le script est publié dans le dépôt asgor-tools : le site ne le sert plus.
        self.assertEqual(self.client.get("/outils/corriger_dependances.py").status_code, 404)
        self.assertIn('href="https://github.com/brahimmachkouri/asgor-tools"', self.client.get("/aide").text)

    def test_outils_lances_et_non_lances(self):
        identifiant = self._terminee(1, rapport(outils={"Gitleaks": "8.30.1"},
                                                outils_non_lances=["Bandit", "pip-audit"]))
        html = self.client.get(f"/analyses/{identifiant}").text
        self.assertIn("Outils lancés : Gitleaks 8.30.1", html)
        self.assertIn("Non lancés, rien à analyser pour ce dépôt : Bandit, pip-audit.", html)

    def test_nombre_de_problemes_par_domaine(self):
        r = rapport(nb_problemes=3)
        r["note"]["domaines"]["secrets"].update(score=0, lettre="F", problemes=1)
        identifiant = self._terminee(1, r)
        html = self.client.get(f"/analyses/{identifiant}").text
        self.assertIn("· 3 problèmes", html)                 # code
        self.assertIn("· 1 problème<", html)                  # secrets, au singulier
        self.assertIn("· 0 problème<", html)                  # dépendances
        self.assertIn("largeur-0 note-f", html)               # trait rouge minimal (CSS)
        css = self.client.get("/static/style.css").text
        self.assertIn(".barre-domaine-remplie.largeur-0 { width: 6px; background: #b91c1c; }", css)

    def test_plus_de_200_problemes(self):
        identifiant = self._terminee(1, rapport(nb_problemes=250))
        html = self.client.get(f"/analyses/{identifiant}").text
        self.assertIn("Les 200 problèmes les plus graves sont affichés sur 250", html)
        self.assertIn("250 élevées", html)                    # accord du pluriel
        self.assertEqual(html.count('class="carte probleme"'), 200)

    def test_rapport_illisible_sans_trace(self):
        identifiant = self._terminee(1)
        with open(os.path.join(self.chemins.rapports, f"{identifiant}.json"), "w") as f:
            f.write("{pas du json")
        r = self.client.get(f"/analyses/{identifiant}")
        self.assertEqual(r.status_code, 500)
        self.assertNotIn("Traceback", r.text)
        self.assertNotIn("JSONDecodeError", r.text)

    def test_autres_etats(self):
        premiere = self._terminee(1)
        for n in (2, 3, 4):
            base.creer_analyse(self.cnx, demande(n))
        base.marquer_existante(self.cnx, demande(2).id, premiere)
        base.echouer(self.cnx, demande(3).id, f"dépôt trop gros {PIEGE}")
        base.annuler(self.cnx, demande(4).id)
        existante = self.client.get(f"/analyses/{demande(2).id}").text
        self.assertIn("Commit déjà analysé", existante)
        self.assertIn(f'href="/analyses/{premiere}"', existante)
        self.assertIn("Analyser quand même", existante)
        echouee = self.client.get(f"/analyses/{demande(3).id}").text
        self.assertIn("dépôt trop gros", echouee)
        self.assertNotIn("<script>alert", echouee)
        self.assertIn("Réessayer", echouee)
        self.assertIn("Analyse annulée", self.client.get(f"/analyses/{demande(4).id}").text)

    # ------------------------------------------------------ actions et exports
    def test_annuler(self):
        base.creer_analyse(self.cnx, demande(1))
        r = self._poster(f"/analyses/{demande(1).id}/annuler", {})
        self.assertEqual(r.status_code, 303)
        self.assertEqual(file.relever(self.chemins.file)[1], [demande(1).id])
        self.assertEqual(self._poster(f"/analyses/{demande(1).id}/annuler", {"x": "1"},
                                      jeton=False).status_code, 403)
        # Corps vide (sans type de formulaire) : refusé aussi, avant même le jeton.
        self.assertEqual(self._poster(f"/analyses/{demande(1).id}/annuler", {},
                                      jeton=False).status_code, 415)

    def test_relancer(self):
        identifiant = self._terminee(1, historique=False)
        r = self._poster(f"/analyses/{identifiant}/relancer", {})
        self.assertEqual(r.status_code, 303)
        d, = file.relever(self.chemins.file)[0]
        self.assertEqual((d.nom, d.forcee, d.historique_complet), ("depot", True, False))
        self.assertEqual(r.headers["location"], f"/analyses/{d.id}")

    def test_exports(self):
        identifiant = self._terminee(1)
        for extension in ("json", "sarif"):
            r = self.client.get(f"/analyses/{identifiant}/rapport.{extension}")
            self.assertEqual(r.status_code, 200)
            self.assertTrue(r.headers["content-type"].startswith("application/json"))
            self.assertIn("attachment;", r.headers["content-disposition"])
            ligne = base.analyse(self.cnx, identifiant)
            self.assertIn(f'filename="asgor-{ligne["proprietaire"]}-{ligne["nom"]}-{identifiant[:12]}.{extension}"',
                          r.headers["content-disposition"])
            json.loads(r.content)

    def test_sante(self):
        self.assertEqual(self.client.get("/sante").text, "ok")
        base.signe_de_vie(self.cnx, base.maintenant() - datetime.timedelta(minutes=5))
        r = self.client.get("/sante")
        self.assertEqual((r.status_code, r.text), (503, "worker sans signe de vie"))


if __name__ == "__main__":
    unittest.main()
