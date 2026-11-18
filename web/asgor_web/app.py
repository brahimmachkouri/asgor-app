"""Application FastAPI d'ASGOR.

Pages : accueil, analyse (avancement, rapport ou message selon l'état),
exports JSON et SARIF, santé. Aucun JavaScript, aucune ressource externe.
"""

import hashlib
import ipaddress
import json
import os
import re
import sqlite3
from dataclasses import dataclass

import jinja2
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException

from asgor_moteur import base, fichiers, file
from asgor_moteur.avancement import CLES
from asgor_moteur.url import UrlInvalide

from . import affichage, guide_html, securite

ICI = os.path.dirname(os.path.abspath(__file__))
_ID = re.compile(r"[0-9a-f]{32}")
NB_MAX_PROBLEMES_AFFICHES = 200
TAILLE_MAX_RAPPORT = 100 * 1024 * 1024


@dataclass(frozen=True)
class Chemins:
    base: str = base.BASE
    file: str = file.FILE
    rapports: str = "/var/lib/asgor/reports"
    outils: str = "/opt/asgor/outils.json"


def creer_app(chemins: Chemins = Chemins()) -> FastAPI:
    """HTTPS : derrière Caddy, la VM reçoit du HTTP. Uvicorn n'accepte les en-têtes
    X-Forwarded-Proto que du proxy déclaré (option --proxy de asgor-web) ; le schéma
    vu ici vaut alors « https », et le cookie CSRF est marqué Secure."""
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, debug=False)
    app.mount("/static", StaticFiles(directory=os.path.join(ICI, "static")), name="static")

    gabarits = jinja2.Environment(
        loader=jinja2.FileSystemLoader(os.path.join(ICI, "templates")),
        # Un champ absent d'un problème (paquet d'un secret…) s'affiche vide.
        autoescape=True,
        trim_blocks=True, lstrip_blocks=True)
    gabarits.filters.update(affichage.FILTRES)
    gabarits.globals.update(lien_sur=securite.lien_sur, lien_github=securite.lien_github, pluriel=affichage.pluriel,
                            STATUTS=affichage.STATUTS, CLASSE_GRAVITE=affichage.CLASSE_GRAVITE)
    # Empreinte de la feuille de style, ajoutée à son adresse (?v=…) : après une mise à
    # jour, le navigateur charge la nouvelle version au lieu de garder l'ancienne en cache.
    with open(os.path.join(ICI, "static", "style.css"), "rb") as f:
        gabarits.globals["VERSION_STYLE"] = hashlib.sha256(f.read()).hexdigest()[:12]

    # ------------------------------------------------------------ utilitaires
    def lecture():
        try:
            return base.ouvrir_lecture(chemins.base)
        except sqlite3.Error:
            return None

    def rendre(requete: Request, nom: str, code: int = 200, rafraichir: int | None = None,
               **contexte) -> HTMLResponse:
        jeton = requete.cookies.get(securite.COOKIE_CSRF)
        nouveau = not securite.jeton_valide(jeton)
        if nouveau:
            jeton = securite.nouveau_jeton()
        html = gabarits.get_template(nom).render(csrf=jeton, rafraichir=rafraichir, **contexte)
        reponse = HTMLResponse(html, status_code=code)
        if nouveau:
            reponse.set_cookie(securite.COOKIE_CSRF, jeton, httponly=True, samesite="strict",
                               secure=requete.url.scheme == "https", path="/")
        return reponse

    def message(requete, titre, texte, code=200, **contexte):
        return rendre(requete, "message.html", code=code, titre=titre, texte=texte, **contexte)

    def identifiant_ou_404(identifiant: str) -> str:
        if not _ID.fullmatch(identifiant):
            raise HTTPException(404)
        return identifiant

    def lire_rapport(identifiant: str, extension: str = "json") -> bytes | None:
        try:
            return fichiers.lire_octets(os.path.join(chemins.rapports, f"{identifiant}.{extension}"),
                                        TAILLE_MAX_RAPPORT)
        except fichiers.LectureRefusee:
            return None

    def outils():
        try:
            donnees = fichiers.lire_json(chemins.outils, 100_000)
        except fichiers.LectureRefusee:
            return {}
        return donnees if isinstance(donnees, dict) else {}

    # ------------------------------------------------------------- en-têtes
    @app.middleware("http")
    async def entetes(requete: Request, suite):
        reponse = await suite(requete)
        for cle, valeur in securite.ENTETES.items():
            reponse.headers.setdefault(cle, valeur)
        if requete.url.scheme == "https":
            reponse.headers.setdefault("Strict-Transport-Security", securite.HSTS)
        if not requete.url.path.startswith("/static/"):
            reponse.headers["Cache-Control"] = "no-store"
        return reponse

    @app.exception_handler(HTTPException)
    async def erreur_http(requete: Request, exc: HTTPException):
        if exc.status_code == 404:
            return message(requete, "Page introuvable",
                           "Cette adresse ne correspond à aucune page ni à aucune analyse.", 404)
        return message(requete, "Requête refusée", "La requête n'a pas pu être traitée.",
                       exc.status_code)

    @app.exception_handler(securite.RequeteRefusee)
    async def requete_refusee(requete: Request, exc: securite.RequeteRefusee):
        return message(requete, "Requête refusée", exc.message, exc.code)

    @app.exception_handler(Exception)
    async def erreur_interne(requete: Request, exc: Exception):
        # Jamais de trace Python dans la page.
        return message(requete, "Erreur", "Une erreur interne est survenue.", 500)

    # ---------------------------------------------------------------- pages
    def accueil(requete: Request, erreur: str = "", url_saisie: str = "",
                historique_coche: bool = True, masquee_cochee: bool = False, code: int = 200):
        cnx = lecture()
        recentes, vivant = [], False
        if cnx is not None:
            try:
                recentes = base.recentes(cnx)
                vivant = base.worker_vivant(cnx)
            except sqlite3.Error:
                pass
            finally:
                cnx.close()
        return rendre(requete, "accueil.html", code=code, recentes=recentes,
                      worker_vivant=vivant, outils=outils(), erreur=erreur,
                      url_saisie=url_saisie, historique_coche=historique_coche,
                      masquee_cochee=masquee_cochee)

    @app.get("/", response_class=HTMLResponse)
    async def page_accueil(requete: Request):
        return accueil(requete)

    @app.post("/analyses")
    async def nouvelle_analyse(requete: Request):
        formulaire = await securite.lire_formulaire(requete)
        securite.verifier_csrf(requete, formulaire)
        url = formulaire.get("url", "").strip()
        historique = formulaire.get("historique") == "oui"
        masquee = formulaire.get("masquee") == "oui"
        try:
            identifiant = file.deposer_demande(url, historique_complet=historique,
                                               masquee=masquee, dossier=chemins.file)
        except UrlInvalide as e:
            return accueil(requete, erreur=f"Adresse refusée : {e}.", url_saisie=url[:300],
                           historique_coche=historique, masquee_cochee=masquee, code=400)
        except file.FilePleine:
            return accueil(requete, erreur="Trop d'analyses sont en attente. Réessayez plus tard.",
                           url_saisie=url[:300], historique_coche=historique,
                           masquee_cochee=masquee, code=503)
        return RedirectResponse(f"/analyses/{identifiant}", status_code=303)

    @app.get("/analyses/{identifiant}", response_class=HTMLResponse)
    async def page_analyse(requete: Request, identifiant: str):
        identifiant = identifiant_ou_404(identifiant)
        cnx = lecture()
        if cnx is None:
            return message(requete, "Service indisponible",
                           "La base des analyses est illisible pour le moment.", 503)
        try:
            ligne = base.analyse(cnx, identifiant)
            if ligne is None:
                if file.demande_en_file(identifiant, chemins.file):
                    return rendre(requete, "avancement.html", rafraichir=3, analyse=None,
                                  identifiant=identifiant, etapes=[], position=None,
                                  ecoule=None, en_file=True, nb_groupes=len(CLES), faits=0)
                raise HTTPException(404)
            etat = ligne["etat"]
            if etat in (base.EN_ATTENTE, base.EN_COURS):
                etapes = base.etapes(cnx, identifiant)
                faits = sum(1 for e in etapes if e["statut"] in ("terminee", "ignoree", "echec"))
                return rendre(requete, "avancement.html", rafraichir=3, analyse=ligne,
                              identifiant=identifiant, etapes=etapes,
                              position=base.position_dans_la_file(cnx, identifiant),
                              ecoule=affichage.ecoule_depuis(ligne["debut"]), en_file=False,
                              nb_groupes=len(etapes) or len(CLES), faits=faits)
            if etat == base.TERMINEE:
                brut = lire_rapport(identifiant)
                if brut is None:
                    return message(requete, "Rapport illisible",
                                   "L'analyse est terminée, mais son rapport est illisible.", 500)
                rapport = json.loads(brut)
                historique = base.historique_depot(cnx, ligne["proprietaire"], ligne["nom"])
                tous = rapport.get("problemes", [])
                problemes = [p for p in tous if not p.get("ecarte")]
                infos = base.ecartes_du_depot(cnx, ligne["proprietaire"], ligne["nom"])
                ecartes = [(p, infos.get(p.get("id"))) for p in tous if p.get("ecarte")]
                return rendre(requete, "rapport.html", analyse=ligne, rapport=rapport,
                              identifiant=identifiant, historique=historique,
                              problemes=problemes[:NB_MAX_PROBLEMES_AFFICHES],
                              nb_problemes=len(problemes),
                              compte=_compter(problemes),
                              groupes=groupes_de(problemes),
                              ecartes=ecartes[:NB_MAX_PROBLEMES_AFFICHES], nb_ecartes=len(ecartes),
                              motif_max=file.MOTIF_MAX,
                              transmis=requete.query_params.get("transmis") == "1")
            if etat == base.EXISTANTE:
                return message(requete, "Commit déjà analysé",
                               "Ce commit a été analysé il y a moins d'une heure.",
                               analyse=ligne, renvoi=ligne["renvoi_vers"], forcer=True)
            if etat == base.ECHOUEE:
                return message(requete, "Analyse impossible",
                               ligne["message"] or "L'analyse a échoué.", analyse=ligne,
                               relancer=True)
            if etat == base.ANNULEE:
                return message(requete, "Analyse annulée", "Cette analyse a été annulée.",
                               analyse=ligne, relancer=True)
            raise HTTPException(404)
        finally:
            cnx.close()

    @app.post("/analyses/{identifiant}/annuler")
    async def annuler(requete: Request, identifiant: str):
        identifiant = identifiant_ou_404(identifiant)
        formulaire = await securite.lire_formulaire(requete)
        securite.verifier_csrf(requete, formulaire)
        file.deposer_annulation(identifiant, chemins.file)
        return RedirectResponse(f"/analyses/{identifiant}", status_code=303)

    @app.post("/analyses/{identifiant}/relancer")
    async def relancer(requete: Request, identifiant: str):
        identifiant = identifiant_ou_404(identifiant)
        formulaire = await securite.lire_formulaire(requete)
        securite.verifier_csrf(requete, formulaire)
        cnx = lecture()
        if cnx is None:
            raise HTTPException(503)
        try:
            ligne = base.analyse(cnx, identifiant)
        finally:
            cnx.close()
        if ligne is None:
            raise HTTPException(404)
        try:
            nouvel = file.deposer_demande(
                f"https://github.com/{ligne['proprietaire']}/{ligne['nom']}",
                historique_complet=bool(ligne["historique_complet"]),
                masquee=bool(ligne["masquee"]), forcee=True, dossier=chemins.file)
        except file.FilePleine:
            return message(requete, "File pleine",
                           "Trop d'analyses sont en attente. Réessayez plus tard.", 503)
        return RedirectResponse(f"/analyses/{nouvel}", status_code=303)

    async def marquage(requete: Request, identifiant: str, action: str):
        """Écarter ou rétablir des résultats (BAREME.md § 6 c) : dépôt dans la file."""
        identifiant = identifiant_ou_404(identifiant)
        formulaire = await securite.lire_formulaire(
            requete, taille_max=securite.TAILLE_MAX_CORPS_MARQUAGE,
            nb_champs_max=file.NB_MAX_EMPREINTES + 5, multiples=("ids",))
        securite.verifier_csrf(requete, formulaire)
        empreintes = formulaire.get("ids", [])
        groupe = formulaire.get("groupe", "")
        if groupe and action == file.ECARTER:
            brut = lire_rapport(identifiant)
            if brut is None:
                raise HTTPException(404)
            actifs = [p for p in json.loads(brut).get("problemes", []) if not p.get("ecarte")]
            trouve = next((g for g in groupes_de(actifs, limite=None) if g["cle"] == groupe), None)
            if trouve is None:
                return message(requete, "Demande refusée", "Ce groupe de résultats n'existe plus.", 400)
            empreintes = trouve["ids"]
        try:
            file.deposer_marquage(identifiant, action, empreintes, formulaire.get("motif", ""),
                                  adresse_client(requete), dossier=chemins.file)
        except file.MarquageInvalide as e:
            return message(requete, "Demande refusée", f"{e}.", 400)
        except file.FilePleine:
            return message(requete, "File pleine", "Trop de demandes en attente. Réessayez plus tard.", 503)
        return RedirectResponse(f"/analyses/{identifiant}?transmis=1", status_code=303)

    @app.post("/analyses/{identifiant}/ecarter")
    async def ecarter(requete: Request, identifiant: str):
        return await marquage(requete, identifiant, file.ECARTER)

    @app.post("/analyses/{identifiant}/retablir")
    async def retablir(requete: Request, identifiant: str):
        return await marquage(requete, identifiant, file.RETABLIR)

    def export(identifiant: str, extension: str, type_mime: str):
        identifiant = identifiant_ou_404(identifiant)
        brut = lire_rapport(identifiant, extension)
        if brut is None:
            raise HTTPException(404)
        return Response(brut, media_type=type_mime, headers={
            "Content-Disposition": f'attachment; filename="{nom_export(identifiant, extension)}"'})

    def nom_export(identifiant: str, extension: str) -> str:
        """asgor-<propriétaire>-<dépôt>-<id>.<ext> : on sait à quel dépôt correspond le fichier."""
        depot = ""
        cnx = lecture()
        if cnx is not None:
            try:
                ligne = base.analyse(cnx, identifiant)
            finally:
                cnx.close()
            if ligne is not None:
                # Noms déjà validés à la saisie de l'URL ; filtrés encore ici pour l'en-tête HTTP.
                depot = re.sub(r"[^A-Za-z0-9._-]", "_", f"{ligne['proprietaire']}-{ligne['nom']}") + "-"
        return f"asgor-{depot}{identifiant[:12]}.{extension}"

    @app.get("/analyses/{identifiant}/rapport.json")
    async def export_json(identifiant: str):
        return export(identifiant, "json", "application/json")

    @app.get("/analyses/{identifiant}/rapport.sarif")
    async def export_sarif(identifiant: str):
        return export(identifiant, "sarif", "application/json")

    aide_html, aide_sommaire = guide_html.charger()      # lu une fois au démarrage

    @app.get("/aide", response_class=HTMLResponse)
    async def aide(requete: Request):
        return rendre(requete, "aide.html", contenu=aide_html, sommaire=aide_sommaire)

    @app.get("/sante", response_class=PlainTextResponse)
    async def sante():
        cnx = lecture()
        if cnx is None:
            return PlainTextResponse("base illisible", status_code=503)
        try:
            vivant = base.worker_vivant(cnx)
        except sqlite3.Error:
            return PlainTextResponse("base illisible", status_code=503)
        finally:
            cnx.close()
        if not vivant:
            return PlainTextResponse("worker sans signe de vie", status_code=503)
        return PlainTextResponse("ok")

    return app


def adresse_client(requete) -> str:
    """Adresse IP du client (donnée par Caddy, option --proxy) ; vide si ce n'en est pas une."""
    hote = requete.client.host if requete.client else ""
    try:
        return str(ipaddress.ip_address(hote))
    except ValueError:
        return ""


def groupes_de(problemes, limite: int | None = 15) -> list:
    """Regroupements de 2 résultats ou plus : même fichier, ou même règle (BAREME.md § 6 c).
    La clé est une empreinte du regroupement : le formulaire ne transmet pas de chemin."""
    par = {}
    for p in problemes:
        pid = p.get("id")
        if not isinstance(pid, str):
            continue
        for sorte, valeur in (("fichier", p.get("fichier")), ("regle", p.get("regle"))):
            if isinstance(valeur, str) and valeur:
                par.setdefault((sorte, valeur), []).append(pid)
    groupes = []
    for (sorte, valeur), ids in par.items():
        ids = list(dict.fromkeys(ids))
        if len(ids) < 2:
            continue
        cle = hashlib.sha256(f"{sorte}\x1f{valeur}".encode("utf-8", "replace")).hexdigest()[:16]
        groupes.append({"cle": cle, "sorte": sorte, "valeur": valeur, "ids": ids, "nombre": len(ids)})
    groupes.sort(key=lambda g: (-g["nombre"], g["sorte"], g["valeur"]))
    return groupes if limite is None else groupes[:limite]


def _compter(problemes) -> list:
    compte = {g: 0 for g in affichage.GRAVITES}
    for p in problemes:
        if p.get("gravite") in compte:
            compte[p["gravite"]] += 1
    # « 2 critiques · 72 élevées · 1 moyenne » (accord du pluriel)
    return [f"{n} {g.lower()}{'s' if n > 1 else ''}" for g, n in compte.items() if n]
