"""Export SARIF 2.1.0 d'un rapport ASGOR.

Fonction pure : rapport (dict, format 2) -> document SARIF (dict).

Choix :
- un seul « run » au nom d'ASGOR : les doublons entre outils sont déjà
  fusionnés ; chaque résultat garde la liste des outils qui l'ont trouvé ;
- la rubrique « Qualité du code » (PHPStan) n'est pas dans les résultats :
  un lecteur de SARIF (GitHub par exemple) l'afficherait comme des alertes de
  sécurité. Seul son résumé est dans les propriétés du run ;
- les secrets restent masqués : le rapport ne contient jamais la valeur en clair.
"""

import datetime
import urllib.parse

VERSION_SARIF = "2.1.0"
SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

# Gravité ASGOR -> niveau SARIF
_NIVEAUX = {
    "Critique": "error",
    "Élevée": "error",
    "Moyenne": "warning",
    "Faible": "note",
    "Information": "note",
}
# « security-severity » : convention de GitHub (nombre de 0 à 10, en texte)
_SEVERITE = {
    "Critique": "9.5",
    "Élevée": "8.0",
    "Moyenne": "5.5",
    "Faible": "2.0",
    "Information": "0.0",
}
_RANG = {g: i for i, g in enumerate(("Critique", "Élevée", "Moyenne", "Faible", "Information"))}

# Champs d'un problème recopiés tels quels dans les propriétés du résultat
_PROPRIETES = ("domaine", "gravite", "outils", "categorie", "flux", "paquet", "version",
               "version_corrigee", "identifiants", "commit", "secret_masque", "occurrences",
               "references")


def _uri(chemin: str) -> str:
    """Chemin relatif du dépôt -> référence d'URI (espaces et accents encodés)."""
    return urllib.parse.quote(chemin.lstrip("/"), safe="/")


def _identifiant_regle(probleme: dict) -> str:
    regle = probleme.get("regle") or probleme.get("categorie") or "asgor"
    return f"{probleme.get('domaine', 'inconnu')}/{regle}"


def _message(probleme: dict) -> str:
    morceaux = [probleme.get("titre", "")]
    if probleme.get("explication"):
        morceaux.append(probleme["explication"])
    if probleme.get("version_corrigee"):
        morceaux.append(f"Version corrigée : {probleme['version_corrigee']}.")
    if probleme.get("correction"):
        morceaux.append(f"À faire : {probleme['correction']}")
    return " ".join(m.strip() for m in morceaux if m and m.strip()) or "Problème détecté"


def _resultat(probleme: dict, index_regle: int) -> dict:
    resultat = {
        "ruleId": _identifiant_regle(probleme),
        "ruleIndex": index_regle,
        "level": _NIVEAUX.get(probleme.get("gravite"), "warning"),
        "message": {"text": _message(probleme)},
        "partialFingerprints": {"asgor/v1": probleme.get("id", "")},
        "properties": {k: probleme[k] for k in _PROPRIETES if probleme.get(k) not in (None, "", [])},
    }
    if probleme.get("ecarte"):
        # Écarté par l'équipe comme faux positif (BAREME.md § 6 c)
        resultat["suppressions"] = [{"kind": "external", "status": "accepted"}]
    fichier = probleme.get("fichier")
    if fichier:
        emplacement = {"artifactLocation": {"uri": _uri(fichier), "uriBaseId": "SRCROOT"}}
        ligne = probleme.get("ligne")
        if isinstance(ligne, int) and ligne >= 1:
            emplacement["region"] = {"startLine": ligne}
        resultat["locations"] = [{"physicalLocation": emplacement}]
    return resultat


def vers_sarif(rapport: dict) -> dict:
    analyse = rapport.get("analyse", {})
    depot = rapport.get("depot", {})
    note = rapport.get("note", {})
    problemes = rapport.get("problemes", [])

    # Une règle par identifiant ; sa gravité est la plus haute vue parmi ses résultats.
    regles, index = [], {}
    for p in problemes:
        cle = _identifiant_regle(p)
        if cle not in index:
            index[cle] = len(regles)
            regles.append({
                "id": cle,
                "name": cle.replace("/", "_").replace(".", "_"),
                "shortDescription": {"text": p.get("titre", cle)},
                "properties": {"security-severity": _SEVERITE.get(p.get("gravite"), "5.5"),
                               "tags": ["security", p.get("domaine", "")],
                               "_rang": _RANG.get(p.get("gravite"), 2)},
            })
        else:
            regle = regles[index[cle]]
            rang = _RANG.get(p.get("gravite"), 2)
            if rang < regle["properties"]["_rang"]:
                regle["properties"]["_rang"] = rang
                regle["properties"]["security-severity"] = _SEVERITE.get(p.get("gravite"), "5.5")
    for regle in regles:
        del regle["properties"]["_rang"]

    run = {
        "tool": {"driver": {
            "name": "ASGOR",
            "version": str(analyse.get("version_moteur", "")),
            "rules": regles,
        }},
        "results": [_resultat(p, index[_identifiant_regle(p)]) for p in problemes],
        "invocations": [{
            "executionSuccessful": True,
            "startTimeUtc": _utc(analyse.get("debut")),
            "endTimeUtc": _utc(analyse.get("fin")),
        }],
        "properties": {
            "note_globale": note.get("globale"),
            "raisons": [p.get("raison") for p in note.get("plafonnements", [])],
            "scores": {d: v.get("score") for d, v in note.get("domaines", {}).items()},
            "historique_complet": analyse.get("historique_complet"),
            "avertissements": rapport.get("avertissements", []),
            "outils": rapport.get("outils", {}),
        },
    }
    # Supprime les dates absentes (champ facultatif en SARIF)
    run["invocations"][0] = {k: v for k, v in run["invocations"][0].items() if v is not None}

    url = depot.get("url")
    commit = depot.get("commit")
    if url:
        provenance = {"repositoryUri": url}
        if commit:
            provenance["revisionId"] = commit
        if depot.get("branche"):
            provenance["branch"] = depot["branche"]
        run["versionControlProvenance"] = [provenance]
        if commit:
            run["originalUriBaseIds"] = {"SRCROOT": {"uri": f"{url}/blob/{commit}/"}}

    qualite = rapport.get("qualite")
    if qualite:
        run["properties"]["qualite"] = {
            "outil": qualite.get("outil"),
            "niveau": qualite.get("niveau"),
            "nb_erreurs": qualite.get("nb_erreurs"),
            "nb_fichiers": qualite.get("nb_fichiers"),
            "effet_sur_la_note": "aucun",
        }

    return {"$schema": SCHEMA, "version": VERSION_SARIF, "runs": [run]}


def _utc(date_iso) -> str | None:
    """« 2026-11-15T15:32:10+01:00 » -> « 2026-11-15T14:32:10Z »."""
    if not isinstance(date_iso, str):
        return None
    try:
        d = datetime.datetime.fromisoformat(date_iso)
    except ValueError:
        return None
    if d.tzinfo is None:
        return None
    return d.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
