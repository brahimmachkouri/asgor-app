"""Commande asgor-scan : analyse un dépôt GitHub public et affiche sa note."""

import argparse
import sys

from .avancement import ObservateurTerminal
from .modele import DOMAINES, GRAVITES, NOMS_DOMAINES
from .moteur import Analyse, AnalyseEnCours, AnalyseImpossible
from .url import UrlInvalide, valider_url


def _resume(rapport: dict, chemin: str) -> str:
    note = rapport["note"]
    lignes = ["", f"Note globale : {note['globale']}"]
    for plafonnement in note["plafonnements"]:
        lignes.append(f"  Raison de la note {plafonnement['note_max']} : {plafonnement['raison']}")
    lignes.append("")
    for domaine in DOMAINES:
        d = note["domaines"][domaine]
        incomplet = "  (évaluation incomplète)" if d["evaluation"] != "complète" else ""
        lignes.append(f"  {NOMS_DOMAINES[domaine]:<12} {d['score']:>3}/100  {d['lettre']}"
                      f"  {d['problemes']} problème(s){incomplet}")
    lignes.append("")
    compte = {g: 0 for g in GRAVITES}
    for p in rapport["problemes"]:
        compte[p["gravite"]] += 1
    lignes.append("  Problèmes : " + " · ".join(
        f"{n} {g.lower()}" for g, n in compte.items() if n) if rapport["problemes"]
        else "  Aucun problème trouvé.")
    qualite = rapport.get("qualite")
    if qualite:
        lignes.append(f"  Qualité du code (PHPStan niveau {qualite['niveau']}, sans effet sur la note) : "
                      f"{qualite['nb_erreurs']} erreur(s) dans {qualite['nb_fichiers']} fichier(s)")
    for avertissement in rapport["avertissements"]:
        lignes.append(f"  Avertissement : {avertissement}")
    lignes.append("")
    lignes.append(f"Durée : {rapport['analyse']['duree_s']:.0f} s")
    lignes.append(f"Rapport : {chemin}")
    return "\n".join(lignes)


def main(arguments=None) -> int:
    analyseur = argparse.ArgumentParser(
        prog="asgor-scan",
        description="Analyse la sécurité d'un dépôt GitHub public et affiche une note de A à F.")
    analyseur.add_argument("url", help="https://github.com/<propriétaire>/<dépôt>")
    analyseur.add_argument("--garder-sources", action="store_true",
                           help="ne pas supprimer le clone après l'analyse (pour le débogage)")
    analyseur.add_argument("--sans-historique", action="store_true",
                           help="analyser le dernier commit seulement (note B au maximum)")
    options = analyseur.parse_args(arguments)

    try:
        depot = valider_url(options.url)
    except UrlInvalide as e:
        print(f"URL refusée : {e}", file=sys.stderr)
        return 2

    analyse = Analyse(depot, garder_sources=options.garder_sources,
                      historique_complet=not options.sans_historique,
                      observateur=ObservateurTerminal())
    try:
        rapport = analyse.lancer()
    except AnalyseEnCours as e:
        print(f"Analyse refusée : {e}", file=sys.stderr)
        return 3
    except AnalyseImpossible as e:
        print(f"Analyse impossible : {e}", file=sys.stderr)
        return 1

    print(_resume(rapport, analyse.chemin_rapport))
    print(f"SARIF : {analyse.chemin_sarif}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
