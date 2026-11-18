#!/usr/bin/env python3
"""Recalcule les scores de rapports ASGOR avec d'autres barèmes, sans relancer de scan.

Sert à étalonner le barème (BAREME.md § 3) et, plus tard, à mesurer l'effet d'un
changement de barème sur tous les rapports existants.

    python3 simuler_bareme.py rapports/*.json
    python3 simuler_bareme.py rapports/*.json --bareme candidats.json

Ce qui change avec le barème : le score de 0 à 100 de chaque domaine et sa lettre.
Ce qui ne change pas : les plafonnements (secret détecté -> F, faille critique -> F,
injection détectée par l'analyse de flux -> C…). Ils ne dépendent pas des points :
l'outil les reprend tels qu'ils sont enregistrés dans chaque rapport.

Format d'un fichier de barèmes (liste JSON) :

    [{"nom": "exemple",
      "poids": {"Critique": 50, "Élevée": 25, "Moyenne": 8, "Faible": 2},
      "degressivite": 1.0,          # 1 = chaque problème compte autant ; 0.8 = le k-ième
                                    #     problème d'une gravité compte poids × 0,8^(k-1)
      "plafond_par_gravite": {"Faible": 10},   # points retirés au plus, par gravité
      "dependance_une_fois": false, # true = une dépendance vulnérable compte une fois
                                    #     (sa gravité la plus haute), quel que soit le
                                    #     nombre d'avis
      "seuils": {"A": 90, "B": 75, "C": 60, "D": 45, "E": 30}}]

Bibliothèque standard uniquement. Ne lance aucun outil, ne modifie aucun rapport.
"""

import argparse
import json
import math
import os
import sys
from dataclasses import dataclass, field

GRAVITES = ("Critique", "Élevée", "Moyenne", "Faible")
DOMAINES = ("secrets", "dependances", "code")
LETTRES = ("A", "B", "C", "D", "E", "F")


@dataclass
class Bareme:
    nom: str
    poids: dict
    degressivite: float = 1.0
    plafond_par_gravite: dict = field(default_factory=dict)
    dependance_une_fois: bool = False
    seuils: dict = field(default_factory=lambda: {"A": 90, "B": 75, "C": 60, "D": 45, "E": 30})
    # « doublement » (barème version 2) : poids = équivalents en problèmes élevés,
    # chaque doublement du total retire points_par_doublement points.
    type: str = "points"
    points_par_doublement: float = 15

    def valider(self) -> None:
        if self.type not in ("points", "doublement"):
            raise ValueError(f"{self.nom} : type « points » ou « doublement » attendu")
        if not self.nom or not isinstance(self.nom, str):
            raise ValueError("chaque barème doit avoir un nom")
        for g in GRAVITES:
            if not isinstance(self.poids.get(g), (int, float)) or self.poids[g] < 0:
                raise ValueError(f"{self.nom} : poids manquant ou négatif pour « {g} »")
        if not 0 < self.degressivite <= 1:
            raise ValueError(f"{self.nom} : la dégressivité doit être entre 0 (exclu) et 1")
        valeurs = [self.seuils.get(l) for l in LETTRES[:-1]]
        if any(not isinstance(v, (int, float)) for v in valeurs) or valeurs != sorted(valeurs, reverse=True):
            raise ValueError(f"{self.nom} : seuils A > B > C > D > E attendus")


# Barème version 1, remplacé par la version 2.
VERSION_1 = Bareme(
    nom="v1",
    poids={"Critique": 50, "Élevée": 25, "Moyenne": 8, "Faible": 2},
    plafond_par_gravite={"Faible": 10},
)
# Barème version 2 (BAREME.md § 3), en service.
VERSION_2 = Bareme(
    nom="v2",
    type="doublement",
    poids={"Critique": 4, "Élevée": 1, "Moyenne": 0.3, "Faible": 0.05},
    dependance_une_fois=True,
)
ACTUEL = VERSION_2


def lire_baremes(chemin: str) -> list:
    with open(chemin, encoding="utf-8") as f:
        donnees = json.load(f)
    if not isinstance(donnees, list):
        raise ValueError("le fichier de barèmes doit contenir une liste")
    baremes = []
    for d in donnees:
        inconnus = set(d) - {"nom", "poids", "degressivite", "plafond_par_gravite",
                             "dependance_une_fois", "seuils", "type", "points_par_doublement"}
        if inconnus:
            raise ValueError(f"clés inconnues dans un barème : {sorted(inconnus)}")
        b = Bareme(**d)
        b.valider()
        baremes.append(b)
    return baremes


# ------------------------------------------------------------------ calcul

def problemes_comptes(problemes: list, domaine: str, bareme: Bareme) -> list:
    """Gravités des problèmes d'un domaine, après regroupement éventuel des dépendances."""
    du_domaine = [p for p in problemes if p.get("domaine") == domaine and p.get("gravite") in GRAVITES]
    if domaine != "dependances" or not bareme.dependance_une_fois:
        return [p["gravite"] for p in du_domaine]
    pire, sans_paquet = {}, []
    for p in du_domaine:
        if not p.get("paquet"):
            sans_paquet.append(p["gravite"])
            continue
        cle = (p["paquet"].lower(), p.get("fichier"))
        g = p["gravite"]
        if cle not in pire or GRAVITES.index(g) < GRAVITES.index(pire[cle]):
            pire[cle] = g
    return sans_paquet + list(pire.values())


def score(gravites: list, bareme: Bareme) -> int:
    if bareme.type == "doublement":
        total = sum(bareme.poids[g] for g in gravites)
        return max(0, int(round(100 - bareme.points_par_doublement * math.log2(1 + total))))
    retrait = 0.0
    for g in GRAVITES:
        n = gravites.count(g)
        if not n:
            continue
        r = bareme.degressivite
        points = bareme.poids[g] * (n if r == 1 else (1 - r ** n) / (1 - r))
        plafond = bareme.plafond_par_gravite.get(g)
        if plafond is not None:
            points = min(points, plafond)
        retrait += points
    return max(0, int(round(100 - retrait)))


def lettre(valeur: int, bareme: Bareme) -> str:
    for l in LETTRES[:-1]:
        if valeur >= bareme.seuils[l]:
            return l
    return "F"


def pire(a: str, b: str) -> str:
    return a if LETTRES.index(a) >= LETTRES.index(b) else b


def noter(rapport: dict, bareme: Bareme) -> dict:
    problemes = rapport.get("problemes", [])
    domaines = {}
    globale = "A"
    for d in DOMAINES:
        actifs = [p for p in problemes if not p.get("ecarte")]
        gravites = problemes_comptes(actifs, d, bareme)
        s = score(gravites, bareme)
        if d == "secrets" and bareme.type == "doublement":
            secrets = [p for p in actifs if p.get("domaine") == "secrets"]
            if any(not p.get("a_verifier") for p in secrets):
                s = min(s, 29)
            elif secrets:
                s = min(s, 59)
        domaines[d] = {"score": s, "lettre": lettre(s, bareme), "comptes": len(gravites)}
        globale = pire(globale, domaines[d]["lettre"])
    plafonds = [p.get("note_max") for p in rapport.get("note", {}).get("tous_les_plafonnements", [])
                if p.get("note_max") in LETTRES]
    for p in plafonds:
        globale = pire(globale, p)
    return {"globale": globale, "domaines": domaines}


# ---------------------------------------------------------------- affichage

def nom_depot(rapport: dict, chemin: str) -> str:
    depot = rapport.get("depot", {})
    return depot.get("nom") or os.path.basename(chemin)


def verifier_actuel(rapports: list) -> list:
    """Le barème recalculé doit retrouver les scores enregistrés par le moteur
    (v1 pour les rapports sans « version_bareme », sinon la version indiquée)."""
    ecarts = []
    for chemin, r in rapports:
        version = r.get("note", {}).get("version_bareme", 1)
        calcul = noter(r, VERSION_2 if version == 2 else VERSION_1)
        for d in DOMAINES:
            enregistre = r.get("note", {}).get("domaines", {}).get(d, {}).get("score")
            if enregistre is not None and enregistre != calcul["domaines"][d]["score"]:
                ecarts.append(f"{nom_depot(r, chemin)} / {d} : enregistré {enregistre}, "
                              f"recalculé {calcul['domaines'][d]['score']}")
    return ecarts


def afficher(rapports: list, baremes: list) -> None:
    largeur = max(len(b.nom) for b in baremes)
    for chemin, r in rapports:
        print(f"\n{nom_depot(r, chemin)}  (note enregistrée : {r.get('note', {}).get('globale', '?')})")
        for b in baremes:
            n = noter(r, b)
            cases = "  ".join(
                f"{d[:5]} {n['domaines'][d]['score']:>3} {n['domaines'][d]['lettre']} "
                f"({n['domaines'][d]['comptes']:>3})" for d in DOMAINES)
            print(f"  {b.nom:<{largeur}}  globale {n['globale']}   {cases}")


def main(arguments=None) -> int:
    o = argparse.ArgumentParser(description="Recalcule les scores de rapports ASGOR avec d'autres barèmes.")
    o.add_argument("rapports", nargs="+", help="rapports JSON (format 2) exportés par ASGOR")
    o.add_argument("--bareme", help="fichier JSON de barèmes candidats (comparés au barème actuel)")
    options = o.parse_args(arguments)
    try:
        baremes = [VERSION_1, VERSION_2] + (lire_baremes(options.bareme) if options.bareme else [])
        rapports = []
        vus = set()
        for chemin in options.rapports:
            with open(chemin, encoding="utf-8") as f:
                r = json.load(f)
            if r.get("version_format") != 2:
                print(f"ignoré (format {r.get('version_format')}, attendu 2) : {chemin}", file=sys.stderr)
                continue
            cle = (nom_depot(r, chemin), r.get("depot", {}).get("commit"))
            if cle in vus:
                continue  # même dépôt, même commit : une seule fois
            vus.add(cle)
            rapports.append((chemin, r))
    except (OSError, ValueError) as e:
        print(f"Arrêt : {e}", file=sys.stderr)
        return 2
    ecarts = verifier_actuel(rapports)
    if ecarts:
        print("ATTENTION : le barème « actuel » recalculé ne retrouve pas les scores du moteur :")
        for e in ecarts:
            print("  " + e)
    else:
        print(f"Contrôle : le barème de chaque rapport retrouve les scores du moteur sur {len(rapports)} rapport(s).")
    print("Colonnes : score, lettre et (nombre de problèmes comptés) par domaine.")
    afficher(rapports, baremes)
    return 0


if __name__ == "__main__":
    sys.exit(main())
