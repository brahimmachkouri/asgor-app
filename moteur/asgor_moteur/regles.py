"""Installation des règles Semgrep (dépôt semgrep/semgrep-rules) sur le poste.

Licence des règles (Semgrep Rules License v1.0, voir README.md) : usage interne, pas
de redistribution. L'image publique ne les contient donc pas : chaque poste les
télécharge lui-même, au commit figé et avec la somme SHA256 de versions-outils.json.

Lancé par le filtre du socket Docker dans une étape dédiée (réseau des étapes
« fetch », seul volume monté : asgor-regles, en écriture). Le filtre fixe lui-même la
commande : python3 -m asgor_moteur.regles <commit> <sha256>
"""

import hashlib
import os
import re
import shutil
import sys
import tarfile
import urllib.request

DOSSIER = "/opt/asgor/regles/semgrep-rules"
TAILLE_MAX = 200 * 1024 * 1024


def installer(commit: str, somme: str, dossier: str = DOSSIER, ouvrir=urllib.request.urlopen) -> str:
    if not re.fullmatch(r"[0-9a-f]{40}", commit) or not re.fullmatch(r"[0-9a-f]{64}", somme):
        raise ValueError("commit ou somme SHA256 invalide")
    os.makedirs(dossier, mode=0o755, exist_ok=True)
    cible = os.path.join(dossier, commit)
    if not os.path.isfile(os.path.join(cible, "LICENSE")):
        archive = os.path.join(dossier, f".{commit}.tar.gz")
        provisoire = os.path.join(dossier, f".{commit}.extraction")
        for chemin in (archive, provisoire):
            if os.path.isdir(chemin):
                shutil.rmtree(chemin)
            elif os.path.lexists(chemin):
                os.unlink(chemin)
        url = f"https://github.com/semgrep/semgrep-rules/archive/{commit}.tar.gz"
        empreinte = hashlib.sha256()
        taille = 0
        with ouvrir(url, timeout=120) as reponse, open(archive, "xb") as sortie:
            while morceau := reponse.read(1024 * 1024):
                taille += len(morceau)
                if taille > TAILLE_MAX:
                    raise ValueError("archive des règles trop grosse")
                empreinte.update(morceau)
                sortie.write(morceau)
        if empreinte.hexdigest() != somme:
            os.unlink(archive)
            raise ValueError(f"somme SHA256 fausse pour l'archive des règles ({empreinte.hexdigest()})")
        os.makedirs(provisoire, mode=0o755)
        with tarfile.open(archive, "r:gz") as tar:
            membres = []
            for membre in tar.getmembers():
                # « semgrep-rules-<commit>/… » : on retire le premier dossier.
                parties = membre.name.split("/", 1)
                if len(parties) < 2 or not parties[1]:
                    continue
                membre.name = parties[1]
                membres.append(membre)
            # Filtre « data » : refuse chemins absolus, « .. », liens vers l'extérieur,
            # fichiers spéciaux ; retire les droits spéciaux.
            tar.extractall(provisoire, members=membres, filter="data")
        os.unlink(archive)
        os.rename(provisoire, cible)
    # Lien « actuel » remplacé d'un coup (le moteur lit …/semgrep-rules/actuel).
    lien = os.path.join(dossier, "actuel")
    provisoire = os.path.join(dossier, ".actuel")
    if os.path.lexists(provisoire):
        os.unlink(provisoire)
    os.symlink(commit, provisoire)
    os.replace(provisoire, lien)
    return cible


def main(arguments=None) -> int:
    commit, somme = (arguments or sys.argv[1:])[:2]
    cible = installer(commit, somme)
    print(f"Règles Semgrep {commit[:7]} installées dans {cible}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
