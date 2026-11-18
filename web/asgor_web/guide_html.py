"""Page « Aide » : convertit le guide d'utilisation (Markdown simple) en HTML.

Pas de bibliothèque Markdown (aucun paquet de plus à épingler) : le guide est
écrit par l'équipe ASGOR et n'utilise que des titres, paragraphes, listes,
tableaux, gras, code et liens. Tout le texte est échappé AVANT la mise en forme ;
seuls les liens https:// et les liens internes au site (/chemin) deviennent cliquables.
"""

import html
import os
import re

from markupsafe import Markup

GUIDE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "guide", "GUIDE-UTILISATION.md")

# https://… ou lien interne au site (/chemin, jamais « // » qui désigne un autre hôte).
_LIEN = re.compile(r"\[([^\]]+)\]\((https://[^\s)\"'<>]+|/(?!/)[A-Za-z0-9._/#-]*)\)")
_URL_SEULE = re.compile(r"(?<![\"=>/])\*\*(https://[^\s*<]+)\*\*|(?<![\"=>/(])(https://[^\s<)]+[^\s<).,;:])")


def _ancre(titre: str) -> str:
    base = re.sub(r"^\d+\.\s*", "", titre).lower()
    base = re.sub(r"[^a-z0-9àâäéèêëîïôöùûüç]+", "-", base).strip("-")
    return base[:60] or "section"


def _en_ligne(texte: str) -> str:
    t = html.escape(texte, quote=True)
    t = re.sub(r"`([^`]+)`", r"<code>\1</code>", t)
    t = _LIEN.sub(lambda m: f'<a href="{m.group(2)}" rel="noopener noreferrer">{m.group(1)}</a>', t)

    def url(m):
        u = m.group(1) or m.group(2)
        lien = f'<a href="{u}" rel="noopener noreferrer">{u}</a>'
        return f"<strong>{lien}</strong>" if m.group(1) else lien
    t = _URL_SEULE.sub(url, t)
    t = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", t)
    return t


def convertir(texte: str) -> tuple:
    """Renvoie (HTML, sommaire) ; sommaire = [(ancre, titre)] des titres de niveau 2."""
    sortie, sommaire = [], []
    lignes = texte.splitlines()
    i = 0
    paragraphe = []

    def fermer_paragraphe():
        if paragraphe:
            sortie.append(f"<p>{_en_ligne(' '.join(paragraphe))}</p>")
            paragraphe.clear()

    while i < len(lignes):
        ligne = lignes[i].rstrip()
        brut = ligne.strip()
        if not brut or brut == "---":
            fermer_paragraphe()
            i += 1
            continue
        m = re.match(r"^(#{1,3})\s+(.*)$", brut)
        if m:
            fermer_paragraphe()
            niveau, titre = len(m.group(1)), m.group(2)
            if niveau == 1:
                i += 1
                continue            # le titre de la page vient du gabarit
            ancre = _ancre(titre)
            if niveau == 2:
                sommaire.append((ancre, titre))
            sortie.append(f'<h{niveau} id="{ancre}" class="titre-section{"" if niveau == 2 else "-petit"}">'
                          f"{_en_ligne(titre)}</h{niveau}>")
            i += 1
            continue
        if brut.startswith("|"):
            fermer_paragraphe()
            rangs = []
            while i < len(lignes) and lignes[i].strip().startswith("|"):
                cellules = [c.strip() for c in lignes[i].strip().strip("|").split("|")]
                if not all(re.fullmatch(r":?-{3,}:?", c) for c in cellules):
                    rangs.append(cellules)
                i += 1
            if rangs:
                tete = "".join(f"<th>{_en_ligne(c)}</th>" for c in rangs[0])
                corps = "".join("<tr>" + "".join(f"<td>{_en_ligne(c)}</td>" for c in r) + "</tr>"
                                for r in rangs[1:])
                sortie.append(f'<div class="tableau-defilant"><table class="tableau-aide">'
                              f"<thead><tr>{tete}</tr></thead><tbody>{corps}</tbody></table></div>")
            continue
        m = re.match(r"^(\s*)(-|\d+\.)\s+(.*)$", ligne)
        if m:
            fermer_paragraphe()
            ordonnee = m.group(2) != "-"
            elements = []
            while i < len(lignes):
                m2 = re.match(r"^(\s*)(-|\d+\.)\s+(.*)$", lignes[i].rstrip())
                if m2 and len(m2.group(1)) == len(m.group(1)):
                    elements.append([m2.group(3), []])
                elif m2 and len(m2.group(1)) > len(m.group(1)) and elements:
                    elements[-1][1].append(m2.group(3))      # sous-liste (un niveau)
                elif lignes[i].startswith("   ") and lignes[i].strip() and elements:
                    elements[-1][0] += " " + lignes[i].strip()
                else:
                    break
                i += 1
            balise = "ol" if ordonnee else "ul"
            morceaux = []
            for texte_el, sous in elements:
                bloc = _en_ligne(texte_el)
                if sous:
                    bloc += "<ul>" + "".join(f"<li>{_en_ligne(s)}</li>" for s in sous) + "</ul>"
                morceaux.append(f"<li>{bloc}</li>")
            sortie.append(f'<{balise} class="liste-aide">{"".join(morceaux)}</{balise}>')
            continue
        paragraphe.append(brut)
        i += 1
    fermer_paragraphe()
    return "\n".join(sortie), sommaire


def charger() -> tuple:
    """(Markup HTML, sommaire), ou un message si le guide est absent."""
    try:
        with open(GUIDE, encoding="utf-8") as f:
            corps, sommaire = convertir(f.read())
    except OSError:
        return Markup("<p>Le guide d'utilisation est introuvable.</p>"), []
    # Markup : le texte a été échappé dans _en_ligne ; seules nos balises restent.
    return Markup(corps), sommaire
