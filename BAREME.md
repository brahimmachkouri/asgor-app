# ASGOR — barème de notation

Ce document décrit comment ASGOR calcule la note d'un dépôt (barème version 2, appliqué par `moteur/asgor_moteur/notation.py`). Le numéro de version du barème est écrit dans chaque rapport.

---

## 1. Principe

La note doit pousser le développeur à corriger les failles et les défauts le plus vite possible. Dans le doute, ASGOR choisit la règle la plus sévère.

1. Chaque problème trouvé reçoit une **gravité** (§ 2).
2. Chaque domaine (**Secrets**, **Dépendances**, **Code**) reçoit un **score de 0 à 100**, puis une lettre (§ 3).
3. La **note globale** est la plus basse des trois lettres. Un domaine très mauvais ne peut pas être compensé par les deux autres.
4. Des **règles de plafonnement** peuvent ensuite abaisser la note globale (§ 4). Le rapport affiche toujours la raison du plafonnement.

**Qualité du code.** Le rapport contient aussi une rubrique « Qualité du code », produite par PHPStan (niveau 5, configuration générée par ASGOR) : bugs probables, types incohérents, code mort. Elle est **sans effet sur la note**. Si PHPStan échoue, la rubrique est absente, avec un avertissement, sans plafonnement.

## 2. Gravités

| Gravité | Exemples |
|---|---|
| Critique | secret détecté hors des chemins « à vérifier » (§ 6) ; faille de dépendance de score CVSS 9 ou plus |
| Élevée | secret « à vérifier » (§ 6) ; faille de dépendance CVSS 7 à 8,9 ; injection SQL, XSS ou injection de commande trouvée par l'analyse de flux (Psalm) |
| Moyenne | faille de dépendance CVSS 4 à 6,9 ; règle Opengrep ou Bandit de niveau moyen |
| Faible | faille de dépendance CVSS inférieure à 4 ; mauvaise pratique sans risque direct |
| Information | affiché dans le rapport, ne compte pas dans le score |

Quand l'outil ne donne pas de score CVSS, ASGOR reprend la gravité que l'outil annonce.

## 3. Score d'un domaine

Le score exprime l'urgence et l'effort de correction. Il bouge dès qu'on corrige, même partiellement.

1. **Les problèmes du domaine sont comptés en « équivalents élevés »** :

   | Gravité | Vaut |
   |---|---|
   | Critique | 4 |
   | Élevée | 1 |
   | Moyenne | 0,3 |
   | Faible | 0,05 |

2. **Une dépendance vulnérable compte une seule fois**, avec sa gravité la plus haute, quel que soit le nombre d'avis de sécurité qui la concernent : une seule mise à jour les corrige tous. Une « dépendance » est un paquet dans un fichier de verrouillage.
3. **Chaque doublement du total retire 15 points** : score = 100 − 15 × log2(1 + total), arrondi, jamais sous 0.

   | Total (en équivalents élevés) | 0 | 1 | 3 | 7 | 15 | 31 | 100 et plus |
   |---|---|---|---|---|---|---|---|
   | Score | 100 | 85 | 70 | 55 | 40 | 25 | 0 |

   Corriger la moitié des problèmes fait donc toujours gagner environ 15 points.
4. **Domaine Secrets** : dès qu'il contient un secret (hors « à vérifier »), son score ne dépasse pas 29 (zone F), pour rester cohérent avec le plafonnement à F. S'il ne contient que des secrets « à vérifier », son score ne dépasse pas 59 (zone D).

Un problème signalé par deux outils ne compte qu'une fois. Un résultat écarté comme faux positif (§ 6 c) ne compte pas.

| Score | Lettre |
|---|---|
| 90 à 100 | A |
| 75 à 89 | B |
| 60 à 74 | C |
| 45 à 59 | D |
| 30 à 44 | E |
| 0 à 29 | F |

`outils/simuler_bareme.py` recalcule les notes de rapports JSON existants avec un autre barème : il sert à mesurer l'effet d'un changement avant de le faire dans le moteur.

## 4. Règles de plafonnement

Elles s'appliquent après le calcul des scores. Si plusieurs règles s'appliquent, la plus sévère l'emporte.

| Condition | Note globale |
|---|---|
| Un secret détecté, **dans les fichiers actuels ou dans n'importe quel ancien commit** | **F** |
| Une faille critique (dépendance ou code) | **F** |
| Seulement des secrets « à vérifier » (fichiers de test, de documentation, d'exemple, bibliothèques minifiées : § 6) | **D au maximum** |
| Injection SQL, XSS ou injection de commande trouvée par l'analyse de flux | **C au maximum** |
| Au moins un problème de gravité moyenne ou plus grave | **B au maximum** |
| Dépendance avec une faille élevée et une version corrigée disponible | **B au maximum** |
| Application sans fichier de verrouillage (§ 5) | **B au maximum**, avec la mention « analyse des dépendances incomplète » |
| Case « Analyser tout l'historique Git » décochée : seuls les fichiers actuels sont cherchés | **B au maximum**, avec la mention « historique Git non analysé » |
| Un outil a échoué ou dépassé son délai | **B au maximum**, et le domaine concerné est marqué « non évalué entièrement » |

La note A n'est donc possible que sans aucun problème de gravité moyenne ou plus grave.

Précisions :

- **Secrets** : un secret retiré du code mais toujours présent dans l'historique Git reste lisible par toute personne qui clone le dépôt. Il compte donc comme un secret présent. ASGOR ne teste pas si le secret fonctionne encore : le tester reviendrait à l'utiliser.
- **Dépendances de développement** : même poids que les dépendances de production, car rien ne garantit qu'elles ne seront pas installées en production.

## 5. Fichier de verrouillage

### De quoi il s'agit

Un projet déclare ses dépendances avec des **plages de versions**, par exemple « Symfony 6.4 ou plus récent dans la série 6 » (`composer.json`, `requirements.txt`). Le **fichier de verrouillage** (`composer.lock`, `poetry.lock`, `uv.lock`, `Pipfile.lock`, `pdm.lock`, ou un `requirements.txt` où chaque ligne a une version exacte `==`) note la **version exacte** de chaque dépendance, y compris les dépendances des dépendances.

La documentation de Composer recommande de conserver ce fichier dans Git, pour que tout le monde installe exactement les mêmes versions.

### Pourquoi son absence compte

1. **Pour le projet** : deux installations à des dates différentes peuvent donner des versions différentes. Personne ne sait exactement ce qui tourne en production.
2. **Pour l'analyse** : sans versions exactes, les outils doivent deviner. Ils peuvent manquer une faille ou en signaler une qui n'existe pas, et ils ne voient pas les dépendances des dépendances.

### Règle

| Cas | Effet |
|---|---|
| **Application** sans fichier de verrouillage | B au maximum + « analyse des dépendances incomplète » |
| **Bibliothèque** sans fichier de verrouillage | avertissement seulement |
| `composer.lock` qui ne correspond plus à `composer.json` (`composer install` le refuse) | problème de dépendances de gravité **moyenne** |

Raison de la différence : d'après la documentation de Composer, le fichier de verrouillage d'une bibliothèque n'a aucun effet sur les projets qui l'utilisent. Ce sont ces projets qui choisissent les versions réellement installées.

Comment ASGOR reconnaît une bibliothèque :

- PHP : `composer.json` contient explicitement `"type": "library"` ou `"type": "symfony-bundle"`. Dans tous les autres cas, le dépôt est traité comme une application (le cas le plus sévère quand on ne sait pas).
- Python : un `pyproject.toml` seul, sans `requirements.txt` ni fichier de verrouillage, est traité comme une bibliothèque. Un `requirements.txt` sans versions exactes, ou un `Pipfile` sans `Pipfile.lock`, est traité comme une application sans verrouillage.

## 6. Faux positifs de secrets

Les outils de recherche de secrets signalent aussi des valeurs factices : vecteurs de test cryptographiques, clés d'exemple dans une documentation, jetons de test. Trois mesures limitent leur effet sur la note.

**a. Regroupement par fichier.** Un seul problème par fichier et par type de secret, avec le nombre d'occurrences.

**b. Secrets « à vérifier ».** Un secret trouvé dans un fichier de test, de documentation, d'exemple ou une bibliothèque minifiée est classé « à vérifier » : gravité élevée (et non critique), note **D au maximum** (et non F). La liste de ces chemins appartient à ASGOR ; un dépôt analysé ne peut pas la modifier :

- dossiers `test`, `tests`, `spec`, `fixtures`, `doc`, `docs`, `documentation`, `example`, `examples` ;
- fichiers `*.md`, `*.example`, `*.dist`, `*.sample`, `*.min.js`, `*.eml` ;
- fichiers de test : `test.js`, `*.test.js`, `*.spec.js`, `*Test.php`, `test_*.py`, `*_test.py`, `*_test.go`.

« À vérifier » ne change que la gravité du secret : ces fichiers restent analysés par tous les outils (secrets et code). Le plafonnement reste sévère, car un vrai secret peut aussi se trouver dans un dossier de test.

**c. Marquage manuel.** Depuis la page du rapport, un membre de l'équipe peut écarter un résultat comme faux positif, avec un motif obligatoire. Le résultat écarté ne compte plus dans la note, pour cette analyse et les suivantes du même dépôt. Il reste affiché dans une rubrique « Résultats écartés », avec la date, le motif et l'adresse IP. Un marquage peut être annulé.

On peut écarter plusieurs résultats à la fois : une case à cocher devant chaque résultat et un bouton « Écarter la sélection » (motif commun obligatoire), plus un bouton « Écarter tout ce groupe » en tête de chaque regroupement (même fichier ou même règle). C'est un formulaire HTML ordinaire, sans JavaScript ; il ne transmet que les identifiants des résultats (500 au plus par envoi), vérifiés un par un par le worker. Le service web dépose le marquage dans la file ; seul le worker écrit dans la base et recalcule la note.

**Affichage du secret.** Le secret reste masqué dans ASGOR (règle 5 de sécurité du moteur, `README.md`). Pour que l'auditeur le voie sans chercher, chaque secret a un lien **« Voir sur GitHub »** vers le fichier, au commit et à la ligne exacts : `https://github.com/<propriétaire>/<dépôt>/blob/<commit>/<fichier>#L<ligne>`. Le lien fonctionne aussi pour un secret qui n'existe plus que dans l'historique. Il est construit par ASGOR à partir de valeurs validées (commit en hexadécimal, chemin encodé), jamais recopié depuis un outil.

## 7. Exemples

**Exemple 1.** Aucun secret. Une dépendance avec une faille élevée, version corrigée disponible. Deux problèmes de code moyens.
- Secrets 100 (A). Dépendances : total 1, score 85 (B). Code : total 0,6, score 90 (A).
- Note la plus basse : B. Plafonnements « faille élevée corrigeable » et « problème moyen » : B au maximum.
- **Note globale : B.**

**Exemple 2.** Une clé d'API dans un commit de 2023, supprimée depuis, dans `config/prod.php`. Rien d'autre.
- Secrets : score 29 au plus (F). Dépendances 100 (A), Code 100 (A).
- Plafonnement « secret détecté » : **note globale F**.

**Exemple 3.** Même clé, mais dans `tests/fixtures/config.php`.
- Secret « à vérifier » : Secrets 59 au plus (D).
- **Note globale D**, raison affichée : « secret à vérifier dans des fichiers de test, de documentation ou d'exemple ». Si l'équipe l'écarte comme faux positif, la note remonte à A.

**Exemple 4.** Application Symfony sans `composer.lock`, aucun problème trouvé.
- Les trois domaines à A.
- Plafonnement « application sans fichier de verrouillage » : **note globale B**, avec « analyse des dépendances incomplète ».

**Exemple 5.** Une version de Django visée par 51 avis de sécurité, dont un critique. Rien d'autre.
- Une seule dépendance, comptée une fois comme critique : total 4, score 65 (C).
- Plafonnement « faille critique » : **note globale F**. Après la mise à jour de Django, le domaine revient à 100.
