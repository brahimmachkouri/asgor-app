# ASGOR — guide d'utilisation

Ce guide est aussi la page « Aide » du site.

Le site n'est accessible que depuis les adresses IP autorisées. Son adresse vous est donnée par l'administrateur d'ASGOR.

---

## 1. À quoi sert ASGOR

ASGOR (*Automated Security Grading Of Repositories*) analyse la sécurité d'un dépôt GitHub **public** et donne une **note de A à F**, comme SSL Labs pour les sites web. Il cherche trois choses :

| Domaine | Ce qui est cherché |
|---|---|
| **Secrets** | mots de passe, clés d'API, jetons, clés privées, dans les fichiers **et dans tout l'historique Git** |
| **Dépendances** | bibliothèques utilisées (Composer, npm, pip…) qui ont une faille connue |
| **Code** | failles dans le code PHP et Python : injection SQL, XSS, injection de commande, fonctions dangereuses… |

ASGOR ne modifie jamais le dépôt et n'exécute jamais son code.

---

## 2. Lancer une analyse

1. Sur la page d'accueil, collez l'adresse du dépôt dans **« URL du dépôt GitHub »**, sous la forme `https://github.com/organisation/depot`.
2. Deux cases :
   - **« Analyser tout l'historique Git (secrets) »** (cochée par défaut) : laissez-la cochée. Sans elle, les secrets des anciens commits ne sont pas cherchés et la note ne peut pas dépasser B.
   - **« Ne pas afficher dans les analyses récentes »** : cochez-la si vous ne voulez pas que l'analyse apparaisse sur la page d'accueil.
3. Cliquez sur **« Analyser »**.

La page suivante montre l'avancement étape par étape et se met à jour toute seule. Une analyse dure de quelques secondes à quelques minutes (roundcube : 4 minutes environ). Le bouton **« Annuler l'analyse »** l'arrête.

Bon à savoir :

- **Une seule analyse à la fois.** Les autres attendent leur tour ; la page indique la position dans la file.
- **Limites** : 500 Mo par dépôt, 30 minutes par analyse, 20 demandes en attente au plus.
- **Commit déjà analysé** : si le même commit a été analysé il y a moins d'une heure, ASGOR propose le rapport existant. Le bouton **« Analyser quand même »** relance une analyse.
- Le bouton **« Relancer l'analyse »**, sur un rapport, analyse à nouveau le dépôt (utile après une correction).
- Si un bandeau rouge dit que **le service d'analyse ne donne plus signe de vie**, prévenez l'administrateur.

---

## 3. Lire la note

### Note de chaque domaine

Chaque domaine reçoit un **score de 0 à 100**, puis une lettre :

| Score | 90-100 | 75-89 | 60-74 | 45-59 | 30-44 | 0-29 |
|---|---|---|---|---|---|---|
| Lettre | A | B | C | D | E | F |

Le score baisse de **15 points chaque fois que le nombre de problèmes double** (en comptant un problème critique comme 4 problèmes élevés, un moyen comme 0,3, un faible comme 0,05). Conséquence pratique : **corriger la moitié des problèmes fait toujours gagner environ 15 points**. Une dépendance vulnérable compte une seule fois, même si elle a 50 failles connues : une seule mise à jour les corrige toutes.

### Note globale

La note globale est **la plus basse des trois lettres**, puis certaines règles la limitent :

| Situation | Note au maximum |
|---|---|
| Un secret trouvé (fichiers ou historique) | **F** |
| Une faille critique | **F** |
| Seulement des secrets « à vérifier » (voir § 5) | **D** |
| Injection SQL, XSS ou de commande trouvée par l'analyse de flux (Psalm) | **C** |
| Un problème moyen ou plus grave, une faille élevée corrigeable dans une dépendance, une application sans fichier de verrouillage (`composer.lock`…), l'historique non analysé, un outil en échec | **B** |
| Aucun problème moyen ou plus grave | **A** possible |

Les raisons qui fixent la note sont affichées sous les scores (« Note F : 2 secrets détectés… »).

**Pourquoi tant de F ?** Un seul secret suffit pour un F : un secret publié, même supprimé depuis, reste lisible par toute personne qui clone le dépôt. C'est voulu.

---

## 4. Lire les problèmes

Les problèmes sont triés du plus grave au moins grave (les 200 premiers sont affichés ; les exports contiennent tout). Pour chacun :

- la **gravité** (Critique, Élevée, Moyenne, Faible) et le domaine ;
- le **fichier et la ligne**, l'outil qui l'a trouvé et sa règle ;
- pour une dépendance : le paquet, sa version et **la version corrigée** ;
- une **explication** et **« À faire »** : ce qu'il faut corriger ;
- les références (CVE, avis de sécurité).

La rubrique **« Qualité du code »** (lien dans la barre du haut) liste les erreurs trouvées par PHPStan : bugs probables, types incohérents. Elle est **sans effet sur la note**. Cliquez sur son titre pour la déplier.

---

## 5. Les secrets

- La valeur n'est **jamais affichée en entier** : seulement les 4 premiers caractères puis `****`.
- Le lien **« Voir sur GitHub »** ouvre le fichier à la bonne ligne et au bon commit, même si le secret n'existe plus que dans l'historique.
- Un même type de secret dans un même fichier n'apparaît qu'**une fois**, avec le nombre d'occurrences (exemple : « 905 occurrences dans ce fichier »).
- **« À vérifier »** : secret trouvé dans un fichier de test, de documentation ou d'exemple (dossiers `test`, `tests`, `docs`, `examples`…, fichiers `.md`, `.example`, `.dist`, `.min.js`, `*Test.php`, `test_*.py`…). C'est souvent une valeur factice. La note est limitée à D au lieu de F. Ces fichiers restent analysés normalement : seul le classement du secret change.

**Si le secret est réel** : il faut le **révoquer** (le désactiver chez le fournisseur) et en créer un nouveau. Le supprimer du code ne suffit pas : il reste dans l'historique Git.

ASGOR ne teste jamais si un secret fonctionne : le tester reviendrait à l'utiliser.

---

## 6. Écarter un faux positif

Un outil se trompe parfois : vecteur de test, clé d'exemple de la documentation, empreinte de fichier prise pour une clé… On peut alors **écarter** le résultat.

1. Dans le cadre **« Écarter des faux positifs »**, saisissez un **motif** (obligatoire), par exemple « vecteurs de test cryptographiques » ou « nom d'algorithme, pas un secret ».
2. Puis, au choix :
   - cochez les résultats concernés (case à gauche de chaque titre) et cliquez sur **« Écarter la sélection »** ;
   - ou cliquez sur **« Écarter tout ce groupe »** à côté d'un groupe (tous les résultats d'un même fichier ou d'une même règle).
3. La page affiche « Demande transmise ». **Rechargez-la après quelques secondes** pour voir la nouvelle note.

Ce qu'il faut savoir :

- Un résultat écarté **ne compte plus dans la note**, pour cette analyse et **pour les analyses suivantes du même dépôt**.
- Il reste visible dans la rubrique **« Résultats écartés »**, avec la date, l'adresse IP et le motif. Pour l'annuler, cochez-le et cliquez sur **« Rétablir la sélection »**.
- 500 résultats au plus par envoi.
- **Attention aux groupes de secrets** : écarter un secret écarte ce type de secret pour tout le fichier. Si un vrai secret du même type y apparaît plus tard, il sera écarté lui aussi.
- **N'écartez que ce que vous avez vérifié.** En cas de doute, laissez le résultat.

---

## 7. Exports

- **« Exporter JSON »** : le rapport complet, pour un traitement automatique ou un archivage.
- **« Exporter SARIF »** : format standard des outils d'analyse, lisible par les éditeurs de code (VS Code avec l'extension SARIF Viewer) et par GitHub (onglet « Security » du dépôt, si vous en êtes propriétaire). Les résultats écartés y sont marqués comme tels.

Le nom du fichier exporté indique le dépôt : `asgor-<propriétaire>-<dépôt>-<identifiant>.json` (ou `.sarif`).

### Corriger les dépendances avec l'export JSON

Pour les développeurs. Le script `corriger_dependances.py`, publié dans le dépôt **[asgor-tools](https://github.com/brahimmachkouri/asgor-tools)**, lit un export JSON et met à jour les dépendances vulnérables du dépôt analysé. Il se lance sur votre poste, dans une copie du dépôt analysé, avec Python 3 (rien à installer).

**Attention : le script modifie le dépôt** (fichiers de dépendances, `node_modules/`, `vendor/`) et exécute des commandes (npm, pnpm, Composer, tests du projet). **Une mise à jour de dépendance peut casser l'application**, même si les tests réussissent. Sauvegardez vos données, travaillez sur une copie isolée du dépôt, affichez d'abord le plan (`--plan`), et relisez les changements avant de les fusionner. Le script est fourni « tel quel », sans garantie (licence MIT).

Commandes :

- voir ce qui serait fait, sans rien modifier : `python3 corriger_dependances.py rapport.json --plan --depot ~/mon-projet`
- appliquer (une confirmation est demandée) : `python3 corriger_dependances.py rapport.json --depot ~/mon-projet`

Ce que fait le script, ce qu'il ne fait pas et ses options : voir le [README d'asgor-tools](https://github.com/brahimmachkouri/asgor-tools).

---

## 8. Ce qu'ASGOR ne fait pas

- Il n'analyse que les **dépôts publics**.
- Il n'analyse le **code** que pour le **PHP** et le **Python** (les dépendances JavaScript sont bien analysées, pas le code JavaScript).
- Il ne voit pas les **erreurs de logique** : contrôle d'accès oublié, droits mal vérifiés, règle métier contournable. Une note A ne veut pas dire « application sûre ».
- Il ne cherche pas encore le **code malveillant** volontairement caché.
- Il n'analyse pas en continu : une note vaut **au moment de l'analyse**. Une nouvelle faille publiée demain dans une dépendance n'apparaîtra qu'à la prochaine analyse.
- Les résultats des outils sont des **indices** : ils doivent être vérifiés par une personne.

Pour vos propres dépôts, activez aussi **Dependabot** et la **recherche de secrets** de GitHub (gratuit) : ils alertent en continu.
