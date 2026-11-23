# Mes repas et recettes

Appli personnelle, protégée par un code d'accès.

Le contenu de l'appli est chiffré dans `index.html` (AES-256-GCM, clé tirée du code avec PBKDF2-SHA256, 600 000 tours). Sans le code, la page ne montre que l'écran du code. Une fois le bon code tapé, le téléphone garde la clé et l'appli s'ouvre toute seule, même sans réseau.

`verrou.py` sert à déchiffrer la page pour la modifier, puis à la rechiffrer (il reprend le sel de la page déjà en ligne, pour ne pas redemander le code).
