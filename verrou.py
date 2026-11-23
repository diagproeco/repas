#!/usr/bin/env python3
"""Verrou : met une appli d'une seule page derrière un code d'accès.

Le contenu de l'appli (tout index.html, plus les fichiers JSON qu'elle charge)
est chiffré en AES-256-GCM. La clé vient du code d'accès (PBKDF2-SHA256,
600 000 tours). La page publiée ne contient que l'écran du code et le contenu
chiffré : sans le code, on ne peut rien lire.

Le code est simplifié avant usage : minuscules, sans accents, sans espaces ni
ponctuation (« Galet bleu 47 » = « galetbleu47 »).

Chiffrer (la source est le dossier de l'appli en clair) :
  python3 verrou.py chiffrer --source DOSSIER --sortie DOSSIER --app ventoux \
      --titre "Séances Ventoux 2027" --court Ventoux --couleur "#F5C400" \
      --fond "#FAFAF7" --texte-bouton "#1A1A1A" [--integrer recettes.json seances.json]
  Le code est demandé au clavier (ou variable d'environnement CODE_ACCES).
  Si DOSSIER_SORTIE/index.html existe déjà et est verrouillé, son sel est
  repris : les téléphones déjà ouverts n'ont pas à retaper le code.

Déchiffrer (pour modifier l'appli) :
  python3 verrou.py dechiffrer --page index.html --sortie appli_en_clair.html
"""
import argparse, base64, getpass, html, json, os, re, sys, unicodedata

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

TOURS = 600_000
MARQUE = 'id="coffre"'


def simplifier(code):
    s = unicodedata.normalize("NFD", code)
    s = "".join(c for c in s if unicodedata.category(c) != "Mn").lower()
    return re.sub(r"[^a-z0-9]", "", s)


def cle(code, sel, tours):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=sel, iterations=tours)
    return kdf.derive(simplifier(code).encode("utf-8"))


def lire_coffre(page_html):
    m = re.search(r'<script type="application/json" id="coffre">(.*?)</script>', page_html, re.S)
    return json.loads(m.group(1)) if m else None


def lire_code():
    code = os.environ.get("CODE_ACCES") or getpass.getpass("Code d'accès : ")
    if len(simplifier(code)) < 4:
        sys.exit("Code trop court.")
    return code


def json_dans_script(texte):
    return texte.replace("</", "<\\/").replace("<!--", "<\\!--")


def preparer_appli(source, integrer):
    page = open(os.path.join(source, "index.html"), encoding="utf-8").read()
    if not integrer:
        return page
    donnees = {}
    for nom in integrer:
        donnees[nom] = json.load(open(os.path.join(source, nom), encoding="utf-8"))
    cale = (
        "<script>\n/* Données de l'appli, chiffrées avec elle : fetch() les sert sans réseau. */\n"
        "(function () {\n  var D = " + json_dans_script(json.dumps(donnees, ensure_ascii=False, separators=(",", ":"))) + ";\n"
        "  var f = window.fetch;\n"
        "  window.fetch = function (u, o) {\n"
        "    var n = String(u && u.url ? u.url : u).split('#')[0].split('?')[0].split('/').pop();\n"
        "    if (Object.prototype.hasOwnProperty.call(D, n)) return Promise.resolve(new Response(JSON.stringify(D[n]), {status: 200, headers: {'Content-Type': 'application/json'}}));\n"
        "    return f.apply(this, arguments);\n"
        "  };\n"
        "})();\n</script>\n"
    )
    i = page.find("<script")
    if i < 0:
        sys.exit("Pas de <script> dans index.html")
    return page[:i] + cale + page[i:]


ECRAN = """<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{titre}</title>
<meta name="robots" content="noindex,nofollow">
<meta name="theme-color" content="{couleur}">
<meta name="mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-title" content="{court}">
<link rel="manifest" href="manifest.webmanifest">
<link rel="icon" type="image/png" sizes="192x192" href="icon-192.png">
<link rel="apple-touch-icon" href="icon-180.png">
<style>
*{{box-sizing:border-box}}
html,body{{margin:0;height:100%;background:{fond};color:#1A1A1A;font-family:system-ui,-apple-system,"Segoe UI",Roboto,Arial,sans-serif}}
#verrou{{min-height:100%;display:flex;align-items:center;justify-content:center;padding:24px}}
#verrou[hidden]{{display:none}}
.carte{{width:100%;max-width:340px;text-align:center}}
.carte img{{width:88px;height:88px;border-radius:20px;display:block;margin:0 auto 16px}}
h1{{font-size:22px;line-height:1.25;margin:0 0 6px}}
p{{margin:0 0 20px;color:#555;font-size:15px}}
label{{display:block;text-align:left;font-size:14px;font-weight:600;margin-bottom:6px}}
input{{width:100%;font-size:20px;padding:14px 16px;border:2px solid #C9C9C2;border-radius:12px;background:#fff;color:#1A1A1A}}
input:focus{{outline:none;border-color:{couleur}}}
button{{width:100%;margin-top:14px;font-size:18px;font-weight:700;padding:15px;border:0;border-radius:12px;background:{couleur};color:{texte_bouton}}}
button:disabled{{opacity:.6}}
#erreur{{min-height:22px;margin:12px 0 0;color:#B3261E;font-size:15px;font-weight:600}}
</style>
</head>
<body>
<div id="verrou" hidden>
  <form class="carte" id="formulaire" autocomplete="off">
    <img src="icon-192.png" alt="">
    <h1>{titre}</h1>
    <p>Appli privée : tape ton code d'accès.<br>Une seule fois sur ce téléphone.</p>
    <label for="code">Code d'accès</label>
    <input id="code" name="code" type="text" inputmode="text" autocapitalize="none" autocorrect="off" spellcheck="false" enterkeyhint="go">
    <button id="ouvrir" type="submit">Ouvrir</button>
    <div id="erreur" role="alert"></div>
  </form>
</div>
<script type="application/json" id="coffre">{coffre}</script>
<script>
(function () {{
  "use strict";
  var CLE = "acces-{app}";
  var coffre = JSON.parse(document.getElementById("coffre").textContent);
  var $ = function (id) {{ return document.getElementById(id); }};
  if ("serviceWorker" in navigator) navigator.serviceWorker.register("sw.js").catch(function () {{}});

  function octets(b64) {{ var s = atob(b64), u = new Uint8Array(s.length); for (var i = 0; i < s.length; i++) u[i] = s.charCodeAt(i); return u; }}
  function base64(buf) {{ var u = new Uint8Array(buf), s = ""; for (var i = 0; i < u.length; i++) s += String.fromCharCode(u[i]); return btoa(s); }}
  function simplifier(c) {{ return c.normalize("NFD").replace(/[\\u0300-\\u036f]/g, "").toLowerCase().replace(/[^a-z0-9]/g, ""); }}
  function lsLire() {{ try {{ return localStorage.getItem(CLE); }} catch (e) {{ return null; }} }}
  function lsEcrire(v) {{ try {{ localStorage.setItem(CLE, v); }} catch (e) {{}} }}
  function lsEffacer() {{ try {{ localStorage.removeItem(CLE); }} catch (e) {{}} }}

  function dechiffrer(cle) {{
    return crypto.subtle.decrypt({{name: "AES-GCM", iv: octets(coffre.iv)}}, cle, octets(coffre.ct))
      .then(function (buf) {{ return new TextDecoder().decode(buf); }});
  }}
  /* On remplace la page seulement quand elle a fini de charger : avant, document.write
     ajouterait l'appli dans l'écran du code au lieu de le remplacer. */
  function afficher(page) {{
    function remplacer() {{ document.open(); document.write(page); document.close(); }}
    if (document.readyState === "complete") remplacer();
    else window.addEventListener("load", function () {{ setTimeout(remplacer, 0); }}, {{once: true}});
  }}
  function montrer(message) {{
    $("verrou").hidden = false;
    $("erreur").textContent = message || "";
    $("code").focus();
  }}

  if (!window.crypto || !crypto.subtle || !window.TextDecoder) {{
    montrer("Ce navigateur ne peut pas ouvrir l'appli. Ouvre-la dans Chrome ou Safari.");
    $("ouvrir").disabled = true;
    return;
  }}

  var memo = lsLire();
  if (memo) {{
    crypto.subtle.importKey("raw", octets(memo), {{name: "AES-GCM"}}, true, ["decrypt"])
      .then(dechiffrer).then(afficher)
      .catch(function () {{ lsEffacer(); montrer(); }});
  }} else {{
    montrer();
  }}

  $("formulaire").addEventListener("submit", function (e) {{
    e.preventDefault();
    var code = simplifier($("code").value || "");
    if (!code) {{ montrer("Tape ton code d'accès."); return; }}
    $("ouvrir").disabled = true;
    $("ouvrir").textContent = "Ouverture…";
    $("erreur").textContent = "";
    crypto.subtle.importKey("raw", new TextEncoder().encode(code), "PBKDF2", false, ["deriveKey"])
      .then(function (base) {{
        return crypto.subtle.deriveKey({{name: "PBKDF2", salt: octets(coffre.sel), iterations: coffre.tours, hash: "SHA-256"}},
          base, {{name: "AES-GCM", length: 256}}, true, ["decrypt"]);
      }})
      .then(function (cle) {{
        return dechiffrer(cle).then(function (page) {{
          return crypto.subtle.exportKey("raw", cle).then(function (brut) {{ lsEcrire(base64(brut)); return page; }});
        }});
      }})
      .then(afficher)
      .catch(function () {{
        $("ouvrir").disabled = false;
        $("ouvrir").textContent = "Ouvrir";
        montrer("Ce n'est pas le bon code. Réessaie.");
        $("code").select();
      }});
  }});
}})();
</script>
</body>
</html>
"""


def chiffrer(a):
    code = lire_code()
    os.makedirs(a.sortie, exist_ok=True)
    sel, tours = os.urandom(16), TOURS
    ancienne = os.path.join(a.sortie, "index.html")
    if os.path.exists(ancienne):
        c = lire_coffre(open(ancienne, encoding="utf-8").read())
        if c:
            sel, tours = base64.b64decode(c["sel"]), c["tours"]
            print("Sel repris de l'ancienne page.")
    appli = preparer_appli(a.source, a.integrer)
    iv = os.urandom(12)
    ct = AESGCM(cle(code, sel, tours)).encrypt(iv, appli.encode("utf-8"), None)
    coffre = json.dumps({
        "v": 1, "algo": "AES-256-GCM / PBKDF2-SHA256", "tours": tours,
        "sel": base64.b64encode(sel).decode(), "iv": base64.b64encode(iv).decode(),
        "ct": base64.b64encode(ct).decode(),
    })
    page = ECRAN.format(
        titre=html.escape(a.titre), court=html.escape(a.court), couleur=a.couleur, fond=a.fond,
        texte_bouton=a.texte_bouton, app=a.app, coffre=coffre,
    )
    open(ancienne, "w", encoding="utf-8").write(page)
    print("Écrit :", ancienne, len(page), "octets ; appli en clair :", len(appli), "octets")


def dechiffrer(a):
    code = lire_code()
    c = lire_coffre(open(a.page, encoding="utf-8").read())
    if not c:
        sys.exit("Cette page n'est pas verrouillée.")
    k = cle(code, base64.b64decode(c["sel"]), c["tours"])
    try:
        clair = AESGCM(k).decrypt(base64.b64decode(c["iv"]), base64.b64decode(c["ct"]), None)
    except InvalidTag:
        sys.exit("Ce n'est pas le bon code.")
    open(a.sortie, "wb").write(clair)
    print("Écrit :", a.sortie, len(clair), "octets")


def main():
    p = argparse.ArgumentParser(description="Verrou par code d'accès pour une appli d'une page")
    s = p.add_subparsers(dest="action", required=True)
    c = s.add_parser("chiffrer")
    c.add_argument("--source", required=True)
    c.add_argument("--sortie", required=True)
    c.add_argument("--app", required=True)
    c.add_argument("--titre", required=True)
    c.add_argument("--court", required=True)
    c.add_argument("--couleur", required=True)
    c.add_argument("--fond", default="#FFFFFF")
    c.add_argument("--texte-bouton", dest="texte_bouton", default="#FFFFFF")
    c.add_argument("--integrer", nargs="*", default=[])
    d = s.add_parser("dechiffrer")
    d.add_argument("--page", required=True)
    d.add_argument("--sortie", required=True)
    a = p.parse_args()
    chiffrer(a) if a.action == "chiffrer" else dechiffrer(a)


if __name__ == "__main__":
    main()
