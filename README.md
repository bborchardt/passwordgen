Password Generator
==================
A simple web app that can be used to translate something you can remember to a website password. Useful for web sites that have overly restrictive password rules (such a limited password length or no support for special characters).

Everything happens in your browser. Nothing is stored and nothing is sent anywhere, so the same input always gives you the same password on any machine, with no vault to sync or lose.

Usage
-----
Open the app, type the phrase you remember, and give it the site you are making
a password for. The same phrase plus the same site always produces the same
password, on any machine, with nothing stored or synced.

- **Site** is what binds a password to one place. It is required: it is the
  reason a breach at one site does not expose the rest.
- **Username** is optional, for when you hold more than one account at a site.
- **Counter** starts at 1. Bump it when a site forces you to change a password;
  you get a fresh one without touching the phrase you memorised.
- **Include symbols** is on by default. Turn it off for sites that reject them
  — the original reason this tool exists.

Site and username are matched case-insensitively and trimmed, so `Gmail.com`
and `gmail.com ` give the same password rather than silently diverging.

Your master phrase is the whole security of this scheme, so the app shows what
it is worth. The estimate is deliberately pessimistic and errs low.

How it works
------------
    salt   = "passwordgen/v2" + site + username + counter   (length-prefixed)
    seed   = PBKDF2-HMAC-SHA256(phrase, salt, 4,000,000 iterations)
    stream = HKDF-SHA256(seed)
    password = rejection-sample(stream) into the chosen alphabet,
               one character guaranteed from each class, then shuffled

PBKDF2 runs natively through WebCrypto, so 4,000,000 iterations costs about
0.7s rather than the minutes the old in-JavaScript implementation would need.
Only one 32-byte block is derived from it; the character stream is expanded
cheaply with HKDF. Deriving the whole stream from PBKDF2 directly would re-run
every iteration per block and make long passwords cost seconds.

Rejection sampling means every character is uniform over the alphabet — taking
a byte modulo the alphabet size would quietly favour its first few characters.
Class coverage comes from placing one character of each class and shuffling,
never from v1's retry rule, which made two different phrases collide.

**WebCrypto requires a secure context**, so v2 needs the page served over HTTPS
(localhost and `file://` also qualify). v1 works anywhere.

Migrating from v1
-----------------
v2 produces different passwords from v1 — that is the point of it. Existing
passwords are not broken and not rewritten: tick **Use the old scheme (v1)** to
reproduce anything you generated before, so you can sign in and change it over
at your own pace.

There is no marker in a generated password saying which scheme made it, and
there cannot be retroactively — v1 recorded nothing. Only you know which of
your accounts are still on v1.

Deploying
---------
`.github/workflows/ci.yml` publishes the `web/` directory to GitHub Pages on
every push to `master`, but only after the test suite passes on all three Node
versions — the site is never published from a red build. Pages is served from
the workflow artifact, so no `gh-pages` branch is involved.

To serve it anywhere else, the app is just static files: point any web server at
`web/`.

**Serve it over HTTPS.** The entire security of this tool rests on your browser
running exactly this code. Over plain HTTP anyone on the network can replace the
scripts with a version that keeps a copy of your passphrase, and nothing in the
page can prevent that. GitHub Pages serves HTTPS; leave "Enforce HTTPS" on.

The page ships a Content Security Policy that denies it any means of sending
data out (`connect-src 'none'`, `form-action 'none'`), so its "nothing leaves
your browser" claim can be checked rather than taken on faith. That policy works
from the `<meta>` tag and so applies on Pages.

Two things cannot be done from a `<meta>` tag, and GitHub Pages does not allow
custom response headers, so neither is available there:

- `Content-Security-Policy: frame-ancestors 'none'`. The practical exposure is
  small — a page that frames this one still cannot read across origins — but the
  framing itself cannot be refused on Pages. Behind a server or CDN you control,
  send the header.
- `Strict-Transport-Security`. Not needed for the default domain: `github.io` is
  on the browsers' HSTS preload list, so HTTPS is already forced. A **custom
  domain is not preloaded**, so if you point one at this site, put a CDN or proxy
  in front to add HSTS, or accept that the first request can be downgraded.

No vendored crypto
------------------
Both schemes derive entirely through the browser's native [Web Crypto
API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
(`crypto.subtle`) — PBKDF2, HKDF, and SHA-256 all come from the browser
engine itself. Nothing here is a third-party library: there is no
JavaScript crypto implementation in this repo to vendor, pin, or audit.

v1 previously ran its PBKDF2 step through a trimmed, unversioned build of
the Stanford Javascript Crypto Library (`web/js/sjcl.js`) that had no
retained version banner and couldn't be pinned to an upstream release from
the compiled artifact alone. It's been replaced with the same
`crypto.subtle` PBKDF2-HMAC-SHA256 call v2 already used: PBKDF2 is a
deterministic standard, so for the same password, salt, iteration count,
and hash, any correct implementation produces the same bytes. That's
exactly what `test/v1-vectors.json` confirms — the golden vectors generated
against the old SJCL implementation still pass unchanged.

Known limitations
-----------------
**v2**

- The salt is built from the site and username, which an attacker can guess. It
  stops one precomputation from covering every user and every site, but it does
  not stop someone targeting *you* specifically. Against that, the cost of
  PBKDF2 and the strength of your phrase are the only defences — which is why
  the meter is there.
- PBKDF2 is not memory-hard, so GPUs remain considerably more efficient at
  attacking it than your browser is at running it. Argon2id would narrow that
  gap, at the cost of a vendored WebAssembly binary nobody can read and a
  loosened Content Security Policy. Passphrase entropy was judged the better
  place to spend the effort: going from a weak phrase to a good one is worth
  far more than the change of algorithm.
- The strength meter has no dictionary. It charges every run of letters as
  though an attacker already knows the word, which under-rates genuinely random
  phrases, and it does not recognise common *phrases* — "my dog has fleas"
  scores as four independent words. Treat it as a floor, not a verdict.
- Everything about the derivation is frozen. The iteration count, the
  alphabets, the salt encoding and the shuffle are all part of the contract;
  changing any of them changes every password.

**v1** (kept only so old passwords stay reachable)

- The same phrase gives the same password on every site.
- The salt is a single public constant shared by every user.
- Phrase `X` and phrase `X1` collide whenever `X` fails the character-mix
  check — roughly 43% of inputs at its default length of 12.
- 100,000 PBKDF2 iterations in JavaScript, well below current guidance.
