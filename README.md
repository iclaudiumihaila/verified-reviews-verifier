# Verified Reviews — Verifier

Verifier standalone, zero-dependențe (Node 18+), pentru registrele publice de recenzii
din rețeaua **Primer Verified Reviews** (stadiu: pilot/demo).

## Utilizare

```bash
curl -O https://raw.githubusercontent.com/iclaudiumihaila/verified-reviews-verifier/main/verify.mjs
node verify.mjs https://<salon-sau-platforma>
# sau, doar chain-ul dintr-un export local:
node verify.mjs export.jsonl
```

Copia `verify.mjs` de aici trebuie să fie **byte-identică** cu cea servită de salon la
`/reviews/verify.mjs` — compară-le înainte de rulare.

## Ce verifică (fără să creadă nimic pe cuvânt)

1. Semnăturile Ed25519 ale documentelor publice (salon + platformă), cu cheile din JWKS.
2. Hash-chain-ul complet al registrului (SHA-256 peste canonical JSON, `sha256-canonicaljson-v2`).
3. `KEY_ANCHOR` — cheia publică a salonului e fixată în propriul chain (rotația e detectabilă).
4. `authorProof` — fiecare recenzie e semnată de dispozitivul clientului (registrul de dispozitive e semnat de salon).
5. Ancorele OpenTimestamps — **parse real al formatului `.ots`** (nu doar magic bytes):
   digest-ul din proof trebuie să fie exact root-ul publicat, operațiile sunt parcurse până la
   attestation, iar attestation-ul Bitcoin e coroborat cu un explorer public
   (`mempool.space/api/block-height/<h>` → hash → `/api/block/<hash>` → timestamp).
6. **Inclusion proof** — head-ul salonului este inclus în Merkle root-ul de rețea; salonul nu poate prezenta un ledger alternativ.
7. Contoarele publice (inclusiv cele economice: plăți, recurență) vs. registrul efectiv.
8. Reviewerii cu prezență la mai multe saloane — confirmați în chain-urile celorlalte saloane.

## Ce NU verifică (și spune explicit)

- **Ancore pending**: un attestation `PendingAttestation` (tag `83dfe30d2ef90c8e`) înseamnă
  SUBMITTED la calendar, în așteptarea confirmării Bitcoin (normal <24h) — **nu e eșec**.
  Verdictul final e atunci „VALID CRIPTOGRAFIC — ancorele Bitcoin sunt în așteptare",
  nu „TOTUL VALID". Verdictul „TOTUL VALID" apare doar când și ancorele sunt CONFIRMED.
- **Explorer inaccesibil**: dacă explorerul public nu răspunde, ancora e „neverificabil acum" — notă, nu eșec.
- **Afirmațiile salonului**: câmpurile `paidVisit`, `paymentMethod`, `returningClient`,
  `visitCount`, `reviewerSince` sunt declarate de salon (marcate în payload în
  `claimSource.salon`) — sunt înghețate în hash, dar neverificabile de un terț.
- **Independența operatorului de rețea**: în stadiul de pilot, rețeaua e operată de un singur
  operator; scriptul verifică criptografia, nu guvernanța.
- Niciodată scriptul nu raportează „valid" pentru verificări doar structurale (magic bytes,
  prezența unui substring).

## Formatul `.ots` (OpenTimestamps) — cum îl parsezi fără biblioteca oficială

Toate numerele multi-byte sunt **varuint** (7 biți/octet, bitul 8 = continuare):

```
offset 0:   magic de 31 bytes: 00 "OpenTimestamps" 00 00 "Proof" 00 bf89e2e884e89294
apoi:       varuint versiune (de regulă 01)
apoi:       08                — op-ul SHA256 (hash-ul fișierului timestampuit)
apoi:       digest (32 bytes) — trebuie să fie EXACT root-ul publicat în document
apoi:       operații, până la EOF:
  00        — attestation: tag (8 bytes) + varuint lungime + payload
  08        — aplică SHA256 peste mesajul curent
  02        — aplică RIPEMD160 peste mesajul curent
  f0 / f1   — prepend / append: varuint lungime + atâția bytes la mesaj
  ff        — fork: ramurile se serializează consecutiv
```

Tag-uri de attestation:

- `0588960d73d71901` — **BitcoinBlockHeader**: payload-ul este **doar un varuint cu block
  height-ul** (NU un block header de 80 bytes — header-ul nu mai e inclus din OTS 1.0 încoace).
- `83dfe30d2ef90c8e` — **PendingAttestation**: payload-ul este URI-ul calendarului
  (unele calendare îl serializează dublu-împachetat: varuint len + URI în interiorul
  payload-ului — tolerant la ambele variante).

**Atenție la re-interogare**: `GET /timestamp/<digest>` pe calendarele OTS publice întoarce
404 chiar și pentru digesturi reale deja trimise. Verificarea se face exclusiv din fișierul
proof `.ots` publicat alături de registru, nu prin re-interogarea calendarului.

## Formatul registrului

- Canonical JSON: chei sortate, fără whitespace; doar întregi, stringuri, boolean, null, array, obiect.
- Entry hash: `sha256(canonicalJson({algo, createdAt, kind, payloadHash, prevHash, reviewId, salonId, seq, supersedesReviewId}))`.
- Merkle: frunze `sha256(0x00 || canonicalJson({entryHash, salonId, seq}))`, noduri `sha256(0x01 || stânga || dreapta)`, nod impar promovat.
- Semnături: Ed25519 peste `canonicalJson(document fără câmpul signature)`.

Codul e neofuscat — citește-l înainte de rulare sau rescrie-l după specificația de mai sus.
