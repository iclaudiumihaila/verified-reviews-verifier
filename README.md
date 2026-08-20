# Verified Reviews — Verifier

Verifier standalone, zero-dependențe (Node 18+), pentru registrele publice de recenzii
din rețeaua **Primer Verified Reviews**.

## Utilizare

```bash
curl -O https://raw.githubusercontent.com/iclaudiumihaila/verified-reviews-verifier/main/verify.mjs
node verify.mjs https://<salon-sau-platforma>
# sau, doar chain-ul dintr-un export local:
node verify.mjs export.jsonl
```

## Ce verifică (fără să creadă nimic pe cuvânt)

1. Semnăturile Ed25519 ale documentelor publice (salon + platformă), cu cheile din JWKS.
2. Hash-chain-ul complet al registrului (SHA-256 peste canonical JSON, `sha256-canonicaljson-v2`).
3. `KEY_ANCHOR` — cheia publică a salonului e fixată în propriul chain (rotația e detectabilă).
4. `authorProof` — fiecare recenzie e semnată de dispozitivul clientului (registrul de dispozitive e semnat de salon).
5. Ancorele OpenTimestamps zilnice per salon (digest recomputat = digest din proof-ul `.ots`).
6. **Inclusion proof** — head-ul salonului este inclus în Merkle root-ul de rețea; salonul nu poate prezenta un ledger alternativ.
7. Ancorele root-ului de rețea pe 3 calendare OTS independente.
8. Contoarele publice (inclusiv cele economice: plăți, recurență) vs. registrul efectiv.
9. Reviewerii cu prezență la mai multe saloane — confirmați în chain-urile celorlalte saloane.

## Format

- Canonical JSON: chei sortate, fără whitespace; doar întregi, stringuri, boolean, null, array, obiect.
- Entry hash: `sha256(canonicalJson({algo, createdAt, kind, payloadHash, prevHash, reviewId, salonId, seq, supersedesReviewId}))`.
- Merkle: frunze `sha256(0x00 || canonicalJson({entryHash, salonId, seq}))`, noduri `sha256(0x01 || stânga || dreapta)`, nod impar promovat.
- Semnături: Ed25519 peste `canonicalJson(document fără câmpul signature)`.

Codul are ~200 de linii, neofuscate — citește-l înainte de rulare sau rescrie-l după specificația de mai sus.
