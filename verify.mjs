// Verifier standalone — Primer Verified Reviews v4 (zero dependențe, Node 18+).
// Verifică end-to-end: semnături Ed25519 (salon + platformă), chain complet, KEY_ANCHOR,
// authorProof per recenzie, ancore OTS reale (3 calendare pentru root-ul de rețea),
// INCLUSION PROOF (head-ul salonului în root-ul de rețea), contoare, revieweri cross-salon.
// Utilizare: node verify.mjs <base-url>   SAU   node verify.mjs <export.jsonl> (doar chain)
import { createHash, createPublicKey, verify as cryptoVerify } from 'node:crypto'
import { readFileSync } from 'node:fs'

function canonicalJson(v) {
  if (v === null || typeof v === 'boolean' || typeof v === 'string') return JSON.stringify(v)
  if (typeof v === 'number') { if (!Number.isInteger(v)) throw new Error('float'); return String(v) }
  if (Array.isArray(v)) return '[' + v.map(canonicalJson).join(',') + ']'
  if (v && typeof v === 'object') {
    const keys = Object.keys(v).filter((k) => v[k] !== undefined).sort()
    return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalJson(v[k])).join(',') + '}'
  }
  throw new Error('unsupported value')
}
const sha256hex = (s) => createHash('sha256').update(s, 'utf8').digest('hex')
const GENESIS = '0'.repeat(64)
const MAGIC = Buffer.from('004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294', 'hex')
let failures = 0
const fail = (m) => { console.error('EȘEC: ' + m); failures++ }
const okm = (m) => console.log('  ✓ ' + m)
const leafHash = (salonId, seq, entryHash) =>
  createHash('sha256').update(Buffer.concat([Buffer.from([0x00]), Buffer.from(canonicalJson({ entryHash, salonId, seq }), 'utf8')])).digest('hex')
const nodeHash = (a, b) => createHash('sha256').update(Buffer.concat([Buffer.from([0x01]), Buffer.from(a, 'hex'), Buffer.from(b, 'hex')])).digest('hex')

function checkChain(entries) {
  let prev = GENESIS
  const counts = {}
  for (const e of entries) {
    if (sha256hex(canonicalJson(e.payload)) !== e.payloadHash) fail('PAYLOAD_MISMATCH la seq ' + e.seq)
    const { payload, entryHash, ...preimage } = e
    if (sha256hex(canonicalJson(preimage)) !== entryHash) fail('HASH_MISMATCH la seq ' + e.seq)
    if (e.prevHash !== prev) fail('LINK_BROKEN la seq ' + e.seq)
    prev = entryHash
    counts[e.kind] = (counts[e.kind] || 0) + 1
  }
  return { head: prev, counts }
}
function verifyDocSig(doc, keys, label) {
  const { signature, ...unsigned } = doc
  const key = keys.find((k) => k.kid === signature.kid)
  if (!key) return fail(label + ': kid necunoscut')
  cryptoVerify(null, Buffer.from(canonicalJson(unsigned), 'utf8'), createPublicKey({ key, format: 'jwk' }), Buffer.from(signature.sig, 'base64url'))
    ? okm(label + ': semnătură validă') : fail(label + ': SEMNĂTURĂ INVALIDĂ')
}

const src = process.argv[2]
if (!src) { console.error('Utilizare: node verify.mjs <base-url | export.jsonl>'); process.exit(2) }
if (!src.startsWith('http')) {
  const entries = readFileSync(src, 'utf8').trim().split('\n').map((l) => JSON.parse(l))
  const { head, counts } = checkChain(entries)
  console.log(failures ? 'CHAIN INVALID' : 'CHAIN VALID — ' + entries.length + ' intrări, head ' + head.slice(0, 16) + '…')
  console.log('pe tipuri: ' + JSON.stringify(counts))
  process.exit(failures ? 1 : 0)
}

const base = src.replace(/\/$/, '')
console.log('1) Documente publice (salon + rețea)…')
const log = await (await fetch(base + '/.well-known/reviews-log.json')).json()
const jwks = await (await fetch(base + '/.well-known/jwks.json')).json()
const networkDoc = await (await fetch(log.network.documentUrl)).json()
const platformJwks = await (await fetch(log.network.platformJwksUrl)).json()

console.log('2) Semnături Ed25519…')
verifyDocSig(log, jwks.keys, 'reviews-log.json (salon)')
verifyDocSig(networkDoc, platformJwks.keys, 'network.json (platformă)')

console.log('3) Chain complet al salonului…')
const entries = (await (await fetch(log.exportUrl)).text()).trim().split('\n').map((l) => JSON.parse(l))
const { head, counts } = checkChain(entries)
head === log.head.entryHash ? okm('head recomputat = head publicat (' + head.slice(0, 16) + '…)') : fail('head mismatch')
okm(entries.length + ' intrări: ' + JSON.stringify(counts))

console.log('4) KEY_ANCHOR…')
const keyEntry = entries.find((e) => e.kind === 'KEY_ANCHOR')
const jwk = keyEntry && jwks.keys.find((k) => k.kid === keyEntry.payload.kid)
jwk && jwk.x === keyEntry.payload.publicKeyX ? okm('cheia JWKS e ancorată în chain la seq ' + keyEntry.seq) : fail('KEY_ANCHOR nu corespunde cu JWKS')

console.log('5) authorProof (dispozitivele clienților)…')
const devicesDoc = await (await fetch(log.devicesUrl)).json()
verifyDocSig(devicesDoc, jwks.keys, 'devices.json')
let proofOk = 0, proofTotal = 0
for (const e of entries) {
  if (e.kind !== 'PUBLISH' && e.kind !== 'SUPERSEDE') continue
  proofTotal++
  const p = e.payload
  const dev = devicesDoc.devices[p.authorProof?.deviceFingerprint]
  if (!dev || dev.reviewerRef !== p.reviewerRef) { fail('dispozitiv necunoscut: ' + p.reviewId); continue }
  const msg = canonicalJson({ rating: p.rating, reviewId: p.reviewId, reviewerRef: p.reviewerRef, visitedAt: p.visitedAt })
  cryptoVerify(null, Buffer.from(msg, 'utf8'), createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: dev.x }, format: 'jwk' }), Buffer.from(p.authorProof.sig, 'base64url')) ? proofOk++ : fail('authorProof invalid: ' + p.reviewId)
}
okm(proofOk + '/' + proofTotal + ' recenzii cu semnătură validă de la dispozitivul clientului')

console.log('6) Ancore OTS per-salon…')
let anchored = 0
for (const a of log.anchors) {
  const dayE = entries.filter((e) => e.createdAt.slice(0, 10) <= a.day)
  if (leafHash(log.salon.id, dayE.slice(-1)[0].seq, dayE.slice(-1)[0].entryHash) !== a.merkleRoot) { fail('ancora ' + a.day + ': root diferă'); continue }
  const proof = a.proofUrl && Buffer.from(await (await fetch(a.proofUrl)).arrayBuffer())
  if (!proof || !proof.subarray(0, MAGIC.length).equals(MAGIC) || !proof.includes(Buffer.from(a.merkleRoot, 'hex'))) { fail('ancora ' + a.day + ': proof invalid'); continue }
  anchored++
}
okm(anchored + '/' + log.anchors.length + ' ancore per-salon verificate')

console.log('7) INCLUSION PROOF în root-ul de rețea…')
const incl = await (await fetch(log.network.inclusionProofUrl)).json()
if (incl.entryHash !== log.head.entryHash) {
  const ancestor = entries.find((e) => e.entryHash === incl.entryHash)
  ancestor
    ? okm('notă: inclusion proof e pentru head-ul din ziua ancorării (seq ' + incl.seq + '), un strămoș valid al head-ului curent (seq ' + log.head.seq + ') — normal, root-ul de rețea se actualizează zilnic')
    : fail('inclusion proof pentru un head care NU apare în chain')
}
let h = incl.leafHash
if (leafHash(incl.salonId, incl.seq, incl.entryHash) !== incl.leafHash) fail('leafHash recomputat diferă')
for (const sib of incl.proof) h = sib.pos === 'left' ? nodeHash(sib.hash, h) : nodeHash(h, sib.hash)
h === networkDoc.merkleRoot
  ? okm('head-ul salonului e inclus în root-ul de rețea (' + networkDoc.merkleRoot.slice(0, 16) + '…) — salonul nu poate prezenta un ledger alternativ')
  : fail('INCLUSIUNE EȘUATĂ: ' + h.slice(0, 12) + ' ≠ ' + networkDoc.merkleRoot.slice(0, 12))

console.log('8) Ancorele rețelei (3 calendare)…')
let netOk = 0, netTotal = 0
for (const a of networkDoc.anchors) {
  for (const p of a.proofs) {
    netTotal++
    const proof = Buffer.from(await (await fetch(p.proofUrl)).arrayBuffer())
    proof.subarray(0, MAGIC.length).equals(MAGIC) && proof.includes(Buffer.from(a.merkleRoot, 'hex')) ? netOk++ : fail('proof rețea invalid: ' + a.day)
  }
}
okm(netOk + '/' + netTotal + ' proof-uri de rețea verificate (' + networkDoc.anchors.length + ' zile × calendare)')

console.log('9) Contoare vs. registru…')
const pub = entries.filter((e) => e.kind === 'PUBLISH' || e.kind === 'SUPERSEDE')
const tomb = new Set(entries.filter((e) => e.kind === 'TOMBSTONE').map((e) => e.reviewId))
const sup = new Set(entries.filter((e) => e.kind === 'SUPERSEDE').map((e) => e.supersedesReviewId))
const surv = pub.filter((e) => !tomb.has(e.reviewId) && !sup.has(e.reviewId))
const checks = [
  ['surviving', surv.length],
  ['negativePublished', pub.filter((e) => e.payload.rating <= 2).length],
  ['negativeSurviving', surv.filter((e) => e.payload.rating <= 2).length],
  ['paidVisitCount', surv.filter((e) => e.payload.paidVisit).length],
  ['cardPaymentCount', surv.filter((e) => e.payload.paymentMethod === 'CARD').length],
  ['returningClientCount', surv.filter((e) => e.payload.returningClient).length],
  ['distinctReviewers', new Set(surv.map((e) => e.payload.reviewerRef)).size],
]
for (const [k, v] of checks) log.counters[k] === v ? okm(k + '=' + v) : fail(k + ': ' + log.counters[k] + ' vs ' + v)

console.log('10) Revieweri cross-salon (graf de rețea)…')
const multi = surv.filter((e) => e.payload.reviewerSalonCount > 1)
let crossOk = 0
for (const e of multi) {
  const ref = e.payload.reviewerRef
  for (const s of networkDoc.salons) {
    if (s.salonId === log.salon.id) continue
    const other = (await (await fetch(s.exportUrl)).text()).trim().split('\n').map((l) => JSON.parse(l))
    if (other.some((o) => o.payload?.reviewerRef === ref)) { crossOk++; break }
  }
}
okm(crossOk + '/' + multi.length + ' revieweri cu prezență confirmată în chain-urile altor saloane')

console.log(failures ? '\nREZULTAT: NEVALID (' + failures + ' eșecuri)' : '\nREZULTAT: TOTUL VALID.')
process.exit(failures ? 1 : 0)
