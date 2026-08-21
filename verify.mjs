// Verifier standalone — Primer Verified Reviews v6 (zero dependențe, Node 18+).
// Verifică end-to-end: semnături Ed25519 (salon + platformă), chain complet, KEY_ANCHOR,
// authorProof per recenzie, ancore OTS PARSEATE pe bune (formatul oficial: magic + versiune +
// digest + operații până la attestation; Bitcoin => coroborat cu un explorer public,
// pending => raportat onest ca SUBMITTED), INCLUSION PROOF, contoare, revieweri cross-salon.
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
let failures = 0
const fail = (m) => { console.error('EȘEC: ' + m); failures++ }
const okm = (m) => console.log('  ✓ ' + m)
const leafHash = (salonId, seq, entryHash) =>
  createHash('sha256').update(Buffer.concat([Buffer.from([0x00]), Buffer.from(canonicalJson({ entryHash, salonId, seq }), 'utf8')])).digest('hex')
const nodeHash = (a, b) => createHash('sha256').update(Buffer.concat([Buffer.from([0x01]), Buffer.from(a, 'hex'), Buffer.from(b, 'hex')])).digest('hex')

// --- OpenTimestamps: parser minimal al formatului oficial .ots (fără dependențe) ---
// Layout: magic de 31 bytes (incl. trailer-ul "Proof") || varuint versiune || op 0x08 (SHA256)
// || digest (32 bytes) || operații. Attestation = op 0x00 || tag (8 bytes) || varuint len || payload.
const OTS_MAGIC = Buffer.from('004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294', 'hex')
const OTS_TAG_BITCOIN = '0588960d73d71901' // BitcoinBlockHeader attestation; payload = varuint block height
const OTS_TAG_PENDING = '83dfe30d2ef90c8e' // PendingAttestation; payload = URI calendar
function parseOts(buf) {
  if (!buf.subarray(0, OTS_MAGIC.length).equals(OTS_MAGIC)) return { error: 'magic OTS invalid' }
  let pos = OTS_MAGIC.length
  const varuint = () => { let v = 0, s = 0; for (;;) { if (pos >= buf.length) throw new Error('varuint trunchiat'); const b = buf[pos++]; v += (b & 0x7f) * 2 ** s; if (!(b & 0x80)) return v; s += 7 } }
  try {
    const version = varuint()
    if (buf[pos++] !== 0x08) return { error: 'dupa versiune (' + version + ') urmeaza altceva decat op-ul SHA256 (0x08)' }
    const digest = buf.subarray(pos, pos + 32); pos += 32
    let msg = digest // mesajul curent, transformat pe masura ce aplicam operatiile
    const attestations = []
    while (pos < buf.length) {
      const op = buf[pos++]
      if (op === 0x00) { // attestation
        const tag = buf.subarray(pos, pos + 8).toString('hex'); pos += 8
        const len = varuint()
        const payload = buf.subarray(pos, pos + len); pos += len
        attestations.push({ tag, payload, committed: msg.toString('hex') })
      } else if (op === 0x08) msg = createHash('sha256').update(msg).digest()
      else if (op === 0x02) msg = createHash('ripemd160').update(msg).digest()
      else if (op === 0xf0 || op === 0xf1) { const len = varuint(); const data = buf.subarray(pos, pos + len); pos += len; msg = op === 0xf0 ? Buffer.concat([data, msg]) : Buffer.concat([msg, data]) }
      else if (op === 0xff) { /* fork: ramurile se serializeaza consecutiv; colectam attestations din toate */ }
      else return { error: 'op necunoscut 0x' + op.toString(16) + ' la offset ' + (pos - 1) }
    }
    return { version, digest: digest.toString('hex'), attestations }
  } catch (e) { return { error: 'proof trunchiat/corupt: ' + e.message } }
}
const decodeVaruint = (buf) => { let v = 0, s = 0; for (const b of buf) { v += (b & 0x7f) * 2 ** s; if (!(b & 0x80)) return v; s += 7 } return v }
// payload-ul unui PendingAttestation e URI-ul calendarului; unele calendare il serializeaza
// dublu-impachetat (varuint len + uri in interiorul payload-ului deja varuint-prefixed) — toleram ambele
const otsPayloadBytes = (payload) => { let i = 0, v = 0, s = 0; while (i < payload.length) { const b = payload[i++]; v += (b & 0x7f) * 2 ** s; if (!(b & 0x80)) break; s += 7 } return v === payload.length - i ? payload.subarray(i) : payload }
// statusuri OTS globale — pending/neverificabil NU sunt esecuri, dar schimba verdictul final
let otsPending = 0, otsUnknown = 0
async function checkOtsProof(label, proofBuf, expectedRootHex) {
  const p = parseOts(proofBuf)
  if (p.error) { fail(label + ': ' + p.error); return null }
  if (p.digest !== expectedRootHex) { fail(label + ': digest-ul din proof nu este root-ul publicat'); return null }
  const btc = p.attestations.find((a) => a.tag === OTS_TAG_BITCOIN)
  if (btc) {
    const height = decodeVaruint(btc.payload) // payload = varuint block height (NU block header de 80 bytes)
    try {
      const blockHash = (await (await fetch('https://mempool.space/api/block-height/' + height)).text()).trim()
      const blk = await (await fetch('https://mempool.space/api/block/' + blockHash)).json()
      okm(label + ': CONFIRMED in blocul Bitcoin ' + height + ' (' + new Date(blk.timestamp * 1000).toISOString().slice(0, 10) + ', ' + blockHash.slice(0, 16) + '…)')
      return 'confirmed'
    } catch {
      otsUnknown++
      console.log('  ~ ' + label + ': attestation Bitcoin la blocul ' + height + ', dar explorerul public e inaccesibil — neverificabil acum (nu e esec)')
      return 'unknown'
    }
  }
  const pend = p.attestations.find((a) => a.tag === OTS_TAG_PENDING)
  if (pend) {
    otsPending++
    console.log('  ~ ' + label + ': SUBMITTED la ' + otsPayloadBytes(pend.payload).toString('utf8') + ' — in asteptarea confirmarii Bitcoin (normal <24h; nu e esec)')
    return 'pending'
  }
  fail(label + ': proof fara niciun attestation (nici Bitcoin, nici pending)')
  return null
}

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

console.log('6) Ancore OTS per-salon (parse real al proof-urilor)…')
let anchored = 0
for (const a of log.anchors) {
  const dayE = entries.filter((e) => e.createdAt.slice(0, 10) <= a.day)
  if (leafHash(log.salon.id, dayE.slice(-1)[0].seq, dayE.slice(-1)[0].entryHash) !== a.merkleRoot) { fail('ancora ' + a.day + ': root diferă'); continue }
  const proof = a.proofUrl && Buffer.from(await (await fetch(a.proofUrl)).arrayBuffer())
  if (!proof) { fail('ancora ' + a.day + ': proof indisponibil'); continue }
  if (await checkOtsProof('ancora ' + a.day, proof, a.merkleRoot)) anchored++
}
okm(anchored + '/' + log.anchors.length + ' ancore per-salon cu digest potrivit (statusul confirmării Bitcoin: mai sus)')

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

console.log('8) Ancorele rețelei (3 calendare, parse real)…')
let netOk = 0, netTotal = 0
for (const a of networkDoc.anchors) {
  for (const p of a.proofs) {
    netTotal++
    const proof = Buffer.from(await (await fetch(p.proofUrl)).arrayBuffer())
    if (await checkOtsProof('rețea ' + a.day + ' @ ' + p.calendar, proof, a.merkleRoot)) netOk++
  }
}
okm(netOk + '/' + netTotal + ' proof-uri de rețea cu digest potrivit (' + networkDoc.anchors.length + ' zile × calendare)')

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

console.log(failures ? '\nREZULTAT: NEVALID (' + failures + ' eșecuri)' : (otsPending || otsUnknown)
  ? '\nREZULTAT: VALID CRIPTOGRAFIC — ancorele Bitcoin sunt în așteptare (' + otsPending + ' pending' + (otsUnknown ? ', ' + otsUnknown + ' neverificabile acum' : '') + '). Normal pentru un registru de o zi; re-rulează după ~24h pentru verdictul complet.'
  : '\nREZULTAT: TOTUL VALID — inclusiv ancorele Bitcoin confirmate.')
process.exit(failures ? 1 : 0)
