import {
  createCipheriv,
  createDecipheriv,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  randomBytes,
  type KeyObject
} from 'node:crypto'
import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import type { Socket } from 'node:net'
import { CAPS, MSG_TYPES, type EncField, type Envelope, type Profile, type TcpFrame } from '../../shared/protocol'

/** Node 16 无 type:'raw' 的 X25519 导入，需包一层 DER 前缀。 */
const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex')
const X25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b656e04220420', 'hex')

const ENC_INFO_PREFIX = Buffer.from('teahouse-enc1-v1')
const TCP_INFO_PREFIX = Buffer.from('teahouse-tcp-enc1-v1')
const TCP_RECORD_AAD = Buffer.from('teahouse-tcp-rec1')
const MAX_RECORD_PLAIN = 64 * 1024
const MAX_RECORD_BODY = 12 + 16 + MAX_RECORD_PLAIN
const IDENTITY_FILE = 'enc-identity.json'

export const ENCRYPTED_TYPES = new Set<string>([
  MSG_TYPES.msg,
  MSG_TYPES.fileCtl,
  MSG_TYPES.group,
  MSG_TYPES.avatar,
  MSG_TYPES.share,
  MSG_TYPES.screen
])

export type { EncField }

export interface EncIdentity {
  nodeId: string
  publicB64: string
  privateKey: KeyObject
  publicKey: KeyObject
}

export type EncDecryptor = (
  enc: EncField,
  meta: { id: string; from: string; type: string; ts: number }
) => { ok: true; payload: unknown } | { ok: false }

export interface TcpE2eContext {
  identity: EncIdentity
  lookupPeer: (nodeId: string) => { encPub?: string; caps: string[] } | undefined
}

interface IdentityFile {
  nodeId: string
  secret: string
  public: string
}

export function isRawEncPubB64(value: unknown): value is string {
  if (typeof value !== 'string' || value.length !== 44 || !/^[A-Za-z0-9+/]{43}=$/.test(value)) return false
  try {
    return Buffer.from(value, 'base64').length === 32
  } catch {
    return false
  }
}

export function parseEncPub(value: unknown): Buffer | null {
  if (!isRawEncPubB64(value)) return null
  const raw = Buffer.from(value, 'base64')
  return raw.length === 32 ? raw : null
}

export function generateEncIdentity(nodeId: string): EncIdentity {
  const pair = generateKeyPairSync('x25519')
  return fromKeyPair(nodeId, pair.privateKey, pair.publicKey)
}

export function loadEncIdentity(dir: string, nodeId: string): { identity: EncIdentity; created: boolean } {
  const path = join(dir, IDENTITY_FILE)
  if (existsSync(path)) {
    try {
      const raw = JSON.parse(readFileSync(path, 'utf8')) as IdentityFile
      if (raw && raw.nodeId === nodeId && isRawEncPubB64(raw.public) && typeof raw.secret === 'string') {
        const sk = Buffer.from(raw.secret, 'base64')
        if (sk.length === 32) {
          return { identity: fromRaw(nodeId, sk, Buffer.from(raw.public, 'base64')), created: false }
        }
      }
    } catch {
      // 损坏或与当前 nodeId 不匹配时重新生成
    }
  }
  const identity = generateEncIdentity(nodeId)
  writeEncIdentity(path, identity)
  return { identity, created: true }
}

export function makeEnvelopeDecryptor(identity: EncIdentity): EncDecryptor {
  return (enc, meta) => decryptPayload(enc, meta, identity)
}

export function peerEncPub(profile: Profile | undefined): Buffer | null {
  if (!profile || !profile.caps.includes(CAPS.e2e)) return null
  return parseEncPub(profile.encPub)
}

export function sealIfNeeded(
  env: Envelope,
  to: string,
  profile: Profile | undefined,
  _identity: EncIdentity
): Envelope {
  if (!ENCRYPTED_TYPES.has(env.type)) return env
  const pub = peerEncPub(profile)
  if (!pub) return env
  const enc = encryptPayload(env.payload, { id: env.id, from: env.from, type: env.type, ts: env.ts, to }, pub)
  return { v: env.v, type: env.type, id: env.id, from: env.from, ts: env.ts, enc } as Envelope
}

export function encryptPayload(
  payload: unknown,
  meta: { id: string; from: string; type: string; ts: number; to: string },
  peerPub: Buffer
): EncField {
  const eph = generateKeyPairSync('x25519')
  const ephRaw = rawPublicKey(eph.publicKey)
  const shared = Buffer.from(
    diffieHellman({ privateKey: eph.privateKey, publicKey: publicFromRaw(peerPub) })
  )
  const key = Buffer.from(hkdfSync('sha256', shared, ephRaw, bindInfo(meta.from, meta.to), 32))
  const nonce = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', key, nonce)
  cipher.setAAD(makeAad(meta))
  const body = Buffer.from(JSON.stringify(payload), 'utf8')
  const ct = Buffer.concat([cipher.update(body), cipher.final(), cipher.getAuthTag()])
  return { v: 1, eph: ephRaw.toString('base64'), n: nonce.toString('base64'), ct: ct.toString('base64') }
}

export function decryptPayload(
  enc: EncField,
  meta: { id: string; from: string; type: string; ts: number },
  identity: EncIdentity
): { ok: true; payload: unknown } | { ok: false } {
  try {
    if (enc.v !== 1) return { ok: false }
    const ephRaw = Buffer.from(enc.eph, 'base64')
    const nonce = Buffer.from(enc.n, 'base64')
    const packed = Buffer.from(enc.ct, 'base64')
    if (ephRaw.length !== 32 || nonce.length !== 12 || packed.length < 17) return { ok: false }
    const shared = Buffer.from(
      diffieHellman({ privateKey: identity.privateKey, publicKey: publicFromRaw(ephRaw) })
    )
    const key = Buffer.from(hkdfSync('sha256', shared, ephRaw, bindInfo(meta.from, identity.nodeId), 32))
    const tag = packed.subarray(packed.length - 16)
    const ct = packed.subarray(0, packed.length - 16)
    const decipher = createDecipheriv('aes-256-gcm', key, nonce)
    decipher.setAAD(makeAad({ ...meta, to: identity.nodeId }))
    decipher.setAuthTag(tag)
    const plain = Buffer.concat([decipher.update(ct), decipher.final()])
    return { ok: true, payload: JSON.parse(plain.toString('utf8')) }
  } catch {
    return { ok: false }
  }
}

export function validateEncField(value: unknown): value is EncField {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false
  const enc = value as Partial<EncField>
  if (enc.v !== 1) return false
  if (!isRawEncPubB64(enc.eph)) return false
  if (!isB64Len(enc.n, 12)) return false
  if (typeof enc.ct !== 'string' || enc.ct.length === 0 || enc.ct.length > 96 * 1024) return false
  if (enc.ct.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(enc.ct)) return false
  try {
    const raw = Buffer.from(enc.ct, 'base64')
    const padding = enc.ct.endsWith('==') ? 2 : enc.ct.endsWith('=') ? 1 : 0
    return raw.length >= 17 && raw.length === (enc.ct.length / 4) * 3 - padding
  } catch {
    return false
  }
}

function encodeControl(frame: TcpFrame): Buffer {
  const body = Buffer.from(JSON.stringify(frame), 'utf8')
  const head = Buffer.alloc(4)
  head.writeUInt32BE(body.length)
  return Buffer.concat([head, body])
}

export async function startTcpClientEncryption(
  socket: Socket,
  opts: { identity: EncIdentity; peerId: string; peerPub: Buffer }
): Promise<void> {
  const eph = generateKeyPairSync('x25519')
  const clientNonce = randomBytes(16)
  const hello: TcpFrame = {
    type: 'enc-hello',
    v: 1,
    from: opts.identity.nodeId,
    eph: rawPublicKey(eph.publicKey).toString('base64'),
    n: clientNonce.toString('base64')
  }
  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => finish(new Error('enc-handshake-timeout')), 10_000)
    const onError = (): void => finish(new Error('enc-handshake'))
    const finish = (err?: Error): void => {
      clearTimeout(timer)
      socket.off('data', onData)
      socket.off('error', onError)
      socket.off('close', onError)
      if (err) reject(err)
      else resolve()
    }
    let pending = Buffer.alloc(0)
    const onData = (chunk: Buffer): void => {
      pending = pending.length === 0 ? chunk : Buffer.concat([pending, chunk])
      if (pending.length < 4) return
      const len = pending.readUInt32BE(0)
      if (len === 0 || len > 64 * 1024) {
        finish(new Error('enc-handshake'))
        return
      }
      if (pending.length < 4 + len) return
      if (pending.length > 4 + len) {
        finish(new Error('enc-handshake'))
        return
      }
      let raw: unknown
      try {
        raw = JSON.parse(pending.subarray(4, 4 + len).toString('utf8'))
      } catch {
        finish(new Error('enc-handshake'))
        return
      }
      if (!isRecord(raw) || raw.type !== 'enc-ok' || raw.v !== 1) {
        finish(new Error('enc-handshake'))
        return
      }
      const serverEph = parseEncPub(raw.eph)
      const serverNonce = typeof raw.n === 'string' ? Buffer.from(raw.n, 'base64') : null
      if (!serverEph || !serverNonce || serverNonce.length !== 16) {
        finish(new Error('enc-handshake'))
        return
      }
      try {
        const keys = deriveTcpKeys({
          ephPrivate: eph.privateKey,
          ephPublic: eph.publicKey,
          peerEph: serverEph,
          staticPrivate: opts.identity.privateKey,
          staticPublic: opts.identity.publicKey,
          peerStatic: opts.peerPub,
          clientNonce,
          serverNonce,
          clientId: opts.identity.nodeId,
          serverId: opts.peerId,
          role: 'client'
        })
        installTcpRecordLayer(socket, keys.c2s, keys.s2c)
        finish()
      } catch {
        finish(new Error('enc-handshake'))
      }
    }
    socket.on('data', onData)
    socket.once('error', onError)
    socket.once('close', onError)
    socket.write(encodeControl(hello))
  })
}

export function acceptTcpServerEncryption(
  frame: TcpFrame,
  socket: Socket,
  ctx: TcpE2eContext
): boolean {
  if (frame.type !== 'enc-hello') return false
  const peerPub = (() => {
    const peer = ctx.lookupPeer(frame.from)
    if (!peer || !peer.caps.includes(CAPS.e2e)) return null
    return parseEncPub(peer.encPub)
  })()
  const clientEph = parseEncPub(frame.eph)
  const clientNonce = Buffer.from(frame.n, 'base64')
  if (!peerPub || !clientEph || clientNonce.length !== 16) {
    socket.destroy()
    return true
  }
  try {
    const eph = generateKeyPairSync('x25519')
    const serverNonce = randomBytes(16)
    const keys = deriveTcpKeys({
      ephPrivate: eph.privateKey,
      ephPublic: eph.publicKey,
      peerEph: clientEph,
      staticPrivate: ctx.identity.privateKey,
      staticPublic: ctx.identity.publicKey,
      peerStatic: peerPub,
      clientNonce,
      serverNonce,
      clientId: frame.from,
      serverId: ctx.identity.nodeId,
      role: 'server'
    })
    const ok: TcpFrame = {
      type: 'enc-ok',
      v: 1,
      eph: rawPublicKey(eph.publicKey).toString('base64'),
      n: serverNonce.toString('base64')
    }
    socket.write(encodeControl(ok))
    installTcpRecordLayer(socket, keys.s2c, keys.c2s)
  } catch {
    socket.destroy()
  }
  return true
}

export function feedTcpPlain(socket: Socket, chunk: Buffer): Buffer[] {
  const layer = socketLayers.get(socket)
  if (!layer) return [chunk]
  return layer.decoder.feed(chunk)
}

export function tcpLayerActive(socket: Socket): boolean {
  return socketLayers.has(socket)
}

export function encryptWriteBuffer(plain: Buffer, key: Buffer): Buffer {
  if (plain.length === 0) return Buffer.alloc(0)
  const parts: Buffer[] = []
  for (let offset = 0; offset < plain.length; offset += MAX_RECORD_PLAIN) {
    const piece = plain.subarray(offset, offset + MAX_RECORD_PLAIN)
    const nonce = randomBytes(12)
    const cipher = createCipheriv('aes-256-gcm', key, nonce)
    cipher.setAAD(TCP_RECORD_AAD)
    const ct = Buffer.concat([cipher.update(piece), cipher.final(), cipher.getAuthTag()])
    const rec = Buffer.concat([nonce, ct])
    const head = Buffer.alloc(4)
    head.writeUInt32BE(rec.length)
    parts.push(head, rec)
  }
  return Buffer.concat(parts)
}

export class RecordDecoder {
  private buf: Buffer = Buffer.alloc(0)

  constructor(private readonly key: Buffer) {}

  feed(chunk: Buffer): Buffer[] {
    this.buf = this.buf.length === 0 ? chunk : Buffer.concat([this.buf, chunk])
    const out: Buffer[] = []
    for (;;) {
      if (this.buf.length < 4) return out
      const len = this.buf.readUInt32BE(0)
      if (len < 28 || len > MAX_RECORD_BODY) throw new Error('bad-record-length')
      if (this.buf.length < 4 + len) return out
      const rec = this.buf.subarray(4, 4 + len)
      this.buf = this.buf.subarray(4 + len)
      const nonce = rec.subarray(0, 12)
      const tag = rec.subarray(rec.length - 16)
      const ct = rec.subarray(12, rec.length - 16)
      const decipher = createDecipheriv('aes-256-gcm', this.key, nonce)
      decipher.setAAD(TCP_RECORD_AAD)
      decipher.setAuthTag(tag)
      out.push(Buffer.concat([decipher.update(ct), decipher.final()]))
    }
  }
}

const socketLayers = new WeakMap<Socket, { decoder: RecordDecoder }>()

function installTcpRecordLayer(socket: Socket, outgoingKey: Buffer, incomingKey: Buffer): void {
  const decoder = new RecordDecoder(incomingKey)
  socketLayers.set(socket, { decoder })
  const rawWrite = socket.write.bind(socket)
  socket.write = function patchedWrite(
    this: Socket,
    data: string | Uint8Array,
    encOrCb?: BufferEncoding | ((error?: Error | null) => void),
    cb?: (error?: Error | null) => void
  ): boolean {
    const callback = typeof encOrCb === 'function' ? encOrCb : cb
    const encoding = typeof encOrCb === 'string' ? encOrCb : undefined
    const buf = Buffer.isBuffer(data)
      ? data
      : typeof data === 'string'
        ? Buffer.from(data, encoding)
        : Buffer.from(data)
    if (buf.length === 0) return rawWrite(buf, callback)
    return rawWrite(encryptWriteBuffer(buf, outgoingKey), callback)
  } as typeof socket.write
}

function deriveTcpKeys(opts: {
  ephPrivate: KeyObject
  ephPublic: KeyObject
  peerEph: Buffer
  staticPrivate: KeyObject
  staticPublic: KeyObject
  peerStatic: Buffer
  clientNonce: Buffer
  serverNonce: Buffer
  clientId: string
  serverId: string
  role: 'client' | 'server'
}): { c2s: Buffer; s2c: Buffer } {
  const peerEph = publicFromRaw(opts.peerEph)
  const peerStatic = publicFromRaw(opts.peerStatic)
  const ee = Buffer.from(diffieHellman({ privateKey: opts.ephPrivate, publicKey: peerEph }))
  const ephToStatic = Buffer.from(diffieHellman({ privateKey: opts.ephPrivate, publicKey: peerStatic }))
  const staticToEph = Buffer.from(diffieHellman({ privateKey: opts.staticPrivate, publicKey: peerEph }))
  const es = opts.role === 'client' ? ephToStatic : staticToEph
  const se = opts.role === 'client' ? staticToEph : ephToStatic
  const ss = Buffer.from(diffieHellman({ privateKey: opts.staticPrivate, publicKey: peerStatic }))
  const ikm = Buffer.concat([ee, es, se, ss])
  const salt = Buffer.concat([opts.clientNonce, opts.serverNonce])
  const info = Buffer.concat([
    TCP_INFO_PREFIX,
    Buffer.from([0]),
    Buffer.from(opts.clientId, 'utf8'),
    Buffer.from([0]),
    Buffer.from(opts.serverId, 'utf8')
  ])
  const okm = Buffer.from(hkdfSync('sha256', ikm, salt, info, 64))
  return { c2s: okm.subarray(0, 32), s2c: okm.subarray(32, 64) }
}

function bindInfo(senderId: string, receiverId: string): Buffer {
  return Buffer.concat([
    ENC_INFO_PREFIX,
    Buffer.from([0]),
    Buffer.from(senderId, 'utf8'),
    Buffer.from([0]),
    Buffer.from(receiverId, 'utf8')
  ])
}

function makeAad(meta: { id: string; from: string; type: string; ts: number; to: string }): Buffer {
  return Buffer.from(JSON.stringify([meta.id, meta.from, meta.type, meta.ts, meta.to]))
}

function fromKeyPair(nodeId: string, privateKey: KeyObject, publicKey: KeyObject): EncIdentity {
  return {
    nodeId,
    publicB64: rawPublicKey(publicKey).toString('base64'),
    privateKey,
    publicKey
  }
}

function fromRaw(nodeId: string, secret: Buffer, pub: Buffer): EncIdentity {
  return {
    nodeId,
    publicB64: pub.toString('base64'),
    privateKey: privateFromRaw(secret),
    publicKey: publicFromRaw(pub)
  }
}

function writeEncIdentity(path: string, identity: EncIdentity): void {
  mkdirSync(dirname(path), { recursive: true })
  const tmp = `${path}.tmp`
  const data: IdentityFile = {
    nodeId: identity.nodeId,
    secret: rawPrivateKey(identity.privateKey).toString('base64'),
    public: identity.publicB64
  }
  writeFileSync(tmp, JSON.stringify(data, null, 2), { encoding: 'utf8', mode: 0o600 })
  try {
    chmodSync(tmp, 0o600)
  } catch {
    // Windows 等平台可能忽略 mode
  }
  renameSync(tmp, path)
  try {
    chmodSync(path, 0o600)
  } catch {
    // ignore
  }
}

function rawPublicKey(key: KeyObject): Buffer {
  const der = key.export({ type: 'spki', format: 'der' }) as Buffer
  return extractRaw(der, X25519_SPKI_PREFIX)
}

function rawPrivateKey(key: KeyObject): Buffer {
  const der = key.export({ type: 'pkcs8', format: 'der' }) as Buffer
  return extractRaw(der, X25519_PKCS8_PREFIX)
}

function publicFromRaw(raw: Buffer): KeyObject {
  return createPublicKey({ key: Buffer.concat([X25519_SPKI_PREFIX, raw]), format: 'der', type: 'spki' })
}

function privateFromRaw(raw: Buffer): KeyObject {
  return createPrivateKey({ key: Buffer.concat([X25519_PKCS8_PREFIX, raw]), format: 'der', type: 'pkcs8' })
}

function extractRaw(der: Buffer, prefix: Buffer): Buffer {
  if (der.length === prefix.length + 32 && der.subarray(0, prefix.length).equals(prefix)) {
    return der.subarray(prefix.length)
  }
  if (der.length >= 32) return der.subarray(der.length - 32)
  throw new Error('bad-der')
}

function isB64Len(value: unknown, bytes: number): value is string {
  if (typeof value !== 'string') return false
  try {
    return Buffer.from(value, 'base64').length === bytes
  } catch {
    return false
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}
