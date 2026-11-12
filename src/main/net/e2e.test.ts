import { existsSync, mkdirSync, readFileSync, rmSync } from 'node:fs'
import { createConnection, createServer, type AddressInfo, type Socket } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { CAPS, MSG_TYPES, UDP_MAX_PAYLOAD, type Envelope, type MsgPayload, type Profile } from '../../shared/protocol'
import { decode, encode, makeEnvelope } from './codec'
import { Messenger, type DedupStore, type QueueStore } from './messenger'
import { PeerRegistry } from './peer-registry'
import { UdpChannel } from './udp'
import {
  encryptPayload,
  encryptWriteBuffer,
  feedTcpPlain,
  generateEncIdentity,
  loadEncIdentity,
  makeEnvelopeDecryptor,
  RecordDecoder,
  sealIfNeeded,
  startTcpClientEncryption,
  acceptTcpServerEncryption
} from './e2e'
import { decodeTcpFrameObject, encodeFrame, FrameReader } from './frame'

function waitClose(socket: Socket): Promise<void> {
  return new Promise((resolve) => socket.once('close', () => resolve()))
}

describe('e2e 信封加密', () => {
  it('往返解密后得到原文，线路上没有明文 payload', () => {
    const alice = generateEncIdentity('alice')
    const bob = generateEncIdentity('bob')
    const env = makeEnvelope<MsgPayload>(MSG_TYPES.msg, 'alice', { kind: 'text', text: '你好茶话间' })
    const profile: Profile = {
      nodeId: 'bob',
      nick: 'bob',
      company: '',
      dept: '',
      team: '',
      avatar: -1,
      profileRev: 1,
      host: 'bob-host',
      platform: 'linux',
      tcpPort: 17879,
      ver: '0.65-encryption',
      caps: [CAPS.e2e],
      encPub: bob.publicB64
    }
    const sealed = sealIfNeeded(env, 'bob', profile, alice)
    expect(sealed.enc).toBeDefined()
    expect(sealed.payload).toBeUndefined()
    const wire = JSON.parse(encode(sealed).toString('utf8')) as Record<string, unknown>
    expect(wire.payload).toBeUndefined()
    expect(JSON.stringify(wire)).not.toContain('你好茶话间')

    const result = decode(encode(sealed), makeEnvelopeDecryptor(bob))
    expect(result).toMatchObject({ ok: true, known: true, env: { type: 'msg', payload: { kind: 'text', text: '你好茶话间' } } })
  })

  it('翻转密文一位即失败，且不抛异常', () => {
    const alice = generateEncIdentity('alice')
    const bob = generateEncIdentity('bob')
    const enc = encryptPayload(
      { kind: 'text', text: 'secret' },
      { id: 'id-1', from: 'alice', type: MSG_TYPES.msg, ts: 1, to: 'bob' },
      Buffer.from(bob.publicB64, 'base64')
    )
    void alice
    const raw = Buffer.from(enc.ct, 'base64')
    raw[0] ^= 0x01
    enc.ct = raw.toString('base64')
    const env: Envelope = { v: 1, type: MSG_TYPES.msg, id: 'id-1', from: 'alice', ts: 1, payload: undefined as unknown as object, enc }
    delete (env as { payload?: unknown }).payload
    expect(decode(encode(env), makeEnvelopeDecryptor(bob))).toEqual({ ok: false, reason: 'bad-enc' })
  })

  it('用错误的收件人密钥无法解密', () => {
    const alice = generateEncIdentity('alice')
    const bob = generateEncIdentity('bob')
    const carol = generateEncIdentity('carol')
    const env = makeEnvelope<MsgPayload>(MSG_TYPES.msg, 'alice', { kind: 'text', text: 'secret' })
    const sealed = sealIfNeeded(env, 'bob', {
      nodeId: 'bob',
      nick: 'b',
      company: '',
      dept: '',
      team: '',
      avatar: -1,
      profileRev: 1,
      host: 'h',
      platform: 'linux',
      tcpPort: 1,
      ver: '0',
      caps: [CAPS.e2e],
      encPub: bob.publicB64
    }, alice)
    expect(decode(encode(sealed), makeEnvelopeDecryptor(carol))).toEqual({ ok: false, reason: 'bad-enc' })
  })

  it('未声明 enc1 或缺少公钥时仍走明文', () => {
    const alice = generateEncIdentity('alice')
    const env = makeEnvelope<MsgPayload>(MSG_TYPES.msg, 'alice', { kind: 'text', text: 'plain' })
    const legacy: Profile = {
      nodeId: 'bob',
      nick: 'bob',
      company: '',
      dept: '',
      team: '',
      avatar: -1,
      profileRev: 1,
      host: 'h',
      platform: 'linux',
      tcpPort: 1,
      ver: '0',
      caps: []
    }
    expect(sealIfNeeded(env, 'bob', legacy, alice).enc).toBeUndefined()
    expect(sealIfNeeded(env, 'bob', { ...legacy, caps: [CAPS.e2e] }, alice).enc).toBeUndefined()
    expect(decode(encode(env))).toMatchObject({ ok: true, env: { payload: { text: 'plain' } } })
  })

  it('加密开销被计入后，临界长度应改走 TCP 而不是丢包', () => {
    const alice = generateEncIdentity('alice')
    const bob = generateEncIdentity('bob')
    const text = 'x'.repeat(900)
    const env = makeEnvelope<MsgPayload>(MSG_TYPES.msg, 'alice', { kind: 'text', text })
    const plainLen = encode(env).length
    expect(plainLen).toBeLessThanOrEqual(UDP_MAX_PAYLOAD)
    const sealed = sealIfNeeded(env, 'bob', {
      nodeId: 'bob',
      nick: 'bob',
      company: '',
      dept: '',
      team: '',
      avatar: -1,
      profileRev: 1,
      host: 'h',
      platform: 'linux',
      tcpPort: 1,
      ver: '0',
      caps: [CAPS.e2e],
      encPub: bob.publicB64
    }, alice)
    const sealedLen = encode(sealed).length
    expect(sealedLen).toBeGreaterThan(plainLen)
    expect(sealedLen - plainLen).toBeGreaterThan(100)
    expect(encode(sealed).toString('utf8')).not.toContain(text)
  })

  it('enc 与明文 payload 同时出现会被拒绝', () => {
    const alice = generateEncIdentity('alice')
    const bob = generateEncIdentity('bob')
    const env = makeEnvelope<MsgPayload>(MSG_TYPES.msg, 'alice', { kind: 'text', text: 'leak' })
    const sealed = sealIfNeeded(env, 'bob', {
      nodeId: 'bob',
      nick: 'b',
      company: '',
      dept: '',
      team: '',
      avatar: -1,
      profileRev: 1,
      host: 'h',
      platform: 'linux',
      tcpPort: 1,
      ver: '0',
      caps: [CAPS.e2e],
      encPub: bob.publicB64
    }, alice)
    const raw = JSON.parse(encode(sealed).toString('utf8')) as Record<string, unknown>
    raw.payload = { kind: 'text', text: 'leak' }
    expect(decode(Buffer.from(JSON.stringify(raw), 'utf8'), makeEnvelopeDecryptor(bob))).toEqual({
      ok: false,
      reason: 'bad-enc'
    })
  })
})

describe('e2e 身份持久化', () => {
  const dirs: string[] = []
  afterEach(() => {
    for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true })
  })

  it('首次生成并按 nodeId 复用，nodeId 变化则换新密钥', () => {
    const dir = join(tmpdir(), `teahouse-enc-${Date.now()}-${Math.random().toString(16).slice(2)}`)
    mkdirSync(dir, { recursive: true })
    dirs.push(dir)
    const first = loadEncIdentity(dir, 'node-a')
    expect(first.created).toBe(true)
    expect(existsSync(join(dir, 'enc-identity.json'))).toBe(true)
    const stored = JSON.parse(readFileSync(join(dir, 'enc-identity.json'), 'utf8')) as { nodeId: string }
    expect(stored.nodeId).toBe('node-a')
    const again = loadEncIdentity(dir, 'node-a')
    expect(again.created).toBe(false)
    expect(again.identity.publicB64).toBe(first.identity.publicB64)
    const rotated = loadEncIdentity(dir, 'node-b')
    expect(rotated.created).toBe(true)
    expect(rotated.identity.publicB64).not.toBe(first.identity.publicB64)
  })
})

describe('e2e TCP 记录层', () => {
  it('分块加密往返，密文不是合法 JSON', () => {
    const key = Buffer.alloc(32, 7)
    const plain = Buffer.from('{"type":"pull","from":"n"}')
    const wire = encryptWriteBuffer(plain, key)
    expect(wire.subarray(4).toString('utf8')).not.toContain('pull')
    expect(() => JSON.parse(wire.toString('utf8'))).toThrow()
    const decoder = new RecordDecoder(key)
    expect(Buffer.concat(decoder.feed(wire)).equals(plain)).toBe(true)
  })

  it('篡改记录后解密失败', () => {
    const key = Buffer.alloc(32, 9)
    const wire = encryptWriteBuffer(Buffer.from('hello-record'), key)
    wire[10] ^= 0x10
    const decoder = new RecordDecoder(key)
    expect(() => decoder.feed(wire)).toThrow()
  })

  it('127.0.0.1 上完成握手后记录层可双向收发', async () => {
    const clientId = generateEncIdentity('client')
    const serverId = generateEncIdentity('server')
    const server = createServer()
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()))
    const port = (server.address() as AddressInfo).port
    const accepted = new Promise<{ socket: Socket; frameType: string }>((resolve, reject) => {
      server.once('connection', (socket) => {
        const reader = new FrameReader(
          (frame) => {
            if (frame.type === 'enc-hello') {
              const ok = acceptTcpServerEncryption(frame, socket, {
                identity: serverId,
                lookupPeer: (id) =>
                  id === 'client' ? { encPub: clientId.publicB64, caps: [CAPS.e2e] } : undefined
              })
              expect(ok).toBe(true)
              return
            }
            resolve({ socket, frameType: frame.type })
          },
          () => undefined,
          (reason) => reject(new Error(reason))
        )
        socket.on('data', (chunk) => {
          try {
            for (const plain of feedTcpPlain(socket, chunk)) reader.feed(plain)
          } catch (err) {
            reject(err)
          }
        })
      })
    })
    const client = createConnection({ host: '127.0.0.1', port })
    await new Promise<void>((resolve, reject) => {
      client.once('error', reject)
      client.once('connect', () => resolve())
    })
    await startTcpClientEncryption(client, {
      identity: clientId,
      peerId: 'server',
      peerPub: Buffer.from(serverId.publicB64, 'base64')
    })
    const replies: Buffer[] = []
    client.on('data', (chunk) => {
      for (const plain of feedTcpPlain(client, chunk)) replies.push(plain)
    })
    client.write(encodeFrame({ type: 'wait' }))
    const got = await accepted
    expect(got.frameType).toBe('wait')
    got.socket.write(encodeFrame({ type: 'wait' }))
    await viWait(() => replies.length > 0)
    const frame = decodeTcpFrameObject(JSON.parse(replies[0]!.subarray(4).toString('utf8')))
    expect(frame).toEqual({ type: 'wait' })
    client.destroy()
    got.socket.destroy()
    await Promise.all([waitClose(client), waitClose(got.socket)])
    await new Promise<void>((resolve) => server.close(() => resolve()))
  })
})

function viWait(pred: () => boolean, timeout = 3000): Promise<void> {
  const started = Date.now()
  return new Promise((resolve, reject) => {
    const tick = (): void => {
      if (pred()) return resolve()
      if (Date.now() - started > timeout) return reject(new Error('timeout'))
      setTimeout(tick, 15)
    }
    tick()
  })
}

class MemQueue implements QueueStore {
  items: Array<{ msgId: string; peerId: string; envelopeJson: string; created: number }> = []
  enqueue(msgId: string, peerId: string, envelopeJson: string, created: number): void {
    this.items.push({ msgId, peerId, envelopeJson, created })
  }
  listByPeer(peerId: string): Array<{ msgId: string; envelopeJson: string }> {
    return this.items.filter((i) => i.peerId === peerId).map((i) => ({ msgId: i.msgId, envelopeJson: i.envelopeJson }))
  }
  remove(msgId: string, peerId: string): void {
    this.items = this.items.filter((i) => !(i.msgId === msgId && i.peerId === peerId))
  }
  prune(): Array<{ msgId: string; peerId: string }> { return [] }
}

class MemDedup implements DedupStore {
  private readonly seen = new Set<string>()
  has(msgId: string): boolean { return this.seen.has(msgId) }
  add(msgId: string, _recvTs?: number): void { this.seen.add(msgId) }
  prune(_ttlMs?: number): void { /* noop */ }
}

describe('e2e messenger 回环', () => {
  it('双方 enc1 时 UDP 消息密文投递并可解密', async () => {
    const aliceId = generateEncIdentity('node-alice')
    const bobId = generateEncIdentity('node-bob')
    const aliceProfile: Profile = {
      nodeId: 'node-alice', nick: 'alice', company: '', dept: '', team: '', avatar: -1, profileRev: 1,
      host: 'a', platform: 'linux', tcpPort: 1, ver: '0', caps: [CAPS.e2e], encPub: aliceId.publicB64
    }
    const bobProfile: Profile = {
      nodeId: 'node-bob', nick: 'bob', company: '', dept: '', team: '', avatar: -1, profileRev: 1,
      host: 'b', platform: 'linux', tcpPort: 1, ver: '0', caps: [CAPS.e2e], encPub: bobId.publicB64
    }
    const aUdp = new UdpChannel({ port: 0, bindAddress: '127.0.0.1', broadcastTargets: [], decrypt: makeEnvelopeDecryptor(aliceId) })
    const bUdp = new UdpChannel({ port: 0, bindAddress: '127.0.0.1', broadcastTargets: [], decrypt: makeEnvelopeDecryptor(bobId) })
    const aReg = new PeerRegistry('node-alice')
    const bReg = new PeerRegistry('node-bob')
    const aMsg = new Messenger({ udp: aUdp, registry: aReg, selfId: 'node-alice', queue: new MemQueue(), dedup: new MemDedup(), e2e: aliceId, timings: { ackRetrySchedule: [200, 200, 200] } })
    const bMsg = new Messenger({ udp: bUdp, registry: bReg, selfId: 'node-bob', queue: new MemQueue(), dedup: new MemDedup(), e2e: bobId, timings: { ackRetrySchedule: [200, 200, 200] } })
    const incoming: Envelope[] = []
    bMsg.on('incoming', (env: Envelope) => incoming.push(env))
    const sniffed: string[] = []
    const original = bUdp.sendBuffer.bind(bUdp)
    // sniff inbound by wrapping Alice's send
    const aSend = aUdp.sendBuffer.bind(aUdp)
    aUdp.sendBuffer = (buf: Buffer, address: string, port: number) => {
      sniffed.push(buf.toString('utf8'))
      aSend(buf, address, port)
    }
    await aUdp.start()
    await bUdp.start()
    try {
      aReg.touch('node-bob', '127.0.0.1', bUdp.port, bobProfile)
      bReg.touch('node-alice', '127.0.0.1', aUdp.port, aliceProfile)
      const env = makeEnvelope<MsgPayload>(MSG_TYPES.msg, 'node-alice', { kind: 'text', text: '加密你好' })
      await expect(aMsg.sendUserMessage('node-bob', env)).resolves.toBe('sent')
      expect(incoming).toHaveLength(1)
      expect(incoming[0]?.payload).toEqual({ kind: 'text', text: '加密你好' })
      expect(sniffed.some((s) => s.includes('加密你好'))).toBe(false)
      expect(sniffed.some((s) => s.includes('"enc"'))).toBe(true)
    } finally {
      aMsg // keep refs
      bMsg
      await aUdp.stop()
      await bUdp.stop()
    }
    void original
  })
})
