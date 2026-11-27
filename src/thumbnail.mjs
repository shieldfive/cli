// Encrypted preview thumbnails for images and video posters, made on this
// machine before upload, so a pushed photo or video shows a picture in Drive
// and Media instead of a type icon.
//
// Same output as the web uploader and the mobile app:
//   - a JPEG, longest side <= 512 px, quality stepped down (0.7, 0.5, 0.35,
//     0.2) until it is <= 55 000 bytes (else the smallest one made);
//   - encrypted in the format every client reads today (web
//     utils/thumbnail.ts, WRITE_THUMBNAIL_V2 = false): AES-256-GCM under the
//     file's content key (the envelope key wrapped in csk_wrapped), IV = a
//     fresh random 4-byte prefix || 8 zero bytes, stored as ciphertext||tag,
//     and the prefix sent as thumbnail_nonce_prefix (base64).
// The server receives only the ciphertext.
//
// Best-effort throughout: a format we cannot decode, a missing encoder, or a
// slow/odd video gives null and the file uploads without a thumbnail.
//
// Encoders: images use sharp (an optional dependency) and fall back to ffmpeg;
// video posters need ffmpeg on PATH. Without either, files upload with no
// thumbnail and push prints one note saying so.

import { spawn } from 'node:child_process'
import { webcrypto } from 'node:crypto'
import { extname } from 'node:path'
import { fileURLToPath } from 'node:url'

import { aesGcmEncrypt, bytesToBase64 } from './uploadCrypto.mjs'

export const THUMBNAIL_MAX_SIDE = 512
export const THUMBNAIL_MAX_BYTES = 55_000
export const THUMBNAIL_QUALITY_STEPS = [0.7, 0.5, 0.35, 0.2]
const NONCE_PREFIX_BYTES = 4
const IV_BYTES = 12
// Matches the server's MAX_THUMBNAIL_CIPHERTEXT_BYTES; a larger one is dropped
// there anyway, so do not send it.
const MAX_CIPHERTEXT_BYTES = 200 * 1024
const FFMPEG_TIMEOUT_MS = 30_000
const PREVIEW_TIMEOUT_MS = 35_000
const PROBE_TIMEOUT_MS = 5_000
// Larger images are not decoded (memory); they upload without a thumbnail.
const MAX_IMAGE_SOURCE_BYTES = 200 * 1024 * 1024

const IMAGE_EXTS = new Set(['.jpg', '.jpeg', '.jpe', '.png', '.gif', '.webp', '.bmp', '.tif', '.tiff', '.avif', '.heic', '.heif'])
const VIDEO_EXTS = new Set(['.mp4', '.m4v', '.mov', '.webm', '.mkv', '.avi', '.3gp', '.mts', '.m2ts', '.wmv', '.mpg', '.mpeg'])

export function mediaKindOf(name) {
  const ext = extname(name).toLowerCase()
  if (IMAGE_EXTS.has(ext)) return 'image'
  if (VIDEO_EXTS.has(ext)) return 'video'
  return null
}

/** AES-256-GCM, legacy thumbnail format (see top of file). */
export function encryptThumbnail(plaintext, cskBytes, prefix = webcrypto.getRandomValues(new Uint8Array(NONCE_PREFIX_BYTES))) {
  if (cskBytes.length !== 32) throw new Error('thumbnail key must be 32 bytes')
  const iv = new Uint8Array(IV_BYTES)
  iv.set(prefix, 0)
  return { ciphertext: aesGcmEncrypt(cskBytes, iv, plaintext), noncePrefix: bytesToBase64(prefix) }
}

/** Encrypt and shape for create-upload-session; null if it would be refused. */
export function thumbnailFields(plaintext, cskBytes) {
  if (!plaintext?.length) return null
  const { ciphertext, noncePrefix } = encryptThumbnail(plaintext, cskBytes)
  if (ciphertext.length > MAX_CIPHERTEXT_BYTES) return null
  return { thumbnail_ciphertext_b64: bytesToBase64(ciphertext), thumbnail_nonce_prefix: noncePrefix }
}

let sharpModule
async function loadSharp() {
  if (sharpModule === undefined) {
    try {
      sharpModule = (await import('sharp')).default
    } catch {
      sharpModule = null
    }
  }
  return sharpModule
}

export async function hasFfmpeg(bin = process.env.SF_FFMPEG || 'ffmpeg') {
  return (await runEncoder(bin, ['-version'], PROBE_TIMEOUT_MS, 1024 * 1024)) !== null
}

/** What this machine can make: { image, video } booleans. */
export async function probeThumbnailSupport() {
  const [sharp, ffmpeg] = await Promise.all([loadSharp(), hasFfmpeg()])
  return { image: Boolean(sharp) || ffmpeg, video: ffmpeg }
}

function runEncoder(bin, args, timeoutMs, maxBytes, { processGroup = true } = {}) {
  return new Promise((resolve) => {
    const detached = processGroup && process.platform !== 'win32'
    const child = spawn(bin, args, { detached, stdio: ['ignore', 'pipe', 'ignore'], windowsHide: true })
    const chunks = []
    let size = 0
    const finish = (result) => {
      clearTimeout(timer)
      resolve(result)
    }
    const stop = () => {
      try {
        if (detached && child.pid) process.kill(-child.pid, 'SIGKILL')
        else child.kill('SIGKILL')
      } catch {
        // The process may have exited while a descendant still had stdout open.
      }
      child.stdout.destroy()
      child.unref()
      finish(null)
    }
    const timer = setTimeout(stop, timeoutMs)
    child.stdout.on('data', (c) => {
      size += c.length
      if (size > maxBytes) stop()
      else chunks.push(c)
    })
    child.once('error', () => finish(null))
    child.once('close', (code) => finish(code === 0 ? Buffer.concat(chunks) : null))
  })
}

function runFfmpeg(args) {
  // The encoder inherits the preview worker's process group so the parent
  // can stop both even when native image processing gets stuck.
  return runEncoder(process.env.SF_FFMPEG || 'ffmpeg', ['-nostdin', ...args], FFMPEG_TIMEOUT_MS,
    20 * 1024 * 1024, { processGroup: false })
}

const previewWorker = fileURLToPath(new URL('./thumbnailWorker.mjs', import.meta.url))

export async function thumbnailSupport() {
  try {
    const output = await runEncoder(process.execPath, [previewWorker], PROBE_TIMEOUT_MS + 2_000, 1024)
    if (output?.length) return JSON.parse(output.toString())
  } catch {
    // An unavailable encoder must not stop its caller.
  }
  return { image: false, video: false }
}

// Quality 0..1 to ffmpeg's mjpeg qscale (2 best .. 31 worst).
const qscale = (q) => String(Math.round(2 + (1 - q) * 29))
const SCALE = `scale='if(gt(iw,ih),min(${THUMBNAIL_MAX_SIDE},iw),-2)':'if(gt(iw,ih),-2,min(${THUMBNAIL_MAX_SIDE},ih))'`

async function stepQuality(encode) {
  let smallest = null
  for (const q of THUMBNAIL_QUALITY_STEPS) {
    const bytes = await encode(q)
    if (!bytes) continue
    if (!smallest || bytes.length < smallest.length) smallest = bytes
    if (bytes.length <= THUMBNAIL_MAX_BYTES) return bytes
  }
  return smallest
}

async function jpegFromSharp(sharp, input) {
  // rotate(): apply EXIF orientation, as browsers do when drawing the image.
  const resized = await sharp(input, { failOn: 'none', animated: false })
    .rotate()
    .resize(THUMBNAIL_MAX_SIDE, THUMBNAIL_MAX_SIDE, { fit: 'inside', withoutEnlargement: true })
    .flatten({ background: '#ffffff' })
    .raw()
    .toBuffer({ resolveWithObject: true })
  const { data, info } = resized
  return stepQuality(async (q) =>
    new Uint8Array(
      await sharp(data, { raw: { width: info.width, height: info.height, channels: info.channels } })
        .jpeg({ quality: Math.round(q * 100), mozjpeg: true })
        .toBuffer(),
    ),
  )
}

async function imageThumbnail(path, size) {
  if (size > MAX_IMAGE_SOURCE_BYTES) return null
  const sharp = await loadSharp()
  if (sharp) {
    try {
      const out = await jpegFromSharp(sharp, path)
      if (out) return out
    } catch {
      // e.g. HEIC (prebuilt sharp has no HEVC decoder): try ffmpeg below.
    }
  }
  if (!(await hasFfmpeg())) return null
  return stepQuality((q) =>
    runFfmpeg(['-v', 'error', '-i', path, '-frames:v', '1', '-vf', SCALE, '-q:v', qscale(q), '-f', 'image2pipe', '-vcodec', 'mjpeg', 'pipe:1']),
  )
}

// A frame about one second in (the web picks a frame shortly after the start,
// past black lead-in frames); very short clips fall back to the first frame.
async function videoThumbnail(path) {
  if (!(await hasFfmpeg())) return null
  const sharp = await loadSharp()
  for (const seek of ['1', '0']) {
    if (sharp) {
      const png = await runFfmpeg(['-v', 'error', '-ss', seek, '-i', path, '-frames:v', '1', '-f', 'image2pipe', '-vcodec', 'png', 'pipe:1'])
      if (png) {
        try {
          const out = await jpegFromSharp(sharp, Buffer.from(png))
          if (out) return out
        } catch {
          // fall through to ffmpeg's own JPEG
        }
      }
    }
    const out = await stepQuality((q) =>
      runFfmpeg(['-v', 'error', '-ss', seek, '-i', path, '-frames:v', '1', '-vf', SCALE, '-q:v', qscale(q), '-f', 'image2pipe', '-vcodec', 'mjpeg', 'pipe:1']),
    )
    if (out) return out
  }
  return null
}

/**
 * The plaintext JPEG thumbnail for `path`, or null (not an image or video,
 * cannot decode, no encoder). Never throws.
 */
export async function encodeThumbnail({ path, name, size }) {
  try {
    const kind = mediaKindOf(name)
    if (kind === 'image') return await imageThumbnail(path, size)
    if (kind === 'video') return await videoThumbnail(path)
  } catch {
    // best-effort
  }
  return null
}

export async function makeThumbnail({ path, name, size }) {
  if (!mediaKindOf(name)) return null
  try {
    const output = await runEncoder(process.execPath, [previewWorker, JSON.stringify({ path, name, size })],
      PREVIEW_TIMEOUT_MS, MAX_CIPHERTEXT_BYTES)
    return output?.length ? new Uint8Array(output) : null
  } catch {
    return null
  }
}
