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

let ffmpegAvailable
export async function hasFfmpeg(bin = process.env.SF_FFMPEG || 'ffmpeg') {
  if (ffmpegAvailable === undefined) {
    ffmpegAvailable = await new Promise((resolve) => {
      const child = spawn(bin, ['-version'], { stdio: 'ignore' })
      child.on('error', () => resolve(false))
      child.on('close', (code) => resolve(code === 0))
    })
  }
  return ffmpegAvailable
}

/** What this machine can make: { image, video } booleans. */
export async function thumbnailSupport() {
  const sharp = await loadSharp()
  const ffmpeg = await hasFfmpeg()
  return { image: Boolean(sharp) || ffmpeg, video: ffmpeg }
}

function runFfmpeg(args, timeoutMs = FFMPEG_TIMEOUT_MS) {
  return new Promise((resolve) => {
    const child = spawn(process.env.SF_FFMPEG || 'ffmpeg', args, { stdio: ['ignore', 'pipe', 'ignore'] })
    const chunks = []
    let size = 0
    child.stdout.on('data', (c) => {
      size += c.length
      if (size > 20 * 1024 * 1024) child.kill('SIGKILL')
      else chunks.push(c)
    })
    const timer = setTimeout(() => child.kill('SIGKILL'), timeoutMs)
    child.on('error', () => {
      clearTimeout(timer)
      resolve(null)
    })
    child.on('close', (code) => {
      clearTimeout(timer)
      resolve(code === 0 && size > 0 ? new Uint8Array(Buffer.concat(chunks)) : null)
    })
  })
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
export async function makeThumbnail({ path, name, size }) {
  try {
    const kind = mediaKindOf(name)
    if (kind === 'image') return await imageThumbnail(path, size)
    if (kind === 'video') return await videoThumbnail(path)
  } catch {
    // best-effort
  }
  return null
}
