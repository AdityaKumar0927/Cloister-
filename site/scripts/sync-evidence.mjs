// Copy the measured artefacts into the site so pages import them rather than restating
// them. If a number appears on the website, it came out of one of these files; if the
// suite stops producing it, the build breaks instead of the page going stale.
import { cp, mkdir, readdir, writeFile } from 'node:fs/promises'
import { existsSync } from 'node:fs'
import path from 'node:path'

const root = path.resolve(import.meta.dirname, '..', '..')
const from = path.join(root, 'evidence')
const dataDir = path.join(import.meta.dirname, '..', 'src', 'data')
const pubDir = path.join(import.meta.dirname, '..', 'public', 'evidence')

await mkdir(dataDir, { recursive: true })
await mkdir(pubDir, { recursive: true })

const names = (await readdir(from)).filter((f) => f.endsWith('.json'))
for (const n of names) await cp(path.join(from, n), path.join(dataDir, n))

// Public copies so a visitor can download the raw evidence and check it themselves.
for (const n of [...names, 'true_doc.txt', 'decoy_doc.txt', 'demo-protected.pdf',
                 'sample-protected-8page.pdf']) {
  if (existsSync(path.join(from, n))) await cp(path.join(from, n), path.join(pubDir, n))
}

const wp = path.join(root, 'whitepaper', 'CLOISTER-whitepaper.pdf')
if (existsSync(wp)) {
  await mkdir(path.join(import.meta.dirname, '..', 'public', 'paper'), { recursive: true })
  await cp(wp, path.join(import.meta.dirname, '..', 'public', 'paper',
                         'CLOISTER-whitepaper.pdf'))
}

await writeFile(path.join(dataDir, 'synced-at.json'),
  JSON.stringify({ files: names.length }, null, 1))
console.log(`  synced ${names.length} evidence files`)
