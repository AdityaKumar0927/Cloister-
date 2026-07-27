import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import demo from '../data/demo.json'

/* ============================================================================
   An adversarial agent that runs entirely in the visitor's tab.

   The agent plays the ATTACKER. It is handed exactly what a real ingestion
   pipeline gets -- the output of a text extractor, or of OCR -- and loops
   plan -> extract -> verify -> critique, trying to recover the ten sensitive
   terms in a protected settlement memorandum.

   Three things about this demo are deliberate.

   1. It runs locally. WebGPU via WebLLM, or Chrome's built-in Gemini Nano, or a
      deterministic extractor when neither exists. No API key, no server, no
      bytes leaving the tab -- which is the same property the product argues for,
      so it would be incoherent to demo it by uploading the document somewhere.

   2. The verify step is a real tool, not a prompt. Every term the model claims
      is checked by string containment against its own input. That is what turns
      "the model failed" into "the model hallucinated, and here is the proof",
      and it is why the failure is legible rather than looking like a small model
      being stupid.

   3. The OCR channel WINS, 10 of 10. It is on the page, one click away, with the
      real tesseract transcript behind it. A demo that only showed the flattering
      channel would be advertising.
   ============================================================================ */

type Backend = 'webllm' | 'chrome' | 'heuristic'
type Channel = 'text_layer' | 'ocr'
type Phase = 'idle' | 'loading' | 'running' | 'done'

interface Step {
  id: number
  kind: 'plan' | 'extract' | 'verify' | 'critique' | 'score'
  title: string
  body: string
  meta?: string
  tone?: 'neutral' | 'good' | 'bad'
}

const TERMS: string[] = demo.document.sensitive_terms
const CHANNELS = demo.channels as Record<Channel, {
  label: string
  what_the_machine_sees: string
  chars: number
  recovered: string[]
}>

const MODEL_PREFERENCE = [
  /^Qwen3-0\.6B.*q4f16/i,
  /^Qwen2\.5-0\.5B-Instruct.*q4f16/i,
  /^Llama-3\.2-1B-Instruct.*q4f16/i,
  /^SmolLM2?-360M.*Instruct/i,
  /-0\.5B-Instruct.*q4f16/i,
  /-1B-Instruct.*q4f16/i,
]

/* ------------------------------------------------------------------ verify tool */
/** Deterministic. The agent may claim anything; this decides what is actually there. */
function verifyClaims(claims: string[], haystack: string) {
  const low = haystack.toLowerCase()
  return claims.map((c) => {
    const t = c.trim().replace(/^["'\s]+|["'.,;\s]+$/g, '')
    return { claim: t, present: t.length > 1 && low.includes(t.toLowerCase()) }
  })
}

function scoreAgainstTruth(found: string[]) {
  const low = found.map((f) => f.toLowerCase())
  const hit = TERMS.filter((t) => low.some((f) => f.includes(t.toLowerCase())))
  return { hit, missed: TERMS.filter((t) => !hit.includes(t)) }
}

/* -------------------------------------------------- the deterministic attacker */
/** A real extractor: money, percentages, dates, capitalised entities, legal terms.
 *  No model, no download. It is not a straw man -- on the OCR channel it recovers
 *  everything, which is exactly why its failure on the text layer means something. */
function heuristicExtract(text: string): string[] {
  const out = new Set<string>()
  const patterns: RegExp[] = [
    /\b\d{1,3}(?:,\d{3})+(?:\.\d+)?\b/g,
    /\b\d{1,3}(?:\.\d+)?%/g,
    /\b\d{4}-\d{2}-\d{2}\b/g,
    /\b(?:[A-Z][a-z]{2,}\s){0,2}(?:Holdings|Industries|Ltd|LLC|Inc|Group|Partners)\b/g,
    /\b(?:escrow|indemnify|indemnity|arbitration|privileged|confidential|settlement|plaintiff|defendant|liability)\b/gi,
  ]
  for (const p of patterns) for (const m of text.matchAll(p)) out.add(m[0].trim())
  // Capitalised multi-word proper nouns mid-sentence: the usual party-name signal.
  for (const m of text.matchAll(/(?<![.!?]\s)(?<!^)\b([A-Z][a-z]{3,}(?:\s+[A-Z][a-z]{3,})?)\b/gm))
    if (m[1] && !/^(The|This|That|Each|Counsel|Settlement)$/.test(m[1])) out.add(m[1])
  return [...out].slice(0, 40)
}

/* ------------------------------------------------------------- backend adapters */
interface Chat {
  ask(system: string, user: string, onToken?: (s: string) => void): Promise<string>
  dispose?(): void
}

async function chromeChat(): Promise<Chat | null> {
  const g = globalThis as any
  const LM = g.LanguageModel ?? g.ai?.languageModel
  if (!LM) return null
  try {
    const avail = await (LM.availability?.() ?? LM.capabilities?.())
    const s = typeof avail === 'string' ? avail : avail?.available
    if (s && /unavailable|no/i.test(String(s))) return null
    return {
      async ask(system, user, onToken) {
        const sess = await LM.create({
          initialPrompts: [{ role: 'system', content: system }],
        })
        try {
          if (sess.promptStreaming) {
            let acc = ''
            for await (const chunk of sess.promptStreaming(user)) {
              // Chrome has shipped both cumulative and delta chunks; normalise.
              const delta = chunk.startsWith(acc) ? chunk.slice(acc.length) : chunk
              acc = chunk.startsWith(acc) ? chunk : acc + chunk
              onToken?.(delta)
            }
            return acc
          }
          const r = await sess.prompt(user)
          onToken?.(r)
          return r
        } finally {
          sess.destroy?.()
        }
      },
    }
  } catch {
    return null
  }
}

async function webllmChat(
  onProgress: (pct: number, label: string) => void,
): Promise<{ chat: Chat; model: string } | null> {
  if (!(navigator as any).gpu) return null
  const webllm = await import('@mlc-ai/web-llm')
  const ids: string[] = (webllm.prebuiltAppConfig?.model_list ?? []).map(
    (m: any) => m.model_id,
  )
  let model = ''
  for (const p of MODEL_PREFERENCE) {
    const hit = ids.find((i) => p.test(i))
    if (hit) {
      model = hit
      break
    }
  }
  if (!model) model = ids[0]
  if (!model) return null

  const engine = await webllm.CreateMLCEngine(model, {
    initProgressCallback: (r: any) => {
      const pct = typeof r.progress === 'number' ? Math.round(r.progress * 100) : 0
      onProgress(pct, r.text ?? 'loading')
    },
  })
  return {
    model,
    chat: {
      async ask(system, user, onToken) {
        const stream = await engine.chat.completions.create({
          messages: [
            { role: 'system', content: system },
            { role: 'user', content: user },
          ],
          temperature: 0.2,
          max_tokens: 320,
          stream: true,
        })
        let acc = ''
        for await (const part of stream as any) {
          const d = part.choices?.[0]?.delta?.content ?? ''
          if (d) {
            acc += d
            onToken?.(d)
          }
        }
        return acc
      },
      dispose() {
        engine.unload?.()
      },
    },
  }
}

/* ---------------------------------------------------------------- the component */
export default function AgentDemo() {
  const [channel, setChannel] = useState<Channel>('text_layer')
  const [backend, setBackend] = useState<Backend>('heuristic')
  const [phase, setPhase] = useState<Phase>('idle')
  const [steps, setSteps] = useState<Step[]>([])
  const [progress, setProgress] = useState({ pct: 0, label: '' })
  const [caps, setCaps] = useState({ webgpu: false, chrome: false, checked: false })
  const [modelName, setModelName] = useState('')
  const [result, setResult] = useState<{ hit: string[]; missed: string[] } | null>(null)
  const [verifiedButWrong, setVerifiedButWrong] = useState<string[]>([])
  const chatRef = useRef<Chat | null>(null)
  const cancelRef = useRef(false)
  const logRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    let live = true
    ;(async () => {
      const webgpu = !!(navigator as any).gpu
      const chrome = !!(await chromeChat())
      if (live) setCaps({ webgpu, chrome, checked: true })
    })()
    return () => {
      live = false
      chatRef.current?.dispose?.()
    }
  }, [])

  const input = CHANNELS[channel].what_the_machine_sees
  const truncated = useMemo(() => input.slice(0, 2600), [input])

  const push = useCallback((s: Omit<Step, 'id'>) => {
    setSteps((prev) => [...prev, { ...s, id: prev.length }])
    requestAnimationFrame(() => {
      logRef.current?.scrollTo({ top: logRef.current.scrollHeight, behavior: 'smooth' })
    })
  }, [])

  const appendToLast = useCallback((text: string) => {
    setSteps((prev) => {
      if (!prev.length) return prev
      const copy = [...prev]
      copy[copy.length - 1] = {
        ...copy[copy.length - 1],
        body: copy[copy.length - 1].body + text,
      }
      return copy
    })
  }, [])

  const loadModel = useCallback(async () => {
    setPhase('loading')
    setProgress({ pct: 0, label: 'starting' })
    try {
      const r = await webllmChat((pct, label) => setProgress({ pct, label }))
      if (!r) throw new Error('WebGPU model unavailable')
      chatRef.current = r.chat
      setModelName(r.model)
      setBackend('webllm')
      setPhase('idle')
    } catch (e) {
      push({
        kind: 'critique',
        title: 'Local model unavailable',
        body: `${e instanceof Error ? e.message : String(e)}. Falling back to the deterministic extractor, which needs no download.`,
        tone: 'bad',
      })
      setBackend('heuristic')
      setPhase('idle')
    }
  }, [push])

  const useChrome = useCallback(async () => {
    const c = await chromeChat()
    if (c) {
      chatRef.current = c
      setBackend('chrome')
      setModelName('Gemini Nano (built into this browser)')
    }
  }, [])

  const run = useCallback(async () => {
    cancelRef.current = false
    setSteps([])
    setResult(null)
    setVerifiedButWrong([])
    setPhase('running')

    const SYS =
      'You are a document extraction agent working for an automated ingestion ' +
      'pipeline. You are terse and you never invent facts. When asked for terms, ' +
      'reply with a comma-separated list and nothing else.'

    const claimed = new Set<string>()
    let rounds = 0
    const MAX = backend === 'heuristic' ? 1 : 3

    try {
      while (rounds < MAX && !cancelRef.current) {
        rounds++

        /* -- 1. plan ---------------------------------------------------------- */
        if (backend === 'heuristic') {
          push({
            kind: 'plan',
            title: `Round ${rounds} · plan`,
            body:
              'Deterministic extractor. Scan for currency amounts, percentages, ' +
              'ISO dates, corporate suffixes, capitalised proper nouns and ' +
              'privilege-bearing legal vocabulary.',
            meta: 'no model · runs instantly',
          })
        } else {
          push({
            kind: 'plan',
            title: `Round ${rounds} · plan`,
            body: '',
            meta: modelName,
          })
          await chatRef.current!.ask(
            SYS,
            `You will be given text extracted from a confidential settlement PDF. In one short sentence, state how you will locate the money amounts, party names and dates.\n\nTEXT:\n${truncated.slice(0, 1200)}`,
            appendToLast,
          )
        }
        if (cancelRef.current) break

        /* -- 2. extract ------------------------------------------------------- */
        let candidates: string[] = []
        if (backend === 'heuristic') {
          candidates = heuristicExtract(input)
          push({
            kind: 'extract',
            title: `Round ${rounds} · extract`,
            body: candidates.length
              ? candidates.join(', ')
              : '(the patterns matched nothing)',
            meta: `${candidates.length} candidate strings`,
          })
        } else {
          push({
            kind: 'extract',
            title: `Round ${rounds} · extract`,
            body: '',
            meta: 'streaming',
          })
          const prev = claimed.size
            ? `\n\nYou already tried these and they were not in the document: ${[...claimed].join(', ')}. Do not repeat them.`
            : ''
          const raw = await chatRef.current!.ask(
            SYS,
            `Extract every settlement amount, percentage, party name and date from this text. Comma-separated list only.${prev}\n\nTEXT:\n${truncated}`,
            appendToLast,
          )
          candidates = raw
            .replace(/^[^:]*:/, '')
            .split(/[,\n]/)
            .map((s) => s.replace(/^[-*\d.\s]+/, '').trim())
            .filter((s) => s.length > 1 && s.length < 60)
            .slice(0, 25)
        }
        if (cancelRef.current) break

        /* -- 3. verify (a tool, not a prompt) --------------------------------- */
        const checked = verifyClaims(candidates, input)
        const real = checked.filter((c) => c.present).map((c) => c.claim)
        const halluc = checked.filter((c) => !c.present).map((c) => c.claim)
        halluc.forEach((h) => claimed.add(h))
        push({
          kind: 'verify',
          title: `Round ${rounds} · verify against the input`,
          body:
            (real.length
              ? `PRESENT in the extracted text (${real.length}): ${real.join(', ')}`
              : 'PRESENT in the extracted text: none') +
            (halluc.length
              ? `\n\nNOT PRESENT — invented by the model (${halluc.length}): ${halluc.join(', ')}`
              : ''),
          meta: 'deterministic string containment',
          tone: halluc.length && !real.length ? 'bad' : 'neutral',
        })
        if (cancelRef.current) break

        /* -- 4. critique / decide whether to loop ----------------------------- */
        const s = scoreAgainstTruth(real)
        // Present in the input, but not one of the terms that actually matter: the decoy's
        // own plausible specifics. This is the outcome worth showing.
        setVerifiedButWrong(
          real.filter((r) => !TERMS.some((t) => r.toLowerCase().includes(t.toLowerCase()))),
        )
        if (s.hit.length === TERMS.length) {
          push({
            kind: 'critique',
            title: `Round ${rounds} · self-critique`,
            body: 'All target terms recovered. Stopping.',
            tone: 'bad',
          })
          setResult(s)
          break
        }
        if (rounds >= MAX) {
          push({
            kind: 'critique',
            title: 'Loop exhausted',
            body:
              backend === 'heuristic'
                ? 'The extractor has no further strategies against this input.'
                : `${MAX} rounds of plan/extract/verify produced no verified target terms. Additional rounds cannot help: the agent can only work with the text it was given.`,
          })
          setResult(s)
          break
        }
        push({
          kind: 'critique',
          title: `Round ${rounds} · self-critique`,
          body: `Recovered ${s.hit.length} of ${TERMS.length} target terms. Retrying with the failed guesses excluded.`,
        })
      }
    } catch (e) {
      push({
        kind: 'critique',
        title: 'Agent error',
        body: e instanceof Error ? e.message : String(e),
        tone: 'bad',
      })
    }
    setPhase('done')
  }, [backend, input, truncated, modelName, appendToLast, push])

  const stop = () => {
    cancelRef.current = true
  }

  const ch = CHANNELS[channel]
  const expected = ch.recovered.length

  return (
    <div className="w-full">
      {/* ---------------------------------------------------- privacy + capability */}
      <div className="panel rounded-lg p-4 mb-5">
        <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-[12.5px]">
          <span className="flex items-center gap-2 text-emerald-400">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
            Runs in this tab. No request leaves your browser.
          </span>
          {caps.checked && (
            <span className="text-slate-400">
              WebGPU {caps.webgpu ? 'available' : 'not available'}
              {' · '}
              built-in model {caps.chrome ? 'available' : 'not available'}
            </span>
          )}
        </div>
      </div>

      {/* ------------------------------------------------------------- controls */}
      <div className="grid md:grid-cols-[1fr_auto] gap-4 mb-5">
        <div className="panel rounded-lg p-4">
          <div className="text-[11px] uppercase tracking-[0.14em] text-slate-400 mb-2.5">
            What the agent is given
          </div>
          <div className="flex gap-2 flex-wrap">
            {(['text_layer', 'ocr'] as Channel[]).map((c) => (
              <button
                key={c}
                onClick={() => {
                  setChannel(c)
                  setSteps([])
                  setResult(null)
                  setPhase('idle')
                }}
                className={`px-3 py-1.5 rounded text-[12.5px] border transition-colors ${
                  channel === c
                    ? 'border-amber-400/70 bg-amber-400/10 text-amber-400'
                    : 'border-ink-600/70 text-slate-400 hover:text-slate-300'
                }`}
              >
                {c === 'text_layer' ? 'Extracted text layer' : 'OCR of the page'}
              </button>
            ))}
          </div>
          <p className="mt-3 text-[12.5px] leading-relaxed text-slate-400">
            {channel === 'text_layer' ? (
              <>
                {ch.label}. This is what an ingestion pipeline, an agent's file reader
                or a RAG loader actually receives — {ch.chars.toLocaleString()}{' '}
                characters of it.
              </>
            ) : (
              <>
                {ch.label}. This is the honest channel:{' '}
                <span className="text-rose-400">
                  the page is readable and OCR recovers everything
                </span>
                . The format layer removes the cheap path, not every path.
              </>
            )}
          </p>
        </div>

        <div className="panel rounded-lg p-4 flex flex-col gap-2 md:w-64">
          <div className="text-[11px] uppercase tracking-[0.14em] text-slate-400 mb-0.5">
            Attacker
          </div>
          <div className="text-[12.5px] text-slate-300">
            {backend === 'heuristic' && 'Deterministic extractor'}
            {backend === 'webllm' && `Local LLM · ${modelName}`}
            {backend === 'chrome' && 'Browser built-in model'}
          </div>
          {backend === 'heuristic' && (
            <div className="flex flex-col gap-1.5 mt-1">
              {caps.chrome && (
                <button
                  onClick={useChrome}
                  className="text-[12px] text-left text-amber-400 hover:underline"
                >
                  Use this browser's built-in model (no download)
                </button>
              )}
              {caps.webgpu && (
                <button
                  onClick={loadModel}
                  disabled={phase === 'loading'}
                  className="text-[12px] text-left text-amber-400 hover:underline disabled:opacity-50"
                >
                  {phase === 'loading'
                    ? `Loading… ${progress.pct}%`
                    : 'Load a local LLM (~400 MB, cached)'}
                </button>
              )}
            </div>
          )}
          {phase === 'loading' && (
            <div className="mt-1">
              <div className="h-1 bg-ink-700 rounded overflow-hidden">
                <div
                  className="h-full bg-amber-400 transition-all"
                  style={{ width: `${progress.pct}%` }}
                />
              </div>
              <div className="mt-1 text-[11px] text-slate-400 truncate">
                {progress.label}
              </div>
            </div>
          )}
          <div className="mt-auto pt-3 flex gap-2">
            <button
              onClick={phase === 'running' ? stop : run}
              disabled={phase === 'loading'}
              className={`flex-1 px-3 py-2 rounded text-[13px] font-medium transition-colors disabled:opacity-40 ${
                phase === 'running'
                  ? 'bg-ink-700 text-slate-300 hover:bg-ink-600'
                  : 'bg-amber-400 text-ink-950 hover:bg-amber-300'
              }`}
            >
              {phase === 'running' ? 'Stop' : phase === 'done' ? 'Run again' : 'Run the attack'}
            </button>
          </div>
        </div>
      </div>

      {/* ------------------------------------------------------------ the log */}
      <div className="panel rounded-lg overflow-hidden">
        <div className="flex items-center justify-between px-4 py-2.5 border-b border-ink-700/60">
          <span className="text-[11px] uppercase tracking-[0.14em] text-slate-400">
            Agent trace
          </span>
          <span className="text-[11px] text-slate-400 font-mono">
            plan → extract → verify → critique
          </span>
        </div>
        <div ref={logRef} className="max-h-[26rem] overflow-y-auto p-4 space-y-3">
          {!steps.length && (
            <p className="text-[13px] text-slate-400 py-8 text-center">
              {phase === 'idle'
                ? 'Press “Run the attack”. The agent gets the extractor output for a real protected PDF and tries to pull the ten sensitive terms out of it.'
                : 'Working…'}
            </p>
          )}
          {steps.map((s) => (
            <div
              key={s.id}
              className={`rounded border-l-2 pl-3 py-1.5 ${
                s.tone === 'bad'
                  ? 'border-rose-400/70'
                  : s.tone === 'good'
                    ? 'border-emerald-400/70'
                    : s.kind === 'verify'
                      ? 'border-amber-400/70'
                      : 'border-ink-600'
              }`}
            >
              <div className="flex items-baseline gap-2 flex-wrap">
                <span className="text-[12.5px] font-medium text-slate-300">{s.title}</span>
                {s.meta && (
                  <span className="text-[11px] text-slate-400 font-mono">{s.meta}</span>
                )}
              </div>
              {s.body && (
                <pre className="mt-1 text-[12px] leading-relaxed text-slate-400 whitespace-pre-wrap font-mono">
                  {s.body}
                </pre>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* ---------------------------------------------------------- the verdict */}
      {result && (
        <div
          className={`mt-5 rounded-lg p-5 border ${
            result.hit.length === 0
              ? 'border-emerald-400/40 bg-emerald-400/[0.06]'
              : 'border-rose-400/40 bg-rose-400/[0.06]'
          }`}
        >
          <div className="flex items-baseline gap-3 flex-wrap">
            <span className="text-2xl font-mono tabnum text-slate-300">
              {result.hit.length}/{TERMS.length}
            </span>
            <span className="text-[13px] text-slate-300">
              sensitive terms recovered from the{' '}
              {channel === 'text_layer' ? 'text layer' : 'OCR transcript'}
            </span>
          </div>
          <p className="mt-3 text-[13px] leading-relaxed text-slate-400 max-w-3xl">
            {channel === 'text_layer' ? (
              <>
                The agent is not being blocked and it is not being confused by
                obfuscation. It is reading a <em>different document</em> — fluent English
                prose from an unrelated committee minute, which is what this PDF's text
                layer actually contains. Extra reasoning rounds cannot recover information
                that was never in the input, which is why the loop stops rather than
                improving.
                {verifiedButWrong.length > 0 && (
                  <>
                    {' '}
                    <span className="text-slate-300">
                      Look at what it did extract, though.
                    </span>{' '}
                    <span className="font-mono text-[12px]">
                      {verifiedButWrong.slice(0, 6).join(' · ')}
                    </span>{' '}
                    — dates, amounts and organisation names that are really present in the
                    text and belong to a document that does not exist. A pipeline does not
                    error here; it indexes those, summarises them, and answers questions
                    with them.
                  </>
                )}
              </>
            ) : (
              <>
                OCR recovers the page, and that is the honest limit of the format layer:
                it removes the cheap, silent, high-volume path — the one an automated
                pipeline takes by default — and imposes a rendering-and-OCR cost on
                anyone determined. It is not a barrier. This is why the design does not
                stop here: layers 2 to 4 add posture-gated decryption, a per-recipient
                fingerprint that survives a photograph, and authorship provenance.
              </>
            )}
          </p>
          {result.missed.length > 0 && (
            <div className="mt-3 text-[12px] text-slate-400">
              <span className="text-slate-300">Never recovered:</span>{' '}
              <span className="font-mono">{result.missed.join(' · ')}</span>
            </div>
          )}
          <div className="mt-3 text-[11.5px] text-slate-400">
            Measured independently by the test suite for this same document:{' '}
            <span className="font-mono text-slate-300">{expected}/{TERMS.length}</span> on
            this channel.{' '}
            {expected === result.hit.length
              ? 'The live run agrees.'
              : 'The live run differs — the model is stochastic; the committed figure is the measured one.'}
          </div>
        </div>
      )}

      {/* ------------------------------------------------- what the machine sees */}
      <details className="mt-5 panel rounded-lg">
        <summary className="px-4 py-3 cursor-pointer text-[12.5px] text-slate-300 hover:text-amber-400">
          Show the raw input the agent was given ({ch.chars.toLocaleString()} characters)
        </summary>
        <pre className="px-4 pb-4 text-[11.5px] leading-relaxed text-slate-400 whitespace-pre-wrap font-mono max-h-72 overflow-y-auto">
          {input}
        </pre>
      </details>
    </div>
  )
}
