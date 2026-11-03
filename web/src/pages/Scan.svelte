<script>
  import { api, events, download, fmtTime } from '../lib/api.js'
  import FindingList from '../lib/FindingList.svelte'

  let { id } = $props()

  let scan = $state(null)
  let result = $state(null)
  let progress = $state({ done: 0, total: 0 })
  let log = $state([])
  let error = $state('')

  async function loadScan() {
    try {
      const r = await api('GET', `/api/scans/${id}`)
      scan = r.scan
      result = r.result
    } catch (e) {
      error = e.message
    }
  }

  $effect(() => {
    const ctl = new AbortController()
    loadScan().then(() => {
      if (scan?.status !== 'running') return
      events(id, (e) => {
        if (e.type === 'progress') {
          progress = { done: e.done, total: e.total }
          log = [...log.slice(-200), e]
        } else if (e.type === 'finished') {
          loadScan()
        }
      }, ctl.signal).catch((e) => {
        if (e.name !== 'AbortError') error = e.message
      })
    })
    return () => ctl.abort()
  })

  async function cancel() {
    await api('POST', `/api/scans/${id}/cancel`)
  }

  async function get(fmt) {
    try {
      await download(`/api/scans/${id}/report?format=${fmt}`, `intrasec-${id}.${fmt}`)
    } catch (e) {
      error = e.message
    }
  }

  const pct = $derived(progress.total ? Math.round((progress.done / progress.total) * 100) : 0)
</script>

{#if error}<section class="card"><p class="error">{error}</p></section>{/if}

{#if scan}
  <section class="card">
    <div class="row between">
      <h2>점검 <code>{scan.id}</code></h2>
      <a href={`#/projects/${scan.project_id}`}>← 프로젝트</a>
    </div>
    <p>
      <span class={`status st-${scan.status}`}>{scan.status}</span>
      {#if scan.safe_mode}<span class="badge ok">운영 안전 모드</span>{/if}
      · 시작 {fmtTime(scan.started_at)}{#if scan.finished_at} · 종료 {fmtTime(scan.finished_at)}{/if}
    </p>
    {#if scan.error}<p class="error">{scan.error}</p>{/if}

    {#if scan.status === 'running'}
      <progress max="100" value={pct}></progress>
      <p>{progress.done} / {progress.total} 작업 ({pct}%)</p>
      <button class="danger" onclick={cancel}>중단</button>
      <ul class="log">
        {#each log as e}
          <li><code>{e.check_id}</code> @ {e.target} — {e.error ? '오류: ' + e.error : (e.findings ?? 0) + '건'}</li>
        {/each}
      </ul>
    {/if}

    {#if result}
      <div class="row">
        <span class="muted">리포트 다운로드:</span>
        <button onclick={() => get('html')}>HTML</button>
        <button onclick={() => get('md')}>Markdown</button>
        <button onclick={() => get('json')}>JSON</button>
        <button onclick={() => get('sarif')}>SARIF</button>
      </div>
    {/if}
  </section>

  {#if result}
    <section class="card">
      <h2>발견 항목 {result.findings.length}건</h2>
      <FindingList findings={result.findings} />
    </section>
    {#if result.errors?.length || result.skipped?.length}
      <section class="card">
        <h2>실행 정보</h2>
        {#if result.skipped?.length}<p class="muted">제외된 점검: {result.skipped.join(', ')}</p>{/if}
        {#if result.errors?.length}<ul class="error">{#each result.errors as e}<li>{e}</li>{/each}</ul>{/if}
      </section>
    {/if}
  {/if}
{/if}
