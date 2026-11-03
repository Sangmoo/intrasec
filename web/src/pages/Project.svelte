<script>
  import { api, fmtTime, SEVERITIES } from '../lib/api.js'
  import ScopeSummary from '../lib/ScopeSummary.svelte'
  import ScopeForm from '../lib/ScopeForm.svelte'
  import CheckPicker from '../lib/CheckPicker.svelte'

  let { id } = $props()

  let project = $state(null)
  let summary = $state(null)
  let config = $state(null)
  let scopeErrors = $state([])
  let scans = $state([])
  let error = $state('')

  // 점검 실행 옵션
  let safe = $state(true)
  let only = $state([]) // 선택한 점검 ID (전체 선택이면 빈 배열)
  let selectedCount = $state(1)
  let passwords = $state({})
  let confirmed = $state(false)
  let plan = $state(null)
  let runError = $state('')
  let busy = $state(false)

  // 대상 정보 수정
  let editing = $state(false)
  let rawEdit = $state(false)
  let formYaml = $state('')
  let rawYaml = $state('')
  let editErrors = $state([])

  // 비교 선택
  let picked = $state([])

  async function load() {
    try {
      const r = await api('GET', `/api/projects/${id}`)
      project = r.project
      summary = r.summary || null
      config = r.config || null
      scopeErrors = r.errors || []
      rawYaml = project.scope_yaml
      if (summary?.safe_mode) safe = true
      scans = await api('GET', `/api/projects/${id}/scans`)
    } catch (e) {
      error = e.message
    }
  }
  load()

  function body(dryRun) {
    return { project_id: id, safe, dry_run: dryRun, only, passwords: dryRun ? {} : passwords }
  }

  // 점검 항목·옵션이 바뀌면 이전 계획은 무효
  $effect(() => {
    only
    safe
    plan = null
    confirmed = false
  })

  async function dryRun() {
    runError = ''
    try {
      plan = (await api('POST', '/api/scans', body(true))).plan
    } catch (e) {
      runError = e.message
    }
  }

  async function start() {
    busy = true
    runError = ''
    try {
      const r = await api('POST', '/api/scans', body(false))
      passwords = {}
      location.hash = `#/scans/${r.scan_id}`
    } catch (e) {
      runError = e.message
    } finally {
      busy = false
    }
  }

  async function saveScope() {
    editErrors = []
    try {
      await api('POST', `/api/projects/${id}`, { scope_yaml: rawEdit ? rawYaml : formYaml })
      editing = false
      await load()
    } catch (e) {
      editErrors = e.errors.length ? e.errors : [e.message]
    }
  }

  async function remove() {
    if (!confirm(`프로젝트 "${project.name}" 와 모든 점검 결과를 삭제합니다.`)) return
    await api('POST', `/api/projects/${id}/delete`)
    location.hash = '#/'
  }

  function togglePick(sid) {
    picked = picked.includes(sid) ? picked.filter((x) => x !== sid) : [...picked, sid].slice(-2)
  }
  // 오래된 점검을 base 로
  const diffHref = $derived.by(() => {
    if (picked.length !== 2) return ''
    const [a, b] = [...picked].sort()
    return `#/diff/${a}/${b}`
  })
</script>

{#if error}
  <section class="card"><p class="error">{error}</p></section>
{:else if project}
  <section class="card">
    <div class="row between">
      <h2>{project.name}</h2>
      <div class="row">
        <button onclick={() => (editing = !editing)}>{editing ? '수정 취소' : '대상 정보 수정'}</button>
        <button class="danger" onclick={remove}>삭제</button>
      </div>
    </div>
    {#if summary && !editing}<ScopeSummary {summary} />{/if}
    {#if scopeErrors.length}<ul class="error">{#each scopeErrors as e}<li>{e}</li>{/each}</ul>{/if}
    {#if editing}
      <div class="row">
        <button class="small" onclick={() => (rawEdit = !rawEdit)}>{rawEdit ? '입력 양식으로' : '고급: YAML 직접 수정'}</button>
      </div>
      {#if rawEdit || !config}
        <textarea rows="22" spellcheck="false" bind:value={rawYaml}></textarea>
      {:else}
        <ScopeForm {config} bind:yaml={formYaml} />
      {/if}
      <button class="primary" onclick={saveScope}>저장</button>
      {#if editErrors.length}<ul class="error">{#each editErrors as e}<li>{e}</li>{/each}</ul>{/if}
    {/if}
  </section>

  {#if summary && !editing}
    <section class="card">
      <h2>보안 점검 실행</h2>
      <h3>1. 점검 항목 선택</h3>
      <CheckPicker bind:only bind:count={selectedCount} />

      <h3>2. 실행 옵션</h3>
      <label class="check">
        <input type="checkbox" bind:checked={safe} disabled={summary.safe_mode} />
        운영 안전 모드 (초당 2요청·동시 1·호스트당 60요청·경로 탐색 최소화)
        {#if summary.safe_mode}<span class="muted">— 대상 정보에서 켜져 있음</span>{/if}
      </label>
      {#each summary.auth_envs as env}
        <label>테스트 계정 비밀번호 <code>{env}</code> (저장되지 않음 · 비우면 서버 환경변수 사용)
          <input type="password" autocomplete="off" bind:value={passwords[env]} />
        </label>
      {/each}

      <h3>3. 확인 후 실행</h3>
      <div class="row">
        <button onclick={dryRun} disabled={selectedCount === 0}>실행 계획 확인 (요청 없음)</button>
        {#if selectedCount === 0}<span class="error">점검 항목을 하나 이상 선택하십시오.</span>{/if}
      </div>
      {#if plan}
        <div class="plan">
          <p>
            {#if plan.in_window}<span class="badge ok">시간대 안</span>{:else}<span class="badge sev-high">시간대 밖 — 실행 불가</span>{/if}
            {plan.safe_mode ? '운영 안전 모드' : '일반 모드'} · 초당 {plan.rate_limit}요청 · 동시 {plan.concurrency}
            · 호스트당 상한 {plan.max_requests_per_target || '무제한'} · 작업 {plan.jobs}건
          </p>
          {#if plan.window_error}<p class="muted">{plan.window_error}</p>{/if}
          <ul>
            {#each Object.entries(plan.targets) as [t, ids]}<li><code>{t}</code>: {ids.join(', ') || '실행할 점검 없음'}</li>{/each}
          </ul>
          {#if plan.skipped.length}<p class="muted">제외: {plan.skipped.join(', ')}</p>{/if}
        </div>
        <label class="check"><input type="checkbox" bind:checked={confirmed} /> 승인된 대상·시간대임을 확인했습니다</label>
        <button class="primary" disabled={!confirmed || !plan.in_window || busy || plan.jobs === 0} onclick={start}>점검 시작</button>
      {/if}
      {#if runError}<p class="error">{runError}</p>{/if}
    </section>
  {/if}

  <section class="card">
    <div class="row between">
      <h2>점검 이력</h2>
      {#if diffHref}<a class="button" href={diffHref}>선택한 2건 비교</a>{:else}<span class="muted">2건을 선택하면 비교할 수 있습니다</span>{/if}
    </div>
    {#if scans.length === 0}
      <p class="muted">점검 이력이 없습니다.</p>
    {:else}
      <table>
        <thead><tr><th></th><th>점검 ID</th><th>상태</th><th>시작</th><th>결과</th></tr></thead>
        <tbody>
          {#each scans as s (s.id)}
            <tr>
              <td><input type="checkbox" checked={picked.includes(s.id)} disabled={!s.summary} onchange={() => togglePick(s.id)} /></td>
              <td><a href={`#/scans/${s.id}`}><code>{s.id}</code></a>{#if s.safe_mode} <span class="badge ok">안전</span>{/if}</td>
              <td><span class={`status st-${s.status}`}>{s.status}</span></td>
              <td>{fmtTime(s.started_at)}</td>
              <td>
                {#each SEVERITIES as sev}
                  {#if s.summary?.[sev]}<span class={`badge sev-${sev}`}>{sev} {s.summary[sev]}</span>{/if}
                {/each}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
  </section>
{/if}
