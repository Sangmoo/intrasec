<script>
  import { api, fmtTime } from '../lib/api.js'
  import ScopeSummary from '../lib/ScopeSummary.svelte'

  const TEMPLATE = `engagement:
  name: ""
  approved_by: ""        # 승인자
  approval_ref: ""       # 결재문서번호 / 승인 메일 제목
  window:
    start: "2026-11-10T19:00:00+09:00"
    end:   "2026-11-10T23:00:00+09:00"

targets:
  - name: ERP
    base_url: https://erp.example.local
    tags: [weblogic]

allow:
  cidrs: [10.0.10.0/28]

options:
  safe_mode: true
`

  let projects = $state([])
  let loadError = $state('')
  let name = $state('')
  let yaml = $state(TEMPLATE)
  let check = $state(null) // {ok, errors, summary}
  let saving = $state(false)
  let saveError = $state('')

  async function load() {
    try {
      projects = await api('GET', '/api/projects')
    } catch (e) {
      loadError = e.message
    }
  }
  load()

  async function validate() {
    check = await api('POST', '/api/scope/validate', { scope_yaml: yaml })
  }

  async function save() {
    saving = true
    saveError = ''
    try {
      const p = await api('POST', '/api/projects', { name, scope_yaml: yaml })
      location.hash = `#/projects/${p.id}`
    } catch (e) {
      saveError = e.message
      if (e.errors.length) check = { ok: false, errors: e.errors }
    } finally {
      saving = false
    }
  }
</script>

<section class="card">
  <h2>점검 프로젝트</h2>
  {#if loadError}<p class="error">{loadError}</p>{/if}
  {#if projects.length === 0}
    <p class="muted">아직 프로젝트가 없습니다. 아래에서 scope 를 등록하십시오.</p>
  {:else}
    <table>
      <thead><tr><th>이름</th><th>등록일</th></tr></thead>
      <tbody>
        {#each projects as p (p.id)}
          <tr><td><a href={`#/projects/${p.id}`}>{p.name}</a></td><td>{fmtTime(p.created_at)}</td></tr>
        {/each}
      </tbody>
    </table>
  {/if}
</section>

<section class="card">
  <h2>새 프로젝트</h2>
  <p class="muted">승인자·승인 근거·점검 시간대가 없는 scope 는 저장할 수 없습니다. 비밀번호는 넣지 마십시오 (password_env 사용).</p>
  <label>이름 <input bind:value={name} placeholder="예: 2026 정기점검 ERP" /></label>
  <label>scope.yaml <textarea rows="22" spellcheck="false" bind:value={yaml}></textarea></label>
  <div class="row">
    <button onclick={validate}>검증</button>
    <button class="primary" disabled={saving || !name.trim()} onclick={save}>저장</button>
  </div>
  {#if saveError}<p class="error">{saveError}</p>{/if}
  {#if check}
    {#if check.ok}
      <ScopeSummary summary={check.summary} />
    {:else}
      <ul class="error">{#each check.errors as e}<li>{e}</li>{/each}</ul>
    {/if}
  {/if}
</section>
