<script>
  import { api, fmtTime } from '../lib/api.js'
  import ScopeForm from '../lib/ScopeForm.svelte'
  import ScopeSummary from '../lib/ScopeSummary.svelte'

  let projects = $state([])
  let loadError = $state('')
  let name = $state('')
  let formYaml = $state('')
  let rawMode = $state(false)
  let rawYaml = $state('')
  let check = $state(null) // {ok, errors, summary}
  let saving = $state(false)
  let saveError = $state('')

  const yaml = $derived(rawMode ? rawYaml : formYaml)

  async function load() {
    try {
      projects = await api('GET', '/api/projects')
    } catch (e) {
      loadError = e.message
    }
  }
  load()

  function toggleRaw() {
    if (!rawMode) rawYaml = formYaml
    rawMode = !rawMode
    check = null
  }

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
    <p class="muted">아직 프로젝트가 없습니다. 아래에서 점검 대상을 등록하십시오.</p>
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
  <div class="row between">
    <h2>새 점검 대상 등록</h2>
    <button class="small" onclick={toggleRaw}>{rawMode ? '입력 양식으로' : '고급: YAML 직접 입력'}</button>
  </div>
  <label>프로젝트 이름 <span class="req">*</span><input bind:value={name} placeholder="예: ERP 운영 WAS" /></label>

  {#if rawMode}
    <label>scope.yaml <textarea rows="24" spellcheck="false" bind:value={rawYaml}></textarea></label>
  {:else}
    <ScopeForm bind:yaml={formYaml} fallbackName={name} />
    <details>
      <summary>생성된 scope.yaml 보기</summary>
      <pre>{formYaml}</pre>
    </details>
  {/if}

  <div class="row">
    <button onclick={validate}>입력 확인</button>
    <button class="primary" disabled={saving || !name.trim()} onclick={save}>저장</button>
  </div>
  {#if saveError}<p class="error">{saveError}</p>{/if}
  {#if check}
    {#if check.ok}
      <p class="ok">입력이 올바릅니다.</p>
      <ScopeSummary summary={check.summary} />
    {:else}
      <ul class="error">{#each check.errors as e}<li>{e}</li>{/each}</ul>
    {/if}
  {/if}
</section>
