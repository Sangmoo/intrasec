<script>
  import { SEVERITIES } from './api.js'
  let { findings = [], filterable = true } = $props()

  let sevFilter = $state(new Set(SEVERITIES))
  let open = $state(new Set())

  const shown = $derived(findings.filter((f) => sevFilter.has(f.severity)))

  function toggleSev(s) {
    const n = new Set(sevFilter)
    n.has(s) ? n.delete(s) : n.add(s)
    sevFilter = n
  }
  function toggleOpen(k) {
    const n = new Set(open)
    n.has(k) ? n.delete(k) : n.add(k)
    open = n
  }
  const count = (s) => findings.filter((f) => f.severity === s).length
</script>

{#if filterable}
  <div class="row filters">
    {#each SEVERITIES as s}
      <button class={`badge sev-${s} ${sevFilter.has(s) ? '' : 'off'}`} onclick={() => toggleSev(s)}>{s} {count(s)}</button>
    {/each}
  </div>
{/if}

{#if shown.length === 0}
  <p class="muted">해당하는 항목이 없습니다.</p>
{:else}
  <ul class="findings">
    {#each shown as f, i (f.id + f.target + i)}
      {@const k = f.id + f.target + i}
      <li>
        <button class="finding-head" onclick={() => toggleOpen(k)} aria-expanded={open.has(k)}>
          <span class={`badge sev-${f.severity}`}>{f.severity}</span>
          <code>{f.check_id}</code>
          <span class="title">{f.title}</span>
          <span class="muted target">{f.target}</span>
        </button>
        {#if open.has(k)}
          <div class="finding-body">
            <p>{f.description}</p>
            <p><b>조치 방법</b>: {f.remediation}</p>
            {#if f.evidence?.note}<p class="muted">{f.evidence.note}</p>{/if}
            <p class="muted">{[...(f.cwe || []), ...(f.owasp || []), ...(f.kisa || []).map((k) => 'KISA ' + k)].join(' · ')}</p>
            {#if f.evidence?.request}<pre>{f.evidence.request}</pre>{/if}
            {#if f.evidence?.response}<pre>{f.evidence.response}</pre>{/if}
          </div>
        {/if}
      </li>
    {/each}
  </ul>
{/if}
