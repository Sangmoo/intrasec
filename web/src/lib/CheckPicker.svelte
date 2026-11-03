<script>
  // 보안 점검 항목 선택. 전체 선택이면 only = [] (서버가 전체 실행), 아니면 선택한 점검 ID 목록.
  import { api } from './api.js'

  let { only = $bindable([]), count = $bindable(0) } = $props()

  let checks = $state([])
  let selected = $state(new Set())
  let error = $state('')

  api('GET', '/api/checks')
    .then((cs) => {
      checks = cs
      selected = new Set(cs.map((c) => c.id))
    })
    .catch((e) => (error = e.message))

  $effect(() => {
    count = selected.size
    only = selected.size === checks.length ? [] : [...selected]
  })

  function toggle(id) {
    const n = new Set(selected)
    n.has(id) ? n.delete(id) : n.add(id)
    selected = n
  }
  const all = (on) => (selected = new Set(on ? checks.map((c) => c.id) : []))

  // 공통 / 시스템 유형별로 묶는다
  const groups = $derived([
    { title: '공통 점검 (모든 대상)', items: checks.filter((c) => c.id.startsWith('COMMON-')) },
    { title: '시스템 유형별 점검 (해당 유형 대상에만 실행)', items: checks.filter((c) => !c.id.startsWith('COMMON-')) },
  ])
</script>

{#if error}<p class="error">{error}</p>{/if}
<div class="row">
  <button class="small" onclick={() => all(true)}>전체 선택</button>
  <button class="small" onclick={() => all(false)}>전체 해제</button>
  <span class="muted">{selected.size} / {checks.length}개 선택</span>
</div>

{#each groups as g}
  {#if g.items.length}
    <p class="group-title">{g.title}</p>
    <div class="checks">
      {#each g.items as c (c.id)}
        <label class={`check-card ${selected.has(c.id) ? 'on' : ''}`}>
          <div class="check-head">
            <input type="checkbox" checked={selected.has(c.id)} onchange={() => toggle(c.id)} />
            <b>{c.name}</b>
            <code>{c.id}</code>
          </div>
          <ul>
            {#each c.items as it}
              <li><span class={`dot sev-${it.severity}`}></span>{it.title}</li>
            {/each}
          </ul>
          {#if c.note}<p class="muted">{c.note}</p>{/if}
        </label>
      {/each}
    </div>
  {/if}
{/each}
