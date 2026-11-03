<script>
  import { api } from '../lib/api.js'
  import FindingList from '../lib/FindingList.svelte'

  let { a, b } = $props()
  let diff = $state(null)
  let error = $state('')

  $effect(() => {
    diff = null
    api('GET', `/api/scans/${a}/diff/${b}`).then((d) => (diff = d)).catch((e) => (error = e.message))
  })
</script>

<section class="card">
  <h2>점검 비교</h2>
  <p>이전 <a href={`#/scans/${a}`}><code>{a}</code></a> → 이후 <a href={`#/scans/${b}`}><code>{b}</code></a></p>
  {#if error}<p class="error">{error}</p>{/if}
</section>

{#if diff}
  <section class="card">
    <h2>신규 {diff.new.length}건</h2>
    <FindingList findings={diff.new} filterable={false} />
  </section>
  <section class="card">
    <h2>조치됨 {diff.resolved.length}건</h2>
    <FindingList findings={diff.resolved} filterable={false} />
  </section>
  <section class="card">
    <h2>미조치 {diff.unchanged.length}건</h2>
    <FindingList findings={diff.unchanged} filterable={false} />
  </section>
{/if}
