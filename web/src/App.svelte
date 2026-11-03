<script>
  import { token } from './lib/api.js'
  import Projects from './pages/Projects.svelte'
  import Project from './pages/Project.svelte'
  import Scan from './pages/Scan.svelte'
  import Diff from './pages/Diff.svelte'

  let hash = $state(location.hash || '#/')
  $effect(() => {
    const on = () => (hash = location.hash || '#/')
    window.addEventListener('hashchange', on)
    return () => window.removeEventListener('hashchange', on)
  })

  const route = $derived.by(() => {
    let m
    if ((m = hash.match(/^#\/projects\/(\d+)$/))) return { page: 'project', id: Number(m[1]) }
    if ((m = hash.match(/^#\/scans\/([\w-]+)$/))) return { page: 'scan', id: m[1] }
    if ((m = hash.match(/^#\/diff\/([\w-]+)\/([\w-]+)$/))) return { page: 'diff', a: m[1], b: m[2] }
    return { page: 'projects' }
  })
</script>

<header class="top">
  <a class="brand" href="#/">intrasec</a>
  <span class="muted">승인된 사내 시스템 보안 점검</span>
</header>

<main class="wrap">
  {#if !token}
    <section class="card warn">
      <h2>인증 토큰 없음</h2>
      <p>터미널에서 <code>intrasec serve</code> 를 실행했을 때 출력된 주소(<code>#token=...</code> 포함)로 다시 여십시오.</p>
    </section>
  {:else if route.page === 'project'}
    {#key route.id}<Project id={route.id} />{/key}
  {:else if route.page === 'scan'}
    {#key route.id}<Scan id={route.id} />{/key}
  {:else if route.page === 'diff'}
    <Diff a={route.a} b={route.b} />
  {:else}
    <Projects />
  {/if}
</main>
