<script>
  // 점검 범위 입력 양식. 입력값으로 scope.yaml 을 만들어 yaml 에 바인딩한다.
  import { api } from './api.js'

  // fallbackName: 점검명을 비워 두면 대신 쓸 이름 (보통 프로젝트 이름)
  let { config = null, yaml = $bindable(''), fallbackName = '' } = $props()

  const TYPES = [
    { tag: 'weblogic', label: 'WebLogic' },
    { tag: 'xplatform', label: 'XPlatform / MiPlatform' },
    { tag: 'php', label: 'PHP' },
  ]
  const KNOWN = TYPES.map((t) => t.tag)

  const pad = (n) => String(n).padStart(2, '0')
  // RFC3339 → <input type="datetime-local"> 값 (로컬 시각)
  function toLocal(iso) {
    const d = iso ? new Date(iso) : null
    if (!d || isNaN(d)) return ''
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`
  }
  // datetime-local 값 → 로컬 오프셋이 붙은 RFC3339
  function fromLocal(v) {
    if (!v) return ''
    const d = new Date(v)
    const off = -d.getTimezoneOffset()
    const sign = off >= 0 ? '+' : '-'
    return `${v}:00${sign}${pad(Math.floor(Math.abs(off) / 60))}:${pad(Math.abs(off) % 60)}`
  }
  function defaultWindow() {
    const s = new Date()
    s.setHours(19, 0, 0, 0)
    const e = new Date(s)
    e.setHours(23)
    return [toLocal(s.toISOString()), toLocal(e.toISOString())]
  }

  function blankTarget(n) {
    return { name: `대상${n}`, base_url: '', ports: '', types: [], extra_tags: [], service_urls: '' }
  }

  function fromConfig(c) {
    const [ws, we] = defaultWindow()
    if (!c) {
      return {
        name: '', approved_by: '', approval_ref: '', start: ws, end: we,
        targets: [blankTarget(1)], cidrs: '', excludes: '',
        auth_on: false,
        auth: { target: '', login_url: '', username_field: 'userId', password_field: 'userPw', username: '', password_env: 'INTRASEC_PW', check_url: '', logged_out_pattern: '' },
        safe_mode: true, rate_limit: 5, concurrency: 4, timeout_sec: 15, active_checks: false,
      }
    }
    const a = c.auth?.[0]
    return {
      name: c.engagement?.name || '',
      approved_by: c.engagement?.approved_by || '',
      approval_ref: c.engagement?.approval_ref || '',
      start: toLocal(c.engagement?.window?.start) || ws,
      end: toLocal(c.engagement?.window?.end) || we,
      targets: (c.targets || []).map((t) => ({
        name: t.name, base_url: t.base_url, ports: (t.ports || []).join(', '),
        types: (t.tags || []).filter((x) => KNOWN.includes(x)),
        extra_tags: (t.tags || []).filter((x) => !KNOWN.includes(x)),
        service_urls: (t.service_urls || []).join('\n'),
      })),
      cidrs: (c.allow?.cidrs || []).join('\n'),
      excludes: (c.exclude_paths || []).join('\n'),
      auth_on: !!a,
      auth: {
        target: a?.target || '', login_url: a?.login_url || '', username_field: a?.username_field || 'userId',
        password_field: a?.password_field || 'userPw', username: a?.username || '', password_env: a?.password_env || 'INTRASEC_PW',
        check_url: a?.check_url || '', logged_out_pattern: a?.logged_out_pattern || '',
      },
      safe_mode: !!c.options?.safe_mode,
      rate_limit: c.options?.rate_limit || 5,
      concurrency: c.options?.concurrency || 4,
      timeout_sec: c.options?.timeout_sec || 15,
      active_checks: !!c.options?.active_checks,
    }
  }

  let f = $state(fromConfig(config))
  let resolveMsg = $state([])

  const lines = (s) => s.split('\n').map((x) => x.trim()).filter(Boolean)
  const q = (s) => JSON.stringify(String(s ?? '')) // JSON 문자열은 그대로 YAML 스칼라로 유효하다
  const list = (arr) => `[${arr.map(q).join(', ')}]`

  function toYAML(f) {
    const out = []
    out.push('engagement:')
    out.push(`  name: ${q(f.name.trim() || fallbackName.trim())}`)
    out.push(`  approved_by: ${q(f.approved_by)}`)
    out.push(`  approval_ref: ${q(f.approval_ref)}`)
    out.push('  window:')
    out.push(`    start: ${q(fromLocal(f.start))}`)
    out.push(`    end: ${q(fromLocal(f.end))}`)
    out.push('', 'targets:')
    for (const t of f.targets) {
      out.push(`  - name: ${q(t.name)}`)
      out.push(`    base_url: ${q(t.base_url.trim())}`)
      const ports = t.ports.split(/[,\s]+/).map(Number).filter((n) => n > 0)
      if (ports.length) out.push(`    ports: [${ports.join(', ')}]`)
      const tags = [...t.types, ...t.extra_tags]
      if (tags.length) out.push(`    tags: ${list(tags)}`)
      const svc = lines(t.service_urls)
      if (svc.length) {
        out.push('    service_urls:')
        for (const s of svc) out.push(`      - ${q(s)}`)
      }
    }
    out.push('', 'allow:')
    out.push(`  cidrs: ${list(lines(f.cidrs))}`)
    const ex = lines(f.excludes)
    if (ex.length) {
      out.push('', 'exclude_paths:')
      for (const e of ex) out.push(`  - ${q(e)}`)
    }
    if (f.auth_on) {
      const a = f.auth
      out.push('', 'auth:')
      out.push(`  - target: ${q(a.target || f.targets[0]?.name)}`)
      out.push('    type: "form"')
      for (const k of ['login_url', 'username_field', 'password_field', 'username', 'password_env', 'check_url', 'logged_out_pattern']) {
        if (a[k]) out.push(`    ${k}: ${q(a[k])}`)
      }
    }
    out.push('', 'options:')
    out.push(`  safe_mode: ${f.safe_mode}`)
    out.push(`  rate_limit: ${Number(f.rate_limit) || 5}`)
    out.push(`  concurrency: ${Number(f.concurrency) || 4}`)
    out.push(`  timeout_sec: ${Number(f.timeout_sec) || 15}`)
    out.push(`  active_checks: ${f.safe_mode ? false : f.active_checks}`)
    return out.join('\n') + '\n'
  }

  $effect(() => {
    yaml = toYAML(f)
  })

  function hostOf(u) {
    try { return new URL(u).hostname } catch { return '' }
  }

  // 대상 URL 의 IP 를 DNS 로 확인해 허용 대역(/32)에 추가한다. 대상 서버로는 요청하지 않는다.
  async function resolveIPs() {
    const hosts = [...new Set(f.targets.map((t) => hostOf(t.base_url)).filter(Boolean))]
    if (!hosts.length) {
      resolveMsg = ['대상 URL 을 먼저 입력하십시오.']
      return
    }
    const r = await api('POST', '/api/resolve', { hosts })
    const have = new Set(lines(f.cidrs))
    const msg = []
    for (const [h, v] of Object.entries(r)) {
      if (Array.isArray(v)) {
        for (const ip of v) have.add(ip.includes(':') ? `${ip}/128` : `${ip}/32`)
        msg.push(`${h} → ${v.join(', ')}`)
      } else {
        msg.push(`${h}: ${v.error}`)
      }
    }
    f.cidrs = [...have].join('\n')
    resolveMsg = msg
  }

  function toggleType(t, tag) {
    t.types = t.types.includes(tag) ? t.types.filter((x) => x !== tag) : [...t.types, tag]
  }
</script>

<fieldset>
  <legend>1. 승인 정보</legend>
  <div class="grid2">
    <label>점검명 (비우면 프로젝트 이름) <input bind:value={f.name} placeholder="예: 2026 하반기 ERP 정기점검" /></label>
    <label>승인자 <span class="req">*</span><input bind:value={f.approved_by} placeholder="예: 정보보안팀 홍길동" /></label>
    <label>승인 근거 <span class="req">*</span><input bind:value={f.approval_ref} placeholder="결재문서번호 또는 승인 메일 제목" /></label>
    <span></span>
    <label>점검 시작 <span class="req">*</span><input type="datetime-local" bind:value={f.start} /></label>
    <label>점검 종료 <span class="req">*</span><input type="datetime-local" bind:value={f.end} /></label>
  </div>
  <p class="muted">이 시간대 밖에서는 점검이 시작되지 않습니다. 운영 시스템은 업무 외 시간으로 지정하십시오.</p>
</fieldset>

<fieldset>
  <legend>2. 점검 대상</legend>
  {#each f.targets as t, i}
    <div class="target">
      <div class="grid2">
        <label>이름 <input bind:value={t.name} /></label>
        <label>URL <span class="req">*</span><input bind:value={t.base_url} placeholder="https://erp.example.local 또는 http://10.0.0.5:7001" /></label>
        <label>추가 포트 (선택, 쉼표 구분) <input bind:value={t.ports} placeholder="예: 7001, 7002" /></label>
        <div>
          <span class="label">시스템 유형 (해당 전용 점검 실행)</span>
          <div class="row">
            {#each TYPES as ty}
              <label class="check"><input type="checkbox" checked={t.types.includes(ty.tag)} onchange={() => toggleType(t, ty.tag)} /> {ty.label}</label>
            {/each}
          </div>
        </div>
      </div>
      {#if t.types.includes('xplatform')}
        <label>XPlatform 조회 서비스 URL (한 줄에 하나, 저장·삭제류는 거부됨)
          <textarea rows="3" bind:value={t.service_urls} placeholder="/svc/selectUserList.do"></textarea>
        </label>
      {/if}
      {#if f.targets.length > 1}
        <button class="danger small" onclick={() => f.targets.splice(i, 1)}>대상 삭제</button>
      {/if}
    </div>
  {/each}
  <button onclick={() => f.targets.push(blankTarget(f.targets.length + 1))}>+ 대상 추가</button>
</fieldset>

<fieldset>
  <legend>3. 허용 IP 대역 <span class="req">*</span></legend>
  <p class="muted">요청은 DNS 해석 후 실제 IP 가 이 대역 안일 때만 나갑니다. 승인받은 서버의 IP 인지 반드시 확인하십시오.</p>
  <div class="row">
    <button onclick={resolveIPs}>대상 URL 의 IP 확인 후 추가</button>
    <span class="muted">(DNS 조회만, 대상 서버로 요청 없음)</span>
  </div>
  {#if resolveMsg.length}<ul class="muted">{#each resolveMsg as m}<li>{m}</li>{/each}</ul>{/if}
  <textarea rows="3" bind:value={f.cidrs} placeholder={'10.0.10.5/32\n10.0.20.0/28'}></textarea>
  <label>제외 경로 (선택, 한 줄에 하나 · logout/delete/결재 등은 기본 제외)
    <textarea rows="2" bind:value={f.excludes} placeholder="/approval/*"></textarea>
  </label>
</fieldset>

<fieldset>
  <legend>4. 로그인 (선택)</legend>
  <label class="check"><input type="checkbox" bind:checked={f.auth_on} /> 테스트 계정으로 로그인 후 점검 (관리자 계정 사용 금지)</label>
  {#if f.auth_on}
    <div class="grid2">
      <label>적용 대상
        <select bind:value={f.auth.target}>
          {#each f.targets as t}<option value={t.name}>{t.name}</option>{/each}
        </select>
      </label>
      <label>로그인 페이지 URL <input bind:value={f.auth.login_url} placeholder="https://erp.example.local/login.do" /></label>
      <label>아이디 입력칸 name <input bind:value={f.auth.username_field} /></label>
      <label>비밀번호 입력칸 name <input bind:value={f.auth.password_field} /></label>
      <label>테스트 계정 아이디 <input bind:value={f.auth.username} placeholder="scan_test01" /></label>
      <label>비밀번호 환경변수 이름 <input bind:value={f.auth.password_env} /></label>
      <label>로그인 확인 페이지 (선택) <input bind:value={f.auth.check_url} placeholder="https://erp.example.local/main.do" /></label>
      <label>세션 만료 문구 정규식 (선택) <input bind:value={f.auth.logged_out_pattern} placeholder="세션이 만료" /></label>
    </div>
    <p class="muted">비밀번호는 저장되지 않습니다. 점검 시작 화면에서 입력하거나 서버 실행 전에 환경변수로 지정하십시오.</p>
  {/if}
</fieldset>

<fieldset>
  <legend>5. 실행 옵션</legend>
  <label class="check"><input type="checkbox" bind:checked={f.safe_mode} /> 운영 안전 모드 (운영 서버 권장: 초당 2요청·동시 1·호스트당 60요청·경로 탐색 최소화)</label>
  {#if !f.safe_mode}
    <div class="grid3">
      <label>초당 요청 수 <input type="number" min="1" max="50" bind:value={f.rate_limit} /></label>
      <label>동시 실행 <input type="number" min="1" max="32" bind:value={f.concurrency} /></label>
      <label>요청 제한시간(초) <input type="number" min="1" bind:value={f.timeout_sec} /></label>
    </div>
  {/if}
</fieldset>
