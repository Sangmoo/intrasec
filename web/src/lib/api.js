// 토큰은 serve 가 연 URL 의 프래그먼트(#token=...)로 받아 sessionStorage 에만 둔다 (서버 로그·Referer 에 남지 않음).
const KEY = 'intrasec-token'

function initToken() {
  const m = location.hash.match(/token=([0-9a-f]+)/)
  if (m) {
    try { sessionStorage.setItem(KEY, m[1]) } catch { /* 저장 불가 시 메모리만 */ }
    history.replaceState(null, '', location.pathname + '#/')
    return m[1]
  }
  try { return sessionStorage.getItem(KEY) || '' } catch { return '' }
}

export const token = initToken()

export class ApiError extends Error {
  constructor(status, body) {
    super(body?.error || `HTTP ${status}`)
    this.status = status
    this.errors = body?.errors || []
  }
}

export async function api(method, path, body) {
  const res = await fetch(path, {
    method,
    headers: { 'X-Intrasec-Token': token, ...(body ? { 'Content-Type': 'application/json' } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  })
  const text = await res.text()
  let data = null
  try { data = text ? JSON.parse(text) : null } catch { data = { error: text } }
  if (!res.ok) throw new ApiError(res.status, data)
  return data
}

// events 는 SSE 를 fetch 스트림으로 읽는다 (EventSource 는 토큰 헤더를 보낼 수 없음).
export async function events(scanId, onEvent, signal) {
  const res = await fetch(`/api/scans/${scanId}/events`, { headers: { 'X-Intrasec-Token': token }, signal })
  if (!res.ok) throw new ApiError(res.status, null)
  const reader = res.body.getReader()
  const dec = new TextDecoder()
  let buf = ''
  for (;;) {
    const { value, done } = await reader.read()
    if (done) return
    buf += dec.decode(value, { stream: true })
    let i
    while ((i = buf.indexOf('\n\n')) >= 0) {
      const chunk = buf.slice(0, i)
      buf = buf.slice(i + 2)
      const line = chunk.split('\n').find((l) => l.startsWith('data: '))
      if (line) onEvent(JSON.parse(line.slice(6)))
    }
  }
}

// download 는 토큰 헤더를 붙여 리포트를 받아 저장한다.
export async function download(path, filename) {
  const res = await fetch(path, { headers: { 'X-Intrasec-Token': token } })
  if (!res.ok) throw new ApiError(res.status, null)
  const url = URL.createObjectURL(await res.blob())
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info']

export function fmtTime(s) {
  if (!s) return '-'
  return new Date(s).toLocaleString('ko-KR', { hour12: false })
}
