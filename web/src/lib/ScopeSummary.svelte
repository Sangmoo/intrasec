<script>
  import { fmtTime } from './api.js'
  let { summary } = $props()
</script>

<dl class="summary">
  <dt>점검명</dt><dd>{summary.engagement}</dd>
  <dt>승인</dt><dd>{summary.approved_by} ({summary.approval_ref})</dd>
  <dt>시간대</dt>
  <dd>
    {fmtTime(summary.window_start)} ~ {fmtTime(summary.window_end)}
    {#if summary.in_window}<span class="badge ok">지금 실행 가능</span>{:else}<span class="badge">시간대 밖</span>{/if}
  </dd>
  <dt>대상</dt><dd>{#each summary.targets as t}<div><code>{t}</code></div>{/each}</dd>
  <dt>모드</dt>
  <dd>
    {#if summary.safe_mode}<span class="badge ok">운영 안전 모드</span>{:else}일반{/if}
    {#if summary.active_checks}<span class="badge sev-high">active 점검 허용</span>{/if}
  </dd>
</dl>
