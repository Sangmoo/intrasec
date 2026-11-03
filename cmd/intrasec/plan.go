package main

import (
	"fmt"
	"io"
	"strings"

	"github.com/Sangmoo/intrasec/internal/engine"
	"github.com/Sangmoo/intrasec/internal/scope"
)

// printPlan 은 scan --dry-run 의 실행 계획을 출력한다. 요청은 보내지 않는다.
func printPlan(w io.Writer, cfg *scope.Config, p *engine.Plan) {
	o := p.Options
	fmt.Fprintf(w, "실행 계획 (요청 없음): %s\n", cfg.Engagement.Name)
	fmt.Fprintf(w, "  승인: %s (%s)\n", cfg.Engagement.ApprovedBy, cfg.Engagement.ApprovalRef)
	if p.WindowErr != nil {
		fmt.Fprintf(w, "  시간대: 지금 실행하면 거부됨 — %v\n", p.WindowErr)
	} else {
		fmt.Fprintln(w, "  시간대: 허용 시간대 안")
	}
	mode := "일반"
	if o.SafeMode {
		mode = "운영 안전 모드"
	}
	budget := "무제한"
	if o.MaxRequestsPerTarget > 0 {
		budget = fmt.Sprintf("%d", o.MaxRequestsPerTarget)
	}
	fmt.Fprintf(w, "  모드: %s / 초당 %v요청 / 동시 %d / 호스트당 상한 %s / 연속 5xx %d회 일시정지 / active %v\n",
		mode, o.RateLimit, o.Concurrency, budget, o.PauseOn5xx, o.ActiveChecks)
	for _, t := range p.Targets {
		var ids []string
		for _, j := range p.Jobs {
			if j.Target.Name == t.Name {
				ids = append(ids, j.Check.ID())
			}
		}
		fmt.Fprintf(w, "  대상 %s %s: %s\n", t.Name, t.BaseURL, strings.Join(ids, ", "))
	}
	for _, s := range p.Skipped {
		fmt.Fprintf(w, "  제외: %s\n", s)
	}
	fmt.Fprintf(w, "  작업 %d건\n", len(p.Jobs))
}
