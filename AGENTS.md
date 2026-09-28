<!-- LOVABLE:BEGIN -->
> [!IMPORTANT]
> This project is connected to [Lovable](https://lovable.dev). Avoid rewriting
> published git history — force pushing, or rebasing/amending/squashing commits
> that are already pushed — as it rewrites history on Lovable's side and the
> user will likely lose their project history.
>
> Commits you push to the connected branch sync back to Lovable and show up in
> the editor, so keep the branch in a working state.
<!-- LOVABLE:END -->

## SIH26145 console rules
- All backend access goes through `src/lib/api.ts` (typed fetch against `VITE_API_BASE_URL`) and `src/lib/queries.ts` (react-query options); no component fetches directly, so polling intervals and the API base stay in one place.
- Live rows come from `src/hooks/useAlertStream.ts` (WS `/ws/alerts`) merged with polled `/recent_alerts`; the WS is the source of truth and polling is only backfill.
- Component status levels are derived in `src/lib/system.ts` only from `/health`, `/stats`, `/meta`; unknown state must render UNKNOWN rather than assume healthy.
- Never render fabricated metrics: missing backend fields render "not reported" or an `Unavailable`/`Pending` state.
- Motion lives in `src/styles.css` CSS animations (no framer-motion) and is disabled under `prefers-reduced-motion`.
