# Product

## Register

product

## Users

Users batch-check free proxy lists for general HTTPS access and AI service reachability. They work with large pasted lists, repeated detection runs, saved repositories, cloud sync links, scheduled background jobs, and public deployments. The product must stay dense, predictable, protected, and fast to operate.

## Product Purpose

Proxy Checker v6.1 is a self-hosted-first free proxy checker, repository maintainer, and scheduled automation tool. It pulls from continuously updated public proxy sources, deduplicates large batches, checks HTTP, HTTPS, SOCKS4, SOCKS5, and SOCKS5H proxies, and helps users save, filter, re-check, export, sync, schedule, and share usable proxies through stable TXT / JSON repository links.

The product supports five target profiles: generic HTTPS proxy checking, OpenAI, Grok, Gemini, and Claude. Results should explain practical network usefulness: base reachability, service homepage reachability, API-domain reachability, Cloudflare status where relevant, exit IP, country, IP type, grade, and recommended use.

Detection results are deployment-relative. The recommended deployment target is the same server that will actually use the proxies, because a proxy reachable from one server may be unreachable from another. The product must keep repeating this idea in plain language: the useful path is the user's server to proxy IP to target service.

Account registration must not be inferred from a registration-page HTTP probe. Signup success depends on platform risk controls, phone/email inputs, browser state, account history, and timing. The product should avoid presenting "registration ready" as a proxy quality dimension.

## Brand Personality

Technical, direct, utilitarian, and friendly to linux.do-style operators. The README can sell the tool with practical enthusiasm, but the app itself should feel like a reliable operations panel, not a marketing landing page.

## Anti-references

Avoid marketing-page composition, decorative cards, oversized hero sections, hidden primary actions, hover-only essential actions, and server-specific defaults that would leak a private deployment into the public GitHub version.

## Design Principles

- Keep repeated workflows one click away.
- Make status and failure reasons visible without extra ceremony.
- Preserve standard controls and predictable button placement.
- Prefer public, portable defaults over private deployment assumptions.
- Keep the UI compact enough for large proxy batches and long source lists.
- Treat registration-page reachability as out of scope; show network usefulness instead of signup promises.
- Protect operational actions with a configurable login password while keeping generated repository links usable by other programs.
- On same-origin self-hosted deployments, unauthenticated users should receive only the login page, not the main app shell.
- Keep auto mode backend-driven on self-hosted Python deployments; browser timers must not be the source of truth for scheduled checks.
- Show scheduled times in one explicit plan timezone, never by mixing server-local text with browser-local timestamp formatting.
- Keep run history visible through a product-level log view, not only process logs.
- Make serverless deployments degrade clearly when background scheduling is unavailable.
- Treat `config.local.json`, environment variables, logs, repository data, checked history, auto state, and run logs as deployment-local state.
- Keep result tags understandable through plain-language title text.

## Accessibility & Inclusion

Prefer complete, low-friction workflows that do not require manual stitching. Keep actions explicit, labels plain, buttons visible by default, and controls reachable without relying on hover-only discovery.

## Release Context

v6.1 is the current public GitHub release line. It keeps the v6.0 general-purpose proxy checker foundation: target profiles for generic/OpenAI/Grok/Gemini/Claude, registration-page detection removal, practical usefulness labels, exit IP/country/IP-type reporting, dynamic proxy source aggregation at 1W+ scale, repository filtering and cloud sync, refresh-safe detection, visible row actions, password-gated same-origin app shell, global settings, run logs, timezone-aware backend auto tasks, automatic repository maintenance, serverless degradation messaging, smoke coverage, and release documentation.

v6.1 focuses on release polish for real large-batch use: result lists render in batches instead of pushing every proxy into the DOM at once, saved detection results are debounced, filters re-render from data instead of walking huge DOM lists, Cloudflare wording is more honest, settings rounds sync back into the main detection controls, the concurrent setting remains wired through to both the frontend request and backend semaphore/client limits, auto mode wording is standardized as auto tasks, modal actions are more compact, the header/stat layout is tighter, Deep Check status moves into settings, repository action labels are shorter, and visible buttons use emoji labels for faster scanning.
