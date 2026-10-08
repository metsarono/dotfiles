# Telegram wake-lane patch notes

No live service, private registry, secret file, harness checkout, stow target, or
running session was changed.  These artifacts are review inputs; crossing the
live apply/restart gate still requires the Admiral's explicit approval.

## Hermes finding

`gateway/platforms/api_server.py::_handle_session_chat` ordinarily executes a
turn and returns the assistant content to the HTTP caller.  Its sole mirroring
exception is `_answer_through_live_bot_chat`, which is restricted by
`_admit_to_live_bot_chat` to the canonical Desktop Bot Chat lineage held by a
live Desktop owner.  Naming a Telegram transcript or supplying a continuation
header does not turn that ordinary API response into Telegram output.

Hermes does have the correct internal route:
`hermes_cli/plugins.py::PluginContext.inject_message` schedules
`gateway/run_inbound.py::_dispatch_plugin_message_injection`, which restores the
durable session origin, resolves its authorized delivery adapter, and calls
`BasePlatformAdapter.handle_message`.  The managed patch
`all/.bots/patches/hermes-mailcortex-idle-prompt.patch` exposes a narrow,
authenticated conditional endpoint around that platform path.  It accepts only
an existing Telegram DM key, refuses any observed work or pending adapter input,
and returns `accepted` only after the adapter's real session guard accepts the
event.  Therefore the injected turn and its adapter-delivered reply occupy the
Telegram lane the Admiral watches.

## DeepSeek finding

The dsh RPC persists `session/prompt.request.requestId` as
`user/message.data.source.rpcId`.  `src/harness/bridge.ts` already maps every
event in a bound `telegram-...` session to its owner chat, but
`src/extensions/harness-feed.ts::handleTurnEnd` publishes final prose only when
`Bridge.pendingInbound(chatId)` identifies a Telegram-owned turn.  An RPC turn
had no pending inbound, so `assistant/message` still reached the pvox observer
while the feed discarded the final Telegram reply.

The managed patch
`all/.local/share/dotcortex/patches/dsh-telegram-mailcortex-wake.patch` makes the
Bridge claim only the watcher-owned `mailcortex-` request-ID namespace as a
Telegram inbound.  The existing harness feed then publishes through its own
Telegram transport exactly as it does for an owner-originated turn.  The
watcher requires a `telegram-...` target and mints an unguessable ID in that
namespace; it does not call the Bot API.

The remaining live defect was a cold-start ordering race.  Restoring a session
called `adopt()` before reinstalling its durable chat binding.  Adoption can
synchronously replay the queued MailCortex `user/message`, so the Bridge
dropped that event as unbound.  The later assistant event arrived after the
session became live: pvox spoke it, but the feed had no pending Telegram
inbound and sent nothing.  The patch now binds the validated persisted session
before adoption, preserving the wake event without changing pvox behavior.

## Ductor finding

The v1 `ductor_bot.api.idle_prompt::_run_turn` returned final text only on the
encrypted API WebSocket.  Closing that client after the admission ACK therefore
left the reply in the session.  Ductor already has the correct delivery path:
`bus.adapters.from_webhook_wake` produces a unicast envelope, `MessageBus`
selects transport `tg`, and
`messenger.telegram.transport.TelegramTransport._deliver_webhook_wake` sends
the result through Ductor's configured Telegram bot.

The v2 seam makes `mirror_to_telegram: true` part of the exact encrypted
admission shape.  It refuses admission unless the flat `tg:<owner>` session and
a registered Telegram transport are present.  After the admitted turn, it
submits the result through that MessageBus path with `LockMode.NONE`, avoiding a
second acquisition of the two locks already held for the turn.  The old API
hook remains byte-stable for safe v1 migration; the new
`idle_prompt_telegram.patch` independently retains the bus on the orchestrator.

## Exact private-registry migration

Apply this field-shape change in the private `mailcortex.seats.v1` registry.
Retain each seat's existing URL and private token/key-file path; replace only the
target fields shown here.  Every uppercase value is a placeholder.

```diff
@@ YOUR_DEEPSEEK_SEAT @@
   "deepseek_url": "http://YOUR_LOOPBACK_HOST:YOUR_DEEPSEEK_PORT",
   "deepseek_cookie_file": "YOUR_DEEPSEEK_COOKIE_FILE",
-  "deepseek_session": "YOUR_HIDDEN_API_SESSION",
+  "deepseek_session": "telegram-YOUR_TELEGRAM_SESSION",

@@ YOUR_HERMES_SEAT @@
   "hermes_url": "http://YOUR_LOOPBACK_HOST:YOUR_HERMES_PORT",
   "hermes_api_key_file": "YOUR_HERMES_API_KEY_FILE",
-  "hermes_session": "YOUR_HIDDEN_API_SESSION",
-  "hermes_session_key": "YOUR_HIDDEN_API_SESSION_KEY",
+  "hermes_target": {
+    "mode": "gateway_platform_session",
+    "session_key": "agent:YOUR_PROFILE:telegram:dm:YOUR_CHAT_ID"
+  },

@@ YOUR_NANOBOT_SEAT @@
   "nanobot_url": "http://YOUR_LOOPBACK_HOST:YOUR_NANOBOT_PORT",
   "nanobot_api_token_file": "YOUR_NANOBOT_API_TOKEN_FILE",
-  "nanobot_session": "YOUR_NANOBOT_API_SESSION",
+  "nanobot_target": {
+    "mode": "telegram_gateway",
+    "channel": "telegram",
+    "chat_id": "YOUR_CHAT_ID",
+    "session_key": "telegram:YOUR_CHAT_ID"
+  },
```

The Nano gateway process must receive this private environment setting, pointing
to the same mode-0600 bearer-token file read by the watcher:

```text
NANOBOT_MAILCORTEX_TOKEN_FILE=YOUR_NANOBOT_API_TOKEN_FILE
```

Do not put the token, chat identity, session identity, listener address, or port
in DotCortex.  The Hermes seam continues to use the already-configured Hermes
API authentication.  The Nano seam creates no listener; it adds authenticated
routes to Nano's existing health listener.

## Review and activation order

1. Preflight the complete dsh patch series against a pristine copy of its pinned
   revision, build it, and run its full suite.  On the approved DotCortex
   checkout, the coordinator applies it with:

   ```bash
   cd ~/DotCortex
   tangle-one package-bun.org
   BUN_BUILD_ONLY=dsh-telegram bun-apply
   cd ~/HelmCortex/NEXUS/git/dsh-telegram
   npm run check
   ```

   Do not pass `--help` to `bun-apply`.  After the check passes, restart only
   Orca through the verified local service owner, and only after the Admiral's
   explicit approval.  Require the existing readiness check to pass before
   releasing queued MailCortex work.
2. Run `ductor-seam-apply --site YOUR_DISPOSABLE_SITE` against a pristine Ductor
   0.20.1 copy, then repeat with `--check`.  The complete series, including
   `idle_prompt_telegram.patch`, must apply with zero fuzz and compile.  With
   explicit approval, apply it to Ductor, restart Ductor only, and require
   `/busy` to advertise `ductor.idle_prompt.v2` for the exact default session.
3. Review and apply the Hermes patch to the pinned private Hermes checkout, then
   run the disposable seam test with `HERMES_AGENT_SOURCE=YOUR_HERMES_CHECKOUT`.
4. Review the Nano ordered patch series through `nanobot-apply`'s pristine staged
   preflight.  The complete series must patch and compile before live mutation.
5. Provision the private Nano token-file environment and make the registry
   field-shape changes above.
6. With explicit approval, restart the remaining harnesses one at a time and
   verify each status endpoint.  Restart the watcher last, only after every
   target harness is ready.

Busy or unavailable status leaves mail queued.  An exact negative admission ACK
also leaves it queued.  Once an admission request may have crossed the harness
boundary, a missing or malformed acknowledgement becomes `delivery_unknown`;
the persisted receipt prevents automatic resend.

## Verification ledger

- RED before implementation: watcher suite, 38 tests, 6 errors (new target
  schema and conditional endpoints absent).
- GREEN after implementation: watcher 38/38; Hermes disposable seam 4/4; Nano
  disposable seam 5/5; MailCortex command fixtures 9/9; watcher lifecycle 7/7;
  Syncthing prerequisite fixtures 7/7; Nano cache-policy 2/2, search-isolation
  5/5, and voice-reply 6/6.  Total: 83/83 relevant tests.
- DeepSeek follow-up RED: focused dsh Bridge suite 20/21, with the new RPC-turn
  Telegram-delivery assertion failing before the seam.
- DeepSeek follow-up GREEN: watcher 39/39 and the pristine, fully patched dsh
  suite 75/75.  Cumulative relevant GREEN count at this point: 159/159.
- Orca restart-race RED: the real bridge/feed fixture passed the already-bound
  case but failed the adopt-before-bind restart case, 1/2; the expected final
  Telegram send list was empty while the later assistant event remained
  routable.
- Orca restart-race GREEN: generated patch applies cleanly to both the exact
  staged pvox-bearing runtime shape and the pristine pinned ordered patch
  series.  Focused suites pass 25/25 bridge-final-answer and 6/6 chat-bindings.
  The official process-isolated package check passes 75/75 test files; running
  those files individually to expose case totals passes exactly 697/697, up
  from the previous 694/694 by the three requested integration regressions.
- Ductor follow-up RED: focused encrypted-router fixture 0/1; the admitted final
  result did not reach the fake Telegram transport.  The first complete-series
  preflight also refused the incompatible combined v1/v2 patch before mutation;
  splitting the new core hook preserved safe v1 migration.
- Ductor follow-up GREEN: encrypted idle-prompt 21/21; busy authority and seam
  applier 21/21; idle-compaction 10/10; watcher 39/39.  The unique requested
  follow-up suites are 166/166 (dsh 75 + watcher 39 + Ductor 52); cumulative
  relevant GREEN count including the earlier Hermes/Nano work is 211/211.
- Syntax checks: the watcher and Python fixtures compile; `nanobot-apply` and
  `nanobot-health` pass `bash -n`; both managed runtime patches apply with
  `--fuzz=0` to disposable copies; Nano's complete ordered patch series applies
  with zero fuzz to a pristine pinned package tree; all patched modules compile.
