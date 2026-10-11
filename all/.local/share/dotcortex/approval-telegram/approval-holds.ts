// Runs inside the EXISTING Telegram plugin, which owns its token and poller.
// The gate speaks over a private Unix socket; never starts getUpdates itself.
import { chmodSync } from 'fs'
import { join, isAbsolute } from 'path'

export async function runApprovalHelper(value: Record<string, unknown>, presence = false) {
  const helper = process.env[presence ? 'APPROVAL_PRESENCE_HELPER' : 'APPROVAL_VERDICT_HELPER']
  if (!helper || !isAbsolute(helper) || helper.includes('YOUR_')) return null
  const proc = Bun.spawn([helper], { stdin: new Blob([JSON.stringify(value)]), stdout: 'pipe', stderr: 'ignore' })
  const timer = setTimeout(() => proc.kill(), 2000)
  try {
    const output = await new Response(proc.stdout).text()
    return (await proc.exited) === 0 ? output : null
  } finally { clearTimeout(timer) }
}

export async function approvalPresence(sender: string) {
  await runApprovalHelper({ sender }, true)
}

export async function handleApprovalCallback(ctx: any, data: string, access: {allowFrom: string[]}) {
  const match = /^gate:([ad]):([0-9a-f]{24}):([0-9a-f]{32})$/.exec(data)
  if (!match) return false
  const sender = String(ctx.from?.id ?? '')
  if (!access.allowFrom.includes(sender)) {
    await ctx.answerCallbackQuery({text:'Not authorized.'}).catch(() => {})
    return true
  }
  const [, answer, id, nonce] = match
  const result = await runApprovalHelper({id, nonce, sender, behavior:answer === 'a' ? 'allow' : 'deny'})
  const label = result === null ? 'Expired, already answered, or unauthorized.' : answer === 'a' ? 'Allowed once.' : 'Denied.'
  await ctx.answerCallbackQuery({text:label}).catch(() => {})
  if (result !== null) await ctx.editMessageReplyMarkup({reply_markup:{inline_keyboard:[]}}).catch(() => {})
  return true
}

export function startApprovalHolds(bot: any, loadAccess: () => {allowFrom:string[]}, stateDir: string) {
  // Missing helper leaves the ordinary channel untouched and the gate's send
  // fails closed immediately. A reviewed installation enables this seam.
  if (!process.env.APPROVAL_VERDICT_HELPER) return
  const path = process.env.APPROVAL_TELEGRAM_HOLD_SOCKET ?? join(stateDir, 'approval-telegram-hold.sock')
  if (!isAbsolute(path)) throw new Error('approval hold socket must be absolute')
  const server = Bun.serve({ unix:path, maxRequestBodySize:4096, async fetch(request) {
    if (request.method !== 'POST' || new URL(request.url).pathname !== '/hold') return new Response('', {status:404})
    try {
      const value = await request.json() as {id:string; nonce:string}
      if (Object.keys(value).sort().join(',') !== 'id,nonce' || !/^[0-9a-f]{24}$/.test(value.id) || !/^[0-9a-f]{32}$/.test(value.nonce)) return new Response('', {status:400})
      // Preview comes from the held queue record, never from caller-supplied prose.
      const raw = await runApprovalHelper({...value, action:'preview'})
      if (raw === null) return new Response('', {status:409})
      const details = JSON.parse(raw)
      const sender = details.admiral
      if (!loadAccess().allowFrom.includes(sender)) return new Response('', {status:403})
      const preview = JSON.stringify(details.request.tool_input, null, 2)
      const text = `Held approval ${value.id}\n${details.request.tool_name}: ${preview}\n\nTimeout: ${details.timeout_seconds}s; then deny and morning queue.`
      // Full preview is mandatory. Never truncate into an uninformed allow.
      if (text.length > 3900) return new Response('', {status:413})
      void bot.api.sendMessage(sender, text, { reply_markup:{inline_keyboard:[[
        {text:'Allow once', callback_data:`gate:a:${value.id}:${value.nonce}`},
        {text:'Deny', callback_data:`gate:d:${value.id}:${value.nonce}`},
      ]]}}).catch(() => runApprovalHelper({...value, action:'delivery_failed'}))
      // Accepted by the paired plugin; delivery completes asynchronously. A
      // failed Bot API send is recorded in the same queue and releases the hold.
      return new Response('sent')
    } catch { return new Response('', {status:503}) }
  }})
  chmodSync(path, 0o600)
  process.once('exit', () => server.stop(true))
}
