;;; metsatron-idle-compaction.el --- idle prompt-cache compaction -*- lexical-binding: t; -*-
;; Canonical source: emacs-doom.org.  Regenerate this payload with
;; `tangle-one emacs-doom.org`; do not edit the tangled file in the overlay.

(require 'cl-lib)
(require 'json)
(require 'subr-x)

;; Protocol/package declarations are intentionally soft: Doom may load this
;; file before either IDE package, but byte compilation should still document
;; the exact optional entry points used by the live integration.
(declare-function claude-code-ide--terminal-send-string "claude-code-ide"
                  (string))
(declare-function claude-code-ide--terminal-send-return "claude-code-ide" ())
(declare-function codex-ide-session-thread-id "codex-ide-session" (session))
(declare-function codex-ide-session-directory "codex-ide-session" (session))
(declare-function codex-ide-session-process "codex-ide-session" (session))
(declare-function codex-ide-session-buffer "codex-ide-session" (session))
(declare-function codex-ide-session-status "codex-ide-session" (session))
(declare-function codex-ide--session-metadata-get "codex-ide-session"
                  (session key))
(declare-function codex-ide--session-metadata-put "codex-ide-session"
                  (session key value))
(declare-function codex-ide--session-for-thread-id "codex-ide-session"
                  (thread-id &optional directory))
(declare-function codex-ide--request-sync "codex-ide-protocol"
                  (&optional session method params))
(declare-function codex-ide--request-async "codex-ide-session"
                  (session method params callback))

(defgroup metsatron-idle-compaction nil
  "Idle prompt-cache compaction for Claude and Codex IDE sessions."
  :group 'tools)

(defcustom metsatron-idle-compaction-enabled t
  "Whether idle compaction is enabled globally."
  :type 'boolean :group 'metsatron-idle-compaction)

(defcustom metsatron-idle-compaction-debug nil
  "Whether to log idle-compaction state transitions."
  :type 'boolean :group 'metsatron-idle-compaction)

(defcustom claude-idle-compact-seconds (* 55 60)
  "Idle delay before cache-harvest compaction for one-hour Claude caches."
  :type 'integer :group 'metsatron-idle-compaction)

(defcustom claude-short-cache-idle-compact-seconds (* 4 60)
  "Idle delay before compaction for short-lived Claude prompt caches."
  :type 'integer :group 'metsatron-idle-compaction)

(defcustom claude-idle-compact-min-tokens 70000
  "Minimum active Claude input-context tokens before idle compaction."
  :type 'integer :group 'metsatron-idle-compaction)

(defcustom claude-idle-compact-long-cache-ttl-seconds (* 60 60)
  "Assumed warm-cache TTL for the Claude long-cache profile."
  :type 'integer :group 'metsatron-idle-compaction)

(defcustom claude-idle-compact-short-cache-ttl-seconds (* 5 60)
  "Warm-cache TTL for the Claude short-cache profile."
  :type 'integer :group 'metsatron-idle-compaction)

(defcustom claude-idle-compact-cache-profile 'auto
  "Default Claude prompt-cache profile for new sessions.
`auto' only recognizes explicit environment flags and never guesses a dynamic
subscription/usage-credit TTL."
  :type '(choice (const long) (const short) (const auto))
  :group 'metsatron-idle-compaction)

(defcustom codex-idle-compact-seconds (* 27 60)
  "Idle delay before presumed warm-cache-budget compaction for Codex.
This is a local governor delay, not a backend-reported cache lifetime."
  :type 'integer :group 'metsatron-idle-compaction)

(defcustom codex-presumed-warm-seconds (* 30 60)
  "Presumed Codex warm-cache interval used by the idle governor.
This is a configurable policy budget, not an observed or guaranteed backend
cache lifetime."
  :type 'integer :group 'metsatron-idle-compaction)

(defcustom codex-custom-presumed-warm-seconds (* 30 60)
  "Default presumed warm-cache interval for Codex custom policy sessions.
The interval is deliberately separate from the public API guidance because the
ChatGPT-authenticated app-server backend does not expose its selected policy."
  :type 'integer :group 'metsatron-idle-compaction)

(defcustom codex-cache-policy 'presumed-30m
  "Codex idle-compaction policy.
`disabled' never requests idle compaction.  `presumed-30m' uses the public
GPT-5.6 API minimum-retention guidance as a heuristic warm-cache budget.
`custom' uses `codex-custom-presumed-warm-seconds' or a session override.
None of these values claims to be the authenticated backend's actual policy."
  :type '(choice (const disabled) (const presumed-30m) (const custom))
  :group 'metsatron-idle-compaction)

(defcustom codex-cache-policy-source
  "public GPT-5.6 API minimum-retention documentation"
  "Source label for the global Codex warm-cache policy.
This label describes the policy heuristic, not a wire-level Codex guarantee."
  :type 'string :group 'metsatron-idle-compaction)

(defcustom codex-cache-policy-confidence "heuristic/backend-unverified"
  "Confidence label for the global Codex warm-cache policy."
  :type 'string :group 'metsatron-idle-compaction)

(defcustom codex-idle-compact-raw-telemetry-enabled nil
  "Whether to request and record privacy-safe Codex raw usage telemetry.
When enabled, future `thread/start' requests opt into experimental raw events.
The governor remains fully functional when this is nil."
  :type 'boolean :group 'metsatron-idle-compaction)

(defcustom codex-idle-compact-raw-telemetry-provider-class "unknown"
  "Provider-class label attached to optional Codex raw usage records.
Use values such as `chatgpt-authenticated', `api-key', or `custom' when the
launcher knows the class.  This value is a label only and never contains an
endpoint, account identity, or credential."
  :type 'string :group 'metsatron-idle-compaction)

(defcustom codex-idle-compact-min-tokens 70000
  "Minimum Codex-native current context usage before idle compaction."
  :type 'integer :group 'metsatron-idle-compaction)

(defcustom metsatron-cache-policy-helper
  (expand-file-name "HelmCortex/FORGE/bin/cache-policy" "~")
  "Fleet cache-policy resolver executable."
  :type 'file :group 'metsatron-idle-compaction)

(defcustom metsatron-cache-policy-path
  (expand-file-name
   "HelmCortex/ROOTS/DotRoot/agent-session/centre/data/cache-policy.json" "~")
  "Published endpoint/model cache-policy artifact."
  :type 'file :group 'metsatron-idle-compaction)

;; Compatibility note: Codex 0.146.0 does not expose the ChatGPT backend's
;; selected prompt-cache retention policy.  The governor therefore speaks only
;; of a presumed warm-cache budget and records its source/confidence explicitly.

(defcustom codex-custom-idle-compact-seconds nil
  "Optional global idle delay for Codex custom policy.
When nil, custom policy uses `codex-idle-compact-seconds', capped below the
selected presumed warm-cache interval."
  :type '(choice (const :tag "Derive from default delay" nil) integer)
  :group 'metsatron-idle-compaction)

(defcustom metsatron-idle-compaction-emacs-server "doom"
  "Named Emacs server used by Claude hook helpers."
  :type 'string :group 'metsatron-idle-compaction)

(defvar metsatron/claude-idle-compact--sessions (make-hash-table :test #'equal)
  "Claude idle-compaction state keyed by the unique launch channel.")

(defconst metsatron/codex-idle-compact--metadata-key
  :metsatron-idle-compaction
  "Codex session metadata key for governor state.")

(defun metsatron/idle-compaction--now ()
  "Return the wall-clock timestamp used by idle-compaction state."
  (float-time))

(defun metsatron/idle-compaction--short-id (value)
  "Return a safe truncated representation of VALUE for debug logging."
  (let ((text (format "%s" (or value "unknown"))))
    (if (> (length text) 12) (concat (substring text 0 8) "…") text)))

(defun metsatron/idle-compaction--log (kind id format-string &rest args)
  "Log KIND and safe ID when debugging is enabled.
FORMAT-STRING and ARGS must not contain prompt or authentication data."
  (when metsatron-idle-compaction-debug
    (apply #'message
           (concat "[idle-compact " (symbol-name kind) " "
                   (metsatron/idle-compaction--short-id id) "] "
                   format-string)
           args)))

(defun metsatron/idle-compaction--cancel-timer (timer)
  "Cancel TIMER when it is a live Emacs timer."
  (when (timerp timer) (cancel-timer timer)))

(defun metsatron/idle-compaction--positive-finite-p (value)
  "Return non-nil for a finite positive numeric VALUE."
  (and (numberp value) (> value 0) (< value 1.0e+INF)))

(defun metsatron/idle-compaction--known-name-p (value)
  "Return non-nil when VALUE is an explicit nonempty identity name."
  (and (stringp value) (not (string-empty-p (string-trim value)))
       (not (equal (downcase (string-trim value)) "unknown"))))

(defun metsatron/idle-compaction-set-session-endpoint (provider endpoint-id)
  "Bind PROVIDER and ENDPOINT-ID to the current owning IDE session.
This adapter API must be called by an owner that knows the actual endpoint.
It never infers endpoints from provider names or raw response telemetry.
Unknown identity leaves measured policy unavailable.  The binding expires
when the owning session or connection changes; model identity is read fresh."
  (let* ((state (metsatron/idle-compaction--current-state))
         (claude (plist-get state :channel))
         (identity (list :provider provider :endpoint-id endpoint-id
                         :owner-id (plist-get state (if claude :session-id :thread-id))
                         :connection (plist-get state (if claude :process :connection)))))
    (unless state (user-error "No Claude or Codex IDE session owns this buffer"))
    (if claude
        (metsatron/claude-idle-compact--put claude :cache-policy-endpoint identity)
      (metsatron/codex-idle-compact--put
       (plist-get state :session) :cache-policy-endpoint identity))))

(defun metsatron/idle-compaction--endpoint (state owner-id connection)
  "Return STATE's explicit endpoint binding for OWNER-ID and CONNECTION."
  (let ((identity (plist-get state :cache-policy-endpoint)))
    (when (and owner-id connection
               (equal owner-id (plist-get identity :owner-id))
               (eq connection (plist-get identity :connection)))
      identity)))

(defun metsatron/claude-idle-compact--window (state snapshot)
  "Resolve fresh policy for STATE using its owning status SNAPSHOT."
  (let* ((fallback (metsatron/claude-idle-compact--profile-values
                    (metsatron/claude-idle-compact--state-profile state)))
         (identity (metsatron/idle-compaction--endpoint
                    state (plist-get state :session-id) (plist-get state :process)))
         (model (and (equal (plist-get state :channel) (alist-get 'channel snapshot))
                     (equal (plist-get state :session-id) (alist-get 'session_id snapshot))
                     (alist-get 'model snapshot))))
    (metsatron/idle-compaction--measured-window
     "claude" (plist-get identity :provider) (plist-get identity :endpoint-id)
     model (car fallback) (cadr fallback))))

(defun metsatron/codex-idle-compact--window (session state)
  "Resolve fresh policy for owning SESSION without recycling measured timers."
  (let* ((policy (metsatron/codex-idle-compact--state-policy state))
         (local (plist-get state :policy-local))
         (warm (if local (plist-get state :presumed-warm-seconds)
                 (metsatron/codex-idle-compact--global-warm-seconds policy)))
         (delay (metsatron/codex-idle-compact--delay-for-warm
                 warm (if local (plist-get state :idle-compaction-delay-seconds)
                        (and (eq policy 'custom) codex-custom-idle-compact-seconds))))
         (identity (metsatron/idle-compaction--endpoint
                    state
                    (and (fboundp 'codex-ide-session-thread-id)
                         (codex-ide-session-thread-id session))
                    (and (fboundp 'codex-ide-session-process)
                         (codex-ide-session-process session))))
         (model (codex-ide--session-metadata-get session :model-name)))
    (if (or local (eq policy 'disabled))
        (list delay warm nil)
      (metsatron/idle-compaction--measured-window
       "codex" (plist-get identity :provider) (plist-get identity :endpoint-id)
       model delay warm))))

(defun metsatron/idle-compaction--measured-window
    (harness provider endpoint model fallback-delay fallback-cache)
  "Resolve measured cache policy or return FALLBACK-DELAY/FALLBACK-CACHE.
The external resolver owns freshness, support, and cross-harness endpoint
matching.  No shell is involved and failures preserve the caller's fallback."
  (let ((fallback (list fallback-delay fallback-cache nil)))
    (if (or (not (metsatron/idle-compaction--known-name-p model))
            (not (metsatron/idle-compaction--known-name-p provider))
            (not (metsatron/idle-compaction--known-name-p endpoint))
            (not (file-executable-p metsatron-cache-policy-helper))
            (not (file-readable-p metsatron-cache-policy-path)))
        fallback
      (condition-case nil
          (with-temp-buffer
            (let ((status
                   (call-process
                    metsatron-cache-policy-helper nil t nil
                    "resolve" "--policy" metsatron-cache-policy-path
                    "--harness" harness "--provider" provider
                    "--endpoint" endpoint "--model" model
                    "--fallback-compact" (number-to-string fallback-delay)
                    "--fallback-cache" (number-to-string fallback-cache))))
              (if (not (equal status 0))
                  fallback
                (let ((decision
                       (json-parse-buffer :object-type 'plist
                                          :array-type 'array
                                          :null-object nil
                                          :false-object nil)))
                  (let ((delay (plist-get decision :compact_before_seconds))
                        (ttl (plist-get decision :cache_expires_seconds)))
                    (if (and (equal (plist-get decision :mode) "measured")
                             (equal (plist-get decision :confidence) "supported")
                             (metsatron/idle-compaction--positive-finite-p delay)
                             (metsatron/idle-compaction--positive-finite-p ttl)
                             (< delay ttl))
                        (list delay ttl decision)
                      fallback))))))
        (error fallback)))))

(defun metsatron/idle-compaction--process-model (process)
  "Return an explicit --model value from PROCESS, when present."
  (when (processp process)
    (let ((args (process-command process)) found)
      (while args
        (let ((arg (pop args)))
          (cond
           ((and (member arg '("--model" "-m")) args)
            (setq found (car args) args nil))
           ((string-prefix-p "--model=" arg)
            (setq found (substring arg (length "--model=")) args nil)))))
      found)))

(defun metsatron/claude-idle-compact--effective-profile (&optional profile)
  "Resolve PROFILE to `long' or `short'.
The `auto' case uses only explicit environment flags."
  (let ((profile (or profile claude-idle-compact-cache-profile)))
    (if (memq profile '(long short))
        profile
      (cond
       ((member (getenv "FORCE_PROMPT_CACHING_5M") '("1" "true" "TRUE"))
        'short)
       ((member (getenv "ENABLE_PROMPT_CACHING_1H") '("1" "true" "TRUE"))
        'long)
       (t 'long)))))

(defun metsatron/claude-idle-compact--profile-values (profile)
  "Return `(DELAY TTL)' for Claude PROFILE."
  (if (eq (metsatron/claude-idle-compact--effective-profile profile) 'short)
      (list claude-short-cache-idle-compact-seconds
            claude-idle-compact-short-cache-ttl-seconds)
    (list claude-idle-compact-seconds claude-idle-compact-long-cache-ttl-seconds)))

(defun metsatron/claude-idle-compact--state-profile (state)
  "Return the effective per-session Claude cache profile for STATE."
  (or (plist-get state :effective-profile)
      (metsatron/claude-idle-compact--effective-profile
       (plist-get state :cache-profile))))

(defun metsatron/claude-idle-compact--state (channel)
  "Return Claude state for CHANNEL."
  (gethash channel metsatron/claude-idle-compact--sessions))

(defun metsatron/claude-idle-compact--put (channel key value)
  "Set KEY to VALUE in Claude CHANNEL state and return the state."
  (when-let ((state (metsatron/claude-idle-compact--state channel)))
    (setq state (plist-put state key value))
    (puthash channel state metsatron/claude-idle-compact--sessions)
    state))

(defun metsatron/claude-idle-compact--current-state (&optional buffer)
  "Return the Claude state owning BUFFER, or the current buffer."
  (setq buffer (or buffer (current-buffer)))
  (catch 'state
    (maphash (lambda (_channel state)
               (when (eq buffer (plist-get state :buffer))
                 (throw 'state state)))
             metsatron/claude-idle-compact--sessions)
    nil))

(defun metsatron/claude-idle-compact--cancel (state reason)
  "Cancel STATE's pending timer with REASON."
  (when state
    (let* ((channel (plist-get state :channel))
           (generation (1+ (or (plist-get state :timer-generation) 0))))
      (metsatron/idle-compaction--cancel-timer (plist-get state :timer))
      (setq state (plist-put state :timer nil))
      (setq state (plist-put state :timer-generation generation))
      (setq state (plist-put state :last-cancellation-reason reason))
      (puthash channel state metsatron/claude-idle-compact--sessions)
      (metsatron/idle-compaction--log 'cancelled channel "reason=%s" reason)
      state)))

(defun metsatron/claude-idle-compact--vterm-draft-present-p ()
  "Return non-nil when the current Claude vterm has unsent input.
Fail closed when the installed vterm does not expose its input accessor."
  (if (fboundp 'vterm--get-input)
      (condition-case _err
          (not (string-empty-p (string-trim (or (vterm--get-input) ""))))
        (error t))
    t))

(defun metsatron/claude-idle-compact--snapshot (state)
  "Read and validate the latest status-line snapshot for Claude STATE."
  (let* ((runtime (getenv "XDG_RUNTIME_DIR"))
         (channel (plist-get state :channel))
         (session-id (plist-get state :session-id))
         (path (and runtime
                    (expand-file-name
                     (format "claude-idle-compact-%s.json" channel) runtime))))
    (when (and path (file-readable-p path))
      (condition-case _err
          (let ((json-object-type 'alist)
                (json-array-type 'list)
                (json-key-type 'symbol))
            (let ((snapshot (json-read-file path)))
              (when (and (equal channel (alist-get 'channel snapshot))
                         (equal session-id (alist-get 'session_id snapshot))
                         (numberp (alist-get 'current_input_context_tokens snapshot)))
                snapshot)))
        (error nil)))))

(defun metsatron/claude-idle-compact--arm (state &optional remaining window)
  "Arm one Claude idle timer for STATE when lifecycle permits it."
  (when (and state metsatron-idle-compaction-enabled
             (plist-get state :enabled) (plist-get state :dirty)
             (equal (plist-get state :status) "idle")
             (not (plist-get state :compacting))
             (not (plist-get state :timer))
             (buffer-live-p (plist-get state :buffer))
             (process-live-p (plist-get state :process)))
    (let* ((channel (plist-get state :channel))
           (session-id (plist-get state :session-id))
           (completed-at (plist-get state :last-normal-turn-completed-at))
           (profile (metsatron/claude-idle-compact--state-profile state))
           (window (or window (metsatron/claude-idle-compact--window
                               state (metsatron/claude-idle-compact--snapshot state))))
           (delay (car window))
           (generation (1+ (or (plist-get state :timer-generation) 0)))
           (timer (run-at-time (or remaining delay) nil
                               #'metsatron/claude-idle-compact--timer-fired
                               channel session-id completed-at generation)))
      (metsatron/idle-compaction--cancel-timer (plist-get state :timer))
      (setq state (plist-put state :effective-profile profile))
      (setq state (plist-put state :measured-cache-ttl-seconds (cadr window)))
      (setq state (plist-put state :cache-policy-decision (caddr window)))
      (setq state (plist-put state :timer-generation generation))
      (setq state (plist-put state :timer timer))
      (puthash channel state metsatron/claude-idle-compact--sessions)
      (metsatron/idle-compaction--log 'armed channel "profile=%s delay=%ss"
                                      profile delay)
      state)))

(defun metsatron/claude-idle-compact--timer-fired
    (channel session-id completed-at generation)
  "Run the atomic Claude gate for captured timer identity."
  (when-let ((state (metsatron/claude-idle-compact--state channel)))
    (when (and (= generation (plist-get state :timer-generation))
               (equal session-id (plist-get state :session-id))
               (equal completed-at (plist-get state :last-normal-turn-completed-at)))
      (metsatron/claude-idle-compact--put channel :timer nil)
      (metsatron/claude-idle-compact--attempt state t))))

(defun metsatron/claude-idle-compact--attempt (state &optional automatic)
  "Run the complete Claude eligibility gate for STATE."
  (let* ((channel (plist-get state :channel))
         (buffer (plist-get state :buffer))
         (process (plist-get state :process))
         (completion (plist-get state :last-normal-turn-completed-at))
         (elapsed (and completion (- (metsatron/idle-compaction--now) completion)))
         (snapshot (and (buffer-live-p buffer)
                        (process-live-p process)
                        (metsatron/claude-idle-compact--snapshot state)))
         (window (metsatron/claude-idle-compact--window state snapshot))
         (delay (car window))
         (ttl (cadr window))
         (tokens (and snapshot
                      (alist-get 'current_input_context_tokens snapshot))))
    (setq state (metsatron/claude-idle-compact--put
                 channel :cache-policy-decision (caddr window)))
    (setq state (metsatron/claude-idle-compact--put
                 channel :measured-cache-ttl-seconds ttl))
    (when (numberp tokens)
      (setq state (metsatron/claude-idle-compact--put
                   channel :active-input-context-tokens tokens)))
    (cond
     ((not metsatron-idle-compaction-enabled)
      (metsatron/idle-compaction--log 'cancelled channel "globally-disabled"))
     ((not (plist-get state :enabled))
      (metsatron/idle-compaction--log 'cancelled channel "session-disabled"))
     ((not (plist-get state :dirty))
      (metsatron/idle-compaction--log 'cancelled channel "clean"))
     ((plist-get state :compacting)
      (metsatron/idle-compaction--log 'cancelled channel "already-compacting"))
     ((not (and (buffer-live-p buffer)
                (with-current-buffer buffer (derived-mode-p 'vterm-mode))))
      (metsatron/idle-compaction--log 'cancelled channel "buffer-not-vterm"))
     ((not (process-live-p process))
      (metsatron/idle-compaction--log 'cancelled channel "process-gone"))
     ((not (equal process (get-buffer-process buffer)))
      (metsatron/idle-compaction--log 'cancelled channel "process-replaced"))
     ((not completion)
      (metsatron/idle-compaction--log 'cancelled channel "no-completion-time"))
     ((or (null elapsed) (>= elapsed ttl))
      (metsatron/idle-compaction--log 'cancelled channel "cache-already-cold"))
     ((not (equal (plist-get state :status) "idle"))
      (metsatron/idle-compaction--log 'cancelled channel "session-active"))
     ((not snapshot)
      (metsatron/idle-compaction--log 'cancelled channel "missing-or-stale-status"))
     ((and (numberp (plist-get state :last-local-keyboard-at))
           (> (plist-get state :last-local-keyboard-at) completion))
      (metsatron/idle-compaction--log 'cancelled channel "user-input"))
     ((with-current-buffer buffer
        (metsatron/claude-idle-compact--vterm-draft-present-p))
      (metsatron/idle-compaction--log 'cancelled channel "draft-present"))
     ((or (not (metsatron/idle-compaction--positive-finite-p tokens))
          (< tokens claude-idle-compact-min-tokens))
      (metsatron/idle-compaction--log 'cancelled channel
                                      "below-token-threshold tokens=%s" tokens))
     ((and automatic (< elapsed delay))
      (metsatron/claude-idle-compact--arm state (- delay elapsed) window))
     (t
      (setq state (plist-put state :compacting t))
      (puthash channel state metsatron/claude-idle-compact--sessions)
      (metsatron/idle-compaction--log 'compaction-requested channel "Claude /compact")
      (condition-case _err
          (with-current-buffer buffer
            (claude-code-ide--terminal-send-string "/compact")
            (claude-code-ide--terminal-send-return))
        (error
         (setq state (plist-put state :compacting nil))
         (puthash channel state metsatron/claude-idle-compact--sessions)
         (metsatron/idle-compaction--log 'compaction-failed channel
                                         "synchronous submission failure")))))))

(defun metsatron/claude-idle-compact--local-activity ()
  "Cancel Claude idle compaction after local buffer activity."
  (when-let ((state (metsatron/claude-idle-compact--current-state)))
    (metsatron/claude-idle-compact--put
     (plist-get state :channel) :last-local-keyboard-at
     (metsatron/idle-compaction--now))
    (metsatron/claude-idle-compact--cancel state "user-input")))

(defun metsatron/claude-idle-compact--process-gone (channel process)
  "Cancel CHANNEL when PROCESS disappears."
  (when-let ((state (metsatron/claude-idle-compact--state channel)))
    (when (eq process (plist-get state :process))
      (metsatron/claude-idle-compact--cancel state "process-gone"))))

(defun metsatron/claude-idle-compact-register
    (channel buffer process &optional session-id)
  "Register a Claude CHANNEL owned by BUFFER and PROCESS."
  (when (and (stringp channel) (buffer-live-p buffer))
    (let ((state (list :channel channel :buffer buffer :process process
                       :session-id session-id :status "idle" :enabled t
                       :cache-profile claude-idle-compact-cache-profile
                       :effective-profile
                       (metsatron/claude-idle-compact--effective-profile
                        claude-idle-compact-cache-profile)
                       :dirty nil :compacting nil :timer nil
                       :timer-generation 0 :last-local-keyboard-at nil
                       :last-normal-turn-completed-at nil
                       :active-input-context-tokens nil
                       :last-cancellation-reason nil)))
      (puthash channel state metsatron/claude-idle-compact--sessions)
      (with-current-buffer buffer
        (add-hook 'pre-command-hook
                  #'metsatron/claude-idle-compact--local-activity nil t)
        (add-hook 'kill-buffer-hook
                  (lambda ()
                    (when-let ((current
                               (metsatron/claude-idle-compact--current-state)))
                      (metsatron/claude-idle-compact--cancel
                       current "buffer-unloaded")))
                  nil t))
      (when (processp process)
        (let ((old-sentinel (process-sentinel process)))
          (set-process-sentinel
           process
           (lambda (proc event)
             (when (functionp old-sentinel)
               (funcall old-sentinel proc event))
             (metsatron/claude-idle-compact--process-gone channel proc)))))
      state)))

(defun metsatron/claude-idle-compact-handle-hook
    (event channel session-id)
  "Handle validated Claude hook EVENT for CHANNEL and SESSION-ID.
This function is called only by `claude-hook-idle-event'."
  (when-let ((state (metsatron/claude-idle-compact--state channel)))
    (when (or (null (plist-get state :session-id))
              (equal session-id (plist-get state :session-id)))
      (setq state (plist-put state :session-id session-id))
      (pcase event
       ('stop
         (if (plist-get state :compacting)
             (progn
               ;; A /compact command can also produce Stop.  It is not a new
               ;; ordinary turn: leave `compacting' set until PostCompact so
               ;; this notification can never create an idle loop.
               (setq state (plist-put state :status "idle"))
               (puthash channel state metsatron/claude-idle-compact--sessions)
               (metsatron/claude-idle-compact--cancel state "compaction-stop"))
           (setq state (plist-put state :status "idle"))
           (setq state (plist-put state :dirty t))
           (setq state (plist-put state :last-normal-turn-completed-at
                                  (metsatron/idle-compaction--now)))
           (puthash channel state metsatron/claude-idle-compact--sessions)
           (metsatron/claude-idle-compact--cancel state "new-normal-turn")
           (metsatron/claude-idle-compact--arm state)))
        ('user-prompt-submit
         (setq state (plist-put state :status "active"))
         (metsatron/claude-idle-compact--cancel state "prompt-submit"))
        ('post-compact
         (setq state (plist-put state :status "idle"))
         (setq state (plist-put state :dirty nil))
         (setq state (plist-put state :compacting nil))
         (setq state (plist-put state :active-input-context-tokens nil))
         (puthash channel state metsatron/claude-idle-compact--sessions)
         (metsatron/claude-idle-compact--cancel state "compaction-completed")
         (metsatron/idle-compaction--log 'compaction-completed channel "Claude"))
        ('session-activity
         (setq state (plist-put state :status "active"))
         (puthash channel state metsatron/claude-idle-compact--sessions)
         (metsatron/claude-idle-compact--cancel state "session-active"))
        ((or 'stop-failure 'session-end)
         (setq state (plist-put state :status (symbol-name event)))
         (puthash channel state metsatron/claude-idle-compact--sessions)
         (metsatron/claude-idle-compact--cancel state (symbol-name event)))))))

(defun metsatron/claude-idle-compact-set-profile (profile)
  "Set the current Claude session cache PROFILE and re-arm its timer.
PROFILE is one of `long', `short', or `auto'."
  (interactive
   (list (intern (completing-read "Claude cache profile: "
                                  '("long" "short" "auto") nil t))))
  (let ((state (metsatron/claude-idle-compact--current-state)))
    (unless state (user-error "The current buffer is not a Claude IDE session"))
    (setq state (plist-put state :cache-profile profile))
    (setq state (plist-put state :effective-profile
                           (metsatron/claude-idle-compact--effective-profile
                            profile)))
    (puthash (plist-get state :channel) state metsatron/claude-idle-compact--sessions)
    (metsatron/claude-idle-compact--cancel state "profile-changed")
    (metsatron/claude-idle-compact--arm state)
    (message "Claude idle-compaction profile: %s (effective %s)"
             profile (metsatron/claude-idle-compact--effective-profile profile))))

(defun metsatron/codex-idle-compact--state (session)
  "Return or initialize governor state for Codex SESSION."
  (when (and session (fboundp 'codex-ide--session-metadata-get))
    (or (codex-ide--session-metadata-get
         session metsatron/codex-idle-compact--metadata-key)
        (let* ((policy codex-cache-policy)
               (warm (metsatron/codex-idle-compact--global-warm-seconds policy))
               (state (list :session session
                            :thread-id (codex-ide-session-thread-id session)
                            :connection (codex-ide-session-process session)
                            :owning-buffer (codex-ide-session-buffer session)
                            :status (or (codex-ide-session-status session) "idle")
                            :timer nil :timer-generation 0 :enabled t
                            :dirty nil :compacting nil
                            :cache-policy policy
                            :policy-local nil
                            :presumed-warm-seconds warm
                            :idle-compaction-delay-seconds
                            (metsatron/codex-idle-compact--delay-for-warm warm)
                            :cache-policy-source
                            (metsatron/codex-idle-compact--policy-source policy)
                            :cache-policy-confidence
                            (metsatron/codex-idle-compact--policy-confidence policy)
                            :last-normal-turn-completed-at nil
                            :last-local-input-at nil
                            :last-lifecycle-activity-at nil
                            :lifecycle-sequence 0
                            :completion-lifecycle-sequence nil
                            :current-context-tokens nil
                            :context-window-size nil
                            :prompt-draft-dirty nil
                            :normal-turn-in-progress nil
                            :normal-agent-item-observed nil
                            :normal-agent-item-completed nil
                            :normal-turn-completion-confirmed nil
                            :compaction-turn-in-progress nil
                            :compaction-item-observed nil
                            :compaction-item-completed nil
                            :last-active-operation-kind nil
                            :last-lifecycle-evidence nil
                            :compaction-result 'none
                            :raw-cached-input-tokens nil
                            :raw-cache-write-input-tokens nil
                            :raw-input-tokens nil
                            :raw-total-tokens nil
                            :raw-model nil
                            :raw-provider-class
                            codex-idle-compact-raw-telemetry-provider-class
                            :last-raw-usage-at nil
                            :last-cancellation-reason nil
                            :last-error nil)))
          (codex-ide--session-metadata-put
           session metsatron/codex-idle-compact--metadata-key state)
          state))))

(defun metsatron/codex-idle-compact--global-warm-seconds (policy)
  "Return the configured presumed warm-cache budget for POLICY.
The result is never presented as a backend TTL."
  (pcase policy
    ('presumed-30m codex-presumed-warm-seconds)
    ('custom codex-custom-presumed-warm-seconds)
    (_ nil)))

(defun metsatron/codex-idle-compact--delay-for-warm (warm &optional configured)
  "Return a safe idle delay below presumed WARM seconds.
CONFIGURED is the requested delay; the result is nil when WARM is unusable."
  (when (and (numberp warm) (> warm 1))
    (min (max 1 (or configured codex-idle-compact-seconds))
         (max 1 (1- warm)))))

(defun metsatron/codex-idle-compact--state-policy (state)
  "Return STATE's policy, falling back to the global policy."
  (or (plist-get state :cache-policy) codex-cache-policy))

(defun metsatron/codex-idle-compact--state-warm-seconds (state)
  "Return STATE's presumed warm-cache budget, or nil when disabled."
  (let ((policy (metsatron/codex-idle-compact--state-policy state))
        (decision (plist-get state :cache-policy-decision)))
    (cond
     ((plist-get state :policy-local)
      (plist-get state :presumed-warm-seconds))
     ((equal (plist-get decision :mode) "measured")
      (plist-get decision :cache_expires_seconds))
     (t (metsatron/codex-idle-compact--global-warm-seconds policy)))))

(defun metsatron/codex-idle-compact--state-delay-seconds (state)
  "Return STATE's actual idle-compaction delay in seconds."
  (let ((decision (plist-get state :cache-policy-decision)))
    (if (and (not (plist-get state :policy-local))
             (equal (plist-get decision :mode) "measured"))
        (plist-get decision :compact_before_seconds)
      (metsatron/codex-idle-compact--delay-for-warm
       (metsatron/codex-idle-compact--state-warm-seconds state)
       (if (plist-get state :policy-local)
           (plist-get state :idle-compaction-delay-seconds)
         (and (eq (metsatron/codex-idle-compact--state-policy state) 'custom)
              (or (plist-get state :idle-compaction-delay-seconds)
                  codex-custom-idle-compact-seconds)))))))

(defun metsatron/codex-idle-compact--policy-source (policy)
  "Return the source label for global POLICY."
  (pcase policy
    ('presumed-30m codex-cache-policy-source)
    ('custom "user-configured presumed warm-cache budget")
    (_ "disabled")))

(defun metsatron/codex-idle-compact--policy-confidence (policy)
  "Return the confidence label for global POLICY."
  (pcase policy
    ('presumed-30m codex-cache-policy-confidence)
    ('custom "user-configured")
    (_ "not-applicable")))

(defun metsatron/codex-idle-compact--state-source (state)
  "Return STATE's cache-policy source label."
  (let ((decision (plist-get state :cache-policy-decision)))
    (if (equal (plist-get decision :mode) "measured")
        "measured endpoint/model cache-policy.v1"
      (or (and (plist-get state :policy-local)
               (plist-get state :cache-policy-source))
          (metsatron/codex-idle-compact--policy-source
           (metsatron/codex-idle-compact--state-policy state))))))

(defun metsatron/codex-idle-compact--state-confidence (state)
  "Return STATE's cache-policy confidence label."
  (let ((decision (plist-get state :cache-policy-decision)))
    (if (equal (plist-get decision :mode) "measured")
        (or (plist-get decision :confidence) "supported")
      (or (and (plist-get state :policy-local)
               (plist-get state :cache-policy-confidence))
          (metsatron/codex-idle-compact--policy-confidence
           (metsatron/codex-idle-compact--state-policy state))))))

(defun metsatron/codex-idle-compact--all-sessions ()
  "Return the owning client's currently tracked Codex sessions."
  (and (boundp 'codex-ide--sessions) codex-ide--sessions))

(defun metsatron/codex-idle-compact--connection-gone (connection)
  "Cancel every governor state owned by disappeared CONNECTION."
  (dolist (session (metsatron/codex-idle-compact--all-sessions))
    (when-let ((state (metsatron/codex-idle-compact--state session)))
      (when (eq connection (plist-get state :connection))
        (if (plist-get state :compacting)
            (metsatron/codex-idle-compact--finish-compaction
             session 'failed "connection-gone")
          (metsatron/codex-idle-compact--cancel
           session "connection-gone"))))))

(defun metsatron/codex-idle-compact--put (session key value)
  "Set Codex SESSION state KEY to VALUE and return the state."
  (when-let ((state (metsatron/codex-idle-compact--state session)))
    (setq state (plist-put state key value))
    (codex-ide--session-metadata-put
     session metsatron/codex-idle-compact--metadata-key state)
    state))

(defun metsatron/codex-idle-compact--put-many (session &rest pairs)
  "Set successive KEY VALUE PAIRS in Codex SESSION state."
  (while pairs
    (metsatron/codex-idle-compact--put session (pop pairs) (pop pairs)))
  (metsatron/codex-idle-compact--state session))

(defun metsatron/codex-idle-compact--note-activity (session kind &optional reason)
  "Record session activity KIND and invalidate pending idle work.
REASON is the cancellation label used when it is meaningful."
  (when-let ((state (metsatron/codex-idle-compact--state session)))
    (setq state (plist-put state :last-active-operation-kind kind))
    (setq state (plist-put state :last-lifecycle-activity-at
                           (metsatron/idle-compaction--now)))
    (setq state (plist-put state :lifecycle-sequence
                           (1+ (or (plist-get state :lifecycle-sequence) 0))))
    (codex-ide--session-metadata-put
     session metsatron/codex-idle-compact--metadata-key state)
    (when reason
      (metsatron/codex-idle-compact--cancel session reason))
    state))

(defun metsatron/codex-idle-compact--normal-item-p (type)
  "Return non-nil when Codex item TYPE demonstrates agent work."
  (and (stringp type)
       (not (member type '("userMessage" "contextCompaction" "system")))))

(defun metsatron/codex-idle-compact--status-name (status)
  "Normalize an app-server STATUS object/string for governor state."
  (let ((raw (if (stringp status) status (alist-get 'type status))))
    (and (stringp raw) (downcase raw))))

(defun metsatron/codex-idle-compact--mark-normal-complete (session evidence)
  "Mark a normal Codex turn complete from EVIDENCE and arm after idle.
The caller must have established agent work and an idle session."
  (when-let ((state (metsatron/codex-idle-compact--state session)))
    (unless (or (plist-get state :compaction-turn-in-progress)
                (plist-get state :compaction-item-observed)
                (plist-get state :last-error)
                ;; A single Codex turn may be reported through both the
                ;; normalized client hook and raw `turn/completed'.  Once the
                ;; current lifecycle sequence has established completion,
                ;; preserve the original timestamp and timer identity.
                (and (plist-get state :dirty)
                     (equal (plist-get state :completion-lifecycle-sequence)
                            (plist-get state :lifecycle-sequence))))
      (setq state (plist-put state :dirty t))
      (setq state (plist-put state :last-normal-turn-completed-at
                             (metsatron/idle-compaction--now)))
      (setq state (plist-put state :completion-lifecycle-sequence
                             (plist-get state :lifecycle-sequence)))
      (setq state (plist-put state :last-lifecycle-evidence evidence))
      (setq state (plist-put state :last-active-operation-kind 'normal-completed))
      (setq state (plist-put state :normal-turn-in-progress nil))
      (setq state (plist-put state :normal-agent-item-observed nil))
      (setq state (plist-put state :normal-agent-item-completed nil))
      (setq state (plist-put state :prompt-draft-dirty nil))
      (codex-ide--session-metadata-put
       session metsatron/codex-idle-compact--metadata-key state)
      (metsatron/codex-idle-compact--arm session)
      state)))

(defun metsatron/codex-idle-compact--finish-compaction
    (session result evidence)
  "Record Codex compaction RESULT from lifecycle EVIDENCE.
Only `succeeded' clears DIRTY.  `unknown' is deliberately visible and does not
re-arm the governor."
  (when-let ((state (metsatron/codex-idle-compact--state session)))
    (setq state (plist-put state :compacting nil))
    (setq state (plist-put state :compaction-result result))
    (setq state (plist-put state :last-lifecycle-evidence evidence))
    (setq state (plist-put state :compaction-turn-in-progress nil))
    (setq state (plist-put state :compaction-item-observed nil))
    (setq state (plist-put state :compaction-item-completed nil))
    (setq state (plist-put state :last-error
                           (unless (eq result 'succeeded) evidence)))
    (unless (eq result 'succeeded)
      (setq state (plist-put state :last-cancellation-reason
                             (format "compaction-%s" result))))
    (when (eq result 'succeeded)
      (setq state (plist-put state :dirty nil))
      (metsatron/idle-compaction--log
       'compaction-completed (plist-get state :thread-id) "Codex"))
    (codex-ide--session-metadata-put
     session metsatron/codex-idle-compact--metadata-key state)
    (unless (eq result 'succeeded)
      (metsatron/idle-compaction--log
       (if (eq result 'unknown) 'cancelled 'compaction-failed)
       (plist-get state :thread-id) "result=%s evidence=%s" result evidence))
    state))

(defun metsatron/codex-idle-compact--handle-status
    (session status &optional reason)
  "Apply Codex STATUS to SESSION's lifecycle state."
  (when-let ((state (metsatron/codex-idle-compact--state session)))
    (let ((status (metsatron/codex-idle-compact--status-name status)))
      (when status
        (metsatron/codex-idle-compact--put-many
         session :status status :last-status-reason reason)
        (if (equal status "idle")
            (cond
            ((or (plist-get state :compaction-turn-in-progress)
                  (plist-get state :compaction-item-observed))
              (unless (eq (plist-get state :compaction-result) 'succeeded)
                (let ((failure (plist-get state :last-error)))
                  (metsatron/codex-idle-compact--finish-compaction
                   session (if failure 'failed 'unknown)
                   (or failure "idle-without-success-event")))))
             ((and (plist-get state :normal-turn-in-progress)
                   (plist-get state :normal-agent-item-observed)
                   (plist-get state :normal-agent-item-completed))
              (metsatron/codex-idle-compact--mark-normal-complete
               session "agent-item-plus-idle"))
             ((and (plist-get state :dirty)
                   (not (plist-get state :compacting))
                   (not (memq (plist-get state :compaction-result)
                              '(pending unknown failed interrupted))))
              ;; Duplicate idle notifications must leave an existing one-shot
              ;; timer alone; `--arm' is idempotent when it is already present.
              (metsatron/codex-idle-compact--arm session)))
          (let ((failure-status
                 (member status
                         '("error" "systemerror" "notloaded"
                           "disconnected"))))
            (if (and failure-status
                     (or (plist-get state :compacting)
                         (plist-get state :compaction-turn-in-progress)
                         (plist-get state :compaction-item-observed)))
                (metsatron/codex-idle-compact--finish-compaction
                 session 'failed status)
              (metsatron/codex-idle-compact--note-activity
               session
               (if (member status '("active" "running" "submitted"))
                   'normal-or-active
                 (intern (format "%s" status)))
               (cond
                ((member status '("active" "running" "submitted"))
                 "session-active")
                (failure-status status)
                (t "session-active"))))))))))

(defun metsatron/codex-idle-compact--cancel (session reason)
  "Cancel the Codex SESSION timer with REASON."
  (when-let ((state (metsatron/codex-idle-compact--state session)))
    (metsatron/idle-compaction--cancel-timer (plist-get state :timer))
    (setq state (plist-put state :timer nil))
    (setq state (plist-put state :timer-generation
                           (1+ (or (plist-get state :timer-generation) 0))))
    (setq state (plist-put state :last-cancellation-reason reason))
    (codex-ide--session-metadata-put
     session metsatron/codex-idle-compact--metadata-key state)
    (metsatron/idle-compaction--log 'cancelled
                                    (plist-get state :thread-id)
                                    "reason=%s" reason)
    state))

(defun metsatron/codex-idle-compact--arm (session &optional remaining window)
  "Arm one Codex idle timer for SESSION when it is eligible to wait."
  (when-let ((state (metsatron/codex-idle-compact--state session)))
    (let* ((policy (metsatron/codex-idle-compact--state-policy state))
           (window (or window (metsatron/codex-idle-compact--window session state)))
           (delay (car window))
           (warm (cadr window)))
      (when (and metsatron-idle-compaction-enabled
                 (not (eq policy 'disabled))
                 (plist-get state :enabled)
                 (plist-get state :dirty)
                 (equal (plist-get state :status) "idle")
                 (not (plist-get state :compacting))
                 (not (plist-get state :timer))
                 (numberp warm) (> warm 1)
                 (numberp delay) (> delay 0)
                 (process-live-p (plist-get state :connection))
                 (buffer-live-p (plist-get state :owning-buffer)))
        (let* ((thread-id (plist-get state :thread-id))
               (completion (plist-get state :last-normal-turn-completed-at))
               (generation (1+ (or (plist-get state :timer-generation) 0)))
               (timer (run-at-time (or remaining delay) nil
                                   #'metsatron/codex-idle-compact--timer-fired
                                   session thread-id completion generation)))
          (metsatron/idle-compaction--cancel-timer (plist-get state :timer))
          (setq state (plist-put state :timer-generation generation))
          (setq state (plist-put state :timer timer))
          (setq state (plist-put state :cache-policy-decision (caddr window)))
          (setq state (plist-put state :idle-compaction-delay-seconds delay))
          (setq state (plist-put state :presumed-warm-seconds warm))
          (codex-ide--session-metadata-put
           session metsatron/codex-idle-compact--metadata-key state)
          (metsatron/idle-compaction--log
           'armed thread-id
           "policy=%s presumed-warm-cache-budget=%ss delay=%ss confidence=%s"
           policy warm delay
           (metsatron/codex-idle-compact--state-confidence state))
          state)))))

(defun metsatron/codex-idle-compact--timer-fired
    (session thread-id completion generation)
  "Run the atomic Codex gate for captured timer identity."
  (when-let ((state (metsatron/codex-idle-compact--state session)))
    (when (and (= generation (plist-get state :timer-generation))
               (equal thread-id (plist-get state :thread-id))
               (equal completion (plist-get state :last-normal-turn-completed-at)))
      (metsatron/codex-idle-compact--put session :timer nil)
      (metsatron/codex-idle-compact--attempt session generation))))

(defun metsatron/codex-idle-compact--draft-present-p (session)
  "Return non-nil when Codex SESSION has unsent or queued prompt input."
  (or (and (fboundp 'codex-ide--current-input-empty-p)
           (condition-case _err
               (not (codex-ide--current-input-empty-p session))
             (wrong-number-of-arguments
              (not (codex-ide--current-input-empty-p)))))
      (and (fboundp 'codex-ide-session-prompt-history-draft)
           (let ((draft (codex-ide-session-prompt-history-draft session)))
             (and (stringp draft) (not (string-empty-p (string-trim draft))))))
      (and (plist-get (metsatron/codex-idle-compact--state session)
                      :prompt-draft-dirty)
           t)
      ;; Older local builds without `codex-ide--current-input-empty-p' need
      ;; the marker fallback.  Do not run it on current builds: the visible
      ;; `> ' prompt prefix is not user input and is deliberately outside the
      ;; package's authoritative input-boundary calculation.
      (and (not (fboundp 'codex-ide--current-input-empty-p))
           (fboundp 'codex-ide-session-input-prompt-start-marker)
           (fboundp 'codex-ide-session-mode--input-end-position)
           (let* ((buffer (codex-ide-session-buffer session))
                  (start (codex-ide-session-input-prompt-start-marker session))
                  (end (codex-ide-session-mode--input-end-position session))
                  (end-position (if (markerp end) (marker-position end) end)))
             (and (buffer-live-p buffer)
                  (markerp start)
                  (integer-or-marker-p end)
                  (eq (marker-buffer start) buffer)
                  (integer-or-marker-p end-position)
                  (< (marker-position start) end-position)
                  (with-current-buffer buffer
                    (let ((draft (string-trim
                                  (buffer-substring-no-properties
                                   (marker-position start)
                                   end-position))))
                      (not (string-empty-p
                            (string-remove-prefix "> " draft))))))))
      ;; Older local builds used this metadata slot for queued prompts.  Keep
      ;; the fallback harmless and session-local when present.
      (and (fboundp 'codex-ide--session-metadata-get)
           (codex-ide--session-metadata-get session :queued-prompts))))

(defun metsatron/codex-idle-compact--owned-p (session thread-id)
  "Return non-nil when THREAD-ID is still owned by SESSION."
  (and (equal thread-id (codex-ide-session-thread-id session))
       (or (not (fboundp 'codex-ide--session-for-thread-id))
           (let ((directory
                  (and (fboundp 'codex-ide-session-directory)
                       (codex-ide-session-directory session))))
             (condition-case nil
                 ;; Timer callbacks need the owning directory explicitly;
                 ;; their current buffer is not guaranteed to be the session
                 ;; buffer.  Older test doubles accepted only THREAD-ID.
                 (eq session
                     (codex-ide--session-for-thread-id thread-id directory))
               (wrong-number-of-arguments
                (eq session (codex-ide--session-for-thread-id thread-id))))))))

(defun metsatron/codex-idle-compact--attempt
    (session &optional expected-generation)
  "Run the complete Codex eligibility gate for SESSION.
When EXPECTED-GENERATION is non-nil, it must still be the current timer
generation.  A nil value is used by the manual command."
  (when-let ((state (metsatron/codex-idle-compact--state session)))
    (let* ((thread-id (plist-get state :thread-id))
           (connection (plist-get state :connection))
           (buffer (plist-get state :owning-buffer))
           (completion (plist-get state :last-normal-turn-completed-at))
           (elapsed (and completion (- (metsatron/idle-compaction--now) completion)))
           (tokens (plist-get state :current-context-tokens))
           (policy (metsatron/codex-idle-compact--state-policy state))
           (window (metsatron/codex-idle-compact--window session state))
           (delay (car window))
           (warm (cadr window))
           (sequence (plist-get state :lifecycle-sequence))
           (completion-sequence
            (plist-get state :completion-lifecycle-sequence)))
      (setq state (metsatron/codex-idle-compact--put-many
                   session :cache-policy-decision (caddr window)
                   :presumed-warm-seconds warm
                   :idle-compaction-delay-seconds delay))
      (cond
       ((not metsatron-idle-compaction-enabled)
        (metsatron/idle-compaction--log 'cancelled thread-id "globally-disabled"))
       ((eq policy 'disabled)
        (metsatron/idle-compaction--log 'cancelled thread-id "policy-disabled"))
       ((not (plist-get state :enabled))
        (metsatron/idle-compaction--log 'cancelled thread-id "session-disabled"))
       ((and expected-generation
             (/= expected-generation (or (plist-get state :timer-generation) 0)))
        (metsatron/idle-compaction--log 'cancelled thread-id "stale-timer"))
       ((not (equal (plist-get state :status) "idle"))
        (metsatron/idle-compaction--log 'cancelled thread-id "session-active"))
       ((not (plist-get state :dirty))
        (metsatron/idle-compaction--log 'cancelled thread-id "clean"))
       ((plist-get state :compacting)
        (metsatron/idle-compaction--log 'cancelled thread-id "already-compacting"))
       ((not (process-live-p connection))
        (metsatron/idle-compaction--log 'cancelled thread-id "connection-gone"))
       ((not (eq connection (codex-ide-session-process session)))
        (metsatron/idle-compaction--log 'cancelled thread-id "connection-replaced"))
       ((not (and (buffer-live-p buffer)
                  (eq buffer (codex-ide-session-buffer session))))
        (metsatron/idle-compaction--log 'cancelled thread-id "buffer-unloaded"))
       ((not (metsatron/codex-idle-compact--owned-p session thread-id))
        (metsatron/idle-compaction--log 'cancelled thread-id "thread-replaced"))
       ((metsatron/codex-idle-compact--draft-present-p session)
        (metsatron/idle-compaction--log 'cancelled thread-id "draft-present"))
       ((or (null warm) (null elapsed) (>= elapsed warm))
        (metsatron/idle-compaction--log
         'cancelled thread-id "presumed-warm-budget-expired"))
       ((and completion-sequence sequence
             (/= completion-sequence sequence))
        (metsatron/idle-compaction--log
         'cancelled thread-id "contradictory-lifecycle-activity"))
       ((plist-get state :normal-turn-in-progress)
        (metsatron/idle-compaction--log
         'cancelled thread-id "session-active"))
       ((plist-get state :compaction-turn-in-progress)
        (metsatron/idle-compaction--log
         'cancelled thread-id "compaction-active"))
       ((or (not (metsatron/idle-compaction--positive-finite-p tokens))
            (< tokens codex-idle-compact-min-tokens))
        (metsatron/idle-compaction--log 'cancelled thread-id
                                        "below-token-threshold tokens=%s" tokens))
       ((and expected-generation (< elapsed delay))
        (metsatron/codex-idle-compact--arm session (- delay elapsed) window))
       (t
        ;; Invalidate the one-shot timer before changing the state.  This makes
        ;; a stale callback harmless if it was queued concurrently with this
        ;; final gate.
        (metsatron/codex-idle-compact--cancel session "compaction-requested")
        (setq state (metsatron/codex-idle-compact--state session))
        (setq state (plist-put state :compacting t))
        (setq state (plist-put state :compaction-turn-in-progress t))
        (setq state (plist-put state :compaction-result 'pending))
        (setq state (plist-put state :last-active-operation-kind 'compaction))
        (codex-ide--session-metadata-put
         session metsatron/codex-idle-compact--metadata-key state)
        (metsatron/idle-compaction--log 'compaction-requested thread-id
                                        "Codex thread/compact/start")
        (condition-case _err
            (codex-ide--request-async
             session "thread/compact/start"
             `((threadId . ,thread-id))
             (lambda (_result error)
               (when error
                 (metsatron/codex-idle-compact--finish-compaction
                  session 'failed "compact-rpc-error")
                 (metsatron/idle-compaction--log
                  'compaction-failed thread-id "RPC request failed"))))
          (error
           (metsatron/codex-idle-compact--finish-compaction
            session 'failed "compact-synchronous-error")
           (metsatron/idle-compaction--log
            'compaction-failed thread-id "synchronous request failure"))))))))

(defun metsatron/codex-idle-compact--local-activity ()
  "Cancel Codex idle compaction after local session-buffer activity."
  (when (and (derived-mode-p 'codex-ide-session-mode)
             (fboundp 'codex-ide--session-for-current-buffer))
    (when-let ((session (codex-ide--session-for-current-buffer)))
      (metsatron/codex-idle-compact--put
       session :last-local-input-at (metsatron/idle-compaction--now))
      (metsatron/codex-idle-compact--put session :prompt-draft-dirty t)
      (metsatron/codex-idle-compact--note-activity
       session 'local-input "user-input"))))

;; The owning `codex-ide-session' remains authoritative; notification thread
;; IDs are only cross-checks, and missing raw turn/completed events are handled
;; by completed agent items followed by an idle status.

(defun metsatron/codex-idle-compact--alist-get-any (alist &rest keys)
  "Return the first present value for KEYS in ALIST."
  (catch 'value
    (dolist (key keys)
      (when (and (listp alist) (assq key alist))
        (throw 'value (alist-get key alist))))
    nil))

(defun metsatron/codex-idle-compact--record-raw-usage (session params)
  "Record privacy-safe raw response usage from PARAMS for SESSION."
  (when codex-idle-compact-raw-telemetry-enabled
    (let* ((usage (alist-get 'usage params))
           (details (metsatron/codex-idle-compact--alist-get-any
                     usage 'input_tokens_details 'inputTokensDetails))
           (cached (or (metsatron/codex-idle-compact--alist-get-any
                        usage 'cachedInputTokens 'cached_input_tokens)
                       (metsatron/codex-idle-compact--alist-get-any
                        details 'cached_tokens 'cachedInputTokens)))
           (write (or (metsatron/codex-idle-compact--alist-get-any
                       usage 'cacheWriteInputTokens 'cache_write_input_tokens)
                      (metsatron/codex-idle-compact--alist-get-any
                       details 'cache_write_tokens 'cacheWriteInputTokens)))
           (input (metsatron/codex-idle-compact--alist-get-any
                   usage 'input_tokens 'inputTokens))
           (total (metsatron/codex-idle-compact--alist-get-any
                   usage 'total_tokens 'totalTokens))
           (model (metsatron/codex-idle-compact--alist-get-any
                   params 'model))
           (provider (metsatron/codex-idle-compact--alist-get-any
                      params 'modelProvider 'model_provider))
           (existing-model
            (or (plist-get (metsatron/codex-idle-compact--state session)
                           :raw-model)
                (and (fboundp 'codex-ide--session-metadata-get)
                     (codex-ide--session-metadata-get session :model-name))))
           (existing-provider
            (plist-get (metsatron/codex-idle-compact--state session)
                       :raw-provider-class)))
      (metsatron/codex-idle-compact--put-many
       session
       :raw-cached-input-tokens cached
       :raw-cache-write-input-tokens write
       :raw-input-tokens input
       :raw-total-tokens total
       :raw-model (or model existing-model)
       :raw-provider-class
       (if (and existing-provider
                (not (equal existing-provider "unknown")))
           existing-provider
         (or provider codex-idle-compact-raw-telemetry-provider-class))
       :last-raw-usage-at (metsatron/idle-compaction--now))
      (metsatron/idle-compaction--log
       'raw-usage-recorded
       (plist-get (metsatron/codex-idle-compact--state session) :thread-id)
       "cached=%s cache-write=%s input=%s total=%s"
       (or cached "unknown") (or write "unknown")
       (or input "unknown") (or total "unknown")))))

(defun metsatron/codex-idle-compact--observe-turn-started (session params)
  "Record a newly started Codex turn for SESSION."
  (let ((turn (alist-get 'turn params))
        (turn-id (or (alist-get 'id (alist-get 'turn params))
                     (alist-get 'turnId params))))
    (metsatron/codex-idle-compact--note-activity
     session 'turn-started "session-active")
    (metsatron/codex-idle-compact--put-many
     session
     :current-turn-id (or turn-id (alist-get 'id turn))
     :normal-turn-in-progress t
     :normal-agent-item-observed nil
     :normal-agent-item-completed nil
     :compaction-turn-in-progress nil
     :compaction-item-observed nil
     :compaction-item-completed nil
     :compaction-result 'none
     :last-error nil)))

(defun metsatron/codex-idle-compact--observe-item
    (session item completed-p)
  "Observe Codex ITEM for SESSION; COMPLETED-P selects its lifecycle edge."
  (let* ((type (alist-get 'type item))
         (status (alist-get 'status item))
         (compaction (equal type "contextCompaction")))
    (cond
     (compaction
      (if completed-p
          (progn
            (metsatron/codex-idle-compact--note-activity
             session 'compaction-item-completed)
            (metsatron/codex-idle-compact--put-many
             session
             :compaction-item-observed t
             :compaction-item-completed t
             :compaction-turn-in-progress t
             :last-error
             (and (member status '("failed" "interrupted" "error"))
                  (format "contextCompaction item status=%s" status))))
        (metsatron/codex-idle-compact--note-activity
         session 'compaction "compaction-started")
        (metsatron/codex-idle-compact--put-many
         session
         :compacting t
         :compaction-turn-in-progress t
         :compaction-item-observed t
         :compaction-item-completed nil
         :compaction-result 'pending
         :normal-turn-in-progress nil
         :normal-agent-item-observed nil
         :normal-agent-item-completed nil)))
     ((metsatron/codex-idle-compact--normal-item-p type)
      (unless completed-p
        (metsatron/codex-idle-compact--note-activity
         session 'normal-agent-work "session-active"))
      (metsatron/codex-idle-compact--put-many
       session
       :normal-turn-in-progress t
       :normal-agent-item-observed t
       :normal-agent-item-completed
       (or (plist-get (metsatron/codex-idle-compact--state session)
                      :normal-agent-item-completed)
           completed-p)
       :last-active-operation-kind 'normal-agent-work
       :compaction-result 'none
       :last-error nil)))))

(defun metsatron/codex-idle-compact--handle-turn-completed
    (session params source)
  "Handle a completed Codex turn from SOURCE for owning SESSION."
  (let* ((turn (alist-get 'turn params))
         (status (or (alist-get 'status turn) "completed"))
         (turn-id (or (alist-get 'id turn) (alist-get 'turnId params)))
         (items (alist-get 'items turn))
         (normal-item-in-turn
          (cl-some (lambda (item)
                     (metsatron/codex-idle-compact--normal-item-p
                      (alist-get 'type item)))
                   items))
         (compaction-item-in-turn
          (cl-some (lambda (item)
                     (equal (alist-get 'type item) "contextCompaction"))
                   items))
         (state (metsatron/codex-idle-compact--state session))
         (compaction (or (plist-get state :compaction-turn-in-progress)
                         (plist-get state :compaction-item-observed)
                         compaction-item-in-turn
                         (memq (plist-get state :compaction-result)
                               '(pending unknown))))
         (failed
          (or (member status '("failed" "interrupted" "error"))
              ;; `thread/status/changed' may report idle between the
              ;; contextCompaction item and the successful turn completion.
              ;; `idle-without-success-event' is an ambiguity marker, not a
              ;; backend failure; allow the later completed turn to resolve
              ;; it as success.
              (and (plist-get state :last-error)
                   (not (equal (plist-get state :last-error)
                               "idle-without-success-event"))))))
    (when turn-id
      (metsatron/codex-idle-compact--put session :last-completed-turn-id turn-id))
    (if compaction
        (metsatron/codex-idle-compact--finish-compaction
         session
         (if (and (equal status "completed") (not failed))
             'succeeded
           (if (equal status "interrupted") 'interrupted 'failed))
         (format "%s-turn-completed" source))
      (when (equal status "completed")
        ;; A raw turn completion is itself reliable completion evidence when
        ;; a turn was observed.  Item notifications, when present, provide
        ;; the stronger agent-work evidence; turn items fill that gap for
        ;; clients that omit item notifications.
        (let ((completed-state
               (metsatron/codex-idle-compact--put-many
                session
                :normal-turn-completion-confirmed t
                :normal-agent-item-observed
                (or (plist-get state :normal-agent-item-observed)
                    normal-item-in-turn
                    (plist-get state :normal-turn-in-progress))
                :normal-agent-item-completed
                (or (plist-get state :normal-agent-item-completed)
                    normal-item-in-turn
                    (plist-get state :normal-turn-in-progress)))))
          (when (and (equal (plist-get completed-state :status) "idle")
                     (plist-get completed-state :normal-agent-item-observed)
                     (plist-get completed-state :normal-agent-item-completed))
            (metsatron/codex-idle-compact--mark-normal-complete
             session (format "%s-turn-completed" source)))))
    (unless (equal status "completed")
      (metsatron/codex-idle-compact--put-many
       session
       :normal-turn-in-progress nil
       :normal-agent-item-observed nil
       :normal-agent-item-completed nil
       :normal-turn-completion-confirmed nil
       :last-error (format "%s turn status=%s" source status))))))

(defun metsatron/codex-idle-compact--handle-session-event
    (event session payload)
  "Handle normalized EVENT from owning Codex SESSION.
PAYLOAD is the plist emitted by `codex-ide--run-session-event'."
  (when (and session (metsatron/codex-idle-compact--state session))
    ;; `codex-ide--initialize-session-buffer' binds `codex-ide--session'
    ;; after `codex-ide-session-mode-hook' runs.  Install the local-input and
    ;; cleanup hooks again from the first normalized lifecycle event, when the
    ;; owning session is authoritative and the buffer is fully bound.
    (metsatron/codex-idle-compact--install-session-buffer session)
    (pcase event
      ('status-changed
       (metsatron/codex-idle-compact--handle-status
        session (plist-get payload :status) (plist-get payload :reason)))
      ('turn-started
       (metsatron/codex-idle-compact--observe-turn-started
        session (list (cons 'turnId (plist-get payload :turn-id)))))
      ('turn-completed
       (if (plist-get payload :closing-note)
           (metsatron/codex-idle-compact--handle-turn-completed
            session '((turn . ((status . "interrupted")))) "normalized")
         (metsatron/codex-idle-compact--handle-turn-completed
          session '((turn . ((status . "completed")))) "normalized")))
      ((or 'thread-attached 'reset)
       (metsatron/codex-idle-compact--cancel session (symbol-name event))
       (metsatron/codex-idle-compact--put-many
        session
        :dirty (and (eq event 'reset) nil)
        :last-normal-turn-completed-at nil
        :normal-turn-in-progress nil
        :normal-agent-item-observed nil
        :normal-agent-item-completed nil
        :normal-turn-completion-confirmed nil
        :compaction-turn-in-progress nil
        :compaction-item-observed nil
        :compaction-item-completed nil
        :compaction-result 'none
        :thread-id (codex-ide-session-thread-id session)
        :connection (codex-ide-session-process session)
        :owning-buffer (codex-ide-session-buffer session)
        :status (or (codex-ide-session-status session) "idle")
        :last-active-operation-kind (if (eq event 'reset) 'reset 'initialization)))
      ((or 'approval-requested 'prompt-submitted)
       (metsatron/codex-idle-compact--note-activity
        session event "session-active")))))

(defun metsatron/codex-idle-compact--request-sync-filter (args)
  "Add the optional raw-events flag to future Codex thread starts."
  (if (and codex-idle-compact-raw-telemetry-enabled
           (equal (nth 1 args) "thread/start"))
      (let ((filtered (copy-sequence args))
            (params (copy-tree (nth 2 args))))
        (setf (nth 2 filtered)
              (cons '(experimentalRawEvents . t)
                    (assq-delete-all 'experimentalRawEvents params)))
        filtered)
    args))

(defun metsatron/codex-idle-compact--handle-notification
    (original session message)
  "Observe source-backed Codex lifecycle MESSAGE for owning SESSION."
  (let* ((method (alist-get 'method message))
         (params (alist-get 'params message))
         (thread-id (and (listp params) (alist-get 'threadId params)))
         (state (and session (metsatron/codex-idle-compact--state session)))
         (owner-ok (and state
                        (or (null thread-id)
                            (equal thread-id (plist-get state :thread-id))))))
    (when owner-ok
      (pcase method
        ("turn/started"
         (metsatron/codex-idle-compact--observe-turn-started session params))
        ("item/started"
         (metsatron/codex-idle-compact--observe-item
          session (alist-get 'item params) nil))
        ("thread/tokenUsage/updated"
         (let* ((usage (alist-get 'tokenUsage params))
                (last (alist-get 'last usage)))
           ;; `last.totalTokens' is Codex-native current context usage.  Do
           ;; not fall back to cumulative `total.totalTokens'.
           (metsatron/codex-idle-compact--put-many
            session
            :current-context-tokens (alist-get 'totalTokens last)
            :context-window-size (alist-get 'modelContextWindow usage))))
        ("rawResponse/completed"
         (metsatron/codex-idle-compact--record-raw-usage session params))))
    ;; Always let emacs-codex-ide process the notification, including a
    ;; cross-thread notification it will reject itself.  The owning session is
    ;; only the governor's routing authority.
    (unwind-protect
        (funcall original session message)
      (when owner-ok
        (pcase method
          ("thread/status/changed"
           (let ((raw-status (or (alist-get 'status params)
                                 (alist-get 'status (alist-get 'thread params)))))
             (metsatron/codex-idle-compact--handle-status
              session raw-status 'thread-status-changed)))
          ("item/completed"
           (metsatron/codex-idle-compact--observe-item
            session (alist-get 'item params) t))
          ("turn/completed"
           (metsatron/codex-idle-compact--handle-turn-completed
            session params "raw"))
          ("error"
           (let ((state (metsatron/codex-idle-compact--state session)))
             (metsatron/codex-idle-compact--put
              session :last-error "app-server error")
             (if (or (plist-get state :compacting)
                     (plist-get state :compaction-item-observed))
                 (metsatron/codex-idle-compact--finish-compaction
                  session 'failed "app-server-error")
               (metsatron/codex-idle-compact--note-activity
                session 'error "error")))))))))

(defun metsatron/codex-idle-compact--buffer-killed ()
  "Cancel the governor when its owning Codex buffer is unloaded."
  (when-let* ((session (and (boundp 'codex-ide--session)
                            (codex-ide-session-p codex-ide--session)))
              (state (metsatron/codex-idle-compact--state session)))
    (if (plist-get state :compacting)
        (metsatron/codex-idle-compact--finish-compaction
         session 'failed "buffer-unloaded")
      (metsatron/codex-idle-compact--cancel
       session "buffer-unloaded"))))

(defun metsatron/codex-idle-compact--install-session-buffer (&optional session)
  "Install Codex local-input and process cleanup hooks for SESSION.
When SESSION is nil, resolve it from the current Codex buffer.  The optional
argument is needed because `codex-ide-session-mode-hook' runs before the
package binds `codex-ide--session' in a newly created buffer."
  (setq session
        (or session
            (and (fboundp 'codex-ide--session-for-current-buffer)
                 (codex-ide--session-for-current-buffer))))
  (when-let* ((process (and session (codex-ide-session-process session)))
              (buffer (codex-ide-session-buffer session)))
    (when (and (process-live-p process) (buffer-live-p buffer))
      (with-current-buffer buffer
        (unless (bound-and-true-p
                 metsatron-codex-idle-compact-buffer-hooks-installed)
          (setq-local metsatron-codex-idle-compact-buffer-hooks-installed t)
          (add-hook 'pre-command-hook
                    #'metsatron/codex-idle-compact--local-activity nil t)
          (add-hook 'kill-buffer-hook
                    #'metsatron/codex-idle-compact--buffer-killed nil t)))
      (unless (process-get process 'metsatron-codex-idle-compact-sentinel)
        (process-put process 'metsatron-codex-idle-compact-sentinel t)
        (let ((old-sentinel (process-sentinel process)))
          (set-process-sentinel
           process
           (lambda (proc event)
             (unless (process-live-p proc)
               ;; Run before codex-ide's sentinel removes its owning session
               ;; from `codex-ide--sessions', so every session on this
               ;; connection is cancelled, not only the first one.
               (metsatron/codex-idle-compact--connection-gone proc))
             (when (functionp old-sentinel)
               (funcall old-sentinel proc event))
             (ignore event))))))))

(defun metsatron/idle-compaction--current-codex-session ()
  "Return the Codex session owning the current buffer, if any."
  (and (fboundp 'codex-ide--session-for-current-buffer)
       (codex-ide--session-for-current-buffer)))

(defun metsatron/idle-compaction--current-state ()
  "Return the current Claude or Codex governor state."
  (or (metsatron/claude-idle-compact--current-state)
      (when-let ((session (metsatron/idle-compaction--current-codex-session)))
        (metsatron/codex-idle-compact--state session))))

(defun metsatron/idle-compaction-enable ()
  "Enable idle compaction globally."
  (interactive)
  (setq metsatron-idle-compaction-enabled t)
  (maphash (lambda (_channel state)
             (metsatron/claude-idle-compact--arm state))
           metsatron/claude-idle-compact--sessions)
  (dolist (session (metsatron/codex-idle-compact--all-sessions))
    (metsatron/codex-idle-compact--arm session))
  (message "Idle compaction enabled globally"))

(defun metsatron/idle-compaction-disable ()
  "Disable idle compaction globally and cancel all pending timers."
  (interactive)
  (setq metsatron-idle-compaction-enabled nil)
  (maphash (lambda (_channel state)
             (metsatron/claude-idle-compact--cancel state "globally-disabled"))
           metsatron/claude-idle-compact--sessions)
  (when (boundp 'codex-ide--sessions)
    (dolist (session codex-ide--sessions)
      (metsatron/codex-idle-compact--cancel session "globally-disabled")))
  (message "Idle compaction disabled globally"))

(defun metsatron/codex-idle-compact--apply-global-policy (session policy)
  "Apply global Codex POLICY to SESSION and refresh its one-shot timer."
  (when session
    (let* ((warm (metsatron/codex-idle-compact--global-warm-seconds policy))
           (configured (and (eq policy 'custom)
                            codex-custom-idle-compact-seconds))
           (delay (metsatron/codex-idle-compact--delay-for-warm
                   warm configured)))
      (metsatron/codex-idle-compact--put-many
       session
       :cache-policy policy
       :policy-local nil
       :presumed-warm-seconds warm
       :idle-compaction-delay-seconds delay
       :cache-policy-source (metsatron/codex-idle-compact--policy-source policy)
       :cache-policy-confidence
       (metsatron/codex-idle-compact--policy-confidence policy))
      (metsatron/codex-idle-compact--cancel session "cache-policy-changed")
      (metsatron/codex-idle-compact--arm session))))

(defun metsatron/codex-idle-compact--set-global-policy (policy)
  "Set global Codex idle-compaction POLICY and refresh live sessions."
  (setq codex-cache-policy policy)
  (dolist (session (metsatron/codex-idle-compact--all-sessions))
    (metsatron/codex-idle-compact--apply-global-policy session policy)))

(defun metsatron/codex-idle-compact-disable ()
  "Disable Codex idle compaction without disabling Claude's governor."
  (interactive)
  (metsatron/codex-idle-compact--set-global-policy 'disabled)
  (message "Codex idle compaction disabled; policy=disabled"))

(defun metsatron/codex-idle-compact-select-presumed-30m ()
  "Select the heuristic presumed-30m Codex warm-cache policy globally."
  (interactive)
  (setq codex-presumed-warm-seconds (* 30 60))
  (metsatron/codex-idle-compact--set-global-policy 'presumed-30m)
  (message "Codex policy=presumed-30m; 30m presumed warm-cache budget, 27m idle delay"))

(defun metsatron/codex-idle-compact-set-global-custom-warm-interval
    (seconds)
  "Set global Codex custom presumed warm-cache budget to SECONDS."
  (interactive "nGlobal Codex presumed warm-cache budget (seconds): ")
  (unless (and (numberp seconds) (> seconds 1))
    (user-error "Warm-cache budget must be greater than one second"))
  (setq codex-custom-presumed-warm-seconds seconds
        codex-cache-policy 'custom)
  (dolist (session (metsatron/codex-idle-compact--all-sessions))
    (metsatron/codex-idle-compact--apply-global-policy session 'custom))
  (message "Codex policy=custom; presumed warm-cache budget=%ss" seconds))

(defun metsatron/codex-idle-compact-set-custom-warm-interval
    (seconds)
  "Set the current Codex session's custom presumed warm budget to SECONDS."
  (interactive "nCurrent Codex presumed warm-cache budget (seconds): ")
  (let ((session (metsatron/idle-compaction--current-codex-session)))
    (unless session (user-error "The current buffer is not a Codex session"))
    (unless (and (numberp seconds) (> seconds 1))
      (user-error "Warm-cache budget must be greater than one second"))
    (let ((delay (metsatron/codex-idle-compact--delay-for-warm
                  seconds
                  (or codex-custom-idle-compact-seconds
                      codex-idle-compact-seconds))))
      (metsatron/codex-idle-compact--put-many
       session
       :cache-policy 'custom
       :policy-local t
       :presumed-warm-seconds seconds
       :idle-compaction-delay-seconds delay
       :cache-policy-source "user-configured presumed warm-cache budget"
       :cache-policy-confidence "user-configured")
      (metsatron/codex-idle-compact--cancel session "cache-policy-changed")
      (metsatron/codex-idle-compact--arm session)
      (message "Codex session policy=custom; presumed warm-cache budget=%ss delay=%ss"
               seconds delay))))

(defun metsatron/codex-idle-compact-enable-raw-telemetry ()
  "Enable privacy-safe Codex raw usage telemetry for future thread starts."
  (interactive)
  (setq codex-idle-compact-raw-telemetry-enabled t)
  (message "Codex raw cache telemetry enabled for future thread/start requests"))

(defun metsatron/codex-idle-compact-disable-raw-telemetry ()
  "Disable Codex raw usage telemetry."
  (interactive)
  (setq codex-idle-compact-raw-telemetry-enabled nil)
  (message "Codex raw cache telemetry disabled"))

(defun metsatron/codex-idle-compact-toggle-raw-telemetry ()
  "Toggle privacy-safe Codex raw usage telemetry."
  (interactive)
  (if codex-idle-compact-raw-telemetry-enabled
      (metsatron/codex-idle-compact-disable-raw-telemetry)
    (metsatron/codex-idle-compact-enable-raw-telemetry)))

(defun metsatron/idle-compaction-enable-session ()
  "Enable idle compaction for the current Claude or Codex session."
  (interactive)
  (let ((state (metsatron/idle-compaction--current-state)))
    (unless state (user-error "No Claude or Codex IDE session owns this buffer"))
    (if (plist-get state :channel)
        (progn
          (setq state (plist-put state :enabled t))
          (puthash (plist-get state :channel) state
                   metsatron/claude-idle-compact--sessions)
          (metsatron/claude-idle-compact--arm state))
      (let ((session (plist-get state :session)))
        (metsatron/codex-idle-compact--put session :enabled t)
        (metsatron/codex-idle-compact--arm session)))
    (message "Idle compaction enabled for current session")))

(defun metsatron/idle-compaction-disable-session ()
  "Disable idle compaction for the current Claude or Codex session."
  (interactive)
  (let ((state (metsatron/idle-compaction--current-state)))
    (unless state (user-error "No Claude or Codex IDE session owns this buffer"))
    (if (plist-get state :channel)
        (progn
          (setq state (plist-put state :enabled nil))
          (puthash (plist-get state :channel) state
                   metsatron/claude-idle-compact--sessions)
          (metsatron/claude-idle-compact--cancel state "session-disabled"))
      (let ((session (plist-get state :session)))
        (metsatron/codex-idle-compact--put session :enabled nil)
        (metsatron/codex-idle-compact--cancel session "session-disabled")))
    (message "Idle compaction disabled for current session")))

(defun metsatron/idle-compaction-cancel-current ()
  "Cancel the current session's pending idle-compaction timer."
  (interactive)
  (let ((state (metsatron/idle-compaction--current-state)))
    (unless state (user-error "No Claude or Codex IDE session owns this buffer"))
    (if (plist-get state :channel)
        (metsatron/claude-idle-compact--cancel state "manual-cancel")
      (metsatron/codex-idle-compact--cancel
       (plist-get state :session) "manual-cancel"))))

(defun metsatron/idle-compaction-show-state ()
  "Display safe idle-compaction state for the current agent session."
  (interactive)
  (let ((state (metsatron/idle-compaction--current-state)))
    (unless state (user-error "No Claude or Codex IDE session owns this buffer"))
    (when (plist-get state :channel)
      (when-let ((snapshot (metsatron/claude-idle-compact--snapshot state)))
        (setq state
              (metsatron/claude-idle-compact--put
               (plist-get state :channel)
               :active-input-context-tokens
               (alist-get 'current_input_context_tokens snapshot)))))
    (let* ((claude (plist-get state :channel))
           (completion (plist-get state :last-normal-turn-completed-at))
           (profile (and claude
                          (metsatron/claude-idle-compact--state-profile state)))
           (values (and claude
                         (metsatron/claude-idle-compact--profile-values profile)))
           (threshold (if claude claude-idle-compact-min-tokens
                        codex-idle-compact-min-tokens))
           (tokens (plist-get state (if claude :active-input-context-tokens
                                      :current-context-tokens))))
      (if claude
          (message
           "Claude id=%s status=%s dirty=%s compacting=%s tokens=%s threshold=%s completion=%s idle=%s ttl=%ss deadline=%s draft=%s cancelled=%s profile=%s delay=%ss"
           (or (plist-get state :session-id) "unknown")
           (plist-get state :status) (plist-get state :dirty)
           (plist-get state :compacting) (or tokens "unknown") threshold
           completion
           (and completion (- (metsatron/idle-compaction--now) completion))
           (cadr values) (and completion (+ completion (cadr values)))
           (metsatron/claude-idle-compact--vterm-draft-present-p)
           (plist-get state :last-cancellation-reason)
           profile (car values))
        (let* ((policy (metsatron/codex-idle-compact--state-policy state))
               (warm (metsatron/codex-idle-compact--state-warm-seconds state))
               (delay (metsatron/codex-idle-compact--state-delay-seconds state))
               (session (plist-get state :session)))
          (message
           (concat
            "Codex id=%s status=%s dirty=%s compacting=%s "
            "current-context-usage=%s threshold=%s completion=%s idle=%s "
            "cache-policy=%s source=%s confidence=%s "
            "presumed-warm-cache-budget=%ss idle-delay=%ss deadline=%s "
            "draft=%s raw-cached-input=%s raw-cache-write=%s "
            "raw-model=%s raw-provider=%s last-raw-usage=%s "
            "lifecycle-evidence=%s compaction-result=%s "
            "cancelled=%s")
           (or (plist-get state :thread-id) "unknown")
           (plist-get state :status) (plist-get state :dirty)
           (plist-get state :compacting) (or tokens "unknown") threshold
           completion
           (and completion (- (metsatron/idle-compaction--now) completion))
           policy (metsatron/codex-idle-compact--state-source state)
           (metsatron/codex-idle-compact--state-confidence state)
           (or warm "disabled") (or delay "disabled")
           (and completion delay (+ completion delay))
           (metsatron/codex-idle-compact--draft-present-p session)
           (or (plist-get state :raw-cached-input-tokens) "unknown")
           (or (plist-get state :raw-cache-write-input-tokens) "unknown")
           (or (plist-get state :raw-model) "unknown")
           (or (plist-get state :raw-provider-class) "unknown")
           (or (plist-get state :last-raw-usage-at) "unknown")
           (or (plist-get state :last-lifecycle-evidence) "unknown")
           (or (plist-get state :compaction-result) "none")
           (or (plist-get state :last-cancellation-reason) "none")))))))

(defun metsatron/idle-compaction-trigger-current ()
  "Run the same validated idle-compaction gate for the current session."
  (interactive)
  (let ((state (metsatron/idle-compaction--current-state)))
    (unless state (user-error "No Claude or Codex IDE session owns this buffer"))
    (if (plist-get state :channel)
        (metsatron/claude-idle-compact--attempt state)
      (metsatron/codex-idle-compact--attempt (plist-get state :session)))))

(with-eval-after-load 'codex-ide
  (when (fboundp 'codex-ide--handle-notification)
    (advice-add 'codex-ide--handle-notification :around
                #'metsatron/codex-idle-compact--handle-notification))
  (when (fboundp 'codex-ide--request-sync)
    (advice-add 'codex-ide--request-sync :filter-args
                #'metsatron/codex-idle-compact--request-sync-filter))
  (add-hook 'codex-ide-session-event-hook
            #'metsatron/codex-idle-compact--handle-session-event)
  (add-hook 'codex-ide-session-mode-hook
            #'metsatron/codex-idle-compact--install-session-buffer))

(provide 'metsatron-idle-compaction)
;;; metsatron-idle-compaction.el ends here
