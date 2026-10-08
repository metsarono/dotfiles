;;; metsatron-idle-compaction-tests.el --- governor fixtures -*- lexical-binding: t; -*-
;; Canonical source: emacs-doom.org.  Regenerate this payload with
;; `tangle-one emacs-doom.org`; do not edit the tangled file in the overlay.
(require 'ert)
(load-file (expand-file-name "metsatron-idle-compaction.el"
                            (file-name-directory (or load-file-name
                                                      default-directory))))

(defun metsatron/idle-test--claude-state (tokens)
  "Return a fake Claude state with TOKENS in the status snapshot."
  (list :channel "claude-test"
        :buffer (generate-new-buffer " *idle-claude-test*")
        :process 'fake-process :session-id "claude-session"
        :status "idle" :enabled t :cache-profile 'long :dirty t
        :compacting nil :timer nil :timer-generation 0
        :last-local-keyboard-at nil
        :last-normal-turn-completed-at (- (float-time) 10)
        :active-input-context-tokens tokens
        :test-snapshot `((channel . "claude-test")
                         (session_id . "claude-session")
                         (current_input_context_tokens . ,tokens))))

(defun metsatron/idle-test--codex-bindings (session)
  "Return temporary Codex SESSION metadata bindings."
  (let ((metadata (make-hash-table :test #'eq)))
    (list
     (lambda (s key) (when (eq s session) (gethash key metadata)))
     (lambda (s key value)
       (when (eq s session) (puthash key value metadata))
       value))))

(defun metsatron/idle-test--kill-buffer (buffer)
  "Kill BUFFER without invoking the process query hook used by live vterm."
  (let ((kill-buffer-query-functions nil))
    (kill-buffer buffer)))

(ert-deftest metsatron/idle-claude-default-is-absolute-threshold ()
  (should (= claude-idle-compact-min-tokens 70000))
  (should (= claude-idle-compact-min-tokens 70000))
  (should (equal (metsatron/claude-idle-compact--profile-values 'long)
                 (list claude-idle-compact-seconds
                       claude-idle-compact-long-cache-ttl-seconds))))

(ert-deftest metsatron/idle-claude-below-threshold-does-not-compact ()
  (let ((state (metsatron/idle-test--claude-state 69999))
        (requests 0))
    (puthash "claude-test" state metsatron/claude-idle-compact--sessions)
    (cl-letf (((symbol-function 'metsatron/claude-idle-compact--snapshot)
               (lambda (_state) (plist-get state :test-snapshot)))
              ((symbol-function 'metsatron/claude-idle-compact--vterm-draft-present-p)
               (lambda () nil))
              ((symbol-function 'process-live-p) (lambda (_process) t))
              ((symbol-function 'get-buffer-process) (lambda (_buffer) 'fake-process))
              ((symbol-function 'codex-ide--terminal-send-string)
               (lambda (&rest _args) (setq requests (1+ requests))))
              ((symbol-function 'claude-code-ide--terminal-send-string)
               (lambda (&rest _args) (setq requests (1+ requests))))
              ((symbol-function 'claude-code-ide--terminal-send-return)
               (lambda (&rest _args) nil)))
      (metsatron/claude-idle-compact--attempt state)
      (should (= requests 0))
      (metsatron/idle-test--kill-buffer (plist-get state :buffer)))))

(ert-deftest metsatron/idle-claude-at-threshold-compacts-with-million-window ()
  (let ((state (metsatron/idle-test--claude-state 70000))
        (requests 0))
    (puthash "claude-test" state metsatron/claude-idle-compact--sessions)
    (cl-letf (((symbol-function 'metsatron/claude-idle-compact--snapshot)
               (lambda (_state) (plist-get state :test-snapshot)))
              ((symbol-function 'metsatron/claude-idle-compact--vterm-draft-present-p)
               (lambda () nil))
              ((symbol-function 'process-live-p) (lambda (_process) t))
              ((symbol-function 'get-buffer-process) (lambda (_buffer) 'fake-process))
              ((symbol-function 'claude-code-ide--terminal-send-string)
               (lambda (&rest _args) (setq requests (1+ requests))))
              ((symbol-function 'claude-code-ide--terminal-send-return)
               (lambda (&rest _args) nil))
              ((symbol-function 'derived-mode-p) (lambda (&rest _modes) t)))
      (metsatron/claude-idle-compact--attempt state)
      (should (= requests 1))
      (should (plist-get (gethash "claude-test"
                                  metsatron/claude-idle-compact--sessions)
                         :compacting))
      (metsatron/idle-test--kill-buffer (plist-get state :buffer)))))

(ert-deftest metsatron/idle-claude-expired-timer-skips ()
  (let ((state (metsatron/idle-test--claude-state 80000))
        (requests 0))
    (setq state (plist-put state :last-normal-turn-completed-at
                           (- (float-time) claude-idle-compact-long-cache-ttl-seconds 1)))
    (puthash "claude-test" state metsatron/claude-idle-compact--sessions)
    (cl-letf (((symbol-function 'metsatron/claude-idle-compact--snapshot)
               (lambda (_state) (plist-get state :test-snapshot)))
              ((symbol-function 'metsatron/claude-idle-compact--vterm-draft-present-p)
               (lambda () nil))
              ((symbol-function 'process-live-p) (lambda (_process) t))
              ((symbol-function 'get-buffer-process) (lambda (_buffer) 'fake-process))
              ((symbol-function 'claude-code-ide--terminal-send-string)
               (lambda (&rest _args) (setq requests (1+ requests))))
              ((symbol-function 'claude-code-ide--terminal-send-return)
               (lambda (&rest _args) nil))
              ((symbol-function 'derived-mode-p) (lambda (&rest _modes) t)))
      (metsatron/claude-idle-compact--attempt state)
      (should (= requests 0))
      (metsatron/idle-test--kill-buffer (plist-get state :buffer)))))

(ert-deftest metsatron/idle-claude-post-compact-clears-dirty-and-tokens ()
  (let ((state (metsatron/idle-test--claude-state 80000)))
    (puthash "claude-test" state metsatron/claude-idle-compact--sessions)
    (metsatron/claude-idle-compact-handle-hook
     'post-compact "claude-test" "claude-session")
    (setq state (gethash "claude-test" metsatron/claude-idle-compact--sessions))
    (should-not (plist-get state :dirty))
    (should-not (plist-get state :compacting))
    (should-not (plist-get state :active-input-context-tokens))
    (metsatron/idle-test--kill-buffer (plist-get state :buffer))))

(ert-deftest metsatron/idle-claude-compaction-stop-does-not-rearm ()
  (let ((state (metsatron/idle-test--claude-state 80000)))
    (setq state (plist-put state :compacting t))
    (puthash "claude-test" state metsatron/claude-idle-compact--sessions)
    (metsatron/claude-idle-compact-handle-hook
     'stop "claude-test" "claude-session")
    (setq state (gethash "claude-test" metsatron/claude-idle-compact--sessions))
    (should (plist-get state :compacting))
    (should (plist-get state :dirty))
    (should-not (plist-get state :timer))
    (metsatron/idle-test--kill-buffer (plist-get state :buffer))))

(ert-deftest metsatron/idle-codex-token-fixture-uses-last-total ()
  (let* ((session 'codex-session)
         (metadata (make-hash-table :test #'eq))
         (get (lambda (_s key) (gethash key metadata)))
         (put (lambda (_s key value) (puthash key value metadata))))
    (cl-letf (((symbol-function 'codex-ide--session-metadata-get) get)
              ((symbol-function 'codex-ide--session-metadata-put) put)
              ((symbol-function 'codex-ide-session-thread-id) (lambda (_s) "thread-1"))
              ((symbol-function 'codex-ide-session-process) (lambda (_s) 'process))
              ((symbol-function 'codex-ide-session-buffer) (lambda (_s) nil))
              ((symbol-function 'codex-ide-session-status) (lambda (_s) "idle")))
      (metsatron/codex-idle-compact--handle-notification
       (lambda (&rest _args) nil) session
       '((method . "thread/tokenUsage/updated")
         (params . ((threadId . "thread-1")
                    (turnId . "turn-1")
                    (tokenUsage .
                     ((total . ((totalTokens . 900000)))
                      (last . ((inputTokens . 70000)
                               (cachedInputTokens . 12000)
                               (cacheWriteInputTokens . 1000)
                               (totalTokens . 83000)))
                      (modelContextWindow . 1000000)))))))
      (should (= (plist-get (gethash metsatron/codex-idle-compact--metadata-key
                                     metadata)
                            :current-context-tokens)
                 83000)))))

(ert-deftest metsatron/idle-codex-turn-fixture-uses-owning-session ()
  (let* ((session 'codex-session)
         (metadata (make-hash-table :test #'eq))
         (get (lambda (_s key) (gethash key metadata)))
         (put (lambda (_s key value) (puthash key value metadata)))
         (timers 0))
    (cl-letf (((symbol-function 'codex-ide--session-metadata-get) get)
              ((symbol-function 'codex-ide--session-metadata-put) put)
              ((symbol-function 'codex-ide-session-thread-id) (lambda (_s) "thread-1"))
              ((symbol-function 'codex-ide-session-process) (lambda (_s) 'process))
              ((symbol-function 'codex-ide-session-buffer) (lambda (_s) 'buffer))
              ((symbol-function 'codex-ide-session-status) (lambda (_s) "idle"))
              ((symbol-function 'process-live-p) (lambda (_p) t))
              ((symbol-function 'buffer-live-p) (lambda (_b) t))
              ((symbol-function 'run-at-time)
               (lambda (&rest _args) (setq timers (1+ timers)) 'timer))
              ((symbol-function 'timerp) (lambda (_timer) t))
      ((symbol-function 'cancel-timer) (lambda (_timer) nil)))
      ;; Representative 0.146.0 raw ownership fixture: the notification
      ;; carries `{turn}', while the owning session supplies the thread.
      (metsatron/codex-idle-compact--handle-notification
       (lambda (&rest _args) nil) session
       '((method . "item/started")
         (params . ((item . ((id . "item-1") (type . "agentMessage")))))))
      (metsatron/codex-idle-compact--handle-notification
       (lambda (&rest _args) nil) session
       '((method . "item/completed")
         (params . ((item . ((id . "item-1")
                             (type . "agentMessage")))))))
      (metsatron/codex-idle-compact--handle-notification
       (lambda (&rest _args) nil) session
       '((method . "turn/completed")
         (params . ((turn . ((id . "turn-1") (status . "completed") (items . nil)))))))
      (should (plist-get (gethash metsatron/codex-idle-compact--metadata-key
                                  metadata)
                         :dirty))
      (should (= timers 1)))))

(ert-deftest metsatron/idle-codex-duplicate-idle-does-not-arm-twice ()
  (let* ((session 'codex-session)
         (metadata (make-hash-table :test #'eq))
         (get (lambda (_s key) (gethash key metadata)))
         (put (lambda (_s key value) (puthash key value metadata)))
         (timers 0))
    (puthash metsatron/codex-idle-compact--metadata-key
             (list :session session :thread-id "thread-1" :connection 'process
                   :owning-buffer 'buffer :status "idle" :enabled t :dirty t
                   :compacting nil :timer nil :timer-generation 0
                   :last-normal-turn-completed-at (- (float-time) 10)
                   :current-context-tokens 80000)
             metadata)
    (cl-letf (((symbol-function 'codex-ide--session-metadata-get) get)
              ((symbol-function 'codex-ide--session-metadata-put) put)
              ((symbol-function 'codex-ide-session-thread-id) (lambda (_s) "thread-1"))
              ((symbol-function 'codex-ide-session-process) (lambda (_s) 'process))
              ((symbol-function 'codex-ide-session-buffer) (lambda (_s) 'buffer))
              ((symbol-function 'process-live-p) (lambda (_p) t))
              ((symbol-function 'buffer-live-p) (lambda (_b) t))
              ((symbol-function 'run-at-time)
               (lambda (&rest _args) (setq timers (1+ timers)) 'timer))
              ((symbol-function 'timerp) (lambda (_timer) t))
              ((symbol-function 'cancel-timer) (lambda (_timer) nil)))
      (metsatron/codex-idle-compact--arm session)
      (metsatron/codex-idle-compact--arm session)
      (should (= timers 1)))))

(ert-deftest metsatron/idle-codex-duplicate-completion-keeps-timer-identity ()
  "Normalized and raw completion evidence for one turn is idempotent."
  (let* ((session 'codex-duplicate-completion)
         (metadata (make-hash-table :test #'eq))
         (get (lambda (_s key) (gethash key metadata)))
         (put (lambda (_s key value) (puthash key value metadata)))
         (times '(10 20))
         (timers 0))
    (puthash metsatron/codex-idle-compact--metadata-key
             (list :session session :thread-id "thread-duplicate"
                   :connection 'process :owning-buffer 'buffer :status "idle"
                   :enabled t :dirty nil :compacting nil :timer nil
                   :timer-generation 0 :lifecycle-sequence 3
                   :completion-lifecycle-sequence nil
                   :cache-policy 'custom :policy-local t
                   :presumed-warm-seconds 90
                   :idle-compaction-delay-seconds 8)
             metadata)
    (cl-letf (((symbol-function 'codex-ide--session-metadata-get) get)
              ((symbol-function 'codex-ide--session-metadata-put) put)
              ((symbol-function 'process-live-p) (lambda (_p) t))
              ((symbol-function 'buffer-live-p) (lambda (_b) t))
              ((symbol-function 'run-at-time)
               (lambda (&rest _args) (setq timers (1+ timers)) 'timer))
              ((symbol-function 'timerp) (lambda (_timer) t))
              ((symbol-function 'cancel-timer) (lambda (_timer) nil))
              ((symbol-function 'metsatron/idle-compaction--now)
               (lambda () (pop times))))
      (metsatron/codex-idle-compact--mark-normal-complete
       session "normalized-turn-completed")
      (let ((first (gethash metsatron/codex-idle-compact--metadata-key metadata)))
        (metsatron/codex-idle-compact--mark-normal-complete
         session "raw-turn-completed")
        (let ((second (gethash metsatron/codex-idle-compact--metadata-key metadata)))
          (should (= (plist-get first :last-normal-turn-completed-at)
                     (plist-get second :last-normal-turn-completed-at)))
          (should (= (plist-get second :completion-lifecycle-sequence) 3))
          (should (= timers 1)))))))

(ert-deftest metsatron/idle-codex-draft-and-active-gates-block ()
  (let* ((session 'codex-session)
         (metadata (make-hash-table :test #'eq))
         (get (lambda (_s key) (gethash key metadata)))
         (put (lambda (_s key value) (puthash key value metadata)))
         (requests 0))
    (puthash metsatron/codex-idle-compact--metadata-key
             (list :session session :thread-id "thread-1" :connection 'process
                   :owning-buffer 'buffer :status "active" :enabled t :dirty t
                   :compacting nil :last-normal-turn-completed-at (- (float-time) 10)
                   :current-context-tokens 80000)
             metadata)
    (cl-letf (((symbol-function 'codex-ide--session-metadata-get) get)
              ((symbol-function 'codex-ide--session-metadata-put) put)
              ((symbol-function 'codex-ide-session-thread-id) (lambda (_s) "thread-1"))
              ((symbol-function 'codex-ide--session-for-thread-id) (lambda (_id) session))
              ((symbol-function 'codex-ide--current-input-empty-p) (lambda (_s) nil))
              ((symbol-function 'codex-ide-session-process) (lambda (_s) 'process))
              ((symbol-function 'codex-ide-session-buffer) (lambda (_s) 'buffer))
              ((symbol-function 'process-live-p) (lambda (_p) t))
              ((symbol-function 'buffer-live-p) (lambda (_b) t))
              ((symbol-function 'codex-ide--request-async)
               (lambda (&rest _args) (setq requests (1+ requests))))
              ((symbol-function 'timerp) (lambda (_timer) t))
              ((symbol-function 'cancel-timer) (lambda (_timer) nil)))
      (metsatron/codex-idle-compact--attempt session)
      (should (= requests 0))
      (metsatron/codex-idle-compact--put session :status "idle")
      (metsatron/codex-idle-compact--attempt session)
      (should (= requests 0)))))

(ert-deftest metsatron/idle-codex-empty-authoritative-prompt-is-not-a-draft ()
  "The package input-boundary predicate must override the visible prompt prefix."
  (let* ((session 'codex-empty-prompt)
         (metadata (make-hash-table :test #'eq))
         (state (list :session session :prompt-draft-dirty nil)))
    (puthash metsatron/codex-idle-compact--metadata-key state metadata)
    (cl-letf (((symbol-function 'codex-ide--session-metadata-get)
               (lambda (_session key) (gethash key metadata)))
              ((symbol-function 'codex-ide--current-input-empty-p)
               (lambda (_session) t))
              ((symbol-function 'codex-ide-session-prompt-history-draft)
               (lambda (_session) nil)))
      (should-not (metsatron/codex-idle-compact--draft-present-p session)))))

(ert-deftest metsatron/idle-codex-compaction-completion-cleans-without-loop ()
  (let* ((session 'codex-session)
         (metadata (make-hash-table :test #'eq))
         (get (lambda (_s key) (gethash key metadata)))
         (put (lambda (_s key value) (puthash key value metadata))))
    (puthash metsatron/codex-idle-compact--metadata-key
             (list :session session :thread-id "thread-1" :connection 'process
                   :owning-buffer 'buffer :status "idle" :enabled t :dirty t
                   :compacting t :timer nil :last-normal-turn-completed-at
                   (- (float-time) 10) :current-context-tokens 80000)
             metadata)
    (cl-letf (((symbol-function 'codex-ide--session-metadata-get) get)
              ((symbol-function 'codex-ide--session-metadata-put) put)
              ((symbol-function 'codex-ide-session-thread-id) (lambda (_s) "thread-1"))
      ((symbol-function 'codex-ide-session-process) (lambda (_s) 'process))
              ((symbol-function 'codex-ide-session-buffer) (lambda (_s) 'buffer))
              ((symbol-function 'codex-ide-session-status) (lambda (_s) "idle")))
      (metsatron/codex-idle-compact--handle-notification
       (lambda (&rest _args) nil) session
       '((method . "item/started")
         (params . ((item . ((id . "item-1")
                             (type . "contextCompaction")))))))
      (metsatron/codex-idle-compact--handle-notification
       (lambda (&rest _args) nil) session
       '((method . "item/completed")
         (params . ((item . ((id . "item-1")
                             (type . "contextCompaction")
                             (status . "completed")))))))
      (metsatron/codex-idle-compact--handle-notification
       (lambda (&rest _args) nil) session
       '((method . "turn/completed")
         (params . ((turn . ((id . "turn-2") (status . "completed")
                             (items . (((type . "contextCompaction"))))))))))
      (let ((state (gethash metsatron/codex-idle-compact--metadata-key metadata)))
        (should-not (plist-get state :dirty))
        (should-not (plist-get state :compacting))))))

(ert-deftest metsatron/idle-codex-stale-timer-cannot-request ()
  (let* ((session 'codex-session)
         (metadata (make-hash-table :test #'eq))
         (get (lambda (_s key) (gethash key metadata)))
         (put (lambda (_s key value) (puthash key value metadata)))
         (requests 0))
    (puthash metsatron/codex-idle-compact--metadata-key
             (list :session session :thread-id "thread-new" :connection 'process
                   :owning-buffer 'buffer :status "idle" :enabled t :dirty t
                   :compacting nil :timer-generation 2
                   :last-normal-turn-completed-at 200 :current-context-tokens 80000)
             metadata)
    (cl-letf (((symbol-function 'codex-ide--session-metadata-get) get)
              ((symbol-function 'codex-ide--session-metadata-put) put)
              ((symbol-function 'codex-ide--request-async)
               (lambda (&rest _args) (setq requests (1+ requests)))))
      (metsatron/codex-idle-compact--timer-fired session "thread-old" 100 1)
      (should (= requests 0)))))

(ert-deftest metsatron/idle-codex-ownership-check-uses-session-directory ()
  "A timer callback does not depend on its current buffer directory."
  (let ((session 'codex-owned-session)
        (seen nil))
    (cl-letf (((symbol-function 'codex-ide-session-thread-id)
               (lambda (_session) "thread-owned"))
              ((symbol-function 'codex-ide-session-directory)
               (lambda (_session) "/tmp/codex-owned-project"))
              ((symbol-function 'codex-ide--session-for-thread-id)
               (lambda (thread-id directory)
                 (setq seen (list thread-id directory))
                 session)))
      (should (metsatron/codex-idle-compact--owned-p
               session "thread-owned"))
      (should (equal seen '("thread-owned" "/tmp/codex-owned-project"))))))

(ert-deftest metsatron/idle-claude-local-input-cancels-pending-timer ()
  (let ((state (metsatron/idle-test--claude-state 80000)))
    (setq state (plist-put state :timer 'pending-timer))
    (puthash "claude-test" state metsatron/claude-idle-compact--sessions)
    (with-current-buffer (plist-get state :buffer)
      (metsatron/claude-idle-compact--local-activity))
    (setq state (gethash "claude-test" metsatron/claude-idle-compact--sessions))
    (should-not (plist-get state :timer))
    (should (numberp (plist-get state :last-local-keyboard-at)))
    (should (equal (plist-get state :last-cancellation-reason) "user-input"))
    (metsatron/idle-test--kill-buffer (plist-get state :buffer))))

(ert-deftest metsatron/idle-claude-later-turn-rearms-after-successful-compact ()
  (let ((state (metsatron/idle-test--claude-state 80000))
        (timers 0))
    (puthash "claude-test" state metsatron/claude-idle-compact--sessions)
    (cl-letf (((symbol-function 'process-live-p) (lambda (_process) t))
              ((symbol-function 'run-at-time)
               (lambda (&rest _args) (setq timers (1+ timers)) 'timer))
              ((symbol-function 'timerp) (lambda (_timer) t))
              ((symbol-function 'cancel-timer) (lambda (_timer) nil)))
      (metsatron/claude-idle-compact-handle-hook
       'stop "claude-test" "claude-session")
      (should (= timers 1))
      (metsatron/claude-idle-compact-handle-hook
       'post-compact "claude-test" "claude-session")
      (setq state (gethash "claude-test" metsatron/claude-idle-compact--sessions))
      (should-not (plist-get state :dirty))
      (should-not (plist-get state :timer))
      (metsatron/claude-idle-compact-handle-hook
       'stop "claude-test" "claude-session")
      (should (= timers 2)))
    (metsatron/idle-test--kill-buffer (plist-get state :buffer))))

(ert-deftest metsatron/idle-codex-eligible-session-requests-once ()
  (let* ((session 'codex-session)
         (metadata (make-hash-table :test #'eq))
         (get (lambda (_s key) (gethash key metadata)))
         (put (lambda (_s key value) (puthash key value metadata)))
         (requests 0))
    (puthash metsatron/codex-idle-compact--metadata-key
             (list :session session :thread-id "thread-1" :connection 'process
                   :owning-buffer 'buffer :status "idle" :enabled t :dirty t
                   :compacting nil :timer nil
                   :last-normal-turn-completed-at (- (float-time) 10)
                   :current-context-tokens 80000 :prompt-draft-dirty nil)
             metadata)
    (cl-letf (((symbol-function 'codex-ide--session-metadata-get) get)
              ((symbol-function 'codex-ide--session-metadata-put) put)
              ((symbol-function 'codex-ide-session-thread-id)
               (lambda (_s) "thread-1"))
              ((symbol-function 'codex-ide-session-process)
               (lambda (_s) 'process))
              ((symbol-function 'codex-ide-session-buffer)
               (lambda (_s) 'buffer))
              ((symbol-function 'process-live-p) (lambda (_p) t))
              ((symbol-function 'buffer-live-p) (lambda (_b) t))
              ((symbol-function 'codex-ide--request-async)
               (lambda (&rest _args) (setq requests (1+ requests)))))
      (metsatron/codex-idle-compact--attempt session)
      (should (= requests 1))
      (should (plist-get (gethash metsatron/codex-idle-compact--metadata-key
                                  metadata)
                         :compacting)))))

(ert-deftest metsatron/idle-codex-sessions-are-isolated ()
  (let ((metadata (make-hash-table :test #'eq)))
    (dolist (session '(one two))
      (puthash session (list :session session :thread-id (symbol-name session)
                             :connection 'process :owning-buffer 'buffer
                             :status "idle" :enabled t :dirty nil)
               metadata))
    (should-not (plist-get (gethash 'one metadata) :dirty))
    (should-not (plist-get (gethash 'two metadata) :dirty))))

(ert-deftest metsatron/idle-codex-observed-idle-without-turn-completed-marks-dirty ()
  "The installed live path can finish through item completion plus idle."
  (let* ((session 'codex-no-raw-turn)
         (metadata (make-hash-table :test #'eq))
         (get (lambda (_s key) (gethash key metadata)))
         (put (lambda (_s key value) (puthash key value metadata)))
         (timers 0))
    (puthash metsatron/codex-idle-compact--metadata-key
             (list :session session :thread-id "thread-no-raw"
                   :connection 'process :owning-buffer 'buffer
                   :status "active" :enabled t :dirty nil :compacting nil
                   :timer nil :timer-generation 0 :current-context-tokens 80000)
             metadata)
    (cl-letf (((symbol-function 'codex-ide--session-metadata-get) get)
              ((symbol-function 'codex-ide--session-metadata-put) put)
              ((symbol-function 'process-live-p) (lambda (_p) t))
              ((symbol-function 'buffer-live-p) (lambda (_b) t))
              ((symbol-function 'run-at-time)
               (lambda (delay &rest _args) (should (= delay (* 27 60)))
                 (setq timers (1+ timers)) 'timer))
              ((symbol-function 'timerp) (lambda (_timer) t))
              ((symbol-function 'cancel-timer) (lambda (_timer) nil)))
      (metsatron/codex-idle-compact--handle-notification
       (lambda (&rest _args) nil) session
       '((method . "item/started")
         (params . ((item . ((id . "agent-1") (type . "agentMessage")))))))
      (metsatron/codex-idle-compact--handle-notification
       (lambda (&rest _args) nil) session
       '((method . "item/completed")
         (params . ((item . ((id . "agent-1") (type . "agentMessage")))))))
      (metsatron/codex-idle-compact--handle-notification
       (lambda (&rest _args) nil) session
       '((method . "thread/status/changed")
         (params . ((threadId . "thread-no-raw") (status . "idle")))))
      (let ((state (gethash metsatron/codex-idle-compact--metadata-key metadata)))
        (should (plist-get state :dirty))
        (should (= timers 1))
        (should (equal (plist-get state :last-lifecycle-evidence)
                       "agent-item-plus-idle"))))))

(ert-deftest metsatron/idle-codex-initialization-active-idle-stays-clean ()
  (let* ((session 'codex-initialization)
         (metadata (make-hash-table :test #'eq))
         (get (lambda (_s key) (gethash key metadata)))
         (put (lambda (_s key value) (puthash key value metadata)))
         (timers 0))
    (puthash metsatron/codex-idle-compact--metadata-key
             (list :session session :thread-id "thread-init"
                   :connection 'process :owning-buffer 'buffer
                   :status "starting" :enabled t :dirty nil :compacting nil)
             metadata)
    (cl-letf (((symbol-function 'codex-ide--session-metadata-get) get)
              ((symbol-function 'codex-ide--session-metadata-put) put)
              ((symbol-function 'process-live-p) (lambda (_p) t))
              ((symbol-function 'buffer-live-p) (lambda (_b) t))
              ((symbol-function 'run-at-time)
               (lambda (&rest _args) (setq timers (1+ timers)) 'timer)))
      (metsatron/codex-idle-compact--handle-status session "active")
      (metsatron/codex-idle-compact--handle-status session "idle")
      (let ((state (gethash metsatron/codex-idle-compact--metadata-key metadata)))
        (should-not (plist-get state :dirty))
        (should (= timers 0))))))

(ert-deftest metsatron/idle-codex-incomplete-agent-work-does-not-mark-dirty ()
  "An observed item without completion is not a completed normal turn."
  (let* ((session 'codex-incomplete-turn)
         (metadata (make-hash-table :test #'eq))
         (get (lambda (_s key) (gethash key metadata)))
         (put (lambda (_s key value) (puthash key value metadata)))
         (timers 0))
    (puthash metsatron/codex-idle-compact--metadata-key
             (list :session session :thread-id "thread-incomplete"
                   :connection 'process :owning-buffer 'buffer
                   :status "active" :enabled t :dirty nil :compacting nil)
             metadata)
    (cl-letf (((symbol-function 'codex-ide--session-metadata-get) get)
              ((symbol-function 'codex-ide--session-metadata-put) put)
              ((symbol-function 'process-live-p) (lambda (_p) t))
              ((symbol-function 'buffer-live-p) (lambda (_b) t))
              ((symbol-function 'run-at-time)
               (lambda (&rest _args) (setq timers (1+ timers)) 'timer)))
      (metsatron/codex-idle-compact--handle-notification
       (lambda (&rest _args) nil) session
       '((method . "item/started")
         (params . ((item . ((id . "agent-incomplete")
                             (type . "agentMessage")))))))
      (metsatron/codex-idle-compact--handle-notification
       (lambda (&rest _args) nil) session
       '((method . "thread/status/changed")
         (params . ((threadId . "thread-incomplete")
                    (status . "idle")))))
      (let ((state (gethash metsatron/codex-idle-compact--metadata-key metadata)))
        (should-not (plist-get state :dirty))
        (should (= timers 0))))))

(ert-deftest metsatron/idle-codex-event-installs-local-input-hook-after-mode-hook ()
  "A newly created session installs local-input handling after binding.
`emacs-codex-ide' runs its session-mode hook before binding the owning session
in the buffer, so the normalized lifecycle event is the reliable fallback."
  (let* ((session 'codex-hook-install)
         (buffer (generate-new-buffer " *idle-codex-hook-test*"))
         (metadata (make-hash-table :test #'eq))
         (state (list :session session :thread-id "thread-hook"
                      :connection 'process :owning-buffer buffer
                      :status "starting" :enabled t :dirty nil
                      :compacting nil :timer nil)))
    (puthash metsatron/codex-idle-compact--metadata-key state metadata)
    (unwind-protect
        (cl-letf (((symbol-function 'codex-ide--session-metadata-get)
                   (lambda (_session key) (gethash key metadata)))
                  ((symbol-function 'codex-ide--session-metadata-put)
                   (lambda (_session key value) (puthash key value metadata)))
                  ((symbol-function 'codex-ide-session-process)
                   (lambda (_session) 'process))
                  ((symbol-function 'codex-ide-session-buffer)
                   (lambda (_session) buffer))
                  ((symbol-function 'process-live-p)
                   (lambda (_process) t))
                  ((symbol-function 'process-get)
                   (lambda (_process _property) t)))
          (metsatron/codex-idle-compact--handle-session-event
           'status-changed session '(:status "active" :reason "test"))
          (with-current-buffer buffer
            (should (memq #'metsatron/codex-idle-compact--local-activity
                          pre-command-hook))))
      (when (buffer-live-p buffer)
        (kill-buffer buffer)))))

(ert-deftest metsatron/idle-codex-default-policy-is-heuristic ()
  (should (eq codex-cache-policy 'presumed-30m))
  (should (= codex-presumed-warm-seconds (* 30 60)))
  (should (= codex-idle-compact-seconds (* 27 60)))
  (should (string-match-p "heuristic" codex-cache-policy-confidence))
  (should (string-match-p "GPT-5.6" codex-cache-policy-source)))

(ert-deftest metsatron/idle-codex-compaction-idle-without-success-is-unknown ()
  (let* ((session 'codex-ambiguous-compaction)
         (metadata (make-hash-table :test #'eq))
         (get (lambda (_s key) (gethash key metadata)))
         (put (lambda (_s key value) (puthash key value metadata)))
         (timers 0))
    (puthash metsatron/codex-idle-compact--metadata-key
             (list :session session :thread-id "thread-ambiguous"
                   :connection 'process :owning-buffer 'buffer
                   :status "idle" :enabled t :dirty t :compacting nil)
             metadata)
    (cl-letf (((symbol-function 'codex-ide--session-metadata-get) get)
              ((symbol-function 'codex-ide--session-metadata-put) put)
              ((symbol-function 'process-live-p) (lambda (_p) t))
              ((symbol-function 'buffer-live-p) (lambda (_b) t))
              ((symbol-function 'run-at-time)
               (lambda (&rest _args) (setq timers (1+ timers)) 'timer)))
      (metsatron/codex-idle-compact--handle-notification
       (lambda (&rest _args) nil) session
       '((method . "item/started")
         (params . ((item . ((id . "compact-1")
                             (type . "contextCompaction")))))))
      (metsatron/codex-idle-compact--handle-notification
       (lambda (&rest _args) nil) session
       '((method . "item/completed")
         (params . ((item . ((id . "compact-1")
                             (type . "contextCompaction")))))))
      (metsatron/codex-idle-compact--handle-notification
       (lambda (&rest _args) nil) session
       '((method . "thread/status/changed")
         (params . ((threadId . "thread-ambiguous") (status . "idle")))))
      ;; A duplicate idle notification must not turn ambiguity into a retry.
      (metsatron/codex-idle-compact--handle-status session "idle")
      (let ((state (gethash metsatron/codex-idle-compact--metadata-key metadata)))
        (should (plist-get state :dirty))
        (should-not (plist-get state :compacting))
         (should (eq (plist-get state :compaction-result) 'unknown))
        (should (= timers 0))))))

(ert-deftest metsatron/idle-codex-ambiguous-idle-followed-by-completed-turn-succeeds ()
  "A later successful compaction turn completion resolves an early idle race."
  (let* ((session 'codex-late-compaction-success)
         (metadata (make-hash-table :test #'eq))
         (get (lambda (_s key) (gethash key metadata)))
         (put (lambda (_s key value) (puthash key value metadata))))
    (puthash metsatron/codex-idle-compact--metadata-key
             (list :session session :thread-id "thread-late-success"
                   :connection 'process :owning-buffer 'buffer
                   :status "idle" :enabled t :dirty t :compacting nil)
             metadata)
    (cl-letf (((symbol-function 'codex-ide--session-metadata-get) get)
              ((symbol-function 'codex-ide--session-metadata-put) put)
              ((symbol-function 'process-live-p) (lambda (_p) t))
              ((symbol-function 'buffer-live-p) (lambda (_b) t)))
      (metsatron/codex-idle-compact--handle-notification
       (lambda (&rest _args) nil) session
       '((method . "item/started")
         (params . ((item . ((id . "compact-late")
                             (type . "contextCompaction")))))))
      (metsatron/codex-idle-compact--handle-notification
       (lambda (&rest _args) nil) session
       '((method . "item/completed")
         (params . ((item . ((id . "compact-late")
                             (type . "contextCompaction")))))))
      (metsatron/codex-idle-compact--handle-status session "idle")
      (metsatron/codex-idle-compact--handle-notification
       (lambda (&rest _args) nil) session
       '((method . "turn/completed")
         (params . ((turn . ((id . "compact-turn-late")
                             (status . "completed")))))))
      (let ((state (gethash metsatron/codex-idle-compact--metadata-key metadata)))
        (should-not (plist-get state :dirty))
        (should-not (plist-get state :compacting))
        (should (eq (plist-get state :compaction-result) 'succeeded))))))

(ert-deftest metsatron/idle-codex-failed-compaction-preserves-dirty ()
  (let* ((session 'codex-failed-compaction)
         (metadata (make-hash-table :test #'eq))
         (get (lambda (_s key) (gethash key metadata)))
         (put (lambda (_s key value) (puthash key value metadata))))
    (puthash metsatron/codex-idle-compact--metadata-key
             (list :session session :thread-id "thread-failed"
                   :connection 'process :owning-buffer 'buffer
                   :status "idle" :enabled t :dirty t :compacting t
                   :compaction-turn-in-progress t
                   :compaction-result 'pending)
             metadata)
    (cl-letf (((symbol-function 'codex-ide--session-metadata-get) get)
              ((symbol-function 'codex-ide--session-metadata-put) put))
      (metsatron/codex-idle-compact--finish-compaction
       session 'failed "turn-failed")
      (let ((state (gethash metsatron/codex-idle-compact--metadata-key metadata)))
        (should (plist-get state :dirty))
        (should-not (plist-get state :compacting))
        (should (eq (plist-get state :compaction-result) 'failed))))))

(ert-deftest metsatron/idle-codex-disabled-policy-never-compacts ()
  (let* ((codex-cache-policy 'disabled)
         (session 'codex-disabled)
         (metadata (make-hash-table :test #'eq))
         (get (lambda (_s key) (gethash key metadata)))
         (put (lambda (_s key value) (puthash key value metadata)))
         (requests 0))
    (puthash metsatron/codex-idle-compact--metadata-key
             (list :session session :thread-id "thread-disabled"
                   :connection 'process :owning-buffer 'buffer
                   :status "idle" :enabled t :dirty t
                   :last-normal-turn-completed-at (- (float-time) 10)
                   :current-context-tokens 90000)
             metadata)
    (cl-letf (((symbol-function 'codex-ide--session-metadata-get) get)
              ((symbol-function 'codex-ide--session-metadata-put) put)
              ((symbol-function 'codex-ide--request-async)
               (lambda (&rest _args) (setq requests (1+ requests)))))
      (metsatron/codex-idle-compact--attempt session)
      (should (= requests 0)))))

(ert-deftest metsatron/idle-codex-custom-budget-controls-delay-and-gate ()
  (let* ((session 'codex-custom)
         (metadata (make-hash-table :test #'eq))
         (get (lambda (_s key) (gethash key metadata)))
         (put (lambda (_s key value) (puthash key value metadata)))
         (delay-seen nil)
         (requests 0))
    (puthash metsatron/codex-idle-compact--metadata-key
             (list :session session :thread-id "thread-custom"
                   :connection 'process :owning-buffer 'buffer
                   :status "idle" :enabled t :dirty t :compacting nil
                   :cache-policy 'custom :policy-local t
                   :presumed-warm-seconds 10
                   :idle-compaction-delay-seconds 7
                   :last-normal-turn-completed-at (- (float-time) 2)
                   :current-context-tokens 80000)
             metadata)
    (cl-letf (((symbol-function 'codex-ide-session-process) (lambda (_) 'process))
              ((symbol-function 'codex-ide-session-buffer) (lambda (_) 'buffer))
              ((symbol-function 'codex-ide--session-metadata-get) get)
              ((symbol-function 'codex-ide--session-metadata-put) put)
              ((symbol-function 'process-live-p) (lambda (_p) t))
              ((symbol-function 'buffer-live-p) (lambda (_b) t))
              ((symbol-function 'run-at-time)
               (lambda (delay &rest _args) (setq delay-seen delay) 'timer))
              ((symbol-function 'codex-ide--request-async)
               (lambda (&rest _args) (setq requests (1+ requests))))
              ((symbol-function 'codex-ide-session-thread-id)
               (lambda (_s) "thread-custom"))
              ((symbol-function 'codex-ide--session-for-thread-id)
               (lambda (_id) session)))
      (metsatron/codex-idle-compact--arm session)
      (should (= delay-seen 7))
      (setq delay-seen nil)
      (metsatron/codex-idle-compact--put
       session :last-normal-turn-completed-at (- (float-time) 11))
      (metsatron/codex-idle-compact--attempt session)
      (should (= requests 0)))))

(ert-deftest metsatron/idle-codex-cumulative-total-never-raises-threshold ()
  (let* ((session 'codex-cumulative)
         (metadata (make-hash-table :test #'eq))
         (get (lambda (_s key) (gethash key metadata)))
         (put (lambda (_s key value) (puthash key value metadata))))
    (cl-letf (((symbol-function 'codex-ide--session-metadata-get) get)
              ((symbol-function 'codex-ide--session-metadata-put) put)
              ((symbol-function 'codex-ide-session-thread-id)
               (lambda (_s) "thread-cumulative"))
              ((symbol-function 'codex-ide-session-process)
               (lambda (_s) 'process))
              ((symbol-function 'codex-ide-session-buffer)
               (lambda (_s) 'buffer))
              ((symbol-function 'codex-ide-session-status)
               (lambda (_s) "idle")))
      (metsatron/codex-idle-compact--handle-notification
       (lambda (&rest _args) nil) session
       '((method . "thread/tokenUsage/updated")
         (params . ((threadId . "thread-cumulative")
                    (tokenUsage . ((total . ((totalTokens . 900000)))
                                   (last . ((totalTokens . 69999)))))))))
      (should (= (plist-get
                  (gethash metsatron/codex-idle-compact--metadata-key metadata)
                  :current-context-tokens)
                 69999)))))

(ert-deftest metsatron/idle-codex-raw-usage-missing-fields-stay-unknown ()
  (let* ((session 'codex-raw-usage)
         (metadata (make-hash-table :test #'eq))
         (get (lambda (_s key) (gethash key metadata)))
         (put (lambda (_s key value) (puthash key value metadata)))
         (codex-idle-compact-raw-telemetry-enabled t))
    (cl-letf (((symbol-function 'codex-ide--session-metadata-get) get)
              ((symbol-function 'codex-ide--session-metadata-put) put)
              ((symbol-function 'codex-ide-session-thread-id)
               (lambda (_s) "thread-raw"))
              ((symbol-function 'codex-ide-session-process)
               (lambda (_s) 'process))
              ((symbol-function 'codex-ide-session-buffer)
               (lambda (_s) 'buffer))
              ((symbol-function 'codex-ide-session-status)
               (lambda (_s) "idle")))
      (metsatron/codex-idle-compact--handle-notification
       (lambda (&rest _args) nil) session
       '((method . "rawResponse/completed")
         (params . ((usage . ((input_tokens . 100)
                              (total_tokens . 120)))))))
      (let ((state (gethash metsatron/codex-idle-compact--metadata-key metadata)))
        (should-not (plist-get state :raw-cached-input-tokens))
        (should-not (plist-get state :raw-cache-write-input-tokens))
        (should (= (plist-get state :raw-input-tokens) 100))))))

(ert-deftest metsatron/idle-codex-raw-usage-records-cache-counters-without-retention-claim ()
  (let* ((session 'codex-raw-hit)
         (metadata (make-hash-table :test #'eq))
         (get (lambda (_s key) (gethash key metadata)))
         (put (lambda (_s key value) (puthash key value metadata)))
         (codex-idle-compact-raw-telemetry-enabled t))
    (cl-letf (((symbol-function 'codex-ide--session-metadata-get) get)
              ((symbol-function 'codex-ide--session-metadata-put) put)
              ((symbol-function 'codex-ide-session-thread-id)
               (lambda (_s) "thread-raw-hit"))
              ((symbol-function 'codex-ide-session-process)
               (lambda (_s) 'process))
              ((symbol-function 'codex-ide-session-buffer)
               (lambda (_s) 'buffer))
              ((symbol-function 'codex-ide-session-status)
               (lambda (_s) "idle")))
      (metsatron/codex-idle-compact--handle-notification
       (lambda (&rest _args) nil) session
       '((method . "rawResponse/completed")
         (params . ((model . "gpt-5.6-sol")
                    (modelProvider . "openai")
                    (usage . ((cachedInputTokens . 80)
                              (cacheWriteInputTokens . 10)
                              (inputTokens . 100)
                              (totalTokens . 120)))))))
      (let ((state (gethash metsatron/codex-idle-compact--metadata-key metadata)))
        (should (= (plist-get state :raw-cached-input-tokens) 80))
        (should (= (plist-get state :raw-cache-write-input-tokens) 10))
        (should (equal (plist-get state :raw-model) "gpt-5.6-sol"))
        (should (numberp (plist-get state :last-raw-usage-at)))))))

(ert-deftest metsatron/idle-codex-raw-request-opt-in-is-explicit ()
  (let ((codex-idle-compact-raw-telemetry-enabled t)
        (args (list 'session "thread/start" '((foo . bar)))))
    (setq args (metsatron/codex-idle-compact--request-sync-filter args))
    (should (eq (alist-get 'experimentalRawEvents (nth 2 args)) t))
    (let ((codex-idle-compact-raw-telemetry-enabled nil))
      (should (equal
               (metsatron/codex-idle-compact--request-sync-filter
                (list 'session "thread/start" '((foo . bar))))
               (list 'session "thread/start" '((foo . bar))))))))

(defun metsatron/idle-test--policy-action (harness payload &optional model elapsed endpoint automatic action-payload hazard)
  "Exercise HARNESS arming and public action with resolver PAYLOAD.
MODEL, ELAPSED and ENDPOINT describe the current owning session."
  (let* ((session 'policy-session)
         (buffer (generate-new-buffer " *policy-action*"))
         (metadata (make-hash-table :test #'eq))
         (model (or model "current-model"))
         (endpoint (or endpoint "fixture-endpoint"))
         (completion 100)
         (now (+ completion (or elapsed 500)))
         (native-comp-enable-subr-trampolines nil)
         (requests 0) calls delays
         (state (if (eq harness 'claude)
                    (list :channel "policy-channel" :session-id "policy-id"
                          :buffer buffer :process 'process :status "idle"
                          :enabled t :dirty t :timer-generation 0
                          :cache-profile 'long
                          :last-normal-turn-completed-at completion)
                  (list :session session :thread-id "policy-id"
                        :connection 'process :owning-buffer buffer
                        :status "idle" :enabled t :dirty t :timer-generation 0
                        :cache-policy 'presumed-30m
                        :current-context-tokens 70000
                        :last-normal-turn-completed-at completion)))
         (metsatron/claude-idle-compact--sessions (make-hash-table :test #'equal)))
    (puthash :model-name model metadata)
    (puthash metsatron/codex-idle-compact--metadata-key state metadata)
    (puthash "policy-channel" state metsatron/claude-idle-compact--sessions)
    (unwind-protect
        (cl-letf (((symbol-function 'codex-ide--session-metadata-get)
                   (lambda (_s key) (gethash key metadata)))
                  ((symbol-function 'codex-ide--session-metadata-put)
                   (lambda (_s key value) (puthash key value metadata)))
                  ((symbol-function 'codex-ide-session-thread-id) (lambda (_) "policy-id"))
                  ((symbol-function 'codex-ide-session-process) (lambda (_) 'process))
                  ((symbol-function 'codex-ide-session-buffer) (lambda (_) buffer))
                  ((symbol-function 'codex-ide--session-for-thread-id)
                   (lambda (&rest _) session))
                  ((symbol-function 'codex-ide--current-input-empty-p)
                   (lambda (_) (not (memq hazard '(draft draft-buffer)))))
                  ((symbol-function 'metsatron/idle-compaction--current-state)
                   (lambda () (if (eq harness 'claude)
                                  (gethash "policy-channel" metsatron/claude-idle-compact--sessions)
                                (gethash metsatron/codex-idle-compact--metadata-key metadata))))
                  ((symbol-function 'metsatron/claude-idle-compact--snapshot)
                   (lambda (_) `((channel . "policy-channel") (session_id . "policy-id")
                                 (model . ,model)
                                 (current_input_context_tokens .
                                  ,(pcase hazard ('unknown-tokens nil)
                                     ('below-threshold 69999) (_ 70000))))))
                  ((symbol-function 'metsatron/claude-idle-compact--vterm-draft-present-p)
                   (lambda ()
                     (when (eq hazard 'draft-buffer)
                       (should (eq (current-buffer) buffer)))
                     (memq hazard '(draft draft-buffer))))
                  ((symbol-function 'process-live-p) (lambda (_) t))
                  ((symbol-function 'get-buffer-process) (lambda (_) 'process))
                  ((symbol-function 'derived-mode-p) (lambda (&rest _) t))
                  ((symbol-function 'metsatron/idle-compaction--now) (lambda () now))
                  ((symbol-function 'file-executable-p) (lambda (_) t))
                  ((symbol-function 'file-readable-p) (lambda (_) t))
                  ((symbol-function 'call-process)
                   (lambda (&rest args)
                     (push args calls) (insert payload) (goto-char (point-min)) 0))
                  ((symbol-function 'run-at-time)
                   (lambda (delay &rest _) (push delay delays) 'timer))
                  ((symbol-function 'timerp) (lambda (_) nil))
                  ((symbol-function 'claude-code-ide--terminal-send-string)
                   (lambda (_) (cl-incf requests)))
                  ((symbol-function 'claude-code-ide--terminal-send-return) (lambda () nil))
                  ((symbol-function 'codex-ide--request-async)
                   (lambda (&rest _) (cl-incf requests))))
          ;; Explicit owning-client endpoint binding is optional on old source.
          (when (fboundp 'metsatron/idle-compaction-set-session-endpoint)
            (metsatron/idle-compaction-set-session-endpoint
             (if (eq harness 'claude) "anthropic" "openai") endpoint))
          (if (eq harness 'claude)
              (metsatron/claude-idle-compact--arm state)
            (metsatron/codex-idle-compact--arm session))
          (let ((armed-delay (car delays)))
            (setq delays nil calls nil)
            ;; A launch flag or raw response from an earlier model is not current.
            (setq state (if (eq harness 'claude)
                            (gethash "policy-channel" metsatron/claude-idle-compact--sessions)
                          (gethash metsatron/codex-idle-compact--metadata-key metadata)))
            (setq state (plist-put state :raw-model "foreign-model"))
            (pcase hazard
              ('model-change (setq model "new-current-model")
                             (puthash :model-name model metadata))
              ('missing-model (setq model nil) (puthash :model-name nil metadata))
              ('unknown-tokens
               (setq state (plist-put state :current-context-tokens nil)))
              ('below-threshold
               (setq state (plist-put state :current-context-tokens 69999)))
              ('active (setq state (plist-put state :status "active")))
              ('owner-change
               (setq state (plist-put state :cache-policy-endpoint
                                      '(:provider "foreign" :endpoint-id "foreign"
                                        :owner-id "foreign" :connection process))))
              ('connection-change
               (setq state (plist-put state
                                      (if (eq harness 'claude) :process :connection)
                                      'replaced-process))))
            (setq state (plist-put state :timer nil))
            (if (eq harness 'claude)
                (puthash "policy-channel" state metsatron/claude-idle-compact--sessions)
              (puthash metsatron/codex-idle-compact--metadata-key state metadata))
            (when action-payload (setq payload action-payload))
            (if automatic
                (if (eq harness 'claude)
                    (metsatron/claude-idle-compact--timer-fired
                     "policy-channel" "policy-id" completion
                     (plist-get state :timer-generation))
                  (metsatron/codex-idle-compact--timer-fired
                   session "policy-id" completion (plist-get state :timer-generation)))
              (metsatron/idle-compaction-trigger-current))
            (list :requests requests :calls (nreverse calls) :armed-delay armed-delay
                  :delays delays)))
      (metsatron/idle-test--kill-buffer buffer))))

(ert-deftest metsatron/cache-policy-action-refreshes-current-model-and-endpoint ()
  "Public actions resolve session identity rather than cached/raw model identity."
  (dolist (harness '(claude codex))
    (let* ((result (metsatron/idle-test--policy-action
                    harness "{\"mode\":\"measured\",\"confidence\":\"supported\",\"compact_before_seconds\":300,\"cache_expires_seconds\":900}"
                    nil nil nil nil nil 'model-change))
           (args (car (plist-get result :calls))))
      (should (= (plist-get result :requests) 1))
      (should args)
      (should (equal (cadr (member "--model" args)) "new-current-model"))
      (should (equal (cadr (member "--endpoint" args)) "fixture-endpoint"))
      (should-not (member "--allow-observed" args)))))

(ert-deftest metsatron/cache-policy-malformed-and-observed-retain-fallback ()
  "Malformed decisions cannot supply timer values to either public consumer."
  (dolist (harness '(claude codex))
    (dolist (payload '("{}" "[]" "null" "42" "[300,900]"
                       "{\"mode\":\"observed\",\"confidence\":\"observed\",\"compact_before_seconds\":1,\"cache_expires_seconds\":900}"
                       "{\"mode\":\"measured\",\"confidence\":\"observed\",\"compact_before_seconds\":1,\"cache_expires_seconds\":900}"
                       "{\"mode\":\"measured\",\"confidence\":\"supported\",\"compact_before_seconds\":0,\"cache_expires_seconds\":900}"
                       "{\"mode\":\"measured\",\"confidence\":\"supported\",\"compact_before_seconds\":-1,\"cache_expires_seconds\":900}"
                       "{\"mode\":\"measured\",\"confidence\":\"supported\",\"compact_before_seconds\":\"300\",\"cache_expires_seconds\":900}"
                       "{\"mode\":\"measured\",\"confidence\":\"supported\",\"compact_before_seconds\":true,\"cache_expires_seconds\":900}"
                       "{\"mode\":\"measured\",\"confidence\":\"supported\",\"compact_before_seconds\":300,\"cache_expires_seconds\":300}"
                       "{\"mode\":\"measured\",\"confidence\":\"supported\",\"compact_before_seconds\":900,\"cache_expires_seconds\":300}"
                       "{\"mode\":\"measured\",\"confidence\":\"supported\",\"compact_before_seconds\":300,\"cache_expires_seconds\":1e999}"
                       "{\"mode\":\"measured\",\"confidence\":\"supported\",\"compact_before_seconds\":300}"
                       "{bad-json}"))
      (let ((result (metsatron/idle-test--policy-action harness payload)))
        (should (= (plist-get result :armed-delay)
                   (if (eq harness 'claude) 3300 1620)))))))

(ert-deftest metsatron/cache-policy-public-action-skips-freshly-cold-cache ()
  "A formerly warm cached decision cannot authorize an action after fresh expiry."
  (dolist (harness '(claude codex))
    (let ((result (metsatron/idle-test--policy-action
                   harness "{\"mode\":\"measured\",\"confidence\":\"supported\",\"compact_before_seconds\":300,\"cache_expires_seconds\":900}"
                   nil nil nil nil
                   "{\"mode\":\"measured\",\"confidence\":\"supported\",\"compact_before_seconds\":100,\"cache_expires_seconds\":200}")))
      (should (= (plist-get result :requests) 0)))))

(ert-deftest metsatron/cache-policy-timer-rearms-at-later-fresh-deadline ()
  "A fresh later deadline schedules only the remaining delay and submits nothing."
  (dolist (harness '(claude codex))
    (let ((result (metsatron/idle-test--policy-action
                   harness "{\"mode\":\"measured\",\"confidence\":\"supported\",\"compact_before_seconds\":300,\"cache_expires_seconds\":900}"
                   nil 500 nil t
                   "{\"mode\":\"measured\",\"confidence\":\"supported\",\"compact_before_seconds\":1000,\"cache_expires_seconds\":1200}")))
      (should (= (plist-get result :requests) 0))
      (should (equal (plist-get result :delays) '(500)))
      (should (= (length (plist-get result :calls)) 1)))))

(ert-deftest metsatron/cache-policy-stale-evidence-rearms-declared-fallback ()
  "Fallback after measured evidence disappears never inherits the old timers."
  (dolist (harness '(claude codex))
    (let ((result (metsatron/idle-test--policy-action
                   harness "{\"mode\":\"measured\",\"confidence\":\"supported\",\"compact_before_seconds\":300,\"cache_expires_seconds\":900}"
                   nil 500 nil t "{}")))
      (should (= (plist-get result :requests) 0))
      (should (equal (plist-get result :delays)
                     (list (- (if (eq harness 'claude) 3300 1620) 500)))))))

(ert-deftest metsatron/cache-policy-unknown-identity-keeps-fallback ()
  "Unknown models/endpoints never resolve generic-provider evidence."
  (dolist (harness '(claude codex))
    (dolist (identity '(("" "fixture-endpoint") ("current-model" "")))
      (let ((result (metsatron/idle-test--policy-action
                     harness "{\"mode\":\"measured\",\"confidence\":\"supported\",\"compact_before_seconds\":100,\"cache_expires_seconds\":200}"
                     (car identity) 500 (cadr identity))))
        (should-not (plist-get result :calls))
        (should (= (plist-get result :armed-delay)
                   (if (eq harness 'claude) 3300 1620)))))))

(ert-deftest metsatron/cache-policy-public-action-preserves-safety-gates ()
  "Supported timing never overrides unknown tokens, input or owner safety."
  (dolist (harness '(claude codex))
    (dolist (hazard '(unknown-tokens below-threshold draft draft-buffer active connection-change))
      (let ((result (metsatron/idle-test--policy-action
                     harness "{\"mode\":\"measured\",\"confidence\":\"supported\",\"compact_before_seconds\":300,\"cache_expires_seconds\":900}"
                     nil nil nil nil nil hazard)))
        (should (= (plist-get result :requests) 0))))))

(ert-deftest metsatron/cache-policy-lost-identity-rearms-without-foreign-evidence ()
  "Endpoint-owner drift or a missing current model selects the declared fallback."
  (dolist (harness '(claude codex))
    (dolist (hazard '(owner-change missing-model))
      (let ((result (metsatron/idle-test--policy-action
                     harness "{\"mode\":\"measured\",\"confidence\":\"supported\",\"compact_before_seconds\":300,\"cache_expires_seconds\":900}"
                     nil 500 nil t nil hazard)))
        (should-not (plist-get result :calls))
        (should (= (plist-get result :requests) 0))
        (should (equal (plist-get result :delays)
                       (list (- (if (eq harness 'claude) 3300 1620) 500))))))))
