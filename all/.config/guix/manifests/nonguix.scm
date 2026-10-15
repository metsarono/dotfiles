;; [[file:../../../../package-guix.org::*Guix User profile manifests][Guix User profile manifests:6]]
;; Nonguix-only user manifest.
;; Start empty so it never breaks builds; add packages you want from Nonguix.
(specifications->manifest
 '(
   "hugo@0.158.0"              ; static site generator — ExoCortex + HelmCortex wiki; pinned
   ;; Examples (uncomment IF you want them and the nonguix channel is enabled):
   ;; "signal-desktop"
   ;; "google-chrome"         ; proprietary; Nonguix
   ;; "steam"                 ; Nonguix
   ;; "spotify"               ; Nonguix
   ;; "nvidia-driver"         ; Nonguix
   ;; "visual-studio-code"    ; Nonguix
  ))
;; Guix User profile manifests:6 ends here
