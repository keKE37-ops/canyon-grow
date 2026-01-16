;; Canyon Grow - Zero-Knowledge Identity Verification
;; A privacy-preserving reputation system for verifiable credentials

;; Constants
(define-constant contract-owner tx-sender)
(define-constant err-owner-only (err u100))
(define-constant err-not-found (err u101))
(define-constant err-already-exists (err u102))
(define-constant err-invalid-threshold (err u103))
(define-constant err-unauthorized (err u104))

;; Data Variables
(define-data-var platform-fee uint u1000) ;; 0.1% fee in basis points

;; Credential Canyon Types
(define-map credential-canyons
    { canyon-id: (string-ascii 64) }
    {
        name: (string-utf8 128),
        domain: (string-ascii 32),
        min-threshold: uint,
        max-threshold: uint,
        active: bool,
        total-deposits: uint
    }
)

;; User Credential Deposits
(define-map user-credentials
    { user: principal, canyon-id: (string-ascii 64) }
    {
        credential-hash: (buff 32),
        score: uint,
        verified: bool,
        timestamp: uint,
        growth-level: uint
    }
)

;; Reputation Scores
(define-map user-reputation
    { user: principal }
    {
        total-score: uint,
        verified-canyons: uint,
        trust-level: uint,
        last-updated: uint
    }
)

;; Verifier Registry
(define-map authorized-verifiers
    { verifier: principal }
    { active: bool }
)

;; Growth Path Levels
(define-map growth-paths
    { level: uint }
    {
        name: (string-utf8 64),
        min-score: uint,
        benefits: (string-utf8 256)
    }
)

;; Read-only functions

(define-read-only (get-credential-canyon (canyon-id (string-ascii 64)))
    (map-get? credential-canyons { canyon-id: canyon-id })
)

(define-read-only (get-user-credential (user principal) (canyon-id (string-ascii 64)))
    (map-get? user-credentials { user: user, canyon-id: canyon-id })
)

(define-read-only (get-user-reputation (user principal))
    (default-to
        { total-score: u0, verified-canyons: u0, trust-level: u0, last-updated: u0 }
        (map-get? user-reputation { user: user })
    )
)

(define-read-only (get-growth-path (level uint))
    (map-get? growth-paths { level: level })
)

(define-read-only (is-authorized-verifier (verifier principal))
    (default-to false
        (get active (map-get? authorized-verifiers { verifier: verifier }))
    )
)

(define-read-only (calculate-trust-level (total-score uint) (verified-canyons uint))
    (if (>= verified-canyons u5)
        (if (>= total-score u1000) u5
        (if (>= total-score u750) u4
        (if (>= total-score u500) u3
        (if (>= total-score u250) u2 u1))))
        (if (>= verified-canyons u3)
            (if (>= total-score u500) u3
            (if (>= total-score u250) u2 u1))
            u1)
    )
)

;; Public functions

(define-public (create-credential-canyon 
    (canyon-id (string-ascii 64))
    (name (string-utf8 128))
    (domain (string-ascii 32))
    (min-threshold uint)
    (max-threshold uint))
    (begin
        (asserts! (is-eq tx-sender contract-owner) err-owner-only)
        (asserts! (is-none (map-get? credential-canyons { canyon-id: canyon-id })) err-already-exists)
        (asserts! (< min-threshold max-threshold) err-invalid-threshold)
        (ok (map-set credential-canyons
            { canyon-id: canyon-id }
            {
                name: name,
                domain: domain,
                min-threshold: min-threshold,
                max-threshold: max-threshold,
                active: true,
                total-deposits: u0
            }
        ))
    )
)

(define-public (deposit-credential
    (canyon-id (string-ascii 64))
    (credential-hash (buff 32))
    (score uint))
    (let
        (
            (canyon (unwrap! (map-get? credential-canyons { canyon-id: canyon-id }) err-not-found))
            (current-rep (get-user-reputation tx-sender))
        )
        (asserts! (get active canyon) err-unauthorized)
        (asserts! (and (>= score (get min-threshold canyon)) 
                      (<= score (get max-threshold canyon))) 
                 err-invalid-threshold)
        
        ;; Store credential
        (map-set user-credentials
            { user: tx-sender, canyon-id: canyon-id }
            {
                credential-hash: credential-hash,
                score: score,
                verified: false,
                timestamp: block-height,
                growth-level: u1
            }
        )
        
        ;; Update canyon stats
        (map-set credential-canyons
            { canyon-id: canyon-id }
            (merge canyon { total-deposits: (+ (get total-deposits canyon) u1) })
        )
        
        (ok true)
    )
)

(define-public (verify-credential
    (user principal)
    (canyon-id (string-ascii 64)))
    (let
        (
            (credential (unwrap! (map-get? user-credentials 
                { user: user, canyon-id: canyon-id }) err-not-found))
            (current-rep (get-user-reputation user))
        )
        (asserts! (is-authorized-verifier tx-sender) err-unauthorized)
        
        ;; Mark credential as verified
        (map-set user-credentials
            { user: user, canyon-id: canyon-id }
            (merge credential { verified: true })
        )
        
        ;; Update user reputation
        (let
            (
                (new-total-score (+ (get total-score current-rep) (get score credential)))
                (new-verified-canyons (+ (get verified-canyons current-rep) u1))
            )
            (map-set user-reputation
                { user: user }
                {
                    total-score: new-total-score,
                    verified-canyons: new-verified-canyons,
                    trust-level: (calculate-trust-level new-total-score new-verified-canyons),
                    last-updated: block-height
                }
            )
        )
        
        (ok true)
    )
)

(define-public (add-authorized-verifier (verifier principal))
    (begin
        (asserts! (is-eq tx-sender contract-owner) err-owner-only)
        (ok (map-set authorized-verifiers
            { verifier: verifier }
            { active: true }
        ))
    )
)

(define-public (remove-authorized-verifier (verifier principal))
    (begin
        (asserts! (is-eq tx-sender contract-owner) err-owner-only)
        (ok (map-set authorized-verifiers
            { verifier: verifier }
            { active: false }
        ))
    )
)

(define-public (create-growth-path
    (level uint)
    (name (string-utf8 64))
    (min-score uint)
    (benefits (string-utf8 256)))
    (begin
        (asserts! (is-eq tx-sender contract-owner) err-owner-only)
        (ok (map-set growth-paths
            { level: level }
            {
                name: name,
                min-score: min-score,
                benefits: benefits
            }
        ))
    )
)

;; Initialize default growth paths
(map-set growth-paths { level: u1 } 
    { name: u"Seedling", min-score: u0, benefits: u"Basic credential deposits" })
(map-set growth-paths { level: u2 } 
    { name: u"Sprout", min-score: u250, benefits: u"Cross-platform verification" })
(map-set growth-paths { level: u3 } 
    { name: u"Sapling", min-score: u500, benefits: u"DeFi lending eligibility" })
(map-set growth-paths { level: u4 } 
    { name: u"Tree", min-score: u750, benefits: u"Governance participation" })
(map-set growth-paths { level: u5 } 
    { name: u"Forest", min-score: u1000, benefits: u"Premium features & validator status" })