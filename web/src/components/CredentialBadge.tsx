// Enterprise #5 (secret backends): lets an operator tell at a glance whether a server's
// upstream credential — if any — is externalized to a reference (vault://..., enc:v1:...) or
// stored as a literal, WITHOUT ever showing the value itself. Mirrors HealthBadge/ProtocolBadge's
// styling conventions in this same directory.

interface CredentialBadgeProps {
  hasCredential: boolean
  isReference: boolean
}

export function CredentialBadge({ hasCredential, isReference }: CredentialBadgeProps) {
  if (!hasCredential) {
    return (
      <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
        —
      </span>
    )
  }
  if (isReference) {
    return (
      <span
        className="inline-flex items-center rounded px-1.5 py-0.5 text-xs font-medium"
        style={{
          background: 'color-mix(in srgb, var(--success) 16%, transparent)',
          color: 'var(--success)',
        }}
        title="Credential is externalized to a secret reference (never stored as plaintext by this server form)"
      >
        externalized
      </span>
    )
  }
  return (
    <span
      className="inline-flex items-center rounded px-1.5 py-0.5 text-xs font-medium"
      style={{
        background: 'color-mix(in srgb, var(--text-muted) 16%, transparent)',
        color: 'var(--text-muted)',
      }}
      title="Credential is stored as a literal value under the currently active secret provider"
    >
      literal
    </span>
  )
}
