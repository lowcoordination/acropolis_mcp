import { useParams } from 'react-router'

export function ServerDetail() {
  const { slug } = useParams()
  return (
    <div>
      <h1 className="text-xl font-semibold mb-4">{slug}</h1>
      <p style={{ color: 'var(--text-muted)' }}>Coming soon.</p>
    </div>
  )
}
