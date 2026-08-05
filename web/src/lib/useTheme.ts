import { useCallback, useEffect, useState } from 'react'

export type Theme = 'system' | 'latte' | 'mocha'

const STORAGE_KEY = 'acropolis-theme'

// Mirrors the inline script in index.html, which applies the stored theme before React mounts
// (avoiding a flash of the wrong theme). Kept as the single source of truth for the read side;
// the write side (localStorage.setItem + dataset.theme) is duplicated here intentionally since
// it needs to run synchronously from a click handler, not wait on a script re-parse.
function applyTheme(theme: Theme) {
  if (theme === 'system') {
    delete document.documentElement.dataset.theme
  } else {
    document.documentElement.dataset.theme = theme
  }
}

function readStoredTheme(): Theme {
  const stored = localStorage.getItem(STORAGE_KEY)
  return stored === 'latte' || stored === 'mocha' ? stored : 'system'
}

export function useTheme() {
  const [theme, setThemeState] = useState<Theme>(readStoredTheme)

  useEffect(() => {
    applyTheme(theme)
  }, [theme])

  const setTheme = useCallback((next: Theme) => {
    if (next === 'system') {
      localStorage.removeItem(STORAGE_KEY)
    } else {
      localStorage.setItem(STORAGE_KEY, next)
    }
    setThemeState(next)
  }, [])

  return { theme, setTheme }
}
