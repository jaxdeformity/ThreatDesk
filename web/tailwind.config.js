/** @type {import('tailwindcss').Config} */
// POLARIS-MK1 design tokens. All values come from src/styles/tokens.css via var().
// Spec: docs/superpowers/specs/2026-04-27-socbox-redesign-design.md §4
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // Surfaces
        bg:       'var(--bg)',
        surface:  'var(--surface)',
        surface2: 'var(--surface-2)',
        surface3: 'var(--surface-3)',

        // Hairlines (kept under 'border' name for backwards-compat with existing classes)
        border:          'var(--hairline)',
        'border-strong': 'var(--hairline-strong)',
        hairline:        'var(--hairline)',
        'hairline-strong':'var(--hairline-strong)',

        // Accent — single industrial orange
        accent: {
          DEFAULT: 'var(--accent)',
          hot:     'var(--accent-hot)',
          dim:     'var(--accent-dim)',
          deep:    'var(--accent-deep)',
        },

        // Text (kept under 'ink' name for backwards-compat)
        ink: {
          DEFAULT: 'var(--text)',
          dim:     'var(--text-dim)',
          faint:   'var(--text-faint)',
          ghost:   'var(--text-ghost)',
        },
        text: {
          DEFAULT: 'var(--text)',
          dim:     'var(--text-dim)',
          faint:   'var(--text-faint)',
          ghost:   'var(--text-ghost)',
        },

        // Semantic
        danger:  { DEFAULT: 'var(--crit)', dim: 'var(--crit-dim)', hot: 'var(--crit)' },
        warning: { DEFAULT: 'var(--warn)', dim: 'var(--warn-dim)' },
        success: { DEFAULT: 'var(--ok)',   dim: 'var(--ok-dim)' },
        info:    { DEFAULT: 'var(--info)', dim: 'var(--info-dim)' },
        ok:      'var(--ok)',
        warn:    'var(--warn)',
        crit:    'var(--crit)',

        // Severity scale — backwards-compat
        sev: {
          low:      'var(--sev-low)',
          medium:   'var(--sev-medium)',
          high:     'var(--sev-high)',
          critical: 'var(--sev-critical)',
        },

        // Heat scale — backwards-compat
        heat: {
          faint: 'var(--heat-faint)',
          low:   'var(--heat-low)',
          med:   'var(--heat-med)',
          high:  'var(--heat-high)',
          peak:  'var(--heat-peak)',
        },

        // Investigation-graph node colors
        node: {
          process: 'var(--node-process)',
          network: 'var(--node-network)',
          user:    'var(--node-user)',
          file:    'var(--node-file)',
          c2:      'var(--node-c2)',
        },
      },
      fontFamily: {
        sans:    ['Inter', 'system-ui', 'sans-serif'],
        mono:    ['"IBM Plex Mono"', 'ui-monospace', 'Menlo', 'monospace'],
        display: ['"IBM Plex Mono"', 'ui-monospace', 'monospace'],
      },
      fontSize: {
        '2xs':    ['10px', { lineHeight: '14px' }],
        'xs':     ['11px', { lineHeight: '15px' }],
        'sm':     ['12px', { lineHeight: '17px' }],
        'base':   ['13px', { lineHeight: '19px' }],
        'lg':     ['15px', { lineHeight: '22px' }],
        'xl':     ['18px', { lineHeight: '24px' }],
        'dspl-s': ['22px', { lineHeight: '26px', letterSpacing: '-0.01em' }],
        'dspl-m': ['28px', { lineHeight: '32px', letterSpacing: '-0.015em' }],
        'dspl-l': ['36px', { lineHeight: '40px', letterSpacing: '-0.02em', fontWeight: '600' }],
      },
      spacing: { '0.5': '2px' },
      borderRadius: {
        'xs': '2px', 'sm': '3px', DEFAULT: '4px', 'md': '6px', 'lg': '8px',
      },
      letterSpacing: {
        'caps':    '0.08em',
        'caps-lg': '0.12em',
      },
      animation: {
        'fade-in':       'fadeIn 120ms ease-out',
        'slide-in-right':'slideInRight 160ms cubic-bezier(0.16, 1, 0.3, 1)',
        'slide-in-up':   'slideInUp 140ms cubic-bezier(0.16, 1, 0.3, 1)',
        'pulse-soft':    'pulse 2.5s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'blink':         'blink 0.5s steps(1) infinite',
        'marquee':       'marquee 240s linear infinite',
      },
      keyframes: {
        fadeIn: { '0%': { opacity: 0 }, '100%': { opacity: 1 } },
        slideInRight: {
          '0%': { transform: 'translateX(8px)', opacity: 0 },
          '100%': { transform: 'translateX(0)', opacity: 1 },
        },
        slideInUp: {
          '0%': { transform: 'translateY(8px)', opacity: 0 },
          '100%': { transform: 'translateY(0)', opacity: 1 },
        },
        blink: {
          '0%, 49%': { opacity: 1 },
          '50%, 100%': { opacity: 0.3 },
        },
        marquee: {
          '0%': { transform: 'translateX(0)' },
          '100%': { transform: 'translateX(-50%)' },
        },
      },
    },
  },
  plugins: [],
}
