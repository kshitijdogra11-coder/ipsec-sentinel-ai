/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', 'ui-sans-serif', 'system-ui', 'Segoe UI', 'Roboto', 'sans-serif'],
        mono: ['JetBrains Mono', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace'],
      },
      colors: {
        ink: { 950: '#070b14', 900: '#0b1220', 850: '#0f1729', 800: '#131d33', 700: '#1c2843', 600: '#2a3a5e' },
        accent: { DEFAULT: '#22d3ee', dim: '#0e7490' },
      },
    },
  },
  plugins: [],
}
