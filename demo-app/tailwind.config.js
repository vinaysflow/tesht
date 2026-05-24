/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx,ts,tsx}'],
  theme: {
    extend: {
      colors: {
        pramana: {
          teal:  '#0D9488',
          dark:  '#0F172A',
          card:  '#1E293B',
          border:'#334155',
          muted: '#64748B',
        },
      },
    },
  },
  plugins: [],
}
