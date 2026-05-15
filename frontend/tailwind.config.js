/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        audit: {
          ink: '#0f172a',
          panel: '#111827',
          cyan: '#22d3ee',
        },
      },
    },
  },
  plugins: [],
};
