/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        background: "#050505",
        surface: "#0a0a0a",
        primary: "#00e0ff",
        danger: "#ff4b4b",
        success: "#00cc96",
        border: "#333333"
      }
    },
  },
  plugins: [],
}
