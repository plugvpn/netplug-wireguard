/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: "class",
  content: ["./internal/view/templates/**/*.tmpl", "./styles/**/*.css"],
  safelist: ["np-tag-new", "border-emerald-500", "bg-emerald-950/60", "text-emerald-300"],
  theme: {
    extend: {},
  },
  plugins: [],
};
