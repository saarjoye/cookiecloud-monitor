import path from "node:path";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  publicDir: false,
  build: {
    outDir: path.resolve(__dirname, "../app/static/login-app"),
    emptyOutDir: true,
    cssCodeSplit: false,
    lib: {
      entry: path.resolve(__dirname, "./src/login.jsx"),
      formats: ["es"],
      fileName: () => "login.js",
      cssFileName: "login"
    },
    rollupOptions: {
      output: {
        assetFileNames: (assetInfo) => {
          if (assetInfo.name === "style.css" || assetInfo.name === "login.css") {
            return "login.css";
          }
          return "assets/[name][extname]";
        }
      }
    }
  }
});
