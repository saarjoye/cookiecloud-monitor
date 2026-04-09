import React, { useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import { motion } from "motion/react";
import "./styles.css";

const VIDEO_URL =
  "https://d8j0ntlcm91z4.cloudfront.net/user_38xzZboKViGWJOttwIXH07lWA1P/hf_20260302_085640_276ea93b-d7da-4418-a09b-2aa5b490e838.mp4";

const itemVariants = {
  hidden: { opacity: 0, y: 34 },
  show: (delay = 0) => ({
    opacity: 1,
    y: 0,
    transition: {
      duration: 0.8,
      ease: [0.22, 1, 0.36, 1],
      delay
    }
  })
};

function ReviewBadge() {
  return (
    <div className="inline-flex w-fit items-center gap-4 rounded-full border border-white/60 bg-white/75 px-4 py-3 shadow-[0px_18px_60px_-28px_rgba(15,23,42,0.35)] backdrop-blur-md">
      <div className="flex -space-x-2">
        {["A", "B", "C"].map((letter, index) => (
          <span
            key={letter}
            className={`flex size-9 items-center justify-center rounded-full border border-white/70 text-xs font-medium text-white ${
              index === 0 ? "bg-slate-900" : index === 1 ? "bg-slate-700" : "bg-slate-500"
            }`}
          >
            {letter}
          </span>
        ))}
      </div>
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-1 text-amber-400">
          {Array.from({ length: 5 }).map((_, index) => (
            <svg key={index} viewBox="0 0 20 20" className="size-4 fill-current">
              <path d="M10 1.5l2.5 5.06 5.58.81-4.04 3.94.95 5.56L10 14.24 5.01 16.87l.95-5.56-4.04-3.94 5.58-.81L10 1.5z" />
            </svg>
          ))}
        </div>
        <div className="text-sm text-slate-700">
          <span className="font-semibold text-slate-900">1,020+ Reviews</span>
          <span className="ml-2 opacity-80">by distributed operators</span>
        </div>
      </div>
    </div>
  );
}

function LoginHero() {
  const nextPath = useMemo(() => new URLSearchParams(window.location.search).get("next") || "/dashboard", []);
  const [form, setForm] = useState({ username: "", password: "" });
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");

  async function handleSubmit(event) {
    event.preventDefault();
    setSubmitting(true);
    setError("");
    try {
      const response = await fetch("/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ...form, next: nextPath })
      });
      const payload = await response.json();
      if (!response.ok) {
        setError(payload.message || "Sign in failed");
        return;
      }
      window.location.href = payload.redirect || nextPath;
    } catch (requestError) {
      setError("Network unavailable, please retry.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <section className="relative min-h-screen overflow-hidden bg-white">
      <div className="absolute inset-0">
        <video
          className="w-full h-full object-cover [transform:scaleY(-1)]"
          src={VIDEO_URL}
          autoPlay
          muted
          loop
          playsInline
        />
        <div className="absolute inset-0 bg-gradient-to-b from-[26.416%] from-[rgba(255,255,255,0)] to-[66.943%] to-white" />
      </div>

      <div className="relative mx-auto flex min-h-screen w-full max-w-[1200px] items-start px-6 pb-16 pt-[290px] sm:px-8 lg:px-10">
        <div className="grid w-full gap-14 lg:grid-cols-[1.1fr_460px] lg:gap-12">
          <div className="flex flex-col gap-8">
            <motion.div custom={0} initial="hidden" animate="show" variants={itemVariants}>
              <span className="inline-flex rounded-full border border-slate-200/70 bg-white/75 px-4 py-2 text-xs font-medium uppercase tracking-[0.28em] text-slate-600 shadow-[0px_12px_35px_-24px_rgba(15,23,42,0.4)] backdrop-blur-md">
                CookieCloud Command
              </span>
            </motion.div>

            <motion.h1
              custom={0.08}
              initial="hidden"
              animate="show"
              variants={itemVariants}
              className="font-geist text-[48px] font-medium leading-[0.95] tracking-[-0.04em] text-slate-950 sm:text-[64px] lg:text-[80px]"
            >
              Simple{" "}
              <span className="font-instrument text-[58px] italic tracking-[-0.04em] sm:text-[74px] lg:text-[100px]">
                management
              </span>{" "}
              for your remote team
            </motion.h1>

            <motion.p
              custom={0.16}
              initial="hidden"
              animate="show"
              variants={itemVariants}
              className="max-w-[554px] text-[18px] leading-8 text-[#373a46]/80"
            >
              Securely monitor CookieCloud sync activity, surface operational changes, and notify your enterprise team
              the moment credentials arrive, drift, or trigger a fresh login.
            </motion.p>

            <motion.div custom={0.24} initial="hidden" animate="show" variants={itemVariants}>
              <ReviewBadge />
            </motion.div>
          </div>

          <motion.div
            custom={0.24}
            initial="hidden"
            animate="show"
            variants={itemVariants}
            className="glass-panel rounded-[36px] border border-white/70 p-5 shadow-[0px_24px_90px_-30px_rgba(15,23,42,0.35)]"
          >
            <div className="rounded-[32px] bg-white/88 p-6 shadow-[inset_0px_1px_0px_rgba(255,255,255,0.7)]">
              <div className="mb-8 flex items-center justify-between">
                <div>
                  <p className="text-xs font-medium uppercase tracking-[0.26em] text-slate-500">Secure Access</p>
                  <h2 className="mt-3 text-[32px] font-medium tracking-[-0.04em] text-slate-950">Sign in to dashboard</h2>
                </div>
                <span className="rounded-full bg-slate-950 px-3 py-1 text-xs font-medium text-white">Session Login</span>
              </div>

              <form onSubmit={handleSubmit} className="flex flex-col gap-6">
                <div className="rounded-[40px] border border-slate-200/80 bg-[#fcfcfc] p-2 shadow-[0px_10px_40px_5px_rgba(194,194,194,0.25)]">
                  <div className="grid gap-2 lg:grid-cols-[1fr_1fr_auto]">
                    <input
                      type="text"
                      value={form.username}
                      onChange={(event) => setForm((current) => ({ ...current, username: event.target.value }))}
                      placeholder="Workspace username"
                      autoComplete="username"
                      className="h-14 rounded-[32px] border border-transparent bg-transparent px-5 text-[15px] text-slate-900 outline-none placeholder:text-slate-400"
                      required
                    />
                    <input
                      type="password"
                      value={form.password}
                      onChange={(event) => setForm((current) => ({ ...current, password: event.target.value }))}
                      placeholder="Password"
                      autoComplete="current-password"
                      className="h-14 rounded-[32px] border border-transparent bg-transparent px-5 text-[15px] text-slate-900 outline-none placeholder:text-slate-400"
                      required
                    />
                    <button
                      type="submit"
                      disabled={submitting}
                      className="h-14 rounded-full bg-[linear-gradient(180deg,#252525_0%,#050505_100%)] px-7 text-sm font-medium text-white shadow-[0px_12px_30px_rgba(15,23,42,0.28),inset_-4px_-6px_25px_0px_rgba(201,201,201,0.08),inset_4px_4px_10px_0px_rgba(29,29,29,0.24)] transition hover:translate-y-[-1px] disabled:cursor-not-allowed disabled:opacity-60"
                    >
                      {submitting ? "Signing In..." : "Secure Sign In"}
                    </button>
                  </div>
                </div>

                <div className="grid gap-4 rounded-[28px] border border-slate-200/80 bg-slate-50/80 p-5 text-sm text-slate-600">
                  <div className="flex items-start justify-between gap-4">
                    <div>
                      <p className="font-medium text-slate-900">Push-ready automations</p>
                      <p className="mt-2 leading-7">
                        WeCom app notifications can announce first-time syncs, CK count increases or decreases, and
                        every successful console login.
                      </p>
                    </div>
                    <span className="rounded-full border border-slate-200 bg-white px-3 py-1 text-xs font-medium text-slate-700">
                      WeCom
                    </span>
                  </div>

                  {error ? (
                    <div className="rounded-2xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">{error}</div>
                  ) : null}
                </div>
              </form>
            </div>
          </motion.div>
        </div>
      </div>
    </section>
  );
}

document.documentElement.dataset.loginApp = "ready";

createRoot(document.getElementById("login-root")).render(
  <React.StrictMode>
    <LoginHero />
  </React.StrictMode>
);
