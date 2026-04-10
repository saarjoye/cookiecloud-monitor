import React, { useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import { motion } from "motion/react";
import "./styles.css";

const VIDEO_URL =
  "https://d8j0ntlcm91z4.cloudfront.net/user_38xzZboKViGWJOttwIXH07lWA1P/hf_20260302_085640_276ea93b-d7da-4418-a09b-2aa5b490e838.mp4";

const fadeUp = {
  hidden: { opacity: 0, y: 28 },
  show: (delay = 0) => ({
    opacity: 1,
    y: 0,
    transition: {
      duration: 0.72,
      ease: [0.22, 1, 0.36, 1],
      delay
    }
  })
};

function LoginFeature({ title, detail }) {
  return (
    <div className="login-feature">
      <span className="login-feature-dot" />
      <div>
        <strong>{title}</strong>
        <p>{detail}</p>
      </div>
    </div>
  );
}

function LoginScreen() {
  const nextPath = useMemo(
    () => new URLSearchParams(window.location.search).get("next") || "/dashboard",
    []
  );
  const [form, setForm] = useState({ username: "", password: "" });
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");
  const [showPassword, setShowPassword] = useState(false);

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
        setError(payload.message || "登录失败，请检查账号和密码。");
        return;
      }

      window.location.href = payload.redirect || nextPath;
    } catch {
      setError("网络暂时不可用，请稍后重试。");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <section className="login-scene">
      <div className="login-scene-media">
        <video className="login-scene-video" src={VIDEO_URL} autoPlay muted loop playsInline />
        <div className="login-scene-overlay" />
      </div>

      <div className="login-stage">
        <motion.div className="login-shell" initial="hidden" animate="show" variants={fadeUp}>
          <motion.section className="login-story" variants={fadeUp} custom={0.08}>
            <div className="login-badge">COOKIEPILOT</div>
            <h1>进入同步控制台，查看每天 CookieCloud 是否真的跑成功。</h1>
            <p>
              这里会集中呈现同步成功率、UUID 汇总、站点明细、运行异常和企业微信通知状态，不再依赖弹窗登录。
            </p>

            <div className="login-story-grid">
              <div className="login-story-card">
                <span>能力</span>
                <strong>同步监控</strong>
                <small>按天查看成功、失败和最新同步时间</small>
              </div>
              <div className="login-story-card">
                <span>通知</span>
                <strong>企业微信推送</strong>
                <small>支持首登、增减 CK、同步异常提醒</small>
              </div>
            </div>

            <div className="login-feature-list">
              <LoginFeature title="每日同步概览" detail="快速确认今天有没有同步、有多少次成功、是否出现失败。" />
              <LoginFeature title="站点明细回溯" detail="只展示站点名称、站点域名和同步时间，不暴露 Cookie 明文。" />
              <LoginFeature title="公网安全接入" detail="搭配登录保护和反向代理，适合部署到 NAS 并开放外网使用。" />
            </div>
          </motion.section>

          <motion.section className="login-panel" variants={fadeUp} custom={0.16}>
            <div className="login-panel-head">
              <p className="login-overline">安全登录</p>
              <h2>欢迎回来</h2>
              <p>输入面板账号后进入监控后台。</p>
            </div>

            <motion.form className="login-form" onSubmit={handleSubmit} variants={fadeUp} custom={0.22}>
              <label className="login-field">
                <span>用户名</span>
                <input
                  type="text"
                  placeholder="请输入用户名"
                  value={form.username}
                  autoComplete="username"
                  onChange={(event) => setForm((current) => ({ ...current, username: event.target.value }))}
                  required
                />
              </label>

              <label className="login-field">
                <span>密码</span>
                <div className="login-password-wrap">
                  <input
                    type={showPassword ? "text" : "password"}
                    placeholder="请输入密码"
                    value={form.password}
                    autoComplete="current-password"
                    onChange={(event) => setForm((current) => ({ ...current, password: event.target.value }))}
                    required
                  />
                  <button
                    type="button"
                    className="password-toggle"
                    onClick={() => setShowPassword((value) => !value)}
                    aria-label={showPassword ? "隐藏密码" : "显示密码"}
                  >
                    {showPassword ? "隐藏" : "显示"}
                  </button>
                </div>
              </label>

              {error ? <div className="login-error">{error}</div> : null}

              <button type="submit" className="login-submit" disabled={submitting}>
                {submitting ? "登录中..." : "进入控制台"}
              </button>

              <div className="login-helper">
                登录后可查看同步成功/失败、站点明细、运行日志，并使用企业微信应用接收推送通知。
              </div>
            </motion.form>
          </motion.section>
        </motion.div>
      </div>
    </section>
  );
}

document.documentElement.dataset.loginApp = "ready";

createRoot(document.getElementById("login-root")).render(
  <React.StrictMode>
    <LoginScreen />
  </React.StrictMode>
);
