import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { Activity, Pencil, Trash2 } from "lucide-react";
import type { AppStatus, ProxyInput, ProxyTestResult, ProxyView as Proxy } from "../lib/types";
import { api } from "../lib/tauriApi";

type Props = {
  status: AppStatus;
  onRefresh: () => Promise<void>;
};

type FormState = {
  /// Set when editing an existing proxy; absent while adding a new one.
  id?: string;
  label: string;
  kind: "socks5" | "http_connect";
  host: string;
  port: string;
  username: string;
  password: string;
  /// True while editing a proxy that already has a stored password: an empty
  /// field then means "keep it", not "clear it".
  hadPassword: boolean;
};

const EMPTY_FORM: FormState = {
  label: "",
  kind: "socks5",
  host: "",
  port: "1080",
  username: "",
  password: "",
  hadPassword: false,
};

/// A check in progress or its outcome. Rendered inside the row (or the form)
/// that started it, so the answer is always on screen without scrolling.
type CheckState = {
  /// Proxy id, or "form" for the unsaved fields in the add/edit form.
  target: string;
  phase: "running" | "done";
  result?: ProxyTestResult;
  error?: string;
};

export function ProxySettingsView({ status, onRefresh }: Props) {
  const { t } = useTranslation();
  const [proxies, setProxies] = useState<Proxy[]>([]);
  const [form, setForm] = useState<FormState | null>(null);
  const [check, setCheck] = useState<CheckState | null>(null);
  const [formError, setFormError] = useState("");
  const [listError, setListError] = useState("");

  const proxy = status.proxy;

  /// Switching the route rebuilds the whole network layer, which a live call
  /// would not survive — the backend refuses, and saying so plainly beats
  /// showing the raw error.
  function errorMessage(error: unknown): string {
    const code = (error as { code?: unknown } | null)?.code;
    if (code === "already_in_call") return t("proxy.busyCall");
    return error instanceof Error ? error.message : t("proxy.errProtocol");
  }

  async function load() {
    try {
      setProxies(await api.listProxies());
    } catch {
      // The list stays as it was; the profile may just be locking.
    }
  }

  useEffect(() => {
    load();
  }, []);

  /// Turns a check outcome into one plain sentence. Technical codes never
  /// reach the user as-is.
  function checkMessage(state: CheckState): string {
    if (state.phase === "running") return t("proxy.checking");
    if (state.error) return state.error;
    const result = state.result;
    if (!result) return "";
    if (result.ok) {
      return result.latency_ms != null
        ? t("proxy.checkOkPing", { ms: result.latency_ms })
        : t("proxy.checkOk");
    }
    switch (result.error_code) {
      case "proxy_unreachable":
        return t("proxy.errUnreachable");
      case "proxy_auth_failed":
        return t("proxy.errAuth");
      case "proxy_connect_denied":
        return t("proxy.errDenied");
      case "proxy_timeout":
        return t("proxy.errTimeout");
      case "target_tls_failed":
        return t("proxy.errTargetTls");
      case "no_test_target":
        return t("proxy.errNoTarget");
      default:
        return t("proxy.errProtocol");
    }
  }

  /// The check runs on the backend worker thread and only this row shows
  /// progress — the rest of the page stays usable while it waits out the
  /// network timeout.
  async function runCheck(target: string, proxyId: string | null, input: ProxyInput | null) {
    setCheck({ target, phase: "running" });
    try {
      const result = await api.testProxy(proxyId, input);
      setCheck({ target, phase: "done", result });
    } catch (error) {
      setCheck({ target, phase: "done", error: errorMessage(error) });
    }
    await load();
    // Checking the live proxy moves its health, so pull the app status too —
    // otherwise the header icon would keep showing the pre-check state until
    // the next poll.
    await onRefresh();
  }

  /// Switching on (or switching between proxies) always checks first: an
  /// unreachable proxy must never become the live route.
  async function activate(target: Proxy) {
    setListError("");
    setCheck({ target: target.id, phase: "running" });
    try {
      const activation = await api.enableProxy(target.id);
      setCheck({ target: target.id, phase: "done", result: activation.test });
    } catch (error) {
      setCheck({
        target: target.id,
        phase: "done",
        error: errorMessage(error),
      });
    }
    await load();
    await onRefresh();
  }

  async function turnOff() {
    setListError("");
    try {
      await api.disableProxy();
      setCheck(null);
    } catch (error) {
      setListError(errorMessage(error));
    }
    await onRefresh();
  }

  /// One proxy at a time — switching one on switches the previous one off.
  /// Chained proxies are out of scope.
  async function toggleRow(item: Proxy, next: boolean) {
    if (next) {
      await activate(item);
    } else {
      await turnOff();
    }
  }

  function formToInput(state: FormState): ProxyInput {
    return {
      label: state.label.trim() || state.host.trim(),
      kind: state.kind,
      host: state.host.trim(),
      port: Number(state.port),
      username: state.username.trim() || null,
      // Editing with an empty field keeps the stored secret; an explicit
      // "clear" is the empty string on a proxy that had one.
      password: state.hadPassword && state.password === "" ? null : state.password,
    };
  }

  function formValid(state: FormState): boolean {
    const port = Number(state.port);
    return state.host.trim().length > 0 && Number.isInteger(port) && port > 0 && port < 65536;
  }

  /// Proxies usually arrive as one line — `socks5://user:pass@host:1080`.
  /// Pasting it into the address field fills the whole form.
  async function tryParsePastedLine(text: string) {
    if (!text.includes("://") && !text.includes("@") && !/:\d+$/.test(text.trim())) return;
    try {
      const parsed = await api.parseProxyLine(text);
      setForm((current) =>
        current
          ? {
              ...current,
              label: current.label || parsed.label,
              kind: parsed.kind,
              host: parsed.host,
              port: String(parsed.port),
              username: parsed.username ?? "",
              password: parsed.password ?? current.password,
            }
          : current,
      );
    } catch {
      // Not a proxy line after all — leave the typed text alone.
    }
  }

  async function submitForm() {
    if (!form || !formValid(form)) return;
    setFormError("");
    try {
      const input = formToInput(form);
      setProxies(form.id ? await api.updateProxy(form.id, input) : await api.addProxy(input));
      setForm(null);
      setCheck(null);
      await onRefresh();
    } catch (error) {
      setFormError(error instanceof Error ? error.message : t("proxy.invalidSettings"));
    }
  }

  async function remove(target: Proxy) {
    setListError("");
    try {
      setProxies(await api.removeProxy(target.id));
      if (check?.target === target.id) setCheck(null);
      await onRefresh();
    } catch (error) {
      setListError(errorMessage(error));
    }
  }

  const checking = check?.phase === "running";

  return (
    <section className="settings-section proxy-section">
      <h2>{t("proxy.title")}</h2>
      <p className="hint">{t("proxy.hint")}</p>

      <p className="hint">{t("proxy.failClosedHint")}</p>
      {proxy.enabled && <p className="hint">{t("proxy.callsDisabledHint")}</p>}
      {listError && <p className="error">{listError}</p>}

      <div className="proxy-list">
        {proxies.map((item) => {
          const isActive = proxy.enabled && proxy.active_id === item.id;
          const rowCheck = check?.target === item.id ? check : null;
          return (
            <div className={`proxy-row${isActive ? " active" : ""}`} key={item.id}>
              <div className="proxy-row-head">
                <span className="proxy-row-text">
                  <strong>{item.label}</strong>
                  <small className="hint">
                    {item.kind === "socks5" ? "SOCKS5" : "HTTP CONNECT"} · {item.host}:{item.port}
                    {item.username ? ` · ${item.username}` : ""}
                    {item.has_password ? ` · ${t("proxy.withPassword")}` : ""}
                  </small>
                  {isActive && (
                    <span className={`proxy-chip ${proxy.health}`}>
                      {proxy.health === "down" ? t("proxy.chipDown") : t("proxy.chipActive")}
                    </span>
                  )}
                </span>
                {/* One switch per proxy: turning one on turns the previous
                    one off — the backend keeps a single active proxy. */}
                <label className="veyra-switch" title={t("proxy.useProxy")}>
                  <input
                    type="checkbox"
                    checked={isActive}
                    onChange={(event) => toggleRow(item, event.target.checked)}
                    disabled={checking}
                    aria-label={t("proxy.useProxy")}
                  />
                  <span className="veyra-switch-track" aria-hidden="true" />
                </label>
              </div>
              {/* The check answer is rendered inside the row that started it,
                  so it is on screen without scrolling anywhere. */}
              {rowCheck && (
                <p className={rowCheck.result?.ok ? "hint proxy-check-ok" : "hint proxy-check-bad"}>
                  {checkMessage(rowCheck)}
                </p>
              )}
              <div className="button-row proxy-row-actions">
                <button
                  type="button"
                  onClick={() => runCheck(item.id, item.id, null)}
                  disabled={checking}
                >
                  <Activity size={14} aria-hidden="true" />
                  {t("proxy.check")}
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setFormError("");
                    setCheck(null);
                    setForm({
                      id: item.id,
                      label: item.label,
                      kind: item.kind,
                      host: item.host,
                      port: String(item.port),
                      username: item.username ?? "",
                      password: "",
                      hadPassword: item.has_password,
                    });
                  }}
                >
                  <Pencil size={14} aria-hidden="true" />
                  {t("proxy.edit")}
                </button>
                <button type="button" className="danger" onClick={() => remove(item)}>
                  <Trash2 size={14} aria-hidden="true" />
                  {t("proxy.remove")}
                </button>
              </div>
            </div>
          );
        })}
      </div>

      {form ? (
        <div className="proxy-form">
          <h3>{form.id ? t("proxy.editTitle") : t("proxy.addTitle")}</h3>
          <label>
            {t("proxy.address")}
            <input
              value={form.host}
              onChange={(event) => setForm({ ...form, host: event.target.value })}
              onBlur={(event) => tryParsePastedLine(event.target.value)}
              placeholder={t("proxy.addressPlaceholder")}
              autoComplete="off"
            />
          </label>
          <p className="hint">{t("proxy.addressHint")}</p>
          <label>
            {t("proxy.port")}
            <input
              value={form.port}
              inputMode="numeric"
              onChange={(event) =>
                setForm({ ...form, port: event.target.value.replace(/\D/g, "").slice(0, 5) })
              }
              autoComplete="off"
            />
          </label>
          <label>
            {t("proxy.kind")}
            <select
              value={form.kind}
              onChange={(event) =>
                setForm({ ...form, kind: event.target.value as FormState["kind"] })
              }
            >
              <option value="socks5">SOCKS5</option>
              <option value="http_connect">HTTP CONNECT</option>
            </select>
          </label>
          <label>
            {t("proxy.label")}
            <input
              value={form.label}
              onChange={(event) => setForm({ ...form, label: event.target.value })}
              placeholder={t("proxy.labelPlaceholder")}
              autoComplete="off"
            />
          </label>
          <label>
            {t("proxy.username")}
            <input
              value={form.username}
              onChange={(event) => setForm({ ...form, username: event.target.value })}
              autoComplete="off"
            />
          </label>
          <label>
            {t("proxy.password")}
            <input
              value={form.password}
              onChange={(event) => setForm({ ...form, password: event.target.value })}
              placeholder={form.hadPassword ? t("proxy.passwordKeep") : ""}
              autoComplete="off"
            />
          </label>
          {form.hadPassword && <p className="hint">{t("proxy.passwordKeepHint")}</p>}
          {check?.target === "form" && (
            <p className={check.result?.ok ? "hint proxy-check-ok" : "hint proxy-check-bad"}>
              {checkMessage(check)}
            </p>
          )}
          {formError && <p className="error">{formError}</p>}
          <div className="button-row">
            <button type="button" onClick={submitForm} disabled={!formValid(form)}>
              {t("common.save")}
            </button>
            <button
              type="button"
              onClick={() => runCheck("form", null, formToInput(form))}
              disabled={!formValid(form) || checking}
            >
              <Activity size={14} aria-hidden="true" />
              {t("proxy.check")}
            </button>
            <button type="button" onClick={() => setForm(null)}>
              {t("common.cancel")}
            </button>
          </div>
        </div>
      ) : (
        <div className="proxy-add-row">
          <button
            type="button"
            className="primary"
            onClick={() => {
              setFormError("");
              setCheck(null);
              setForm({ ...EMPTY_FORM });
            }}
          >
            {t("proxy.add")}
          </button>
        </div>
      )}
    </section>
  );
}
