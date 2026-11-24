import { Component, ReactNode } from "react";

type Props = { children: ReactNode };
type State = { error: Error | null; info: string };

// Catches React render errors anywhere below in the tree. Without this, any
// uncaught render error unmounts the entire app and the user sees a blank
// white page with no clue what went wrong. With this boundary the actual
// error message + component stack are shown, the user can either continue
// (resetting the boundary) or reload the window.
export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null, info: "" };

  static getDerivedStateFromError(error: Error): State {
    return { error, info: "" };
  }

  componentDidCatch(error: Error, info: { componentStack?: string | null }) {
    // eslint-disable-next-line no-console
    console.error("[ErrorBoundary] render crash", error, info);
    this.setState({ error, info: info.componentStack ?? "" });
  }

  private reset = () => this.setState({ error: null, info: "" });
  private reload = () => window.location.reload();

  render() {
    const { error, info } = this.state;
    if (!error) return this.props.children;
    return (
      <div
        style={{
          padding: 24,
          fontFamily: "system-ui, sans-serif",
          color: "#2B3035",
          background: "#fff",
          minHeight: "100vh",
          boxSizing: "border-box",
          overflow: "auto",
        }}
      >
        <h1 style={{ marginTop: 0, color: "#05684B" }}>Veyra: render error</h1>
        <p style={{ marginBottom: 16 }}>
          A component crashed. The chat data on disk is unaffected. You can try
          to continue (some state may be stale) or reload the window.
        </p>
        <div style={{ display: "flex", gap: 8, marginBottom: 24 }}>
          <button
            type="button"
            onClick={this.reset}
            style={{
              padding: "8px 16px",
              border: "1px solid #08A95F",
              background: "#08A95F",
              color: "#fff",
              borderRadius: 6,
              cursor: "pointer",
            }}
          >
            Continue
          </button>
          <button
            type="button"
            onClick={this.reload}
            style={{
              padding: "8px 16px",
              border: "1px solid #2B3035",
              background: "#fff",
              color: "#2B3035",
              borderRadius: 6,
              cursor: "pointer",
            }}
          >
            Reload window
          </button>
        </div>
        <h2 style={{ fontSize: 16, marginBottom: 4 }}>{error.name}: {error.message}</h2>
        <pre
          style={{
            fontSize: 12,
            background: "#f5f7f6",
            padding: 12,
            borderRadius: 6,
            border: "1px solid #d8e0dc",
            whiteSpace: "pre-wrap",
            wordBreak: "break-word",
            overflowX: "auto",
          }}
        >
{error.stack || "(no stack available)"}
        </pre>
        {info && (
          <>
            <h3 style={{ fontSize: 14, marginBottom: 4 }}>Component stack</h3>
            <pre
              style={{
                fontSize: 12,
                background: "#f5f7f6",
                padding: 12,
                borderRadius: 6,
                border: "1px solid #d8e0dc",
                whiteSpace: "pre-wrap",
                wordBreak: "break-word",
                overflowX: "auto",
              }}
            >
{info}
            </pre>
          </>
        )}
      </div>
    );
  }
}
