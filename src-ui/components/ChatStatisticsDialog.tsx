import { ChevronLeft, ChevronRight, FileText, Search, X } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import type { Chat, ChatStatistics } from "../lib/types";
import { api } from "../lib/tauriApi";
import { dateTime, timeShort } from "../lib/format";

type Props = {
  chat: Chat;
  onClose: () => void;
};

const PAGE_SIZE = 10;

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
}

export function ChatStatisticsDialog({ chat, onClose }: Props) {
  const { t } = useTranslation();
  const [stats, setStats] = useState<ChatStatistics | null>(null);
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError("");
    const handle = window.setTimeout(() => {
      api
        .getChatStatistics(chat.id, search.trim() || null, page, PAGE_SIZE)
        .then((next) => {
          if (!cancelled) setStats(next);
        })
        .catch(() => {
          if (!cancelled) setError(t("chatStats.failed"));
        })
        .finally(() => {
          if (!cancelled) setLoading(false);
        });
    }, 180);
    return () => {
      cancelled = true;
      window.clearTimeout(handle);
    };
  }, [chat.id, page, search, t]);

  useEffect(() => {
    setPage(0);
  }, [search]);

  const totalPages = useMemo(() => {
    if (!stats) return 1;
    return Math.max(1, Math.ceil(stats.files_total / PAGE_SIZE));
  }, [stats]);

  return (
    <div
      className="modal-backdrop"
      role="dialog"
      aria-modal="true"
      aria-labelledby="chat-stats-title"
      onClick={onClose}
    >
      <section className="modal chat-stats-dialog" onClick={(event) => event.stopPropagation()}>
        <button
          type="button"
          className="modal-close"
          onClick={onClose}
          title={t("common.close")}
          aria-label={t("common.close")}
        >
          <X size={18} />
        </button>
        <h2 id="chat-stats-title">{t("chatStats.title")}</h2>
        {stats && (
          <div className="chat-stats-summary">
            <div><span>{t("chatStats.createdAt")}</span><strong>{dateTime(stats.created_at)}</strong></div>
            <div><span>{t("chatStats.messages")}</span><strong>{stats.message_count}</strong></div>
            <div><span>{t("chatStats.files")}</span><strong>{stats.file_count}</strong></div>
            <div><span>{t("chatStats.storage")}</span><strong>{formatBytes(stats.storage_bytes)}</strong></div>
          </div>
        )}

        <label className="chat-stats-search">
          <Search size={16} aria-hidden="true" />
          <input
            value={search}
            placeholder={t("chatStats.searchFiles")}
            autoCapitalize="none"
            autoCorrect="off"
            spellCheck={false}
            onChange={(event) => setSearch(event.target.value)}
          />
        </label>

        {error && <div className="error inline">{error}</div>}
        <div className="chat-stats-files">
          {loading && <p className="hint">{t("common.loading")}</p>}
          {!loading && stats?.files.length === 0 && <p className="hint">{t("chatStats.noFiles")}</p>}
          {!loading && stats?.files.map((file) => (
            <div className="chat-stats-file" key={file.attachment_id}>
              <FileText size={18} aria-hidden="true" />
              <div>
                <strong>{file.file_name}</strong>
                <small>{formatBytes(file.local_bytes)} / {formatBytes(file.size_bytes)} · {file.mime_type}</small>
              </div>
              <time>{timeShort(file.created_at)}</time>
            </div>
          ))}
        </div>

        <div className="chat-stats-pagination">
          <button type="button" disabled={page <= 0 || loading} onClick={() => setPage((current) => Math.max(0, current - 1))}>
            <ChevronLeft size={16} aria-hidden="true" />
            {t("common.back")}
          </button>
          <span>{t("chatStats.page", { page: page + 1, total: totalPages })}</span>
          <button type="button" disabled={page + 1 >= totalPages || loading} onClick={() => setPage((current) => current + 1)}>
            {t("common.next")}
            <ChevronRight size={16} aria-hidden="true" />
          </button>
        </div>
      </section>
    </div>
  );
}
