//! Optional file log for field diagnostics (2026-07-16): some devices
//! (Asus Zenfone) churn their logcat main buffer in ~2.5 minutes, so an
//! overnight run can never be read back over adb. When the user flips the
//! Network-page toggle, the same tracing stream that goes to logcat is
//! additionally written to a size-rotated file set the user can pull
//! afterwards. Off by default; the writer is a no-op while disabled.
//!
//! The log never contains plaintext messages, keys or passwords — it is the
//! exact stream already visible in logcat (project logging rules apply).

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, SyncSender, TrySendError};
use std::sync::{Mutex, OnceLock};

/// One file's size cap and how many rotated files are kept. 4 × 12 MiB
/// comfortably covers a full DEBUG night (night #3 produced ~8 MiB of
/// quiet-night Rust lines in 7.7 h) while bounding disk use.
const MAX_BYTES_PER_FILE: u64 = 12 * 1024 * 1024;
const KEEP_FILES: usize = 4;
const FILE_NAME: &str = "veyra.log";
/// Buffered log lines waiting for the writer thread. Sized for bursts (the
/// Android debug filter emits hundreds of lines/s during swarm activity);
/// when the disk cannot keep up, lines are DROPPED and counted instead of
/// ever stalling the emitting thread — the first cut of this feature wrote
/// synchronously under a global mutex on the hot path and froze the whole
/// UI the moment the toggle went on (field report 2026-07-16).
const CHANNEL_CAPACITY: usize = 8192;

static ENABLED: AtomicBool = AtomicBool::new(false);
static STATE: Mutex<Option<LogSink>> = Mutex::new(None);
static SENDER: OnceLock<SyncSender<Vec<u8>>> = OnceLock::new();
static DROPPED_LINES: AtomicU64 = AtomicU64::new(0);

struct LogSink {
    dir: PathBuf,
    file: Option<File>,
    written: u64,
}

impl LogSink {
    fn current_path(&self) -> PathBuf {
        self.dir.join(FILE_NAME)
    }

    fn ensure_file(&mut self) -> std::io::Result<&mut File> {
        if self.file.is_none() {
            std::fs::create_dir_all(&self.dir)?;
            let path = self.current_path();
            let file = OpenOptions::new().create(true).append(true).open(&path)?;
            self.written = file.metadata().map(|meta| meta.len()).unwrap_or(0);
            self.file = Some(file);
        }
        Ok(self.file.as_mut().expect("file just ensured"))
    }

    fn rotate_if_needed(&mut self) -> std::io::Result<()> {
        if self.written < MAX_BYTES_PER_FILE {
            return Ok(());
        }
        self.file = None;
        // veyra.log.(KEEP-1) drops, each lower index shifts up, the live
        // file becomes .1.
        let last = self.dir.join(format!("{FILE_NAME}.{}", KEEP_FILES - 1));
        let _ = std::fs::remove_file(last);
        for index in (1..KEEP_FILES).rev() {
            let from = if index == 1 {
                self.current_path()
            } else {
                self.dir.join(format!("{FILE_NAME}.{}", index - 1))
            };
            let to = self.dir.join(format!("{FILE_NAME}.{index}"));
            if from.exists() {
                let _ = std::fs::rename(&from, &to);
            }
        }
        self.written = 0;
        Ok(())
    }

    fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        self.rotate_if_needed()?;
        let file = self.ensure_file()?;
        file.write_all(buf)?;
        self.written += buf.len() as u64;
        Ok(())
    }
}

/// Points the sink at its directory, applies the persisted toggle and
/// spawns the single writer thread. Called once from setup after the data
/// dir (and the stored setting) is known; the tracing layer itself is
/// installed earlier and no-ops until this runs.
pub fn configure(dir: PathBuf, enabled: bool) {
    if let Ok(mut state) = STATE.lock() {
        *state = Some(LogSink {
            dir,
            file: None,
            written: 0,
        });
    }
    SENDER.get_or_init(|| {
        let (tx, rx) = sync_channel::<Vec<u8>>(CHANNEL_CAPACITY);
        let spawned = std::thread::Builder::new()
            .name("veyra-file-log".to_string())
            .spawn(move || {
                while let Ok(buf) = rx.recv() {
                    let Ok(mut state) = STATE.lock() else {
                        continue;
                    };
                    let Some(sink) = state.as_mut() else {
                        continue;
                    };
                    // A broken disk disables the feature for the session
                    // instead of looping on errors; queued lines drain away.
                    if sink.write_all(&buf).is_err() {
                        ENABLED.store(false, Ordering::Relaxed);
                    }
                }
            });
        if let Err(err) = spawned {
            tracing::warn!(?err, "file log writer thread failed to start");
        }
        tx
    });
    ENABLED.store(enabled, Ordering::Relaxed);
    if enabled {
        tracing::info!(version = crate::version::APP_VERSION, "file log enabled");
    }
}

/// Flips the toggle at runtime (the persisted flag is stored by the caller).
pub fn set_enabled(enabled: bool) {
    let was = ENABLED.swap(enabled, Ordering::Relaxed);
    if enabled && !was {
        // Stamp the session so a pulled file identifies its build even when
        // logcat context is long gone.
        tracing::info!(version = crate::version::APP_VERSION, "file log enabled");
    }
}

/// Current toggle, directory and total bytes across the rotated set.
pub fn status() -> (bool, Option<PathBuf>, u64) {
    let enabled = ENABLED.load(Ordering::Relaxed);
    let Ok(state) = STATE.lock() else {
        return (enabled, None, 0);
    };
    let Some(sink) = state.as_ref() else {
        return (enabled, None, 0);
    };
    let mut total = 0u64;
    for index in 0..KEEP_FILES {
        let path = if index == 0 {
            sink.current_path()
        } else {
            sink.dir.join(format!("{FILE_NAME}.{index}"))
        };
        total += std::fs::metadata(path).map(|meta| meta.len()).unwrap_or(0);
    }
    (enabled, Some(sink.dir.clone()), total)
}

/// The log directory for this platform. On Android the app-scoped external
/// files dir is used when available — `adb pull` can read it without root,
/// which is the whole point of the feature; the private data dir is the
/// fallback. Desktop logs live next to the database.
pub fn log_directory(data_dir: &Path) -> PathBuf {
    #[cfg(target_os = "android")]
    {
        let external = PathBuf::from("/storage/emulated/0/Android/data")
            .join("app.veyra.messenger")
            .join("files")
            .join("logs");
        if std::fs::create_dir_all(&external).is_ok() {
            return external;
        }
    }
    data_dir.join("logs")
}

/// `MakeWriter` for the tracing fmt layer. Every formatted event lands here;
/// while the toggle is off the write is a constant-time no-op.
#[derive(Clone, Copy)]
pub struct FileLogMakeWriter;

pub struct FileLogWriter;

impl std::io::Write for FileLogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // HOT PATH: called for every tracing event from every thread. Only
        // an atomic check and a bounded-queue push are allowed here — disk
        // I/O lives on the writer thread. A full queue drops the line and
        // counts it; the emitting thread never blocks.
        if !ENABLED.load(Ordering::Relaxed) {
            return Ok(buf.len());
        }
        if let Some(sender) = SENDER.get() {
            match sender.try_send(buf.to_vec()) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                    DROPPED_LINES.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for FileLogMakeWriter {
    type Writer = FileLogWriter;

    fn make_writer(&'a self) -> Self::Writer {
        FileLogWriter
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sink_rotates_by_size_and_caps_disk_use() {
        // Rotation core, exercised directly (the channel path is covered by
        // the smoke test below — global state keeps these in one process).
        let dir = tempfile::tempdir().unwrap();
        let mut sink = LogSink {
            dir: dir.path().to_path_buf(),
            file: None,
            written: 0,
        };
        let chunk = vec![b'x'; 1024 * 1024];
        let per_file = (MAX_BYTES_PER_FILE / chunk.len() as u64) as usize;
        for _ in 0..(per_file * 3 + 1) {
            sink.write_all(&chunk).unwrap();
        }
        assert!(dir.path().join(FILE_NAME).exists());
        assert!(dir.path().join(format!("{FILE_NAME}.1")).exists());
        assert!(dir.path().join(format!("{FILE_NAME}.2")).exists());
        let mut total = 0u64;
        for entry in std::fs::read_dir(dir.path()).unwrap() {
            total += entry.unwrap().metadata().unwrap().len();
        }
        assert!(total <= MAX_BYTES_PER_FILE * KEEP_FILES as u64);
    }

    #[test]
    fn writer_thread_persists_lines_and_disabled_writer_is_noop() {
        let dir = tempfile::tempdir().unwrap();
        configure(dir.path().to_path_buf(), false);

        // Disabled: the hot path is a no-op, nothing appears on disk.
        let mut writer = FileLogWriter;
        std::io::Write::write(&mut writer, b"dropped while disabled\n").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert!(!dir.path().join(FILE_NAME).exists());

        set_enabled(true);
        std::io::Write::write(&mut writer, b"hello from the writer thread\n").unwrap();
        // The writer thread persists asynchronously; poll briefly.
        let path = dir.path().join(FILE_NAME);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            if let Ok(contents) = std::fs::read_to_string(&path) {
                if contents.contains("hello from the writer thread") {
                    break;
                }
            }
            assert!(
                std::time::Instant::now() < deadline,
                "writer thread never persisted the line"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        set_enabled(false);
    }
}
