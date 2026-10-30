//! Companion supervisor: starts the sidecar, health-checks it, restarts it with exponential backoff,
//! stops it cleanly. The state machine is generic over `Launcher`/`Proc` so it is unit-tested without
//! spawning anything; `RealLauncher` is the process and TCP/HTTP implementation.
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

pub const BACKOFF_BASE_MS: u64 = 1_000;
pub const BACKOFF_CAP_MS: u64 = 30_000;
/// A run at least this long counts as stable and resets the backoff.
pub const STABLE_MS: u64 = 60_000;
/// A fresh process may fail health checks this long before they count.
pub const STARTUP_GRACE_MS: u64 = 20_000;
/// Consecutive failed health checks (after grace) before the process is killed and restarted.
pub const MAX_HEALTH_FAILS: u32 = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    Starting,
    Running,
    /// Waiting to restart: attempt number (1-based) and the delay chosen.
    Restarting { attempt: u32, delay_ms: u64 },
    Stopped,
}

impl Status {
    pub fn label(&self) -> String {
        match self {
            Status::Starting => "Starting".into(),
            Status::Running => "Running".into(),
            Status::Restarting { attempt, .. } => format!("Restarting (attempt {attempt})"),
            Status::Stopped => "Stopped".into(),
        }
    }
}

#[derive(Debug, Default)]
pub struct Backoff {
    attempts: u32,
}
impl Backoff {
    pub fn next_delay(&mut self) -> u64 {
        let shift = self.attempts.min(20);
        self.attempts += 1;
        (BACKOFF_BASE_MS << shift).min(BACKOFF_CAP_MS)
    }
    pub fn reset(&mut self) {
        self.attempts = 0;
    }
    pub fn attempts(&self) -> u32 {
        self.attempts
    }
}

pub trait Proc {
    /// Some(exit code) once the process has exited (-1 if killed by a signal).
    fn try_wait(&mut self) -> Option<i32>;
    /// Ask politely, wait briefly, then force.
    fn terminate(&mut self);
}

pub trait Launcher {
    type P: Proc;
    fn spawn(&mut self) -> std::io::Result<Self::P>;
    fn healthy(&mut self) -> bool;
}

pub struct Supervisor<L: Launcher> {
    launcher: L,
    proc: Option<L::P>,
    status: Status,
    backoff: Backoff,
    started_at: u64,
    next_attempt_at: u64,
    health_fails: u32,
    stopped: bool,
    grace_ms: u64,
}

impl<L: Launcher> Supervisor<L> {
    pub fn new(launcher: L) -> Self {
        Supervisor {
            launcher,
            proc: None,
            status: Status::Starting,
            backoff: Backoff::default(),
            started_at: 0,
            next_attempt_at: 0,
            health_fails: 0,
            stopped: false,
            grace_ms: STARTUP_GRACE_MS,
        }
    }

    /// A model load can take far longer than a Python sidecar start; widen the grace for it.
    pub fn with_grace(mut self, ms: u64) -> Self {
        self.grace_ms = ms;
        self
    }

    pub fn status(&self) -> &Status {
        &self.status
    }

    fn schedule_restart(&mut self, now: u64) {
        let delay = self.backoff.next_delay();
        self.next_attempt_at = now + delay;
        self.status = Status::Restarting { attempt: self.backoff.attempts(), delay_ms: delay };
    }

    /// Advance the state machine. `now` is a monotonic millisecond clock.
    pub fn tick(&mut self, now: u64) -> Status {
        if self.stopped {
            return Status::Stopped;
        }
        if let Some(p) = self.proc.as_mut() {
            if p.try_wait().is_some() {
                self.proc = None;
                if now.saturating_sub(self.started_at) >= STABLE_MS {
                    self.backoff.reset();
                }
                self.schedule_restart(now);
                return self.status.clone();
            }
            let age = now.saturating_sub(self.started_at);
            if self.launcher.healthy() {
                self.health_fails = 0;
                self.status = Status::Running;
                if age >= STABLE_MS {
                    self.backoff.reset();
                }
            } else if age >= self.grace_ms || self.status == Status::Running {
                self.health_fails += 1;
                if self.health_fails >= MAX_HEALTH_FAILS {
                    if let Some(mut p) = self.proc.take() {
                        p.terminate();
                    }
                    self.schedule_restart(now);
                }
            }
            return self.status.clone();
        }
        if now >= self.next_attempt_at {
            match self.launcher.spawn() {
                Ok(p) => {
                    self.proc = Some(p);
                    self.started_at = now;
                    self.health_fails = 0;
                    self.status = Status::Starting;
                }
                Err(_) => self.schedule_restart(now),
            }
        }
        self.status.clone()
    }

    /// Clean stop: terminate the child, never restart.
    pub fn stop(&mut self) {
        self.stopped = true;
        if let Some(mut p) = self.proc.take() {
            p.terminate();
        }
        self.status = Status::Stopped;
    }
}

// ---- real implementation ----

pub struct RealProc(Child);

impl Proc for RealProc {
    fn try_wait(&mut self) -> Option<i32> {
        self.0.try_wait().ok().flatten().map(|s| s.code().unwrap_or(-1))
    }
    fn terminate(&mut self) {
        // The child leads its own process group (see spawn): a PyInstaller onefile binary is a bootloader plus a
        // Python child, and signalling only the parent orphans the child with the port still bound.
        #[cfg(unix)]
        unsafe {
            libc::kill(-(self.0.id() as i32), libc::SIGTERM);
        }
        for _ in 0..50 {
            if self.0.try_wait().ok().flatten().is_some() {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        #[cfg(unix)]
        unsafe {
            libc::kill(-(self.0.id() as i32), libc::SIGKILL);
        }
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

pub struct RealLauncher {
    pub binary: PathBuf,
    pub port: u16,
    /// Where the companion forwards chat turns (the llama-server child), if any.
    pub upstream_url: Option<String>,
    /// llama-server's API key, passed to the companion child through its environment (never argv).
    pub upstream_key: Option<String>,
}

/// Status code of `GET <path>` on a loopback port, or None if nothing answers HTTP.
pub fn http_status(port: u16, path: &str) -> Option<u16> {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).ok()?;
    let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = s.set_write_timeout(Some(Duration::from_secs(2)));
    s.write_all(format!("GET {path} HTTP/1.0\r\nHost: 127.0.0.1:{port}\r\n\r\n").as_bytes()).ok()?;
    let mut buf = [0u8; 12];
    s.read_exact(&mut buf).ok()?;
    if !buf.starts_with(b"HTTP/") {
        return None;
    }
    std::str::from_utf8(&buf[9..12]).ok()?.parse().ok()
}

/// A free high loopback port, found by binding port 0. There is a small window before the child binds it.
pub fn free_port() -> std::io::Result<u16> {
    Ok(std::net::TcpListener::bind("127.0.0.1:0")?.local_addr()?.port())
}

/// Second child: llama-server on loopback, with a model whose sha256 has already been verified by the caller.
pub struct LlamaLauncher {
    pub binary: PathBuf,
    pub model: PathBuf,
    pub port: u16,
    /// Passed as --sleep-idle-seconds: llama-server unloads the model after this much idleness.
    pub idle_seconds: u32,
    /// "vulkan" or "cpu" for a packaged install; None when the binary came from elsewhere.
    pub variant: Option<String>,
    /// The 0600 key file llama-server reads (--api-key-file). None only where no key could be made.
    pub key_file: Option<PathBuf>,
    /// The CPU build to switch to if the Vulkan one fails (packaged install only).
    pub cpu_fallback: Option<PathBuf>,
}

impl LlamaLauncher {
    /// Refuses to build unless the file matches the manifest entry's size and sha256.
    pub fn new(binary: PathBuf, model: PathBuf, entry: &crate::models::Model, port: u16) -> Result<Self, String> {
        if !crate::models::verified(entry, &model) {
            return Err(format!("{}: file missing or sha256 does not match the manifest", entry.id));
        }
        Ok(LlamaLauncher { binary, model, port, idle_seconds: crate::firstrun::DEFAULT_IDLE_SECONDS, variant: None, key_file: None, cpu_fallback: None })
    }
    /// A launcher for a file that is not checked against the manifest: a model the person chose from the files already on this computer (the picker has
    /// checked it is a GGUF file), or an approved model whose file is not there yet (the model service then idles quietly, see userunit ConditionPathExists).
    pub fn unchecked(binary: PathBuf, model: PathBuf, port: u16) -> Self {
        LlamaLauncher { binary, model, port, idle_seconds: crate::firstrun::DEFAULT_IDLE_SECONDS, variant: None, key_file: None, cpu_fallback: None }
    }
    pub fn args(&self) -> Vec<String> {
        let mut a: Vec<String> = vec![
            "--host".into(), "127.0.0.1".into(), "--port".into(), self.port.to_string(),
            "--models-max".into(), "1".into(), "--sleep-idle-seconds".into(), self.idle_seconds.to_string(),
            "--no-webui".into(), "--cors-origins".into(), "localhost".into(), "--no-cors-credentials".into(),
        ];
        // The key goes in as a file path, never as the key itself.
        if let Some(k) = &self.key_file {
            a.push("--api-key-file".into());
            a.push(k.to_string_lossy().into_owned());
        }
        a.push("-m".into());
        a.push(self.model.to_string_lossy().into_owned());
        a
    }
}

impl Launcher for LlamaLauncher {
    type P = RealProc;
    fn spawn(&mut self) -> std::io::Result<RealProc> {
        let mut cmd = Command::new(&self.binary);
        #[cfg(unix)]
        std::os::unix::process::CommandExt::process_group(&mut cmd, 0);
        cmd.args(self.args()).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
        cmd.spawn().map(RealProc)
    }
    /// llama-server answers 503 on /health while loading and 200 when ready.
    fn healthy(&mut self) -> bool {
        http_status(self.port, "/health") == Some(200)
    }
}

impl Launcher for RealLauncher {
    type P = RealProc;
    fn spawn(&mut self) -> std::io::Result<RealProc> {
        // The companion is told loopback and a port; the frozen binary forces loopback itself as well.
        // No pair key is passed here: it stays a file the companion manages, never argv or env.
        let mut cmd = Command::new(&self.binary);
        #[cfg(unix)]
        std::os::unix::process::CommandExt::process_group(&mut cmd, 0);
        if let Some(u) = &self.upstream_url {
            cmd.env("ARROWBRIDGE_UPSTREAM_URL", u);
            // The companion refuses to forward without a model name; a single-model llama-server ignores it.
            cmd.env("ARROWBRIDGE_UPSTREAM_MODEL", "local");
        }
        if let Some(k) = &self.upstream_key {
            cmd.env("ARROWBRIDGE_UPSTREAM_KEY", k);
        }
        cmd.env("ARROWBRIDGE_BIND", "127.0.0.1")
            .env("ARROWBRIDGE_PORT", self.port.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        cmd.spawn().map(RealProc)
    }
    /// Healthy = the loopback port answers an HTTP request with any status line. (Unpaired callers get 404 on
    /// /health by design, so the status code says nothing; only "it speaks HTTP" is measured.)
    fn healthy(&mut self) -> bool {
        http_status(self.port, "/health").is_some()
    }
}

/// Find the sidecar: beside the app executable (bundled, no triple), else beside it with the triple suffix, else
/// `ARROWMEM_COMPANION_BIN`.
pub fn locate_companion() -> Option<PathBuf> {
    locate_sidecar("ARROWMEM_COMPANION_BIN", "arrowbridge-companion")
}

/// Which llama-server build runs: the packaged variants are chosen by device presence, anything else is unknown.
pub fn locate_llama() -> Option<(PathBuf, Option<&'static str>)> {
    let exe_dir = std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.to_path_buf()));
    resolve_llama(
        std::env::var("ARROWMEM_LLAMA_BIN").ok(),
        exe_dir.as_deref(),
        Path::new(SYSTEM_SIDECAR_DIR),
        vulkan_present(Path::new("/dev/dri"), &VULKAN_LOADER_DIRS),
    )
}

pub const VULKAN_LOADER_DIRS: [&str; 4] = ["/usr/lib", "/usr/lib64", "/usr/lib/x86_64-linux-gnu", "/usr/lib/aarch64-linux-gnu"];

/// Cheap, no process spawned: a render node under `dri` and the Vulkan loader library in one of `lib_dirs`.
pub fn vulkan_present(dri: &Path, lib_dirs: &[&str]) -> bool {
    let node = std::fs::read_dir(dri)
        .map(|rd| rd.flatten().any(|e| e.file_name().to_string_lossy().starts_with("renderD")))
        .unwrap_or(false);
    node && lib_dirs.iter().any(|d| Path::new(d).join("libvulkan.so.1").exists())
}

/// env override, then a plain `llama-server` beside the executable (variant unknown); else the packaged builds
/// `llama-server-vulkan` / `llama-server-cpu` in the system dir: vulkan when a device is present and its build is
/// installed, otherwise cpu. The second item is the variant that will run, for the status window.
pub fn resolve_llama(env_val: Option<String>, exe_dir: Option<&Path>, sys_dir: &Path, vulkan: bool) -> Option<(PathBuf, Option<&'static str>)> {
    if let Some(p) = resolve_sidecar(env_val, "llama-server", exe_dir, &sys_dir.join("none")) {
        return Some((p, None));
    }
    let (v, c) = (sys_dir.join("llama-server-vulkan"), sys_dir.join("llama-server-cpu"));
    if vulkan && v.exists() {
        Some((v, Some("vulkan")))
    } else if c.exists() {
        Some((c, Some("cpu")))
    } else {
        None
    }
}

/// Where the Arch package puts both sidecars (llama-server with its shared libraries beside it).
pub const SYSTEM_SIDECAR_DIR: &str = "/usr/lib/arrowmem";

fn locate_sidecar(env: &str, name: &str) -> Option<PathBuf> {
    let exe_dir = std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.to_path_buf()));
    resolve_sidecar(std::env::var(env).ok(), name, exe_dir.as_deref(), Path::new(SYSTEM_SIDECAR_DIR))
}

/// Order: the env override; beside the executable (AppImage and dev: `name`, then `name-<triple>`); then the
/// system dir the package installs into.
pub fn resolve_sidecar(env_val: Option<String>, name: &str, exe_dir: Option<&Path>, sys_dir: &Path) -> Option<PathBuf> {
    if let Some(p) = env_val {
        return Some(PathBuf::from(p));
    }
    if let Some(dir) = exe_dir {
        let plain = dir.join(name);
        if plain.exists() {
            return Some(plain);
        }
        let found = std::fs::read_dir(dir).ok().and_then(|rd| {
            rd.flatten().map(|e| e.path()).find(|p| {
                p.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with(&format!("{name}-")))
            })
        });
        if found.is_some() {
            return found;
        }
    }
    let packaged = sys_dir.join(name);
    packaged.exists().then_some(packaged)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    #[derive(Default)]
    struct World {
        spawns: u32,
        terminated: u32,
        alive: bool,
        healthy: bool,
        spawn_fails: bool,
    }
    struct FakeProc(Rc<RefCell<World>>);
    impl Proc for FakeProc {
        fn try_wait(&mut self) -> Option<i32> {
            if self.0.borrow().alive { None } else { Some(1) }
        }
        fn terminate(&mut self) {
            let mut w = self.0.borrow_mut();
            w.alive = false;
            w.terminated += 1;
        }
    }
    struct FakeLauncher(Rc<RefCell<World>>);
    impl Launcher for FakeLauncher {
        type P = FakeProc;
        fn spawn(&mut self) -> std::io::Result<FakeProc> {
            let mut w = self.0.borrow_mut();
            if w.spawn_fails {
                return Err(std::io::Error::other("no binary"));
            }
            w.spawns += 1;
            w.alive = true;
            Ok(FakeProc(self.0.clone()))
        }
        fn healthy(&mut self) -> bool {
            self.0.borrow().healthy
        }
    }
    fn setup() -> (Supervisor<FakeLauncher>, Rc<RefCell<World>>) {
        let w = Rc::new(RefCell::new(World { healthy: true, ..Default::default() }));
        (Supervisor::new(FakeLauncher(w.clone())), w)
    }

    #[test]
    fn backoff_doubles_then_caps() {
        let mut b = Backoff::default();
        let d: Vec<u64> = (0..8).map(|_| b.next_delay()).collect();
        assert_eq!(d, vec![1000, 2000, 4000, 8000, 16000, 30000, 30000, 30000]);
        b.reset();
        assert_eq!(b.next_delay(), 1000);
    }

    #[test]
    fn starts_then_reports_running() {
        let (mut s, w) = setup();
        assert_eq!(s.tick(0), Status::Starting);
        assert_eq!(w.borrow().spawns, 1);
        assert_eq!(s.tick(500), Status::Running);
    }

    #[test]
    fn crash_restarts_after_growing_delays() {
        let (mut s, w) = setup();
        s.tick(0);
        w.borrow_mut().alive = false; // crash 1
        assert_eq!(s.tick(100), Status::Restarting { attempt: 1, delay_ms: 1000 });
        s.tick(1099);
        assert_eq!(w.borrow().spawns, 1, "must not respawn before the delay");
        s.tick(1100);
        assert_eq!(w.borrow().spawns, 2);
        w.borrow_mut().alive = false; // crash 2, quickly
        assert_eq!(s.tick(1200), Status::Restarting { attempt: 2, delay_ms: 2000 });
        s.tick(3200);
        assert_eq!(w.borrow().spawns, 3);
    }

    #[test]
    fn stable_run_resets_backoff() {
        let (mut s, w) = setup();
        s.tick(0);
        w.borrow_mut().alive = false;
        s.tick(10); // attempt 1
        s.tick(1010); // respawn at 1010
        s.tick(1010 + STABLE_MS); // healthy and stable
        w.borrow_mut().alive = false;
        assert_eq!(
            s.tick(1010 + STABLE_MS + 1),
            Status::Restarting { attempt: 1, delay_ms: 1000 }
        );
    }

    #[test]
    fn unhealthy_after_grace_is_killed_and_restarted() {
        let (mut s, w) = setup();
        s.tick(0);
        w.borrow_mut().healthy = false;
        // inside grace: never counted
        for t in [1000, 5000, 19_000] {
            assert_eq!(s.tick(t), Status::Starting);
        }
        assert_eq!(w.borrow().terminated, 0);
        s.tick(20_000);
        s.tick(21_000);
        let st = s.tick(22_000); // third failure
        assert_eq!(w.borrow().terminated, 1);
        assert!(matches!(st, Status::Restarting { attempt: 1, .. }));
    }

    #[test]
    fn spawn_failure_backs_off_and_retries() {
        let (mut s, w) = setup();
        w.borrow_mut().spawn_fails = true;
        assert!(matches!(s.tick(0), Status::Restarting { attempt: 1, delay_ms: 1000 }));
        assert!(matches!(s.tick(1000), Status::Restarting { attempt: 2, delay_ms: 2000 }));
        w.borrow_mut().spawn_fails = false;
        s.tick(3000);
        assert_eq!(w.borrow().spawns, 1);
    }

    #[test]
    fn stop_terminates_and_never_restarts() {
        let (mut s, w) = setup();
        s.tick(0);
        s.stop();
        assert_eq!(w.borrow().terminated, 1);
        assert_eq!(*s.status(), Status::Stopped);
        assert_eq!(s.tick(1_000_000), Status::Stopped);
        assert_eq!(w.borrow().spawns, 1);
    }

    #[test]
    fn wider_grace_defers_health_kill() {
        let w = Rc::new(RefCell::new(World { healthy: false, ..Default::default() }));
        let mut s = Supervisor::new(FakeLauncher(w.clone())).with_grace(100_000);
        s.tick(0);
        for t in [20_000, 30_000, 40_000, 90_000] {
            s.tick(t);
        }
        assert_eq!(w.borrow().terminated, 0, "still loading inside the widened grace");
        s.tick(100_000);
        s.tick(101_000);
        s.tick(102_000);
        assert_eq!(w.borrow().terminated, 1);
    }

    #[test]
    fn llama_launcher_binds_loopback_and_refuses_unverified_model() {
        let dir = std::env::temp_dir().join(format!("arrowmem-ll-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("m.gguf");
        std::fs::write(&f, b"hello").unwrap();
        let mut e = crate::models::load_manifest().models[0].clone();
        e.size_bytes = 5;
        e.sha256 = "0".repeat(64);
        assert!(LlamaLauncher::new("x".into(), f.clone(), &e, 1).is_err(), "wrong hash must refuse");
        e.sha256 = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824".into(); // sha256("hello")
        let l = LlamaLauncher::new("x".into(), f, &e, 4321).unwrap();
        let a = l.args();
        let i = a.iter().position(|x| x == "--host").unwrap();
        assert_eq!(a[i + 1], "127.0.0.1");
        assert!(!a.iter().any(|x| x == "0.0.0.0"));
        assert!(a.windows(2).any(|w| w == ["--port", "4321"]));
        assert!(a.windows(2).any(|w| w == ["--sleep-idle-seconds", "600"]), "default idle unload");
        assert!(!a.iter().any(|x| x == "--api-key-file"), "no key file given, none passed");
        let mut lk = LlamaLauncher { binary: PathBuf::new(), model: PathBuf::from("/m/x.gguf"), port: 1, idle_seconds: 600, variant: None, key_file: Some(PathBuf::from("/s/llama-api-key")), cpu_fallback: None };
        let ka = lk.args();
        assert!(ka.windows(2).any(|w| w == ["--api-key-file", "/s/llama-api-key"]) && ka.contains(&"--no-webui".to_string()));
        assert!(!ka.iter().any(|x| x == "--api-key" || x.len() == 64), "the key itself is never in argv");
        lk.key_file = None;
        let mut l2 = l;
        l2.idle_seconds = 90;
        assert!(l2.args().windows(2).any(|w| w == ["--sleep-idle-seconds", "90"]), "value comes from the settings field");
    }

    #[test]
    fn free_port_is_high_and_bindable() {
        let p = free_port().unwrap();
        assert!(p > 1024);
        std::net::TcpListener::bind(("127.0.0.1", p)).unwrap();
    }

    /// Supervisor path with a stub standing in for llama-server (a script that honours --host/--port and answers
    /// /health and /v1/chat/completions). Run: ARROWMEM_STUB_BIN=<script> cargo test -- --ignored stub
    #[test]
    #[ignore]
    fn stub_llama_start_crash_restart_stop() {
        let binary = PathBuf::from(std::env::var("ARROWMEM_STUB_BIN").expect("set ARROWMEM_STUB_BIN"));
        let dir = std::env::temp_dir().join(format!("arrowmem-stub-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("tiny.gguf");
        std::fs::write(&f, b"hello").unwrap();
        let mut e = crate::models::load_manifest().models[0].clone();
        e.size_bytes = 5;
        e.sha256 = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824".into();
        let port = free_port().unwrap();
        let mut s = Supervisor::new(LlamaLauncher::new(binary, f, &e, port).unwrap());
        let t0 = std::time::Instant::now();
        let mut until = |s: &mut Supervisor<LlamaLauncher>, want: &dyn Fn(&Status) -> bool| {
            let end = std::time::Instant::now() + Duration::from_secs(20);
            while std::time::Instant::now() < end {
                if want(&s.tick(t0.elapsed().as_millis() as u64)) {
                    return true;
                }
                std::thread::sleep(Duration::from_millis(300));
            }
            false
        };
        assert!(until(&mut s, &|st| *st == Status::Running), "never Running");
        assert_eq!(http_status(port, "/health"), Some(200));
        let pid = s.proc.as_ref().unwrap().0.id();
        unsafe { libc::kill(-(pid as i32), libc::SIGKILL) };
        assert!(until(&mut s, &|st| matches!(st, Status::Restarting { .. })), "crash not seen");
        assert!(until(&mut s, &|st| *st == Status::Running), "no restart");
        s.stop();
        assert_eq!(http_status(port, "/health"), None, "port still answering after stop");
    }

    /// Real process + real HTTP probe. Ignored by default; run with
    /// ARROWMEM_COMPANION_BIN=<frozen binary> cargo test -- --ignored
    #[test]
    #[ignore]
    fn real_companion_start_crash_restart_stop() {
        let binary = PathBuf::from(std::env::var("ARROWMEM_COMPANION_BIN").expect("set ARROWMEM_COMPANION_BIN"));
        let port = 18792;
        let mut s = Supervisor::new(RealLauncher { binary, port, upstream_url: None, upstream_key: None });
        let t0 = std::time::Instant::now();
        let now = || t0.elapsed().as_millis() as u64;
        let until = |s: &mut Supervisor<RealLauncher>, want: &dyn Fn(&Status) -> bool, secs: u64| {
            let end = std::time::Instant::now() + Duration::from_secs(secs);
            while std::time::Instant::now() < end {
                if want(&s.tick(now())) {
                    return true;
                }
                std::thread::sleep(Duration::from_millis(500));
            }
            false
        };
        assert!(until(&mut s, &|st| *st == Status::Running, 40), "never Running");
        // kill the child behind the supervisor's back
        let pid = s.proc.as_ref().unwrap().0.id();
        unsafe { libc::kill(-(pid as i32), libc::SIGKILL) };
        assert!(until(&mut s, &|st| matches!(st, Status::Restarting { .. }), 10), "crash not seen");
        assert!(until(&mut s, &|st| *st == Status::Running, 40), "no restart to Running");
        assert_ne!(s.proc.as_ref().unwrap().0.id(), pid);
        s.stop();
        assert_eq!(*s.status(), Status::Stopped);
        assert!(!RealLauncher { binary: PathBuf::new(), port, upstream_url: None, upstream_key: None }.healthy(), "port still answering after stop");
    }

    #[test]
    fn companion_child_gets_the_key_in_its_environment_and_never_in_argv() {
        use std::os::unix::fs::PermissionsExt;
        let d = std::env::temp_dir().join(format!("childkey-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let bin = d.join("fakecompanion");
        std::fs::write(&bin, format!("#!/bin/sh\necho \"key=$ARROWBRIDGE_UPSTREAM_KEY\" > {0}/env.out\necho \"args=$@\" >> {0}/env.out\n", d.display())).unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        let key = "cd".repeat(32);
        let mut l = RealLauncher { binary: bin.clone(), port: 1, upstream_url: Some("http://127.0.0.1:1".into()), upstream_key: Some(key.clone()) };
        let mut child = l.spawn().unwrap();
        for _ in 0..50 {
            if d.join("env.out").exists() && std::fs::read_to_string(d.join("env.out")).map(|s| s.contains("args=")).unwrap_or(false) { break; }
            std::thread::sleep(Duration::from_millis(100));
        }
        let out = std::fs::read_to_string(d.join("env.out")).unwrap();
        assert!(out.contains(&format!("key={key}")), "{out}");
        assert!(out.contains("args=\n") || out.trim_end().ends_with("args="), "no argv at all: {out}");
        let _ = child;
        let _ = std::fs::remove_file(d.join("env.out"));
        l.upstream_key = None;
        let _c2 = l.spawn().unwrap();
        for _ in 0..50 {
            if d.join("env.out").exists() { break; }
            std::thread::sleep(Duration::from_millis(100));
        }
        std::thread::sleep(Duration::from_millis(200));
        assert!(std::fs::read_to_string(d.join("env.out")).unwrap().starts_with("key=\n"), "no key given, none set");
    }

    #[test]
    fn llama_variant_follows_the_device_and_what_is_installed() {
        let d = std::env::temp_dir().join(format!("llamavar-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let (exe, sys) = (d.join("bin"), d.join("lib"));
        std::fs::create_dir_all(&exe).unwrap();
        std::fs::create_dir_all(&sys).unwrap();
        assert_eq!(resolve_llama(None, Some(&exe), &sys, true), None);
        std::fs::write(sys.join("llama-server-cpu"), "x").unwrap();
        assert_eq!(resolve_llama(None, Some(&exe), &sys, true), Some((sys.join("llama-server-cpu"), Some("cpu"))), "vulkan build absent: cpu");
        std::fs::write(sys.join("llama-server-vulkan"), "x").unwrap();
        assert_eq!(resolve_llama(None, Some(&exe), &sys, true), Some((sys.join("llama-server-vulkan"), Some("vulkan"))));
        assert_eq!(resolve_llama(None, Some(&exe), &sys, false), Some((sys.join("llama-server-cpu"), Some("cpu"))), "no device: cpu");
        std::fs::write(exe.join("llama-server"), "x").unwrap();
        assert_eq!(resolve_llama(None, Some(&exe), &sys, true), Some((exe.join("llama-server"), None)), "beside the exe: variant unknown");
        assert_eq!(resolve_llama(Some("/e/l".into()), Some(&exe), &sys, true), Some((PathBuf::from("/e/l"), None)));
    }

    #[test]
    fn vulkan_needs_a_render_node_and_the_loader() {
        let d = std::env::temp_dir().join(format!("vkpres-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let (dri, lib) = (d.join("dri"), d.join("lib"));
        std::fs::create_dir_all(&dri).unwrap();
        std::fs::create_dir_all(&lib).unwrap();
        let libs = [lib.to_str().unwrap()];
        assert!(!vulkan_present(&dri, &libs));
        std::fs::write(dri.join("card0"), "").unwrap();
        std::fs::write(lib.join("libvulkan.so.1"), "").unwrap();
        assert!(!vulkan_present(&dri, &libs), "a card node alone is not a render node");
        std::fs::write(dri.join("renderD128"), "").unwrap();
        assert!(vulkan_present(&dri, &libs));
        std::fs::remove_file(lib.join("libvulkan.so.1")).unwrap();
        assert!(!vulkan_present(&dri, &libs), "no loader");
        assert!(!vulkan_present(&d.join("missing"), &libs));
    }

    #[test]
    fn sidecar_resolution_order() {
        let d = std::env::temp_dir().join(format!("sidecar-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let (exe, sys) = (d.join("bin"), d.join("lib"));
        std::fs::create_dir_all(&exe).unwrap();
        std::fs::create_dir_all(&sys).unwrap();
        // nothing anywhere
        assert_eq!(resolve_sidecar(None, "llama-server", Some(&exe), &sys), None);
        // packaged install: only the system dir has it
        std::fs::write(sys.join("llama-server"), "x").unwrap();
        assert_eq!(resolve_sidecar(None, "llama-server", Some(&exe), &sys), Some(sys.join("llama-server")));
        // beside the executable wins over the system dir, plain name before name-<triple>
        std::fs::write(exe.join("llama-server-x86_64-unknown-linux-gnu"), "x").unwrap();
        assert_eq!(resolve_sidecar(None, "llama-server", Some(&exe), &sys), Some(exe.join("llama-server-x86_64-unknown-linux-gnu")));
        std::fs::write(exe.join("llama-server"), "x").unwrap();
        assert_eq!(resolve_sidecar(None, "llama-server", Some(&exe), &sys), Some(exe.join("llama-server")));
        // env wins over everything, even a path that does not exist
        assert_eq!(resolve_sidecar(Some("/e/x".into()), "llama-server", Some(&exe), &sys), Some(PathBuf::from("/e/x")));
        // a different name is not matched by prefix of another
        assert_eq!(resolve_sidecar(None, "arrowbridge-companion", Some(&exe), &sys), None);
    }
}
