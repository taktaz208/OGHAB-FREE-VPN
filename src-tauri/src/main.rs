#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[cfg(target_os = "android")]
mod android_bridge;

use reqwest::Client;
#[cfg(windows)]
use reqwest::Proxy;
use serde::Serialize;
use serde_json::json;
use std::{
    sync::atomic::{AtomicBool, Ordering},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tauri::{AppHandle, Manager, State};
use tokio::{net::TcpStream, sync::Notify, task::JoinHandle, time::sleep};
use url::Url;

#[cfg(windows)]
use include_dir::{include_dir, Dir};
#[cfg(windows)]
use std::{
    env,
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};
#[cfg(windows)]
use winreg::{enums::*, RegKey};

#[cfg(windows)]
static XRAY_DIR: Dir = include_dir!("$CARGO_MANIFEST_DIR/xray64");
const SOURCE_URL: &str =
    "https://raw.githubusercontent.com/iboxz/free-v2ray-collector/main/main/vless.txt";
const EXTRA_SOURCE_URL: &str = "https://raw.githubusercontent.com/NiREvil/vless/main/sub.txt";
const PROBE_TARGET_URL: &str = "https://www.gstatic.com/generate_204";
#[cfg(target_os = "android")]
const ANDROID_PROBE_SOCKS_PORT: u16 = 20808;
const ACTIVE_SOCKS_PORT: u16 = 10808;
const ACTIVE_TUN_INTERFACE: &str = "oghab-tun";
const BROWSER_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36";

#[cfg(target_os = "android")]
fn probe_concurrency() -> usize {
    1
}

#[cfg(not(target_os = "android"))]
fn probe_concurrency() -> usize {
    12
}

struct AppState {
    manager: Mutex<XrayManager>,
    scan: Arc<ScanRuntime>,
}

#[derive(Default)]
struct XrayManager {
    #[cfg(windows)]
    child: Option<Child>,
    #[cfg(windows)]
    config_path: Option<PathBuf>,
    #[cfg(windows)]
    log_path: Option<PathBuf>,
    connected_uri: Option<String>,
    tunnel_mode: bool,
}

struct ScanRuntime {
    state: Mutex<ScanState>,
    control: Arc<ScanControl>,
    task: Mutex<Option<JoinHandle<()>>>,
}

struct ScanControl {
    cancelled: AtomicBool,
    paused: AtomicBool,
    notify: Notify,
}

#[derive(Default, Clone)]
struct ScanState {
    lines: Vec<String>,
    profiles: Vec<ServerProfile>,
    scanned_count: usize,
    working_count: usize,
    total_count: usize,
    source_count: usize,
    is_scanning: bool,
    is_paused: bool,
    error: Option<String>,
}

#[derive(Serialize, Clone)]
struct ServerProfile {
    id: String,
    uri: String,
    label: String,
    host: String,
    port: u16,
    latency_ms: u128,
    network: String,
    security: String,
}

#[derive(Serialize)]
struct VpnStatus {
    connected: bool,
    connected_uri: Option<String>,
    tunnel_mode: bool,
}

#[derive(Serialize)]
struct ScanSnapshot {
    lines: Vec<String>,
    profiles: Vec<ServerProfile>,
    scanned_count: usize,
    working_count: usize,
    total_count: usize,
    source_count: usize,
    is_scanning: bool,
    is_paused: bool,
    error: Option<String>,
}

#[derive(Clone)]
struct ParsedVless {
    uri: String,
    label: String,
    host: String,
    port: u16,
    network: String,
    security: String,
    uuid: String,
    flow: Option<String>,
    encryption: String,
    sni: Option<String>,
    fingerprint: Option<String>,
    public_key: Option<String>,
    short_id: Option<String>,
    host_header: Option<String>,
    path: Option<String>,
    service_name: Option<String>,
    authority: Option<String>,
    mode: Option<String>,
    header_type: Option<String>,
    spider_x: Option<String>,
    alpn: Vec<String>,
}

impl XrayManager {
    fn stop(&mut self) -> Result<(), String> {
        #[cfg(windows)]
        {
            if let Some(mut child) = self.child.take() {
                let _ = child.kill();
                let _ = child.wait();
            }

            if let Some(config_path) = self.config_path.take() {
                let _ = fs::remove_file(config_path);
            }

            if let Some(log_path) = self.log_path.take() {
                let _ = fs::remove_file(log_path);
            }

            self.connected_uri = None;
            self.tunnel_mode = false;
            let _ = set_system_proxy(false, "", "");
            let _ = remove_tun_route();
            Ok(())
        }

        #[cfg(target_os = "android")]
        {
            self.connected_uri = None;
            self.tunnel_mode = false;
            Ok(())
        }
    }

    fn status(&self) -> VpnStatus {
        VpnStatus {
            connected: {
                #[cfg(windows)]
                {
                    self.child.is_some()
                }
                #[cfg(target_os = "android")]
                {
                    self.connected_uri.is_some()
                }
            },
            connected_uri: self.connected_uri.clone(),
            tunnel_mode: self.tunnel_mode,
        }
    }
}

impl ScanControl {
    fn new() -> Self {
        Self {
            cancelled: AtomicBool::new(false),
            paused: AtomicBool::new(false),
            notify: Notify::new(),
        }
    }

    fn reset(&self) {
        self.cancelled.store(false, Ordering::SeqCst);
        self.paused.store(false, Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
        self.paused.store(false, Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    fn pause(&self) {
        self.paused.store(true, Ordering::SeqCst);
    }

    fn resume(&self) {
        self.paused.store(false, Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    fn is_paused(&self) -> bool {
        self.paused.load(Ordering::SeqCst)
    }
}

impl ScanRuntime {
    fn new() -> Self {
        Self {
            state: Mutex::new(ScanState::default()),
            control: Arc::new(ScanControl::new()),
            task: Mutex::new(None),
        }
    }

    fn snapshot(&self) -> ScanSnapshot {
        let state = self.state.lock().ok();
        let snapshot = state.as_ref();
        ScanSnapshot {
            lines: snapshot
                .map(|value| value.lines.clone())
                .unwrap_or_default(),
            profiles: snapshot
                .map(|value| value.profiles.clone())
                .unwrap_or_default(),
            scanned_count: snapshot
                .map(|value| value.scanned_count)
                .unwrap_or_default(),
            working_count: snapshot
                .map(|value| value.working_count)
                .unwrap_or_default(),
            total_count: snapshot.map(|value| value.total_count).unwrap_or_default(),
            source_count: snapshot.map(|value| value.source_count).unwrap_or_default(),
            is_scanning: snapshot.map(|value| value.is_scanning).unwrap_or_default(),
            is_paused: snapshot.map(|value| value.is_paused).unwrap_or_default(),
            error: snapshot.and_then(|value| value.error.clone()),
        }
    }

    fn reset(&self) {
        if let Ok(mut state) = self.state.lock() {
            *state = ScanState::default();
        }
    }

    fn stop_task(&self) {
        self.control.cancel();
        if let Ok(mut task) = self.task.lock() {
            if let Some(handle) = task.take() {
                handle.abort();
            }
        }
    }
}

impl Drop for XrayManager {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

#[tauri::command]
async fn start_scan(
    source_urls: Vec<String>,
    _app_handle: AppHandle,
    state: State<'_, AppState>,
) -> Result<ScanSnapshot, String> {
    start_scan_inner(source_urls, _app_handle, state).await
}

#[tauri::command]
fn pause_scan(state: State<'_, AppState>) -> Result<(), String> {
    state.scan.control.pause();
    if let Ok(mut scan) = state.scan.state.lock() {
        scan.is_paused = true;
    }
    Ok(())
}

#[tauri::command]
fn resume_scan(state: State<'_, AppState>) -> Result<(), String> {
    state.scan.control.resume();
    if let Ok(mut scan) = state.scan.state.lock() {
        scan.is_paused = false;
    }
    Ok(())
}

#[tauri::command]
fn stop_scan(state: State<'_, AppState>) -> Result<(), String> {
    state.scan.stop_task();
    if let Ok(mut scan) = state.scan.state.lock() {
        scan.is_scanning = false;
        scan.is_paused = false;
        scan.error = Some("Scan stopped".to_string());
    }
    Ok(())
}

#[tauri::command]
fn vpn_status(state: State<'_, AppState>) -> Result<VpnStatus, String> {
    #[cfg(target_os = "android")]
    {
        let mut manager = state
            .manager
            .lock()
            .map_err(|_| "VPN state lock poisoned".to_string())?;
        if !android_bridge::call_is_vpn_running().unwrap_or(false) {
            manager.connected_uri = None;
            manager.tunnel_mode = false;
        }
        Ok(manager.status())
    }

    #[cfg(not(target_os = "android"))]
    {
        let manager = state
            .manager
            .lock()
            .map_err(|_| "VPN state lock poisoned".to_string())?;
        Ok(manager.status())
    }
}

#[tauri::command]
fn get_scan_snapshot(state: State<'_, AppState>) -> Result<ScanSnapshot, String> {
    Ok(state.scan.snapshot())
}

#[tauri::command]
async fn connect_profile(
    uri: String,
    tunnel_mode: bool,
    _app_handle: AppHandle,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let parsed = parse_vless_uri(&uri)?;
    #[cfg(target_os = "android")]
    let _ = tunnel_mode;
    #[cfg(target_os = "android")]
    let tunnel_mode = true;

    let config = build_xray_config(
        &parsed,
        ACTIVE_SOCKS_PORT,
        tunnel_mode,
        ACTIVE_TUN_INTERFACE,
    )?;

    #[cfg(windows)]
    {
        let (exe_path, config_path, log_path) = prepare_xray_assets("active", &config)?;
        let child = spawn_xray(&exe_path, &config_path, &log_path)?;

        {
            let mut manager = state
                .manager
                .lock()
                .map_err(|_| "VPN state lock poisoned".to_string())?;
            manager.stop()?;
            manager.child = Some(child);
            manager.config_path = Some(config_path);
            manager.log_path = Some(log_path.clone());
            manager.connected_uri = Some(uri);
            manager.tunnel_mode = tunnel_mode;
        }

        sleep(Duration::from_millis(1400)).await;

        {
            let mut manager = state
                .manager
                .lock()
                .map_err(|_| "VPN state lock poisoned".to_string())?;
            if let Some(child) = manager.child.as_mut() {
                if let Ok(Some(status)) = child.try_wait() {
                    let xray_log = read_optional_file(&log_path);
                    manager.stop()?;
                    return Err(format!(
                        "Xray exited unexpectedly with status {status}. {}",
                        summarize_xray_log(&xray_log)
                    ));
                }
            }
        }

        if tunnel_mode {
            set_tun_route(true).map_err(|error| format!("Failed to enable TUN route: {error}"))?;
            let mut manager = state
                .manager
                .lock()
                .map_err(|_| "VPN state lock poisoned".to_string())?;
            manager.tunnel_mode = true;
        } else {
            set_system_proxy(
                true,
                &format!("socks=127.0.0.1:{ACTIVE_SOCKS_PORT}"),
                "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*",
            )
            .map_err(|error| format!("Failed to enable system proxy: {error}"))?;
        }

        return Ok(());
    }

    #[cfg(target_os = "android")]
    {
        android_bridge::call_connect(&config, tunnel_mode)?;

        let mut running = false;
        for _ in 0..180 {
            if android_bridge::call_is_vpn_running()? {
                running = true;
                break;
            }
            sleep(Duration::from_millis(250)).await;
        }

        if !running {
            return Err(
                "Android VPN permission was not granted or VPN service did not start".to_string(),
            );
        }

        {
            let mut manager = state
                .manager
                .lock()
                .map_err(|_| "VPN state lock poisoned".to_string())?;
            manager.connected_uri = Some(uri);
            manager.tunnel_mode = tunnel_mode;
        }

        return Ok(());
    }
}

#[tauri::command]
fn disconnect_vpn(_app_handle: AppHandle, state: State<'_, AppState>) -> Result<(), String> {
    #[cfg(target_os = "android")]
    {
        android_bridge::call_disconnect()?;
    }

    let mut manager = state
        .manager
        .lock()
        .map_err(|_| "VPN state lock poisoned".to_string())?;
    manager.stop()
}

async fn start_scan_inner(
    source_urls: Vec<String>,
    app_handle: AppHandle,
    state: State<'_, AppState>,
) -> Result<ScanSnapshot, String> {
    state.scan.stop_task();
    state.scan.reset();
    state.scan.control.reset();

    {
        let mut scan = state
            .scan
            .state
            .lock()
            .map_err(|_| "Scan state lock poisoned".to_string())?;
        scan.is_scanning = true;
        scan.is_paused = false;
        scan.error = None;
        scan.lines.clear();
        scan.profiles.clear();
        scan.scanned_count = 0;
        scan.working_count = 0;
        scan.total_count = 0;
        scan.source_count = source_urls.len();
    }

    let scan_runtime = state.scan.clone();
    let merged_sources = merge_source_urls(source_urls);
    let task_scan = scan_runtime.clone();
    let handle = tokio::spawn(async move {
        let result = run_scan_task(merged_sources, task_scan.clone(), app_handle.clone()).await;
        if let Ok(mut scan) = task_scan.state.lock() {
            scan.is_scanning = false;
            scan.is_paused = false;
            if let Err(error) = result {
                scan.error = Some(error);
            }
        }
        if let Ok(mut task) = task_scan.task.lock() {
            *task = None;
        }
    });

    {
        let mut task = state
            .scan
            .task
            .lock()
            .map_err(|_| "Scan task lock poisoned".to_string())?;
        *task = Some(handle);
    }

    Ok(scan_runtime.snapshot())
}

fn merge_source_urls(source_urls: Vec<String>) -> Vec<String> {
    let mut unique = Vec::new();
    let mut sources = if source_urls.is_empty() {
        vec![SOURCE_URL.to_string(), EXTRA_SOURCE_URL.to_string()]
    } else {
        source_urls
    };

    for url in sources.drain(..) {
        let trimmed = url.trim();
        if trimmed.is_empty() {
            continue;
        }

        if !unique.iter().any(|item: &String| item == trimmed) {
            unique.push(trimmed.to_string());
        }
    }

    unique
}

async fn run_scan_task(
    source_urls: Vec<String>,
    scan: Arc<ScanRuntime>,
    app_handle: AppHandle,
) -> Result<(), String> {
    let client = Client::builder()
        .timeout(Duration::from_secs(15))
        .danger_accept_invalid_certs(true)
        .user_agent(BROWSER_USER_AGENT)
        .build()
        .map_err(|error| format!("Failed to build HTTP client: {error}"))?;

    let source_text = fetch_source_text(&client, &source_urls, &scan).await?;
    let all_uris: Vec<String> = source_text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && line.starts_with("vless://"))
        .map(ToOwned::to_owned)
        .collect();

    {
        if let Ok(mut state) = scan.state.lock() {
            state.total_count = all_uris.len();
            state.source_count = source_urls.len();
        }
    }

    push_debug_line(
        &scan,
        format!(
            "Loaded {} VLESS URIs from {} sources. Testing target: {PROBE_TARGET_URL}",
            all_uris.len(),
            source_urls.len()
        ),
    );

    let mut profiles = Vec::new();
    let mut in_flight: tokio::task::JoinSet<Result<Option<ServerProfile>, String>> =
        tokio::task::JoinSet::new();
    let probe_concurrency = probe_concurrency();

    for (index, uri) in all_uris.into_iter().enumerate() {
        wait_if_paused(&scan).await?;
        if scan.control.is_cancelled() {
            break;
        }

        while in_flight.len() >= probe_concurrency {
            drain_one_probe(&mut in_flight, &mut profiles, &scan).await;
            if scan.control.is_cancelled() {
                break;
            }
        }

        if scan.control.is_cancelled() {
            break;
        }

        let scan_clone = scan.clone();
        let app_handle = app_handle.clone();
        in_flight
            .spawn(async move { test_profile(uri, index, scan_clone, app_handle.clone()).await });
    }

    while !in_flight.is_empty() {
        drain_one_probe(&mut in_flight, &mut profiles, &scan).await;
    }

    profiles.sort_by_key(|profile| profile.latency_ms);

    if let Ok(mut state) = scan.state.lock() {
        state.profiles = profiles.clone();
        state.working_count = profiles.len();
        state.is_scanning = false;
        state.is_paused = false;
        state.error = None;
    }

    push_debug_line(
        &scan,
        format!("Scan finished. {} working servers found.", profiles.len()),
    );

    Ok(())
}

async fn fetch_source_text(
    client: &Client,
    source_urls: &[String],
    scan: &Arc<ScanRuntime>,
) -> Result<String, String> {
    let mut collected = String::new();
    let mut any_ok = false;

    for url in source_urls {
        match client.get(url).send().await {
            Ok(response) => match response.error_for_status() {
                Ok(ok_response) => match ok_response.text().await {
                    Ok(text) => {
                        any_ok = true;
                        collected.push_str(&text);
                        collected.push('\n');
                    }
                    Err(error) => {
                        push_debug_line(scan, format!("Failed to read source {url}: {error}"));
                    }
                },
                Err(error) => {
                    push_debug_line(scan, format!("Source request failed for {url}: {error}"));
                }
            },
            Err(error) => {
                push_debug_line(scan, format!("Failed to fetch source {url}: {error}"));
            }
        }
    }

    if !any_ok {
        return Err("Failed to fetch any source list".to_string());
    }

    Ok(collected)
}

async fn drain_one_probe(
    in_flight: &mut tokio::task::JoinSet<Result<Option<ServerProfile>, String>>,
    profiles: &mut Vec<ServerProfile>,
    scan: &Arc<ScanRuntime>,
) {
    if in_flight.is_empty() {
        return;
    }

    match in_flight.join_next().await {
        Some(Ok(Ok(Some(profile)))) => {
            profiles.push(profile.clone());
            if let Ok(mut state) = scan.state.lock() {
                state.profiles = profiles.clone();
                state.working_count = profiles.len();
            }
        }
        Some(Ok(Ok(None))) => {}
        Some(Ok(Err(error))) => push_debug_line(scan, format!("Probe error: {error}")),
        Some(Err(error)) => push_debug_line(scan, format!("Probe task join error: {error}")),
        None => {}
    }
}

async fn wait_if_paused(scan: &Arc<ScanRuntime>) -> Result<(), String> {
    while scan.control.is_paused() && !scan.control.is_cancelled() {
        if let Ok(mut state) = scan.state.lock() {
            state.is_paused = true;
        }
        scan.control.notify.notified().await;
    }

    if scan.control.is_cancelled() {
        return Err("Scan stopped".to_string());
    }

    if let Ok(mut state) = scan.state.lock() {
        state.is_paused = false;
    }

    Ok(())
}

async fn test_profile(
    uri: String,
    index: usize,
    scan: Arc<ScanRuntime>,
    _app_handle: AppHandle,
) -> Result<Option<ServerProfile>, String> {
    let parsed = match parse_vless_uri(&uri) {
        Ok(value) => value,
        Err(error) => {
            note_test_result(
                &scan,
                format!("#{index} skipped: invalid URI ({error})"),
                false,
            );
            return Ok(None);
        }
    };

    #[cfg(target_os = "android")]
    {
        let tcp_latency =
            match tcp_connect_latency(&parsed.host, parsed.port, Duration::from_millis(1500)).await
            {
                Ok(latency) => latency,
                Err(error) => {
                    note_test_result(
                        &scan,
                        format!(
                            "#{} {}:{} skipped: TCP failed ({error})",
                            index, parsed.host, parsed.port
                        ),
                        false,
                    );
                    return Ok(None);
                }
            };

        let config = build_xray_config(
            &parsed,
            ANDROID_PROBE_SOCKS_PORT,
            false,
            ACTIVE_TUN_INTERFACE,
        )?;
        let probe_url = PROBE_TARGET_URL.to_string();
        let delay = tokio::task::spawn_blocking(move || {
            android_bridge::call_measure_delay(&config, &probe_url)
        })
        .await
        .map_err(|error| format!("Android delay probe task failed: {error}"))??;

        if scan.control.is_cancelled() {
            return Ok(None);
        }

        if delay < 0 {
            note_test_result(
                &scan,
                format!(
                    "#{} {}:{} failed: Android delay probe returned {}",
                    index, parsed.host, parsed.port, delay
                ),
                false,
            );
            return Ok(None);
        }

        let profile = ServerProfile {
            id: format!("{}-{}", parsed.host, parsed.port),
            uri: parsed.uri,
            label: parsed.label,
            host: parsed.host,
            port: parsed.port,
            latency_ms: (delay as u128).max(tcp_latency),
            network: parsed.network,
            security: parsed.security,
        };

        note_test_result(
            &scan,
            format!(
                "#{} {}:{} OK {} ms [{} / {}]",
                index,
                profile.host,
                profile.port,
                profile.latency_ms,
                profile.network,
                profile.security
            ),
            true,
        );

        return Ok(Some(profile));
    }

    #[cfg(windows)]
    {
        let tcp_latency =
            match tcp_connect_latency(&parsed.host, parsed.port, Duration::from_secs(3)).await {
                Ok(latency) => latency,
                Err(error) => {
                    note_test_result(
                        &scan,
                        format!(
                            "#{} {}:{} skipped: TCP failed ({error})",
                            index, parsed.host, parsed.port
                        ),
                        false,
                    );
                    return Ok(None);
                }
            };

        let probe_port = 16080 + index as u16;
        let config = build_xray_config(&parsed, probe_port, false, ACTIVE_TUN_INTERFACE)?;
        let tag = format!("probe-{index}");
        let (exe_path, config_path, log_path) = prepare_xray_assets(&tag, &config)?;
        let mut child = spawn_xray(&exe_path, &config_path, &log_path)?;

        for _ in 0..18 {
            if scan.control.is_cancelled() {
                let _ = child.kill();
                let _ = child.wait();
                let _ = fs::remove_file(config_path);
                let _ = fs::remove_file(log_path);
                return Ok(None);
            }
            sleep(Duration::from_millis(100)).await;
        }

        if let Ok(Some(status)) = child.try_wait() {
            let xray_log = read_optional_file(&log_path);
            let _ = fs::remove_file(config_path);
            let _ = fs::remove_file(log_path);
            note_test_result(
                &scan,
                format!(
                    "#{} {}:{} failed: Xray exited with {} ({})",
                    index,
                    parsed.host,
                    parsed.port,
                    status,
                    summarize_xray_log(&xray_log)
                ),
                false,
            );
            return Ok(None);
        }

        let proxy_url = format!("socks5h://127.0.0.1:{probe_port}");
        let request_client = Client::builder()
            .timeout(Duration::from_secs(8))
            .danger_accept_invalid_certs(true)
            .user_agent(BROWSER_USER_AGENT)
            .proxy(Proxy::all(&proxy_url).map_err(|error| format!("Invalid proxy: {error}"))?)
            .build()
            .map_err(|error| format!("Failed to build probe client: {error}"))?;

        let started_at = Instant::now();
        let probe_result = request_client.get(PROBE_TARGET_URL).send().await;
        let request_latency = started_at.elapsed().as_millis();

        let _ = child.kill();
        let _ = child.wait();
        let _ = fs::remove_file(config_path);
        let xray_log = read_optional_file(&log_path);
        let _ = fs::remove_file(log_path);

        let response = match probe_result {
            Ok(value) => value,
            Err(error) => {
                note_test_result(
                    &scan,
                    format!(
                        "#{} {}:{} failed: Instagram probe error ({error})",
                        index, parsed.host, parsed.port
                    ),
                    false,
                );
                return Ok(None);
            }
        };

        if !response.status().is_success() && !response.status().is_redirection() {
            note_test_result(
                &scan,
                format!(
                    "#{} {}:{} failed: Instagram returned {} ({})",
                    index,
                    parsed.host,
                    parsed.port,
                    response.status(),
                    summarize_xray_log(&xray_log)
                ),
                false,
            );
            return Ok(None);
        }

        let profile = ServerProfile {
            id: format!("{}-{}", parsed.host, parsed.port),
            uri: parsed.uri,
            label: parsed.label,
            host: parsed.host,
            port: parsed.port,
            latency_ms: request_latency.max(tcp_latency),
            network: parsed.network,
            security: parsed.security,
        };

        note_test_result(
            &scan,
            format!(
                "#{} {}:{} OK {} ms [{} / {}]",
                index,
                profile.host,
                profile.port,
                profile.latency_ms,
                profile.network,
                profile.security
            ),
            true,
        );

        Ok(Some(profile))
    }
}

async fn tcp_connect_latency(
    host: &str,
    port: u16,
    timeout_duration: Duration,
) -> Result<u128, String> {
    let started_at = Instant::now();
    let address = format!("{host}:{port}");

    tokio::time::timeout(timeout_duration, TcpStream::connect(address))
        .await
        .map_err(|_| "TCP connection timed out".to_string())?
        .map_err(|error| format!("TCP connection failed: {error}"))?;

    Ok(started_at.elapsed().as_millis())
}

#[cfg(windows)]
fn prepare_xray_assets(tag: &str, config: &str) -> Result<(PathBuf, PathBuf, PathBuf), String> {
    let exe_path = ensure_xray_binary().map_err(|error| error.to_string())?;
    let config_path = write_temp_config(tag, config).map_err(|error| error.to_string())?;
    let log_path = temp_log_path(tag).map_err(|error| error.to_string())?;
    Ok((exe_path, config_path, log_path))
}

#[cfg(windows)]
fn ensure_xray_binary() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let temp_dir = env::temp_dir().join("oghab-vpn");
    fs::create_dir_all(&temp_dir)?;

    let exe_path = temp_dir.join("xray.exe");
    let embedded = XRAY_DIR
        .get_file("xray-x64.exe")
        .ok_or("xray-x64.exe not found in embedded assets")?;

    let should_replace = match fs::metadata(&exe_path) {
        Ok(metadata) => metadata.len() != embedded.contents().len() as u64,
        Err(_) => true,
    };

    if should_replace {
        let mut file = File::create(&exe_path)?;
        file.write_all(embedded.contents())?;
    }

    Ok(exe_path)
}

#[cfg(windows)]
fn write_temp_config(tag: &str, config: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let temp_dir = env::temp_dir().join("oghab-vpn");
    fs::create_dir_all(&temp_dir)?;

    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
    let path = temp_dir.join(format!("{tag}-{stamp}.json"));
    fs::write(&path, config)?;
    Ok(path)
}

#[cfg(windows)]
fn temp_log_path(tag: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let temp_dir = env::temp_dir().join("oghab-vpn");
    fs::create_dir_all(&temp_dir)?;

    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
    Ok(temp_dir.join(format!("{tag}-{stamp}.log")))
}

#[cfg(windows)]
fn spawn_xray(exe_path: &Path, config_path: &Path, log_path: &Path) -> Result<Child, String> {
    use std::os::windows::process::CommandExt;

    let stdout_file = File::create(log_path)
        .map_err(|error| format!("Failed to create Xray log file: {error}"))?;
    let stderr_file = stdout_file
        .try_clone()
        .map_err(|error| format!("Failed to clone Xray log file: {error}"))?;

    Command::new(exe_path)
        .args(["run", "-c"])
        .arg(config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout_file))
        .stderr(Stdio::from(stderr_file))
        .creation_flags(0x08000000)
        .spawn()
        .map_err(|error| format!("Failed to start Xray: {error}"))
}

#[cfg(windows)]
fn read_optional_file(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_default()
}

#[cfg(windows)]
fn summarize_xray_log(content: &str) -> String {
    let cleaned = content
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("no Xray log output");

    format!("xray log: {}", cleaned.trim())
}

fn parse_vless_uri(uri: &str) -> Result<ParsedVless, String> {
    let url = Url::parse(uri).map_err(|error| format!("Invalid URL: {error}"))?;

    if url.scheme() != "vless" {
        return Err("Only vless:// URIs are supported".to_string());
    }

    let uuid = url.username().trim().to_string();
    if uuid.is_empty() {
        return Err("Missing VLESS user id".to_string());
    }

    let host = url
        .host_str()
        .ok_or("Missing server host".to_string())?
        .to_string();

    let query: std::collections::HashMap<String, String> = url.query_pairs().into_owned().collect();
    let port = url.port().unwrap_or(443);
    let network = query
        .get("type")
        .cloned()
        .unwrap_or_else(|| "tcp".to_string());
    let security = query
        .get("security")
        .cloned()
        .unwrap_or_else(|| "none".to_string());
    let encryption = query
        .get("encryption")
        .cloned()
        .unwrap_or_else(|| "none".to_string());

    let label = url
        .fragment()
        .filter(|fragment| !fragment.is_empty())
        .map(|fragment| {
            urlencoding::decode(fragment)
                .map(|value| value.replace('+', " "))
                .unwrap_or_else(|_| fragment.replace('+', " "))
        })
        .unwrap_or_else(|| format!("{host}:{port}"));

    let alpn = query
        .get("alpn")
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|entry| !entry.is_empty())
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    Ok(ParsedVless {
        uri: uri.to_string(),
        label,
        host,
        port,
        network,
        security,
        uuid,
        flow: query.get("flow").cloned(),
        encryption,
        sni: query.get("sni").cloned(),
        fingerprint: query.get("fp").cloned(),
        public_key: query.get("pbk").cloned(),
        short_id: query.get("sid").cloned(),
        host_header: query.get("host").cloned(),
        path: query.get("path").cloned(),
        service_name: query.get("serviceName").cloned(),
        authority: query.get("authority").cloned(),
        mode: query
            .get("mode")
            .cloned()
            .or_else(|| query.get("xmode").cloned()),
        header_type: query.get("headerType").cloned(),
        spider_x: query
            .get("spx")
            .cloned()
            .or_else(|| query.get("spiderX").cloned()),
        alpn,
    })
}

fn build_xray_config(
    parsed: &ParsedVless,
    socks_port: u16,
    tunnel_mode: bool,
    tun_name: &str,
) -> Result<String, String> {
    let mut user = json!({
        "id": parsed.uuid,
        "encryption": parsed.encryption,
        "level": 8
    });

    if let Some(flow) = &parsed.flow {
        user["flow"] = json!(flow);
    }

    let mut stream_settings = json!({
        "network": parsed.network,
        "security": parsed.security
    });

    match parsed.network.as_str() {
        "tcp" => {
            if parsed.header_type.as_deref() == Some("http") {
                let hosts = parsed
                    .host_header
                    .clone()
                    .unwrap_or_else(|| parsed.host.clone())
                    .split(',')
                    .map(str::trim)
                    .filter(|entry| !entry.is_empty())
                    .map(ToOwned::to_owned)
                    .collect::<Vec<_>>();
                let paths = parsed
                    .path
                    .clone()
                    .unwrap_or_else(|| "/".to_string())
                    .split(',')
                    .map(str::trim)
                    .filter(|entry| !entry.is_empty())
                    .map(ToOwned::to_owned)
                    .collect::<Vec<_>>();

                stream_settings["tcpSettings"] = json!({
                    "header": {
                        "type": "http",
                        "request": {
                            "version": "1.1",
                            "method": "GET",
                            "path": if paths.is_empty() { vec!["/".to_string()] } else { paths },
                            "headers": {
                                "Host": if hosts.is_empty() { vec![parsed.host.clone()] } else { hosts },
                                "User-Agent": [BROWSER_USER_AGENT],
                                "Accept-Encoding": ["gzip, deflate"],
                                "Connection": ["keep-alive"],
                                "Pragma": "no-cache"
                            }
                        }
                    }
                });
            } else {
                stream_settings["tcpSettings"] = json!({
                    "header": {
                        "type": "none"
                    }
                });
            }
        }
        "ws" => {
            stream_settings["wsSettings"] = json!({
                "path": parsed.path.clone().unwrap_or_else(|| "/".to_string()),
                "headers": {
                    "Host": parsed.host_header.clone().unwrap_or_else(|| parsed.host.clone())
                }
            });
        }
        "grpc" => {
            stream_settings["grpcSettings"] = json!({
                "serviceName": parsed.service_name.clone().unwrap_or_default(),
                "authority": parsed.authority.clone().unwrap_or_default()
            });
        }
        "httpupgrade" => {
            stream_settings["httpupgradeSettings"] = json!({
                "path": parsed.path.clone().unwrap_or_else(|| "/".to_string()),
                "host": parsed.host_header.clone().unwrap_or_else(|| parsed.host.clone())
            });
        }
        "xhttp" => {
            stream_settings["xhttpSettings"] = json!({
                "host": parsed.host_header.clone().unwrap_or_default(),
                "path": parsed.path.clone().unwrap_or_else(|| "/".to_string()),
                "mode": parsed.mode.clone().unwrap_or_else(|| "auto".to_string())
            });
        }
        "h2" | "http" => {
            let hosts = parsed
                .host_header
                .clone()
                .unwrap_or_else(|| parsed.host.clone())
                .split(',')
                .map(str::trim)
                .filter(|entry| !entry.is_empty())
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>();
            stream_settings["network"] = json!("h2");
            stream_settings["httpSettings"] = json!({
                "host": if hosts.is_empty() { vec![parsed.host.clone()] } else { hosts },
                "path": parsed.path.clone().unwrap_or_else(|| "/".to_string())
            });
        }
        _ => {}
    }

    match parsed.security.as_str() {
        "tls" => {
            let server_name = parsed
                .sni
                .clone()
                .or_else(|| parsed.host_header.clone())
                .unwrap_or_else(|| parsed.host.clone());

            let mut tls_settings = json!({
                "serverName": server_name,
                "allowInsecure": false
            });

            if !parsed.alpn.is_empty() {
                tls_settings["alpn"] = json!(parsed.alpn);
            }

            if let Some(fingerprint) = &parsed.fingerprint {
                tls_settings["fingerprint"] = json!(fingerprint);
            }

            stream_settings["tlsSettings"] = tls_settings;
        }
        "reality" => {
            let mut reality_settings = json!({
                "serverName": parsed.sni.clone().unwrap_or_else(|| parsed.host.clone()),
                "publicKey": parsed.public_key.clone().unwrap_or_default(),
                "shortId": parsed.short_id.clone().unwrap_or_default(),
                "fingerprint": parsed
                    .fingerprint
                    .clone()
                    .unwrap_or_else(|| "chrome".to_string()),
                "show": false
            });

            if !parsed.alpn.is_empty() {
                reality_settings["alpn"] = json!(parsed.alpn);
            }

            if let Some(spider_x) = &parsed.spider_x {
                reality_settings["spiderX"] = json!(spider_x);
            }

            stream_settings["realitySettings"] = reality_settings;
        }
        _ => {}
    }

    let inbound = if tunnel_mode {
        json!({
            "tag": "tun",
            "protocol": "tun",
            "settings": {
                "name": tun_name,
                "MTU": 1500,
                "userLevel": 8
            },
            "sniffing": {
                "enabled": true,
                "destOverride": ["http", "tls", "quic"]
            }
        })
    } else {
        json!({
            "tag": "socks",
            "listen": "127.0.0.1",
            "port": socks_port,
            "protocol": "socks",
            "settings": {
                "auth": "noauth",
                "udp": true,
                "userLevel": 8
            },
            "sniffing": {
                "enabled": true,
                "destOverride": ["http", "tls", "quic"]
            }
        })
    };

    let config = json!({
        "stats": {},
        "log": {
            "loglevel": "warning"
        },
        "policy": {
            "levels": {
                "8": {
                    "handshake": 4,
                    "connIdle": 300,
                    "uplinkOnly": 1,
                    "downlinkOnly": 1
                }
            },
            "system": {
                "statsOutboundUplink": true,
                "statsOutboundDownlink": true
            }
        },
        "inbounds": [inbound],
        "outbounds": [{
            "tag": "proxy",
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": parsed.host,
                    "port": parsed.port,
                    "users": [user]
                }]
            },
            "streamSettings": stream_settings,
            "mux": {
                "enabled": false
            }
        }, {
            "tag": "direct",
            "protocol": "freedom",
            "streamSettings": {
                "sockopt": {
                    "domainStrategy": "UseIP"
                }
            }
        }, {
            "tag": "block",
            "protocol": "blackhole",
            "settings": {
                "response": {
                    "type": "http"
                }
            }
        }],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": []
        },
        "dns": {
            "hosts": {},
            "servers": []
        }
    });

    serde_json::to_string_pretty(&config)
        .map_err(|error| format!("Failed to serialize Xray config: {error}"))
}

fn note_test_result(scan: &Arc<ScanRuntime>, line: String, success: bool) {
    if let Ok(mut state) = scan.state.lock() {
        state.scanned_count += 1;
        if success {
            state.working_count += 1;
        }
        state.lines.push(line);
        if state.lines.len() > 320 {
            let excess = state.lines.len() - 320;
            state.lines.drain(0..excess);
        }
    }
}

fn push_debug_line(scan: &Arc<ScanRuntime>, line: String) {
    if let Ok(mut state) = scan.state.lock() {
        state.lines.push(line);
        if state.lines.len() > 320 {
            let excess = state.lines.len() - 320;
            state.lines.drain(0..excess);
        }
    }
}

#[cfg(windows)]
fn set_system_proxy(
    enable: bool,
    proxy_server: &str,
    bypass_list: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let settings = hkcu.open_subkey_with_flags(
        "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
        KEY_WRITE,
    )?;

    settings.set_value("ProxyEnable", &(enable as u32))?;
    settings.set_value("ProxyServer", &proxy_server)?;
    settings.set_value("ProxyOverride", &bypass_list)?;

    unsafe {
        winapi::um::wininet::InternetSetOptionW(
            std::ptr::null_mut(),
            winapi::um::wininet::INTERNET_OPTION_SETTINGS_CHANGED,
            std::ptr::null_mut(),
            0,
        );
        winapi::um::wininet::InternetSetOptionW(
            std::ptr::null_mut(),
            winapi::um::wininet::INTERNET_OPTION_REFRESH,
            std::ptr::null_mut(),
            0,
        );
    }

    Ok(())
}

#[cfg(windows)]
fn set_tun_route(enable: bool) -> Result<(), Box<dyn std::error::Error>> {
    if enable {
        set_system_proxy(false, "", "")?;
    }
    Ok(())
}

#[cfg(windows)]
fn remove_tun_route() -> Result<(), Box<dyn std::error::Error>> {
    set_tun_route(false)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(AppState {
            manager: Mutex::new(XrayManager::default()),
            scan: Arc::new(ScanRuntime::new()),
        })
        .setup(|_| {
            #[cfg(windows)]
            let _ = set_system_proxy(false, "", "");
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { .. } = event {
                let state = window.state::<AppState>();
                let stop_result = state.manager.lock();
                if let Ok(mut manager) = stop_result {
                    #[cfg(target_os = "android")]
                    {
                        let _ = android_bridge::call_disconnect();
                    }
                    let _ = manager.stop();
                };
            }
        })
        .invoke_handler(tauri::generate_handler![
            start_scan,
            pause_scan,
            resume_scan,
            stop_scan,
            get_scan_snapshot,
            connect_profile,
            disconnect_vpn,
            vpn_status
        ])
        .run(tauri::generate_context!())
        .expect("error while running OGHAB VPN");
}

#[allow(dead_code)]
fn main() {
    run();
}
