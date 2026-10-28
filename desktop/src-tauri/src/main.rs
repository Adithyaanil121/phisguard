#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct ScanPayload {
    url: String,
}

#[derive(Serialize, Deserialize)]
struct ScanResponse {
    verdict: String,
    action: String,
    risk_score: u32,
    reasons: Vec<String>,
}

#[tauri::command]
async fn scan_url(url: String, api_key: String) -> Result<ScanResponse, String> {
    let client = reqwest::Client::new();
    let res = client
        .post("http://127.0.0.1:8000/api/v1/check-url")
        .header("X-API-Key", api_key)
        .header("Origin", "http://127.0.0.1:3000")
        .json(&ScanPayload { url })
        .send()
        .await
        .map_err(|e| format!("Network error: {}", e))?;

    if !res.status().is_success() {
        return Err(format!("Backend error: {}", res.status()));
    }

    let data: ScanResponse = res
        .json()
        .await
        .map_err(|e| format!("Failed to parse response: {}", e))?;

    Ok(data)
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![scan_url])
        .run(tauri::generate_context!())
        .expect("error while running phishguard desktop agent");
}
