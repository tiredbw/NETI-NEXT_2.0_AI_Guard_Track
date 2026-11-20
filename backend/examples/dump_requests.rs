//! Печатает тела запросов к Ollama для строк dev.jsonl: системный промпт, сообщение и схему.
//! Нужен для замеров задержки по этапам (prompt_eval / eval) без запуска сервиса.
//! cargo run --release --example dump_requests -- ../dev.jsonl 40 > requests.jsonl

use astraguard::contract::CheckRequest;
use astraguard::detector::{build_user_message, request_body};
use astraguard::normalize;

fn main() {
    let mut args = std::env::args().skip(1);
    let path = args.next().expect("путь к dev.jsonl");
    let limit: usize = args.next().and_then(|v| v.parse().ok()).unwrap_or(usize::MAX);
    let text = std::fs::read_to_string(path).expect("читается dev.jsonl");
    for line in text.lines().filter(|l| !l.trim().is_empty()).take(limit) {
        let row: serde_json::Value = serde_json::from_str(line).expect("JSON");
        let req: CheckRequest = serde_json::from_value(serde_json::json!({"user_prompt": row["user_prompt"], "context": row["context"]})).expect("контракт");
        let msg = build_user_message(&req, &normalize::normalize(&req.user_prompt));
        println!("{}", serde_json::json!({"id": row["id"], "body": request_body("qwen3.5:4b", &msg)}));
    }
}
