//! На каких строках dev.jsonl срабатывает правило истории: cargo run --release --example history_scan -- ../dev.jsonl
use astraguard::contract::CheckRequest;
fn main() {
    let path = std::env::args().nth(1).expect("путь к dev.jsonl");
    for line in std::fs::read_to_string(path).expect("читается").lines().filter(|l| !l.trim().is_empty()) {
        let row: serde_json::Value = serde_json::from_str(line).unwrap();
        let req: CheckRequest = serde_json::from_value(serde_json::json!({"user_prompt": row["user_prompt"], "context": row["context"]})).unwrap();
        let hit = astraguard::history::secret_followup(&req, &astraguard::normalize::normalize(&req.user_prompt));
        if let Some(w) = hit { println!("{} expected={} cat={} word={w} | {}", row["id"], row["expected_decision"], row["risk_category"], req.user_prompt); }
        else if !req.context.history.is_empty() { println!("{} (история, правило молчит) expected={} cat={} | {}", row["id"], row["expected_decision"], row["risk_category"], req.user_prompt); }
    }
}
