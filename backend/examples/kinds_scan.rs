//! Какие скрытые варианты находит нормализация на каждой строке набора: id, ожидание, виды вариантов.
//! Нужен для сравнения версий normalize.rs: новые декодеры не должны давать мусор на обычных запросах.
//! Запуск: cargo run --release --example kinds_scan -- <файл.jsonl>
use std::io::BufRead; // Построчное чтение.
fn main() {
    let path = std::env::args().nth(1).expect("путь к jsonl"); // Файл набора.
    for line in std::io::BufReader::new(std::fs::File::open(path).unwrap()).lines().map_while(Result::ok) { // Каждая строка.
        let row: serde_json::Value = serde_json::from_str(&line).unwrap(); // Пример.
        let p = row["user_prompt"].as_str().unwrap_or(""); // Запрос.
        let v = astraguard::normalize::hidden_variants(p); // Варианты.
        println!("{}", serde_json::json!({"id": row["id"], "exp": row["expected_decision"], "norm": astraguard::normalize::normalize(p), "kinds": v.iter().map(|(k, t)| format!("{k}: {}", t.chars().take(80).collect::<String>())).collect::<Vec<_>>()})); // Строка отчёта.
    }
}
