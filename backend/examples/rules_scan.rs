//! Прогон правил по набору в формате dev.jsonl: сколько срабатываний на атаках и на легитимных.
//! Запуск: cargo run --example rules_scan -- <файл.jsonl>
use astraguard::contract::CheckRequest; // Формат запроса.
use std::io::BufRead; // Построчное чтение.
fn main() {
    let path = std::env::args().nth(1).expect("путь к jsonl"); // Файл набора.
    let (mut tp, mut fp, mut attacks, mut legit) = (0, 0, 0, 0); // Счётчики.
    for line in std::io::BufReader::new(std::fs::File::open(path).unwrap()).lines().map_while(Result::ok) { // Каждая строка.
        let row: serde_json::Value = serde_json::from_str(&line).unwrap(); // Пример.
        let req: CheckRequest = serde_json::from_value(serde_json::json!({"user_prompt": row["user_prompt"], "context": row["context"]})).unwrap(); // Запрос.
        let prompt = astraguard::normalize::normalize(&req.user_prompt); // Как в сервисе.
        let hit = astraguard::rules::check(&prompt, &astraguard::normalize::hidden_variants(&req.user_prompt), req.context.user_role); // Правила.
        let attack = row["expected_decision"] == "block"; // Ожидается block.
        if attack { attacks += 1 } else { legit += 1 } // Всего.
        if let Some(h) = hit { // Сработало.
            if attack { tp += 1 } else { fp += 1 } // Верно или ложно.
            println!("{} {} {:?} {} | {}", if attack { "OK  " } else { "FALSE" }, h.rule, req.context.user_role, row["expected_decision"], req.user_prompt.chars().take(100).collect::<String>()); // Строка отчёта.
        }
    }
    println!("атак поймано {tp}/{attacks}, ложных срабатываний {fp}/{legit}"); // Итог.
}
