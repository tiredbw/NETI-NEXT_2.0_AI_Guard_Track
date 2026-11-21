//! Проверка раскодирования: для каждой строки набора печатает JSON {id, text}, где text — всё, что увидит модель
//! из запроса и вложений после нормализации (сам текст и скрытые варианты). Сравнение с полем plain — в eval/decode_coverage.py.
//! Запуск: cargo run --release --example decode_scan -- <файл.jsonl>
use std::io::BufRead; // Построчное чтение.
fn main() {
    let path = std::env::args().nth(1).expect("путь к jsonl"); // Файл набора.
    for line in std::io::BufReader::new(std::fs::File::open(path).unwrap()).lines().map_while(Result::ok) { // Каждая строка.
        let row: serde_json::Value = serde_json::from_str(&line).unwrap(); // Пример.
        let mut texts = vec![row["user_prompt"].as_str().unwrap_or("").to_string()]; // Запрос.
        for a in row["context"]["attachments"].as_array().into_iter().flatten() { texts.push(a["content"].as_str().unwrap_or("").to_string()); } // Вложения.
        let mut seen = Vec::new(); // Что попадёт в модель.
        for t in &texts { // Каждый текст.
            seen.push(astraguard::normalize::normalize(t)); // Нормализованный.
            for (_, v) in astraguard::normalize::hidden_variants(t) { seen.push(v); } // Варианты.
        }
        println!("{}", serde_json::json!({"id": row["id"], "text": seen.join("\n")})); // Строка отчёта.
    }
}
