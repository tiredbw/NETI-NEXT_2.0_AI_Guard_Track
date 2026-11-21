//! Для каждой строки набора: оценка TF-IDF, категория и пропустит ли страховку rules::backstop_skip.
//! Запуск: cargo run --release --example backstop_scan -- <файл.jsonl>
use astraguard::contract::CheckRequest; // Формат запроса.
use std::io::BufRead; // Построчное чтение.
fn main() {
    let path = std::env::args().nth(1).expect("путь к jsonl"); // Файл набора.
    let tf = astraguard::tfidf::Tfidf::load("models/tfidf.json").expect("модель TF-IDF"); // Модель.
    for line in std::io::BufReader::new(std::fs::File::open(path).unwrap()).lines().map_while(Result::ok) { // Каждая строка.
        let row: serde_json::Value = serde_json::from_str(&line).unwrap(); // Пример.
        let req: CheckRequest = serde_json::from_value(serde_json::json!({"user_prompt": row["user_prompt"], "context": row["context"]})).unwrap(); // Запрос.
        let prompt = astraguard::normalize::normalize(&req.user_prompt); // Как в сервисе.
        let variants = astraguard::normalize::hidden_variants(&req.user_prompt); // Скрытые варианты.
        let s = tf.score(&req, &variants); // Оценка.
        let skip = astraguard::rules::backstop_skip(&prompt, !req.context.attachments.is_empty(), !req.context.history.is_empty(), !variants.is_empty(), s.category); // Пропуск страховки.
        println!("{}", serde_json::json!({"id": row["id"], "p": s.p_attack, "cat": astraguard::policy::category_name(s.category), "skip": skip})); // Строка отчёта.
    }
}
