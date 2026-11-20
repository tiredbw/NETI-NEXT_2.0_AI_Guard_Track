//! Отладка нормализации: печатает скрытые варианты для каждой строки stdin.
use std::io::BufRead; // Построчное чтение.
fn main() {
    for line in std::io::stdin().lock().lines().map_while(Result::ok) { // Каждая строка.
        let n = astraguard::normalize::normalize(&line); // Нормализованный текст.
        let v = astraguard::normalize::hidden_variants(&n); // Скрытые варианты.
        println!("{} | {}", if v.is_empty() { "-".to_string() } else { v.iter().map(|(k, s)| format!("{k}: {}", s.chars().take(70).collect::<String>())).collect::<Vec<_>>().join(" ; ") }, n.chars().take(50).collect::<String>()); // Вывод.
    }
}
