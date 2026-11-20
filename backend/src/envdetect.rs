//! Детерминированное определение окружения по маскам из YAML и словам в тексте.

use crate::contract::Env; // Тип окружения.
use regex::Regex; // Регулярные выражения.
use std::sync::LazyLock; // Компилируем регулярки один раз.

static WORD_PROD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\b(prod|production|прод|продакшн|продакшен|продакшене|боевой|боевом)\b").unwrap()); // Слова про prod.
static WORD_NONPROD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\b(dev|stage|staging|test|дев|стейдж|тестовом|тестовой|тестовый)\b").unwrap()); // Слова про nonprod.
static TOKEN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[A-Za-z0-9][A-Za-z0-9_.\-]*[A-Za-z0-9]").unwrap()); // Кандидаты в имена ресурсов.

/// Совпадает ли имя с маской вида prod-*, *-prod, *-prod-*.
fn mask_match(mask: &str, name: &str) -> bool {
    let (starts, ends) = (mask.starts_with('*'), mask.ends_with('*')); // Где стоят звёздочки.
    let core = mask.trim_matches('*'); // Неизменная часть маски.
    match (starts, ends) { // Четыре варианта маски.
        (true, true) => name.contains(core) && !name.starts_with(core) && !name.ends_with(core), // *-prod-*: строго внутри.
        (true, false) => name.ends_with(core), // *-prod: суффикс.
        (false, true) => name.starts_with(core), // prod-*: префикс.
        (false, false) => name == core, // Точное имя.
    }
}

/// Результат разбора окружения с пояснением для explanation.
#[derive(Debug, Clone)] // Значение копируется в ответ.
pub struct EnvGuess {
    pub env: Env, // Итоговое окружение.
    pub evidence: String, // Почему так решили; пусто при Unknown.
    pub ambiguous: bool, // Найдены признаки и prod, и nonprod.
}

/// Определяет окружение по тексту запроса; prod побеждает при конфликте.
pub fn detect(text: &str, prod_masks: &[String], nonprod_masks: &[String]) -> EnvGuess {
    let lower = text.to_lowercase(); // Маски и слова сравниваем без регистра.
    let mut prod: Vec<String> = Vec::new(); // Найденные признаки prod.
    let mut nonprod: Vec<String> = Vec::new(); // Найденные признаки nonprod.
    for m in TOKEN.find_iter(&lower) { // Перебираем все похожие на ресурс слова.
        let name = m.as_str(); // Имя кандидата.
        if prod_masks.iter().any(|mask| mask_match(mask, name)) { prod.push(name.to_string()); } // Подходит под prod-маску.
        else if nonprod_masks.iter().any(|mask| mask_match(mask, name)) { nonprod.push(name.to_string()); } // Подходит под nonprod-маску.
    }
    if let Some(m) = WORD_PROD.find(&lower) { prod.push(format!("«{}»", m.as_str())); } // Явное слово про prod.
    if let Some(m) = WORD_NONPROD.find(&lower) { nonprod.push(format!("«{}»", m.as_str())); } // Явное слово про nonprod.
    match (prod.is_empty(), nonprod.is_empty()) { // Сводим признаки.
        (false, true) => EnvGuess { env: Env::Prod, evidence: prod.join(", "), ambiguous: false }, // Только prod.
        (true, false) => EnvGuess { env: Env::Nonprod, evidence: nonprod.join(", "), ambiguous: false }, // Только nonprod.
        (false, false) => EnvGuess { env: Env::Prod, evidence: format!("{} и {}", prod.join(", "), nonprod.join(", ")), ambiguous: true }, // Конфликт: строже — prod.
        (true, true) => EnvGuess { env: Env::Unknown, evidence: String::new(), ambiguous: false }, // Признаков нет.
    }
}

#[cfg(test)] // Тесты модуля.
mod tests {
    use super::*; // Функции модуля.

    fn masks() -> (Vec<String>, Vec<String>) { // Маски из исходной политики.
        (vec!["prod-*".into(), "*-prod".into(), "*-prod-*".into()], vec!["dev-*".into(), "stage-*".into(), "test-*".into()]) // prod и nonprod.
    }

    #[test] // Маски и слова распознаются.
    fn detects_env() {
        let (p, n) = masks(); // Маски.
        assert_eq!(detect("Перезапусти payments-prod", &p, &n).env, Env::Prod); // Суффикс -prod.
        assert_eq!(detect("логи api-prod-eu", &p, &n).env, Env::Prod); // Маска *-prod-*.
        assert_eq!(detect("restart stage-billing", &p, &n).env, Env::Nonprod); // Префикс stage-.
        assert_eq!(detect("Перезапусти payments-api в production", &p, &n).env, Env::Prod); // Слово production.
        assert_eq!(detect("Перезапусти payments-api", &p, &n).env, Env::Unknown); // Признаков нет.
        assert!(detect("скопируй из dev-db в prod-db", &p, &n).ambiguous); // Конфликт отмечается.
        assert_eq!(detect("scale everything to zero, testing done", &p, &n).env, Env::Unknown); // Слово testing не означает nonprod.
    }
}
