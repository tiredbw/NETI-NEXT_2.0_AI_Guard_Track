//! TF-IDF-классификатор на символьных n-граммах: второй, независимый от Qwen сигнал.
//!
//! Модель обучается в backend/train/tfidf.py на public dev и экспортируется в JSON.
//! Здесь повторена векторизация sklearn (analyzer=char_wb, lowercase, sublinear_tf, l2)
//! и логистическая регрессия. При загрузке сверяем вероятности с контрольными примерами из файла,
//! чтобы расхождение Rust и Python не прошло незаметно.
//!
//! Страховка: если Qwen и политика дали allow, а классификатор уверенно видит атаку (p >= порога),
//! решение меняется на block. Включена по умолчанию, выключается TFIDF_BACKSTOP=0; сигнал в signals пишется всегда.

use crate::contract::{CheckRequest, RiskCategory}; // Вход и категории.
use serde::Deserialize; // Разбор JSON модели.
use std::collections::HashMap; // Словарь n-грамм.

/// Файл модели в формате backend/train/tfidf.py.
#[derive(Deserialize)] // Читается из JSON.
struct ModelFile {
    format: String, // astraguard-tfidf-1.
    ngram_range: (usize, usize), // Длины n-грамм.
    threshold: f64, // Порог страховки, подобранный по кросс-валидации.
    vocabulary: HashMap<String, usize>, // n-грамма -> номер признака.
    idf: Vec<f64>, // IDF признаков.
    attack_coef: Vec<f64>, // Веса бинарной модели «атака».
    attack_intercept: f64, // Свободный член.
    categories: Vec<RiskCategory>, // Категории атак.
    category_coef: Vec<Vec<f64>>, // Веса модели категорий.
    category_intercept: Vec<f64>, // Свободные члены категорий.
    #[serde(default)] // Контроль может отсутствовать.
    controls: Vec<Control>, // Контрольные примеры для сверки.
}

/// Контрольный пример: текст и ожидаемая вероятность из Python.
#[derive(Deserialize)] // Читается из JSON.
struct Control {
    text: String, // Склеенный текст признаков.
    p_attack: f64, // Вероятность атаки по sklearn.
}

/// Порог страховки по умолчанию. Порог из файла (0.703, ≤1 ошибка на dev) на чужих текстах блокировал легитимные просьбы.
pub const BACKSTOP_THRESHOLD: f64 = 0.85;

/// Загруженная модель.
pub struct Tfidf {
    m: ModelFile, // Веса и словарь.
    pub threshold: f64, // Порог страховки (можно переопределить TFIDF_THRESHOLD).
    pub backstop: bool, // Страховка включена (по умолчанию; TFIDF_BACKSTOP=0 выключает).
    pub prefilter: Option<f64>, // Быстрый фильтр до Qwen: при p >= порога модель не вызывается (TFIDF_PREFILTER=0.9).
    pub hint: bool, // Передавать оценку TF-IDF в сообщение для Qwen (TFIDF_HINT=1).
}

/// Оценка классификатора для одного запроса.
#[derive(Debug, Clone, Copy)] // Мелкая копируемая структура.
pub struct Score {
    pub p_attack: f64, // Вероятность атаки.
    pub category: RiskCategory, // Самая вероятная категория атаки.
}

/// Текст признаков: роль, запрос, вложения, последние реплики пользователя. Та же склейка в tfidf.py.
pub fn features_text(req: &CheckRequest, prompt: &str) -> String {
    let ctx = &req.context; // Контекст.
    let mut parts = vec![format!("role {}", crate::policy::role_name(ctx.user_role)), prompt.to_string()]; // Роль и запрос.
    parts.extend(ctx.attachments.iter().take(4).map(|a| a.content.clone())); // До четырёх вложений.
    let skip = ctx.history.len().saturating_sub(4); // Последние четыре реплики истории.
    parts.extend(ctx.history.iter().skip(skip).filter(|t| t.role == "user").map(|t| t.content.clone())); // Только реплики пользователя.
    parts.join("\n")
}

impl Tfidf {
    /// Загружает модель и сверяет её с контрольными примерами.
    pub fn load(path: &str) -> Result<Self, String> {
        let raw = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?; // Файл модели.
        let m: ModelFile = serde_json::from_str(&raw).map_err(|e| format!("{path}: {e}"))?; // Разбор.
        if m.format != "astraguard-tfidf-1" { return Err(format!("неизвестный формат {}", m.format)); } // Версия формата.
        let threshold = std::env::var("TFIDF_THRESHOLD").ok().and_then(|v| v.parse().ok()).unwrap_or(BACKSTOP_THRESHOLD.max(m.threshold)); // Порог страховки.
        let backstop = std::env::var("TFIDF_BACKSTOP").map(|v| !(v == "0" || v.eq_ignore_ascii_case("false"))).unwrap_or(true); // По умолчанию включена: на всём dev с Qwen +0.022.
        let prefilter = std::env::var("TFIDF_PREFILTER").ok().and_then(|v| v.parse().ok()).filter(|p: &f64| *p > 0.0 && *p <= 1.0); // По умолчанию выключен.
        let hint = std::env::var("TFIDF_HINT").map(|v| v == "1" || v.eq_ignore_ascii_case("true")).unwrap_or(false); // По умолчанию выключена.
        let t = Tfidf { m, threshold, backstop, prefilter, hint }; // Модель.
        for c in &t.m.controls { // Сверка с Python.
            let p = t.p_attack_text(&c.text); // Наша вероятность.
            if (p - c.p_attack).abs() > 1e-3 { return Err(format!("расхождение с sklearn: {p:.6} против {:.6}", c.p_attack)); } // Векторизация разошлась.
        }
        Ok(t)
    }

    /// Разреженный TF-IDF-вектор: номер признака -> вес после l2-нормировки.
    fn vectorize(&self, text: &str) -> Vec<(usize, f64)> {
        let lower = text.to_lowercase(); // lowercase=True.
        let (lo, hi) = self.m.ngram_range; // Длины n-грамм.
        let mut counts: HashMap<usize, f64> = HashMap::new(); // Частоты.
        for word in lower.split_whitespace() { // char_wb: n-граммы внутри слов, слово обрамлено пробелами.
            let w: Vec<char> = std::iter::once(' ').chain(word.chars()).chain(std::iter::once(' ')).collect(); // " слово ".
            for n in lo..=hi { // Каждая длина.
                let mut offset = 0; // Как в sklearn _char_wb_ngrams.
                let mut gram = |o: usize| { // Добавляет n-грамму с позиции o.
                    let end = (o + n).min(w.len()); // Короткое слово берётся целиком.
                    let s: String = w[o..end].iter().collect();
                    if let Some(&i) = self.m.vocabulary.get(&s) { *counts.entry(i).or_insert(0.0) += 1.0; } // Только известные n-граммы.
                };
                gram(offset);
                while offset + n < w.len() { offset += 1; gram(offset); }
                if offset == 0 { break; } // Слово короче n: считаем один раз и выходим.
            }
        }
        let mut v: Vec<(usize, f64)> = counts.into_iter().map(|(i, c)| (i, (1.0 + c.ln()) * self.m.idf[i])).collect(); // sublinear_tf * idf.
        let norm = v.iter().map(|(_, x)| x * x).sum::<f64>().sqrt(); // l2-норма.
        if norm > 0.0 { for (_, x) in v.iter_mut() { *x /= norm; } } // Нормировка.
        v
    }

    /// Вероятность атаки по готовому тексту признаков.
    fn p_attack_text(&self, text: &str) -> f64 {
        let v = self.vectorize(text); // Вектор.
        let z = self.m.attack_intercept + v.iter().map(|(i, x)| self.m.attack_coef[*i] * x).sum::<f64>(); // Линейная часть.
        1.0 / (1.0 + (-z).exp()) // Сигмоида.
    }

    /// Оценка запроса: максимум по исходному тексту и раскодированным вариантам.
    pub fn score(&self, req: &CheckRequest, variants: &[(&'static str, String)]) -> Score {
        let texts = std::iter::once(features_text(req, &req.user_prompt)).chain(variants.iter().map(|(_, s)| features_text(req, s))); // Исходный и скрытые.
        let mut best = (f64::MIN, Vec::new()); // Лучшая вероятность и её вектор.
        for t in texts {
            let v = self.vectorize(&t);
            let z = self.m.attack_intercept + v.iter().map(|(i, x)| self.m.attack_coef[*i] * x).sum::<f64>();
            let p = 1.0 / (1.0 + (-z).exp());
            if p > best.0 { best = (p, v); }
        }
        let (p_attack, v) = best; // Самый подозрительный вариант.
        let category = self.m.category_coef.iter().zip(&self.m.category_intercept).zip(&self.m.categories) // Категория: максимум линейной части.
            .map(|((w, b), c)| (b + v.iter().map(|(i, x)| w[*i] * x).sum::<f64>(), *c))
            .max_by(|a, b| a.0.total_cmp(&b.0)).map(|(_, c)| c).unwrap_or(RiskCategory::PromptInjection);
        Score { p_attack, category }
    }
}

#[cfg(test)] // Сверка с sklearn по контрольным примерам из файла модели.
mod tests {
    #[test]
    fn matches_sklearn_controls() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/models/tfidf.json"); // Модель в репозитории.
        let t = super::Tfidf::load(path).expect("модель грузится и совпадает с контролем"); // load сам сверяет контроль.
        assert!(t.threshold > 0.5 && t.threshold < 1.0); // Разумный порог.
    }
}
