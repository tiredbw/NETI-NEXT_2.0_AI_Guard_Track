//! Состояние демо: журнал проверок, входящие заглушки агента, ожидающие подтверждения,
//! сессии и история версий политики. Всё в памяти процесса; журнал дополнительно пишется в JSONL.

use crate::contract::{Confirmation, JournalEntry, PolicyVersionInfo, Receipt, Session};
use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Сколько живёт подтверждение.
pub const CONFIRM_TTL_SECS: u64 = 10 * 60;
/// Ограничения сессий из контракта.
pub const SESSION_MAX_TURNS: usize = 20;
pub const SESSION_TTL_MINUTES: u64 = 60;
/// Сколько записей журнала держим в памяти.
const JOURNAL_CAP: usize = 10_000;
const INBOX_CAP: usize = 1_000;

/// Ожидающее подтверждение: что и кому можно передать после кнопки.
#[derive(Debug, Clone)]
pub struct Pending {
    pub confirmation: Confirmation, // То, что видит клиент.
    pub expires_unix: u64, // Срок.
    pub used: bool, // Одноразовое.
    pub receipt_base: Receipt, // Квитанция, которая появится после подтверждения.
    pub session_id: Option<String>, // Если запрос пришёл из сессии.
}

#[derive(Default)]
struct Inner {
    journal: Vec<JournalEntry>,
    inbox: Vec<Receipt>,
    pending: HashMap<String, Pending>,
    sessions: HashMap<String, Session>,
    policy_history: Vec<PolicyVersionInfo>,
}

/// Общее хранилище; критические секции короткие и без await.
pub struct Store {
    inner: Mutex<Inner>,
    journal_path: Option<PathBuf>,
}

impl Store {
    pub fn new(journal_path: Option<PathBuf>) -> Self {
        if let Some(dir) = journal_path.as_ref().and_then(|p| p.parent()) {
            let _ = std::fs::create_dir_all(dir); // Каталог журнала; ошибка не мешает работе в памяти.
        }
        Self { inner: Mutex::new(Inner::default()), journal_path }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()) // Паника в другом запросе не блокирует сервис.
    }

    // ---------- журнал ----------

    /// Добавляет запись в журнал и дописывает её строкой JSON в файл.
    pub fn journal_push(&self, entry: JournalEntry) {
        if let Some(path) = &self.journal_path {
            if let Ok(line) = serde_json::to_string(&entry) {
                let res = std::fs::OpenOptions::new().create(true).append(true).open(path).and_then(|mut f| writeln!(f, "{line}"));
                if let Err(e) = res { tracing::warn!(%e, "journal file write failed"); }
            }
        }
        let mut g = self.lock();
        g.journal.push(entry);
        if g.journal.len() > JOURNAL_CAP { let extra = g.journal.len() - JOURNAL_CAP; g.journal.drain(..extra); }
    }

    /// Записи журнала, новые сверху, после фильтра; возвращает страницу и общее число.
    pub fn journal_query(&self, filter: impl Fn(&JournalEntry) -> bool, offset: usize, limit: usize) -> (Vec<JournalEntry>, usize) {
        let g = self.lock();
        let all: Vec<&JournalEntry> = g.journal.iter().rev().filter(|e| filter(e)).collect();
        let total = all.len();
        (all.into_iter().skip(offset).take(limit).cloned().collect(), total)
    }

    // ---------- агент ----------

    pub fn deliver(&self, receipt: Receipt) -> Receipt {
        let mut g = self.lock();
        g.inbox.push(receipt.clone());
        if g.inbox.len() > INBOX_CAP { let extra = g.inbox.len() - INBOX_CAP; g.inbox.drain(..extra); }
        receipt
    }

    pub fn inbox(&self, limit: usize) -> Vec<Receipt> {
        self.lock().inbox.iter().rev().take(limit).cloned().collect()
    }

    // ---------- подтверждения ----------

    pub fn pending_put(&self, p: Pending) {
        let mut g = self.lock();
        let now = unix_now();
        g.pending.retain(|_, v| v.expires_unix > now && !v.used); // Чистим старые.
        g.pending.insert(p.confirmation.check_id.clone(), p);
    }

    /// Проверяет подтверждение и помечает его использованным. Ошибка — (HTTP-код, код ошибки, текст).
    pub fn pending_take(&self, check_id: &str, request_hash: &str, user_id: Option<&str>) -> Result<Pending, (u16, &'static str, &'static str)> {
        let mut g = self.lock();
        let Some(p) = g.pending.get_mut(check_id) else { return Err((404, "not_found", "Нет ожидающего подтверждения")) };
        if p.confirmation.user_id.as_deref() != user_id { return Err((403, "wrong_user", "Подтвердить может только автор запроса")); }
        if p.used { return Err((409, "already_used", "Подтверждение уже использовано")); }
        if p.confirmation.request_hash != request_hash { return Err((409, "request_changed", "Запрос или контекст изменены — нужна повторная проверка")); }
        if p.expires_unix <= unix_now() { return Err((410, "expired", "Срок подтверждения истёк")); }
        p.used = true;
        Ok(p.clone())
    }

    // ---------- сессии ----------

    pub fn session_put(&self, s: Session) {
        self.lock().sessions.insert(s.session_id.clone(), s);
    }

    /// Сессии пользователя без истёкших.
    pub fn sessions_of(&self, user_id: &str) -> Vec<Session> {
        let mut g = self.lock();
        let now = unix_now();
        g.sessions.retain(|_, s| s.expires_unix > now);
        let mut v: Vec<Session> = g.sessions.values().filter(|s| s.user_id == user_id).cloned().collect();
        v.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        v
    }

    /// Сессия с проверкой владельца и срока.
    pub fn session_get(&self, id: &str, user_id: &str) -> Result<Session, (u16, &'static str, &'static str)> {
        let mut g = self.lock();
        let Some(s) = g.sessions.get(id) else { return Err((404, "not_found", "Сессия не найдена")) };
        if s.user_id != user_id { return Err((403, "wrong_user", "Сессия принадлежит другому пользователю")); }
        if s.expires_unix <= unix_now() { g.sessions.remove(id); return Err((410, "expired", "Срок хранения сессии истёк")); }
        Ok(s.clone())
    }

    pub fn session_delete(&self, id: &str, user_id: &str) -> Result<(), (u16, &'static str, &'static str)> {
        self.session_get(id, user_id)?;
        self.lock().sessions.remove(id);
        Ok(())
    }

    /// Изменяет сессию под замком, если она ещё существует.
    pub fn session_update(&self, id: &str, f: impl FnOnce(&mut Session)) {
        if let Some(s) = self.lock().sessions.get_mut(id) { f(s); }
    }

    // ---------- политика ----------

    pub fn policy_record(&self, info: PolicyVersionInfo) {
        self.lock().policy_history.push(info);
    }

    pub fn policy_current(&self) -> Option<PolicyVersionInfo> {
        self.lock().policy_history.last().cloned()
    }

    pub fn policy_history(&self) -> Vec<PolicyVersionInfo> {
        self.lock().policy_history.iter().rev().cloned().collect()
    }
}

// ---------- время без внешних зависимостей ----------

pub fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Текущее время в RFC 3339 UTC с миллисекундами: строки сравнимы лексикографически.
pub fn now_iso() -> String {
    let d = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    iso_from(d.as_secs(), d.subsec_millis())
}

pub fn iso_from(secs: u64, millis: u32) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{millis:03}Z", rem / 3600, (rem % 3600) / 60, rem % 60)
}

/// Дата по числу дней от 1970-01-01 (алгоритм Говарда Хиннанта).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    #[test]
    fn iso_dates() {
        assert_eq!(super::iso_from(0, 0), "1970-01-01T00:00:00.000Z");
        assert_eq!(super::iso_from(1_795_190_400, 5), "2026-11-20T16:00:00.005Z");
        assert_eq!(super::iso_from(951_782_400, 0), "2000-02-29T00:00:00.000Z");
    }
}
