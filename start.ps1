# Запуск AstraGuard одной командой (Windows PowerShell 5+):  powershell -ExecutionPolicy Bypass -File .\start.ps1
# Проверяет Ollama и модель, задаёт переменные, собирает сервис при необходимости, ждёт готовности
# и делает контрольный запрос. Если сервер упадёт, скрипт поднимет его снова через 5 секунд. Выход — Ctrl+C.
param(
    [switch]$Build,                    # Пересобрать сервис перед запуском (после git pull).
    [string]$Model = "astraguard-ft",  # Модель в Ollama.
    [int]$Port = 8000                  # Порт сервера.
)
$ErrorActionPreference = "Stop"                          # Любая ошибка останавливает скрипт.
$root = $PSScriptRoot                                    # Корень репозитория.
$backend = Join-Path $root "backend"                     # Папка сервиса: пути политики, фронта и TF-IDF считаются от неё.

function Say($text, $color = "Cyan") { Write-Host "[astraguard] $text" -ForegroundColor $color }  # Сообщение скрипта.
function Fail($text) { Say $text "Red"; exit 1 }                                                  # Сообщение об ошибке и выход.
function OllamaTags { try { Invoke-RestMethod "http://127.0.0.1:11434/api/tags" -TimeoutSec 3 } catch { $null } }  # Список моделей или $null.

# 1. Ollama должна отвечать; если не запущена, поднимаем её сами.
$tags = OllamaTags
if (-not $tags) {
    Say "Ollama не отвечает, запускаю ollama serve"
    try { Start-Process ollama -ArgumentList "serve" -WindowStyle Hidden } catch { Fail "Не найдена команда ollama. Установите Ollama с ollama.com и запустите скрипт снова." }
    for ($i = 0; $i -lt 30 -and -not $tags; $i++) { Start-Sleep 1; $tags = OllamaTags }  # Ждём до 30 секунд.
    if (-not $tags) { Fail "Ollama так и не ответила на 127.0.0.1:11434." }
}

# 2. Модель должна быть в Ollama; если её нет, но рядом с Modelfile лежит GGUF, создаём.
$names = @($tags.models | ForEach-Object { $_.name })
if (-not ($names -contains $Model -or $names -contains "${Model}:latest")) {
    $models = Join-Path $backend "models"
    $gguf = Get-ChildItem $models -Filter *.gguf -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $gguf) { Fail "Модели $Model нет в Ollama, а в backend\models нет файла .gguf. Положите туда astraguard-qwen4b.fixed.gguf или создайте модель вручную: ollama create $Model -f Modelfile в папке с GGUF." }
    Say "Создаю модель $Model из $($gguf.Name)"
    Push-Location $models; ollama create $Model -f Modelfile; $code = $LASTEXITCODE; Pop-Location
    if ($code) { Fail "ollama create завершилась с ошибкой." }
}
Say "Ollama и модель $Model на месте"

# 3. Переменные окружения: боевой режим GPU, без облегчённого режима.
Remove-Item Env:DETECTOR_LITE, Env:DETECTOR_TIMEOUT_MS -ErrorAction SilentlyContinue  # Остатки CPU-экспериментов.
$env:OLLAMA_MODEL = $Model
$env:BIND = "0.0.0.0:$Port"
# Токены журнала и политики: берём из backend\.env.local (в git не попадает), а если их нет — создаём.
$envFile = Join-Path $backend ".env.local"
if (Test-Path $envFile) {
    foreach ($line in Get-Content $envFile) {
        if ($line -match '^\s*([A-Z_]+)\s*=\s*(.+?)\s*$') { Set-Item "Env:$($Matches[1])" $Matches[2] }  # Строки вида КЛЮЧ=значение.
    }
}
foreach ($key in "ADMIN_TOKEN", "AUDIT_TOKEN") {
    if (-not (Get-Item "Env:$key" -ErrorAction SilentlyContinue)) {
        $value = -join ((48..57) + (97..122) | Get-Random -Count 28 | ForEach-Object { [char]$_ })  # Случайная строка из цифр и букв.
        Set-Item "Env:$key" $value
        Add-Content $envFile "$key=$value"
        Say "Создан $key, он сохранён в backend\.env.local"
    }
}

# 4. Сборка: если исполняемого файла нет или передан -Build.
$exe = Join-Path $backend "target\release\astraguard.exe"
if ($Build -or -not (Test-Path $exe)) {
    Say "Собираю сервис (cargo build --release)"
    Push-Location $backend; cargo build --release; $code = $LASTEXITCODE; Pop-Location
    if ($code) { Fail "Сборка не удалась, смотрите вывод cargo выше." }
}

# 5. Порт должен быть свободен, иначе это второй экземпляр сервера.
if (Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue) {
    Fail "Порт $Port уже занят: похоже, сервер уже запущен. Закройте его окно или запустите с -Port 8001."
}

# 6. Запуск с перезапуском при падении; логи в backend\logs.
$logs = Join-Path $backend "logs"
New-Item -ItemType Directory -Force -Path $logs | Out-Null
$probe = @{ user_prompt = "Покажи последние логи dev-api"; context = @{ target_agent = "it_ops_agent"; user_role = "developer"; user_id = "startup-check"; user_name = "startup"; history = @(); attachments = @() } } | ConvertTo-Json -Depth 5
while ($true) {
    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $out = Join-Path $logs "server-$stamp.log"
    Say "Запускаю сервер, лог: $out"
    $proc = Start-Process $exe -WorkingDirectory $backend -NoNewWindow -PassThru -RedirectStandardOutput $out -RedirectStandardError "$out.err"
    # Сервер открывает порт только после прогрева модели, поэтому ответ /health значит, что прогрев закончен.
    $up = $false
    for ($i = 0; $i -lt 200 -and -not $proc.HasExited; $i++) {
        Start-Sleep 1
        try { Invoke-RestMethod "http://127.0.0.1:$Port/health" -TimeoutSec 2 | Out-Null; $up = $true; break } catch { }
    }
    if ($up) {
        # Контрольный запрос: безопасная просьба разработчика должна получить allow, а не block по таймауту модели.
        try {
            $r = Invoke-RestMethod "http://127.0.0.1:$Port/v1/check" -Method Post -ContentType "application/json; charset=utf-8" -Body ([Text.Encoding]::UTF8.GetBytes($probe)) -TimeoutSec 15
            if ($r.decision -eq "allow") { Say "ГОТОВ: http://127.0.0.1:$Port (контрольный запрос: allow за $([int]$r.latency_ms) мс)" "Green" }
            else { Say "ВНИМАНИЕ: контрольный запрос получил $($r.decision): $($r.explanation)" "Yellow" }
        } catch { Say "ВНИМАНИЕ: контрольный запрос не прошёл: $($_.Exception.Message)" "Yellow" }
    } elseif (-not $proc.HasExited) {
        Say "Сервер не открыл порт за 200 секунд, смотрите лог $out" "Yellow"
    }
    $proc.WaitForExit()
    Say "Сервер остановился (код $($proc.ExitCode)) в $(Get-Date -Format HH:mm:ss). Перезапуск через 5 секунд, Ctrl+C — выход." "Yellow"
    Start-Sleep 5
}
