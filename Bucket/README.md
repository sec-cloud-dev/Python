<div align="center">

# 🪣 Bucket Scanner

### Cloud Security Auditor for Yandex Object Storage

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Yandex Cloud](https://img.shields.io/badge/Yandex_Cloud-Object_Storage-FC3F1D?style=for-the-badge)](https://cloud.yandex.ru/services/storage)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=for-the-badge&logo=docker&logoColor=white)](./docker-compose.yml)
[![Prometheus](https://img.shields.io/badge/Prometheus-Metrics-E6522C?style=for-the-badge&logo=prometheus&logoColor=white)](https://prometheus.io/)
[![Grafana](https://img.shields.io/badge/Grafana-Dashboards-F46800?style=for-the-badge&logo=grafana&logoColor=white)](https://grafana.com/)
[![CI](https://img.shields.io/badge/CI-DevSecOps-0A7B3E?style=for-the-badge&logo=githubactions&logoColor=white)](#-cicd--devsecops)

<br/>

**Не просто ACL-чеклист.**  
Полный security-аудит Object Storage: политики бакета, цепочки `VM → SA → Bucket`, CDN, Cloud Functions и ротация статических ключей — с сохранением в PostgreSQL и визуализацией в Grafana.

<br/>

```text
 ┌──────────────────┐      ┌────────────────────┐      ┌─────────────────┐
 │  Yandex Cloud    │      │   Bucket Scanner   │      │   Observability │
 │  • Object Storage│─────▶│  checks · clients  │─────▶│  PostgreSQL     │
 │  • IAM / Compute │      │  risk engine       │      │  Pushgateway    │
 │  • CDN / Triggers│      │                    │      │  Prometheus     │
 └──────────────────┘      └────────────────────┘      │  Grafana        │
                                                        └─────────────────┘
```

</div>

---

## Содержание

- [О проекте](#-о-проекте)
- [Возможности](#-возможности)
- [Архитектура](#-архитектура)
- [Структура репозитория](#-структура-репозитория)
- [Быстрый старт](#-быстрый-старт)
- [Переменные окружения](#-переменные-окружения)
- [Запуск](#-запуск)
- [Метрики и дашборды](#-метрики-и-дашборды)
- [Хранение результатов](#-хранение-результатов)
- [Модель рисков](#-модель-рисков)
- [Тесты](#-тесты)
- [CI/CD / DevSecOps](#-cicd--devsecops)
- [Безопасность эксплуатации](#-безопасность-эксплуатации)
- [Roadmap](#-roadmap)

---

## О проекте

**Bucket Scanner** — контейнеризированный инструмент cloud security для аудита **Yandex Cloud Object Storage** (S3-compatible).

Он обходит бакеты в указанном folder и для каждого собирает risk-отчёт по:

| Слой | Что анализируется |
|------|-------------------|
| **Конфигурация бакета** | Policy, ACL, CORS, Encryption, Versioning, MFA, Object Lock, Logging, Replication, Lifecycle |
| **Идентичности** | Service Accounts, роли Folder / Cloud / Organization, статические access keys |
| **Цепочки доступа** | Виртуальные машины → SA → бакет (с учётом публичного IP) |
| **Сервисы** | Cloud Functions triggers и CDN origin → неявный публичный доступ |

Результаты:

1. Пишутся в **PostgreSQL** (`scan_result_bucket`)
2. Пушатся в **Prometheus Pushgateway**
3. Доступны в **Grafana** из коробки

> Идеально для периодических security-сканов, DevSecOps pipeline и compliance-аудита (в т.ч. контроль ротации ключей ≥ 90 дней / 152‑ФЗ).

---

## Возможности

### Object Storage checks

| Check | Что считается риском |
|-------|----------------------|
| **Policy** | `Effect: Allow` + Principal `*` / `{"AWS":"*"}` |
| **ACL** | публичные группы `AllUsers`, `AuthenticatedUsers` |
| **CORS** | `AllowedOrigins` содержит `*` |
| **Encryption** | отсутствие SSE-конфигурации |
| **Versioning** | статус версионирования |
| **MFA Delete** | `Disabled` / не настроено |
| **Object Lock** | режим `GOVERNANCE` |
| **Logging** | access logging не включён |
| **Replication** | правила со статусом `Disabled` |
| **Lifecycle** | наличие / отсутствие lifecycle-конфигурации |

### Identity & attack-path checks

| Check | Смысл |
|-------|--------|
| **VM → SA → Bucket** | ВМ с SA, имеющим роли на бакет; **критично**, если у ВМ есть публичный IP |
| **All SA** | все SA с ролями `admin` / `editor` / `storage.admin` / `storage.editor` |
| **Static keys** | ключ ≥ 90 дней → `DANGER`; никогда не использовался → `WARNING` |
| **Cloud Functions** | Object Storage trigger → Function и роли SA вызова |
| **CDN** | бакет как origin **активной** CDN-точки = неявный публичный доступ |

---

## Архитектура

```text
                          ┌─────────────────────────────────────┐
                          │              main.py                │
                          │     orchestration + metrics push    │
                          └─────────────────┬───────────────────┘
                                            │
              ┌─────────────────────────────┼─────────────────────────────┐
              ▼                             ▼                             ▼
     ┌────────────────┐          ┌──────────────────┐          ┌──────────────────┐
     │ boto3_client   │          │  yandex_client   │          │    db_client     │
     │ S3 API         │          │  REST + retry    │          │  PostgreSQL      │
     │ storage.yc.net │          │  + pagination    │          │  JSONB reports   │
     └────────┬───────┘          └────────┬─────────┘          └──────────────────┘
              │                           │
              ▼                           ▼
     ┌────────────────┐          ┌────────────────────────────────────────┐
     │ bucket_checks  │          │ vm_checks · sa_checks · function_checks│
     │ Policy/ACL/... │          │ cdn_checks · risk_utils · extract_utils│
     └────────────────┘          └────────────────────────────────────────┘
```

**Стек:**

| Компонент | Технология |
|-----------|------------|
| Runtime | Python 3.11 |
| Cloud API | `boto3` + Yandex REST |
| Persistence | PostgreSQL 15 |
| Metrics | `prometheus_client` → Pushgateway |
| Visualization | Prometheus + Grafana |
| Packaging | Docker / Docker Compose |
| Reliability | `tenacity` retries, botocore adaptive retries |

---

## Структура репозитория

```text
Bucket/
├── src/
│   ├── main.py                  # оркестрация скана + push метрик
│   ├── config.py                # env, роли, botocore Config
│   ├── cli.py                   # scan --fixture … --fail-on high
│   ├── scanner.py               # запуск всех checks → ScanResult
│   ├── inventory.py             # IAM / VM / SA / keys — один раз на folder
│   ├── fixture.py               # офлайн-fixture вместо Yandex API
│   ├── metrics.py               # Pushgateway gauges по severity
│   ├── checks/
│   │   ├── bucket_checks.py     # S3-политики бакета
│   │   ├── vm_checks.py         # VM → SA → Bucket
│   │   ├── sa_checks.py         # SA roles + static keys
│   │   ├── function_checks.py   # Triggers → Functions
│   │   └── cdn_checks.py        # CDN origin groups
│   ├── clients/
│   │   ├── boto3_client.py      # S3 → storage.yandexcloud.net
│   │   ├── yandex_client.py     # YC REST API
│   │   └── db_client.py         # PostgreSQL persistence
│   └── utils/
│       ├── models.py            # Finding / Severity / ScanResult
│       ├── risk_utils.py        # overall_risk, bindings_source
│       ├── extract_utils.py     # разбор access bindings
│       └── error_utils.py       # единый маппинг ClientError
├── tests/                       # pytest + mocks + fixtures/
├── grafana/provisioning/        # datasource + dashboard
├── prometheus.yml
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
└── requirements-dev.txt
```

---

## Быстрый старт

### Требования

- Docker + Docker Compose **или** Python 3.11+
- доступ к Yandex Cloud (IAM-токен + static key для Object Storage)
- права на чтение: buckets, compute, IAM, CDN, triggers, resource-manager, organization-manager

### 60 секунд до первого скана

```bash
git clone https://github.com/sec-cloud-dev/Python.git
cd Python/Bucket

cp .env.example .env   # или создайте .env вручную (см. ниже)
# заполните TOKEN, FOLDER_ID, CLOUD_ID, key_id, secret_key, пароли БД

docker compose up -d --build
```

| Сервис | URL |
|--------|-----|
| Pushgateway | http://localhost:9091 |
| Prometheus | http://localhost:9090 |
| Grafana | http://localhost:3000 — `admin` / `admin` |
| PostgreSQL | `localhost:5432` |

Сканер (`scanner`) отрабатывает один раз → пишет отчёт в БД → пушит метрики → завершается.

---

## Переменные окружения

Создайте файл `.env` в каталоге `Bucket/`:

```env
# ─── Yandex Cloud ───────────────────────────────────────
TOKEN=<IAM или OAuth токен>
FOLDER_ID=<folder-id>
CLOUD_ID=<cloud-id>
key_id=<static access key id>
secret_key=<static secret key>

# ─── PostgreSQL ─────────────────────────────────────────
POSTGRES_DB=scanner
POSTGRES_USER=scanner
POSTGRES_PASSWORD=<strong-password>

DB_HOST=db
DB_NAME=scanner
DB_USER=scanner
DB_PASSWORD=<strong-password>

# ─── Metrics (опционально) ──────────────────────────────
PUSHGATEWAY_URL=http://pushgateway:9091
```

> `.env` уже в `.gitignore` и `.dockerignore`. **Никогда** не коммитьте секреты.

---

## Запуск

### Docker Compose (рекомендуется)

```bash
cd Bucket
docker compose up -d --build

# логи сканера
docker logs -f scanner_bucket
```

### Локально (без Docker)

```bash
cd Bucket
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt

# поднимите Postgres, заполните .env
python -m src.main
```

### CLI (для других пайплайнов)

```bash
cd Bucket
# офлайн, без учётных данных Yandex Cloud
python -m src.cli scan --fixture tests/fixtures/public_bucket.json --fail-on high

# живой Yandex Cloud (переменные из .env), JSON-отчёт
python -m src.cli scan --fail-on high --format json
```

| Код выхода | Значение |
|------------|----------|
| `0` | находок уровня `--fail-on` и выше нет |
| `1` | есть находки уровня `--fail-on` и выше **или** проверки со статусом `unknown` |
| `2` | скан не выполнен (нет конфигурации, API недоступен) |

CLI не пишет в PostgreSQL и Pushgateway — это делает `python -m src.main`.

### Только образ сканера

```bash
docker build -t bucket-scanner:latest .
docker run --rm --env-file .env --network <compose-network> bucket-scanner:latest
```

---

## Метрики и дашборды

После скана метрики доступны в Pushgateway / Prometheus:

| Metric | Описание |
|--------|----------|
| `scanner_danger_findings` | число findings с `severity=high` |
| `scanner_warning_findings` | число `medium` |
| `scanner_safe_findings` | число `low` / `info` |
| `scanner_unknown_findings` | проверки, которые не удалось выполнить (`unknown`) |
| `scanner_buckets_scanned` | сколько бакетов просканировано |
| `scanner_total_checks` | суммарное число проверок |

Gauges считаются по `Finding.severity` — та же находка, что в логах и отчёте. Folder-level IAM находки считаются один раз на скан, а не на каждый бакет.

**Job name:** `bucket_scanner`

Grafana подхватывает Prometheus datasource и dashboard из `grafana/provisioning/`.

---

## Хранение результатов

Таблица `scan_result_bucket`:

| Поле | Тип | Содержание |
|------|-----|------------|
| `scan_date` | `TIMESTAMP` | время скана |
| `bucket_name` | `TEXT` | имя бакета |
| `policy` … `replication` | `TEXT` | `severity` соответствующей проверки |
| `bindings` | `JSONB` | finding `iam.vm_sa_access` (folder-level) |
| `roles` | `JSONB` | finding `iam.sa_roles` (folder-level) |
| `stat_key` | `JSONB` | finding `iam.static_keys` (folder-level) |
| `function` | `JSONB` | finding `functions.trigger_sa` |
| `cdn` | `JSONB` | finding `cdn.origin` |
| `full_report` | `JSONB` | все findings бакета + folder-level findings |

Пример запроса:

```sql
SELECT bucket_name, policy, acl, cors, bindings, scan_date
FROM scan_result_bucket
ORDER BY scan_date DESC
LIMIT 20;
```

---

## Модель рисков

Каждая проверка возвращает один `Finding` одной формы:

```json
{
  "rule_id": "bucket.acl",
  "severity": "high",
  "bucket": "public-bucket",
  "message": "ACL выдаёт доступ AllUsers/AuthenticatedUsers",
  "evidence": {"grants": [{"URI": "http://acs.amazonaws.com/groups/global/AllUsers", "Permission": "READ"}]}
}
```

| Severity | Когда |
|----------|--------|
| `high` | критичный риск: публичный доступ, опасные роли, ключ ≥ 90 дней |
| `medium` | потенциальный риск / неизвестная роль / ключ не использовался |
| `low` | защитная настройка не задана (шифрование, логирование, lifecycle…) |
| `info` | соответствует безопасной конфигурации |
| `unknown` | проверку не удалось выполнить: ошибка API (HTTP ≠ 2xx), нет прав, неполные данные. **Никогда не считается SAFE** |

IAM-проверки (`iam.vm_sa_access`, `iam.sa_roles`, `iam.static_keys`) читают access bindings на уровне folder / cloud / organization, поэтому это **folder-level** находки (`bucket: "*"`, `evidence.scope: "folder"`): роль действует на все бакеты папки, bucket-level bindings не запрашиваются. IAM, VM, SA и статические ключи загружаются один раз на folder, а не на каждый бакет; `listAccessBindings` и `accessKeys` читаются постранично.

Роли задаются в `src/config.py`:

```python
DANGEROUS_ROLES = {"storage.admin", "storage.editor", "admin", "editor"}
SAFE_ROLES      = {"storage.viewer", "storage.configViewer", "viewer"}
```

### Пример критичной цепочки

```text
VM (public IP: yes)
 │
 └── SA  ──roles: admin / storage.editor──▶  Bucket
                                               │
                                               └── overall: DANGER
```

`overall_risk()` агрегирует: любой `DANGER` в наборе поднимает итоговый статус до `DANGER`.

---

## Тесты

```bash
pip install -r requirements-dev.txt
pytest
```

Тесты не требуют учётных данных Yandex Cloud: `tests/fixtures/public_bucket.json` описывает публичный бакет (Policy `Principal "*"`, ACL `AllUsers`) и приватный бакет.

Покрытые сценарии:

- Public ACL / Policy → `high`, и `scanner_danger_findings` растёт вместе с ними
- HTTP ≠ 2xx от Yandex API → `unknown`, а не `SAFE`
- пагинация `listAccessBindings` и `accessKeys`, inventory загружается один раз на folder
- VM + public IP + dangerous role → `high`; static key ≥ 90 дней → `high`, never used → `medium`
- CLI: `--fail-on high` → exit code `1`

---

## CI/CD / DevSecOps

Workflow в корне репозитория — `.github/workflows/ci.yml` (GitHub подхватывает workflows только оттуда):

```text
push / pull_request → main        (working-directory: Bucket)
   │
   ├── install deps     requirements-dev.txt
   ├── pytest           офлайн, на fixture
   ├── flake8           lint
   └── bandit -r src    SAST
```

Docker / Trivy / push в registry в этот workflow пока не входят.

---

## Безопасность эксплуатации

| Практика | Реализация |
|----------|------------|
| Non-root контейнер | `USER appuser` (UID `1001`) |
| Секреты вне образа | `.env` в `.dockerignore` |
| Устойчивость API | `tenacity` (3 попытки, exponential backoff) |
| S3 retries | botocore `adaptive` mode |
| Least privilege | сканеру нужны только **read** права |
| Ротация ключей | алерт при возрасте ≥ 90 дней |

**Рекомендации:**

1. Используйте отдельный SA только для сканера (read-only где возможно).
2. Ротируйте `TOKEN` / static keys регулярно.
3. Смените дефолтный пароль Grafana (`admin`/`admin`) перед продом.
4. Не публикуйте порты Postgres / Grafana в internet без ACL / VPN.

---

## Лицензия и контекст

Проект из организации **[sec-cloud-dev](https://github.com/sec-cloud-dev)** — практика cloud security / DevSecOps для аудита Object Storage в Yandex Cloud.

Репозиторий: [`sec-cloud-dev/Python` → `Bucket/`](https://github.com/sec-cloud-dev/Python/tree/main/Bucket)

---

<div align="center">

### Scan wisely. Least privilege. Rotate keys.

<br/>

`python -m src.main`

<br/>

<sub>Built for Yandex Cloud · Object Storage · DevSecOps</sub>

</div> 
