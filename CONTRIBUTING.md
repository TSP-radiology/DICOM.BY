# Руководство для участников / Contributing to DICOM.BY

Спасибо за интерес к развитию **DICOM.BY**!

## Как устроен проект

- `apps/` — графическое приложение Windows (`dicom_anon_ui.cpp`, `apps/ui/index.html`, `ui_logic.hpp`, `updater.hpp`), CLI (`dicom_anon_cli.cpp`) и верификатор (`dicom_verify_cli.cpp`).
- `core/anon/` — детерминированное C++17-ядро деидентификации (`PS 3.15`), допуска (`Fail-Closed`), OCR-маскирования пикселей, карантина и верификации.
- `standard/` — таблицы допуска, профили `PS 3.15` (`annex_e.json`), политика атрибутов и клинические словари.
- `tools/installer/` — генератор брендированных активов и сценарий установщика Windows (`Inno Setup 6`).

## Правила перед отправкой Pull Request

1. **Никаких реальных данных пациентов:** в коммитах, тестах и Issues запрещено использовать реальные DICOM-файлы, ФИО, ID или даты рождения.
2. **Офлайн-безопасность UI:** внутри `apps/ui/index.html` запрещены внешние CDN, внешние шрифты, трекеры и сетевые запросы (кроме явного модуля обновлений `apps/updater.hpp`, ограниченного `https://dicom.by/`).
3. **Запуск тестов:** перед отправкой PR обязательно соберите и прогоните `test_ui_logic`:
   ```powershell
   cmake --preset windows-slim
   cmake --build build\win-slim --config Release --target test_ui_logic
   .\build\win-slim\Release\test_ui_logic.exe
   ```

## Соглашение о двойном лицензировании (CLA)

Отправляя Pull Request в репозиторий `TSP-radiology/DICOM.BY`, вы подтверждаете, что являетесь автором изменений (или имеете право их передать) и соглашаетесь с тем, что ваш вклад может распространяться проектом как на условиях **GNU AGPLv3**, так и в рамках **коммерческих лицензий** ([COMMERCIAL_LICENSE.md](COMMERCIAL_LICENSE.md)).
