# Руководство для участников / Contributing to DICOM.BY Trust Hub

Спасибо за интерес к открытому контуру верификации **DICOM.BY**!

## Состав публичного репозитория (`Trust Hub`)

- `verify/` — независимый открытый верификатор `dicom_by_verify.py` и самотесты `test_verify.py` (лицензия **MIT**).
- `standard/admission_v5.json` — запечатанная матрица допустимых DICOM-классов и форматов пикселей (лицензия **MIT**).
- `RELEASE_MANIFEST.json` — подписанный **Ed25519** паспорт доказательств и контрольных сумм релиза.
- `DATA_SOURCES.md` и `tools/release/data_licenses/` — реестр открытых источников словарей и лицензий.

*(Исходный код коммерческого/бесплатного C++ движка, шлюза PACS и настольного приложения закрыт — см. [LICENSE](LICENSE) и [COMMERCIAL_LICENSE.md](COMMERCIAL_LICENSE.md).)*

## Правила перед отправкой Pull Request

1. **Никаких реальных данных пациентов:** в коммитах, фикстурах тестов и Issues строго запрещено публиковать реальные DICOM-файлы, ФИО, ID или даты рождения пациентов.
2. **Самопроверка верификатора:** перед отправкой изменений в `verify/` убедитесь, что проходят все модульные и саботажные проверки:
   ```bash
   python verify/test_verify.py
   python verify/dicom_by_verify.py --evidence RELEASE_MANIFEST.json --admission standard/admission_v5.json
   ```

## Лицензирование вкладов

Отправляя Pull Request в открытые компоненты репозитория `TSP-radiology/DICOM.BY` (`verify/`, документация), вы соглашаетесь на распространение вашего вклада на условиях лицензии **MIT** ([LICENSE](LICENSE)).
