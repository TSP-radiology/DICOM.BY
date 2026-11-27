# Сторонние компоненты и модели DICOM.BY

Бинарные пакеты `DICOM.BY Desktop Free` распространяются бесплатно по условиям [LICENSE](LICENSE) (офлайн-регистрация `Ed25519`), а открытый верификатор `verify/` и матрица `standard/admission_v5.json` — на условиях лицензии **MIT**. Используемые библиотеки и модели включены на условиях своих лицензий:

| Компонент | Назначение | Лицензия |
|---|---|---|
| **DCMTK** (`3.6.9`) | Чтение, валидация, DICOM TLS/mTLS и запись файлов DICOM PS 3.10/3.15 | BSD 3-Clause (`OFFIS`) |
| **OpenSSL** (`3.5.3`) | Криптография (HMAC-SHA256, SHA-256, Ed25519, DICOM TLS 1.2/1.3) | Apache-2.0 |
| **ONNX Runtime** (`1.22.0`) | Локальный CPU-инференс детекторов OCR и `DicomEtaNER-v1` (INT8) | MIT |
| **OpenCV** (`core`, `imgproc`) | Подготовка и маскирование областей изображений | Apache-2.0 |
| **OpenJPEG** (`2.5.3`) | Декодирование JPEG 2000 | BSD 2-Clause |
| **Clipper2** | Геометрия пересечений и слияние рамок OCR | Boost Software License 1.0 |
| **nlohmann/json** | Работа с сертификатами `.deid.json`, манифестами и таблицами | MIT |
| **yaml-cpp** | Загрузка клинических словарей `.yaml` | MIT |
| **zlib** | Сжатие и потоки данных | Zlib License |
| **Microsoft Edge WebView2 SDK** (`WebView2LoaderStatic`) | Встраиваемый интерфейс настольного приложения Windows | Microsoft Software License |

Происхождение и лицензии моделей OCR (`PP-OCRv4`, `PP-OCRv5 Slavic`) и `DicomEtaNER-v1` включены в каталог `models/*/SOURCE.md` установленной поставки, а происхождение клинических словарей и таблиц описано в [DATA_SOURCES.md](DATA_SOURCES.md) и `tools/release/data_licenses/RadLex_License_v2.1.pdf`.
