# Сторонние компоненты и модели DICOM.BY

Исходный код DICOM.BY Community Edition распространяется под **GNU AGPLv3** ([LICENSE](LICENSE)), а используемые библиотеки и модели — на условиях своих лицензий:

| Компонент | Назначение | Лицензия |
|---|---|---|
| **DCMTK** | Чтение, валидация и запись файлов DICOM PS 3.10/3.15 | BSD 3-Clause (`OFFIS`) |
| **OpenSSL** (`libcrypto`) | Криптография (HMAC-SHA256, SHA-256, UID/Date pseudonymization) | Apache-2.0 |
| **ONNX Runtime** | Инференс нейросетевых детекторов и распознавания текста | MIT |
| **OpenCV** (`core`, `imgproc`) | Подготовка и маскирование областей изображений | Apache-2.0 |
| **OpenJPEG** | Декодирование и перекодирование JPEG 2000 | BSD 2-Clause |
| **Clipper2** | Геометрия пересечений и слияние рамок OCR | Boost Software License 1.0 |
| **nlohmann/json** | Работа с сертификатами `.deid.json`, манифестами и таблицами | MIT |
| **yaml-cpp** | Загрузка клинических словарей `.yaml` | MIT |
| **zlib** | Сжатие и потоки данных | Zlib License |
| **Microsoft Edge WebView2 SDK** (`WebView2LoaderStatic`) | Встраиваемый интерфейс настольного приложения Windows | Microsoft Software License (`third_party/webview2/LICENSE.txt`) |

Происхождение и лицензии моделей OCR описаны в `models/ppocr/SOURCE.md`, `models/cyrillic/SOURCE.md` и `models/eslav/SOURCE.md`.
Происхождение клинических словарей и таблиц описано в [DATA_SOURCES.md](DATA_SOURCES.md) и `tools/release/data_licenses/RadLex_License_v2.1.pdf`.
