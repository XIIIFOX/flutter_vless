# Закрытие библиотечных пунктов аудита — 12 сентября 2026

База: `ea49e0e5102655239fb8c6058cd8f609804add1e`.
Задание: `output/security/flutter-vless-library-work-items.md`, версия от 9 сентября.
Область: библиотека, пример provider, тесты и собственная поставка; изменения
ProxyControl и гарантии macOS/Windows сюда не входят. По указанию пользователя
iOS проверяется локально без подключённого физического устройства; VPN компьютера
остаётся включённым. Android проверяется локально и на эмуляторе.

Все 83 библиотечных требования реализованы и прошли описанную ниже локальную
приёмку. Независимая проверка кандидата и исправления найденных дефектов завершены.
CI повторяет публичные проверки без приватных профилей. Наличие строки в таблице
не означает прохождение физической приёмки iOS: её ограничения указаны отдельно.

## Проверки

| Проверка | Результат | Что доказывает |
|---|---|---|
| `flutter test` | PASS, 54 теста | Общие API, старые defaults, explicit capability rejection, локальные account models и парсеры |
| `tool/test_ios_tunnel_support.sh` | PASS, 42 теста | Авторизация, DNS/IPv6/privacy, Keychain fault boundary, миграция HEV |
| `tool/test_ios_manager_policy.sh` | PASS | Реальный manager со stub SDK: транзакции, rollback, миграция, cleanup, permission, сохранение политики |
| `tool/test_ios_operation_queue.sh` | PASS | Последовательность start/stop и однократный ответ при гонках |
| `tool/test_ios_hev_auth.sh` | PASS | Настоящий parser закреплённого HEV принимает идентичный runtime YAML с username/password |
| `tool/test_ios_local_proxy_transport.sh`, также `TEST_REAL_HTTPS=1` | PASS | Строгий RFC1929, HTTP CONNECT, неверный пароль/noauth downgrade, TLS trust/hostname, HTTPS через существующий VPN компьютера |
| `tool/test_ios_privacy_runtime.sh` на iOS 26.5 simulator | PASS | Настоящий Xray: отказ noauth/wrong, HTTP на SOCKS-порту, данные с верными реквизитами, приватность заголовков, HTTP/SOCKS DNS TCP+UDP и recovery/refusal |
| `flutter build ios --debug --no-codesign` | PASS | CocoaPods app/plugin + SwiftPM tunnel support и пример provider |
| `xcodebuild -workspace example/ios/Runner.xcworkspace -scheme flutter-vless ... build` | PASS | Отдельный SwiftPM plugin с общим Security-модулем |
| `tool/test_android_dependency_verification.py` | PASS | Реальный Gradle принимает официальный AAR/POM и отклоняет изменённые файлы с прежними координатами |
| Official Gradle verification: normal/repo override/version override | PASS | Требуется strict, неожиданный override отклоняется |
| Android JVM через explicit local Maven wrapper | PASS, 38 тестов; local wrapper также PASS | Native source inputs проверены, локальный AAR проверен, strict metadata восстановлена после проверки |
| Android NativeLocalAuthorizationTest | PASS, 2 device-теста | Настоящий Xray: авторизация и данные; настоящий Keystore: шифрование, tamper и disarm |
| Android host UID TCP/UDP через TUN | PASS | Настоящий tun2socks: YAML auth и передача FD, пакеты самого приложения проходят прокси |
| `tool/test_android_maven_runtime.sh` | PASS | Official AAR/POM; изменённые AAR/POM отвергаются; repo/version/verification=off отвергаются; реальный example APK содержит закреплённые native binaries |
| Android быстрые START/STOP | PASS | 10 пар START/STOP, затем последний START готов; файлы новой сессии сохраняются, финальный STOP удаляет авторизацию и временные конфиги |
| `tool/test_android_security_emulator.sh` | PASS, 21/21, 0 skip | Авторизация, worker/service recovery, host TCP/UDP, routing, Wi-Fi↔cellular, HTTP/SOCKS/VLESS DNS, physical resolver control, replacement/delay/system policy |
| Android physical DNS capture | PASS | 1479 packets, 0 controlled direct DNS; HTTP 5/SOCKS 7/VLESS 5 положительных наблюдений; direct TCP stream gaps=0 |
| Android системная политика VPN | PASS, 4 targeted device-теста | Настоящие Android Settings: always-on/lockdown, восстановление после смерти service, STOP, потеря Keystore-ключа, Forget VPN/onRevoke; посторонний UID остаётся заблокированным при lockdown |
| Android смена сессии и измерение задержки | PASS, 2 targeted device-теста | Старые реквизиты отвергаются новой сессией; STOP → invalid START не оставляет workers; два временных delay runtime и межпроцессный connected delay; Authenticator приложения сохранён |
| Два предоставленных VLESS/Reality профиля на Android | PASS, оба профиля, до/после recovery | Исходные два входа в proxyOnly; VPN отклоняет несовместимый второй вход до смены сессии; эквивалент с одним входом разделяет HTTPS-сайты по native direct/proxy counters и сохраняет правила после падения Xray |
| `tool/test_android_separate_uid.py` | PASS | Отдельный APK UID: SOCKS/HTTP noauth и wrong отвергаются, правильный пароль передаёт данные; origin не получает Proxy-Authorization. Broker блокируется ОС; same-UID real FD control проходит |
| Два предоставленных VLESS/Reality профиля на iOS simulator | PASS | Реальные HTTPS-запросы, исходный proxyOnly с двумя входами; защищённые domain rules direct/proxy, native outbound counters, две генерации каждого runtime |

Итоговый общий Android run: `build/android-security-emulator.Dc18RVQb/summary.json`,
`dns-capture-verification.json` в том же каталоге. Он выполнен после последних
изменений service и включает все дополнительные публичные сценарии. Приватные
профили проверены отдельно и не включены в публикуемые артефакты.

## По каждому требованию

В колонке «Проверка» указан пакет доказательств, применяемый к требованию. Device
и simulator не смешиваются: сетевые гарантии iOS на физическом интерфейсе остаются
отдельной приёмкой интегрирующего приложения.

### IOS-C04: Сохранить защищённый DNS при следующих изменениях

| Пункт | Требование | Проверка |
|---|---|---|
| IOS-C04.1 | Дополнить существующие проверки связки «виртуальный DNS → локальный SOCKS → DNS-outbound по TCP → выбранный прокси» для HTTP- и SOCKS-сервера. Не дублировать уже существующие проверки полей JSON; добавить недостающее покрытие фактической интеграции. | iOS DNS runtime fixture + DNS/IPv6 XCTest |
| IOS-C04.2 | Зафиксировать, что правило приложения UDP → direct не перехватывает запросы к виртуальному системному резолверу: служебные DNS-правила должны иметь более высокий приоритет. | iOS DNS runtime fixture + DNS/IPv6 XCTest |
| IOS-C04.3 | Сохранить предварительное разрешение имени самого прокси до установки туннельного DNS. После активации маршрутов не добавлять fallback системного DNS для пользовательских запросов. | iOS DNS runtime fixture + DNS/IPv6 XCTest |
| IOS-C04.4 | В документации обозначить обе части решения: Swift helper и актуальный пример PacketTunnelProvider. Указать, что обновление только Dart-пакета не меняет код чужого extension target. | iOS DNS runtime fixture + DNS/IPv6 XCTest |
| IOS-C04.5 | В описание устройства проверки добавить отдельную проверку DNS после восстановления транспорта, а не только при первом соединении. | iOS DNS runtime fixture + DNS/IPv6 XCTest |

### IOS-M02: Сохранить блокировку трафика во время восстановления

| Пункт | Требование | Проверка |
|---|---|---|
| IOS-M02.1 | После добавления локальной авторизации и Keychain проверить пути внутреннего восстановления: отказ SOCKS-авторизации, недоступный секрет, падение HEV/Xray, ошибка конфигурации, смена сети. | manager/operation queue + provider runtime/auth tests |
| IOS-M02.2 | Временная ошибка должна оставлять установленную защиту и статус CONNECTING. Повторный запуск транспорта не должен вызывать метод менеджера stop, отключать on-demand или удалять маршруты. | manager/operation queue + provider runtime/auth tests |
| IOS-M02.3 | Сохранить поведение явного stopVless: отключить on-demand, отключить профиль, остановить туннель. Не менять смысл публичного метода stopVless ради маскировки ошибок приложения. | manager/operation queue + provider runtime/auth tests |
| IOS-M02.4 | После перехода на Keychain не выдавать CONNECTED, пока не прочитан рабочий конфиг и не подтверждена авторизованная передача данных. | manager/operation queue + provider runtime/auth tests |
| IOS-M02.5 | Уточнить библиотечную документацию: CONNECTED подтверждает готовность обслуживаемого тракта, а не доступность каждого outbound произвольного конфига. | manager/operation queue + provider runtime/auth tests |

### IOS-M01: Авторизация внутренних SOCKS/HTTP-входов

| Пункт | Требование | Проверка |
|---|---|---|
| IOS-M01.1 | Для новой VPN-сессии генерировать случайные username/password системным криптографическим генератором. Пароль — не менее 128 бит энтропии; формат должен безопасно сериализоваться в JSON и конфиг HEV. | local access/transport XCTest + real Xray/HEV fixtures |
| IOS-M01.2 | Применять их к управляемому библиотекой локальному SOCKS-входу. Сохранять привязку к loopback. Порт сам по себе не является средством авторизации. | local access/transport XCTest + real Xray/HEV fixtures |
| IOS-M01.3 | Передавать те же реквизиты HEV. Проверить интерфейс именно зафиксированной версии Tun2SocksKit/HEV до выбора конкретных ключей конфигурации. Если поддержка отсутствует, включить необходимое изменение bridge/runtime в эту же задачу; выпуск частичной реализации запрещён. | local access/transport XCTest + real Xray/HEV fixtures |
| IOS-M01.4 | Обновить все внутренние SOCKS-клиенты: согласование метода username/password, затем авторизация, затем CONNECT/UDP ASSOCIATE. Неверный пароль не должен приводить к повторной попытке noauth. | local access/transport XCTest + real Xray/HEV fixtures |
| IOS-M01.5 | Обновить временный HTTP-прокси ServerDelayRunner: сейчас buildDelayConfigData заменяет settings на пустой объект. Требуется авторизация и её поддержка клиентом URLSession; данные Proxy-Authorization не должны попадать на конечный HTTP-сервер. | local access/transport XCTest + real Xray/HEV fixtures |
| IOS-M01.6 | Не перезаписывать удалённые users/password/id/keys в outbounds. Локальная авторизация и учётные данные удалённого прокси — разные сущности. | local access/transport XCTest + real Xray/HEV fixtures |
| IOS-M01.7 | Описать и реализовать правило для дополнительных SOCKS/HTTP-inbounds из raw JSON: в обычном VPN-режиме нельзя оставлять незамеченный второй noauth-вход. Управляемые входы защищать; явно пользовательские несовместимые входы отклонять с понятной ошибкой, не менять их назначение молча. | local access/transport XCTest + real Xray/HEV fixtures |
| IOS-M01.8 | Для proxyOnly сохранить отдельный контракт: открытый локальный прокси может быть осознанным назначением режима. Поддержать конфигурацию авторизации и документировать явный noauth; не распространять на такой режим обещание изоляции VPN-входов. | local access/transport XCTest + real Xray/HEV fixtures |
| IOS-M01.9 | Не генерировать новые секреты при каждом getFullConfiguration/парсинге ссылки. Реквизиты принадлежат работающей сессии и не должны попадать в экспортируемую подписку. | local access/transport XCTest + real Xray/HEV fixtures |
| IOS-M01.10 | При внутреннем рестарте сохранять согласованность реквизитов Xray и HEV. При новой сессии менять их. Не отдавать пароль через status/debug snapshot. | local access/transport XCTest + real Xray/HEV fixtures |

### IOS-M05: Хранить секретный конфиг в Keychain, в VPN-профиле — ссылку

| Пункт | Требование | Проверка |
|---|---|---|
| IOS-M05.1 | Хранить полный секретный конфиг в Keychain item. В providerConfiguration оставить версию схемы, persistent reference и не секретные параметры запуска. | SecretStore XCTest + real manager fault fixture + обе сборки |
| IOS-M05.2 | Схема providerConfiguration: configSchemaVersion=2, xrayConfigReference=Data persistent ref, keychainAccessGroup и не секретные параметры; xrayConfig отсутствует. | SecretStore XCTest + real manager fault fixture + обе сборки |
| IOS-M05.3 | Использовать общий Keychain access group приложения и расширения. Существующая настройка App Group не заменяет настройку совместного доступа к Keychain. Добавить соответствующие entitlements в пример и документировать настройку для потребителя. | SecretStore XCTest + real manager fault fixture + обе сборки |
| IOS-M05.4 | Если группе нужен явный параметр, добавить необязательный iOS-параметр keychainAccessGroup в initializeVless и передать его через платформенный контракт. Не вычислять Team ID из произвольной строки App Group. Отсутствие нужного доступа должно давать структурированную ошибку, без fallback к plaintext. | SecretStore XCTest + real manager fault fixture + обе сборки |
| IOS-M05.5 | Базовый класс доступности — AfterFirstUnlockThisDeviceOnly, synchronizable=false. Он подходит для восстановления в фоне после первого разблокирования. До первого unlock после перезагрузки конфиг может быть недоступен: соединение не должно переходить в прямой режим. | SecretStore XCTest + real manager fault fixture + обе сборки |
| IOS-M05.6 | Сохранять обновление транзакционно: новый Keychain item → успешное сохранение VPN-профиля с новой ссылкой → проверка чтения → удаление старого item, когда им уже не пользуется активный provider. При ошибке сохранять работоспособность старой конфигурации и удалять ненужный новый item. | SecretStore XCTest + real manager fault fixture + обе сборки |
| IOS-M05.7 | Миграция старого профиля выполняется содержащим приложением через код плагина при загрузке/активации: прочитать legacy xrayConfig, сохранить в Keychain, записать профиль со ссылкой, удалить legacy-ключ из providerConfiguration. | SecretStore XCTest + real manager fault fixture + обе сборки |
| IOS-M05.8 | Новый provider должен иметь явно определённое поведение для немигрированного профиля после обновления: безопасная ошибка с требованием открыть приложение для миграции; не запускаться с молчаливым fallback на legacy plaintext. Если защитные маршруты уже установлены, их не снимать из-за отсутствия секрета. | SecretStore XCTest + real manager fault fixture + обе сборки |
| IOS-M05.9 | Обновить путь запроса разрешения: он не должен сохранять полный конфиг или включать recovery только ради показа системного согласия. | SecretStore XCTest + real manager fault fixture + обе сборки |
| IOS-M05.10 | При удалении VPN-профиля удалить связанный Keychain item после завершения использующей его сессии. Обычный stopVless не должен безоговорочно удалять профильный секрет, который нужен для последующего разрешённого запуска. | SecretStore XCTest + real manager fault fixture + обе сборки |
| IOS-M05.11 | Проверить большие пользовательские конфиги. При невозможности сохранить значение возвращать понятную ошибку без усечения и без записи в открытый файл. Альтернативное зашифрованное файловое хранение не добавлять незаметно в рамках этой реализации. | SecretStore XCTest + real manager fault fixture + обе сборки |
| IOS-M05.12 | Обеспечить сборку нового общего модуля через оба поддерживаемых пути — CocoaPods и SwiftPM. | SecretStore XCTest + real manager fault fixture + обе сборки |

### IOS-H04: Очистить старый HEV debug-файл при переходе на новую политику

| Пункт | Требование | Проверка |
|---|---|---|
| IOS-H04.1 | Ввести версию политики HEV-лога или новое имя для error-only файла. | HEV log migration XCTest + HEV parser |
| IOS-H04.2 | До запуска HEV, когда старый процесс гарантированно завершён, удалить известный legacy-файл hev-socks5-tunnel.log из использовавшихся библиотекой каталогов: App Group и temporaryDirectory расширения. | HEV log migration XCTest + HEV parser |
| IOS-H04.3 | Удалять только конкретные библиотечные имена. Не очищать весь App Group и не читать/перепубликовывать старое содержимое. | HEV log migration XCTest + HEV parser |
| IOS-H04.4 | Сохранить error-level и ограничения размера. Не возвращать адреса соединений через новый snapshot. | HEV log migration XCTest + HEV parser |
| IOS-H04.5 | Не считать trimIfNeeded эквивалентом удаления исторических чувствительных записей. | HEV log migration XCTest + HEV parser |

### ANDROID-C04: Предоставить библиотечную политику DNS через прокси

| Пункт | Требование | Проверка |
|---|---|---|
| ANDROID-C04.1 | Добавить чистый AndroidTunnelDnsPolicy, по устройству аналогичный iOS helper, но независимый от NetworkExtension. | Android DNS policy/broker tests + full emulator/pcap PASS |
| ANDROID-C04.2 | В режиме proxy объявлять виртуальный системный DNS; в Xray передавать DNS-запросы по TCP через выбранный proxy-outbound, включая HTTP-прокси без UDP. | Android DNS policy/broker tests + full emulator/pcap PASS |
| ANDROID-C04.3 | Добавлять служебное правило выше пользовательского UDP → direct. Само правило direct для остальных назначений сохранять. | Android DNS policy/broker tests + full emulator/pcap PASS |
| ANDROID-C04.4 | Явно определять proxy-outbound: использовать подходящий тег proxy; при отсутствии — единственный подходящий outbound. При неоднозначности требовать указать тег или отклонять конфиг. Не выбирать произвольный сервер молча. | Android DNS policy/broker tests + full emulator/pcap PASS |
| ANDROID-C04.5 | Проверять коллизии служебных тегов и конфликт виртуального DNS-адреса с endpoint/маршрутизацией до переключения работающей сессии. | Android DNS policy/broker tests + full emulator/pcap PASS |
| ANDROID-C04.6 | Отделить bootstrap имени VPN-сервера от DNS пользовательского трафика. Физический DNS broker не должен становиться fallback для запросов пользователей защищённого режима. | Android DNS policy/broker tests + full emulator/pcap PASS |
| ANDROID-C04.7 | При недоступном DNS через proxy возвращать ошибку/ожидать восстановления; не переключаться на публичный резолвер напрямую. | Android DNS policy/broker tests + full emulator/pcap PASS |
| ANDROID-C04.8 | Документировать: такой режим защищает системный DNS, но не отменяет специально настроенный direct к другим DNS/DoH-адресатам и не шифрует незашифрованный транспорт удалённого прокси. | Android DNS policy/broker tests + full emulator/pcap PASS |

### ANDROID-M02: Удерживать защиту при внутреннем восстановлении и корректно поддерживать системный запуск

| Пункт | Требование | Проверка |
|---|---|---|
| ANDROID-M02.1 | VPN service владеет сессией: restartWorkers сохраняет TUN; deactivateSession вызывается при явной деактивации; системный запуск восстанавливает только разрешённый зашифрованный профиль. | SessionRecoveryDeviceTest; SystemPolicy restore/STOP/Forget VPN PASS |
| ANDROID-M02.2 | Удалить безусловную полную cleanup перед повторным START для уже активной VPN-сессии. Сначала проверить новый конфиг; затем переключать workers, сохраняя захват трафика. | SessionRecoveryDeviceTest invalid replacement; SessionReplacementDeviceTest PASS |
| ANDROID-M02.3 | Ошибки запуска/рестарта workers после установления TUN переводить в CONNECTING/recovering. Удерживать TUN даже при исчерпании повторов; наружу сообщать причину, а не отключать защиту автоматически. | SessionRecoveryDeviceTest Xray/tun crash; captured TUN and no direct control PASS |
| ANDROID-M02.4 | Обработать ошибки передачи FD в tun2socks. Исчерпание попыток должно быть явным состоянием восстановления, а не молчаливым продолжением с фиктивно успешным соединением. | FileDescriptorTransferTest: 10 failures/9 backoffs, cancellation/stale generation; real FD TUN traffic PASS |
| ANDROID-M02.5 | Уведомлять service о падении Xray. Сейчас stopCoreAfterUnexpectedExit меняет состояние ядра и уведомления; добавить координированный перезапуск всей рабочей цепочки без потери TUN. | SessionRecoveryDeviceTest Xray crash/restart; domain routing after recovery PASS |
| ANDROID-M02.6 | Сохранять session generation и проверку владельца callback. Поздний callback старого процесса не должен остановить новую сессию или обновить её счётчики. | SessionRecoveryPolicyTest; rapid START/STOP and replacement device tests PASS |
| ANDROID-M02.7 | Ограничить повторные попытки по частоте; после backoff продолжать блокировать трафик и ожидать восстановления/явного действия, не создавать бесконечный быстрый цикл. | SessionRecoveryPolicyTest + FileDescriptorTransferTest; worker recovery device tests PASS |
| ANDROID-M02.8 | Сохранять минимальный необходимый профиль для системного восстановления. Поскольку он содержит удалённые секреты, использовать зашифрованное хранилище с ключом Android Keystore и исключением файла из backup. Не переносить полный JSON в обычные SharedPreferences. Это зависимость задачи восстановления, а не перенос в библиотеку замечания H-01 о профилях ProxyControl. | NativeLocalAuthorizationTest AES-GCM/tamper/disarm; actual Keystore key-loss test PASS |
| ANDROID-M02.9 | null Intent или системный Intent без COMMAND должны восстанавливать разрешённую сессию из сохранённого состояния. Отсутствующий/нерасшифровываемый профиль — отдельная диагностируемая ошибка; не запускать произвольный последний файл. | SystemPolicy always-on restore/key-loss; SessionRecoveryDeviceTest service restart PASS |
| ANDROID-M02.10 | Явный STOP отключает внутреннее автоматическое восстановление. Поведение при системном always-on/lockdown должно соответствовать политике ОС; библиотека не должна обещать отключить её без участия пользователя/администратора. | SystemPolicy actual lockdown + STOP + other UID blocked; Forget VPN revocation PASS |
| ANDROID-M02.11 | CONNECTED выставлять после готовности реального тракта Xray → локальный SOCKS → tun2socks, а не только после появления процесса. Счётчики не заменяют проверку передачи данных. | ProtectedHostTrafficTest real TCP/UDP; native SOCKS/FD readiness; controlled routing PASS |
| ANDROID-M02.12 | До завершения поддержки системного запуска не считать SUPPORTS_ALWAYS_ON=true доказательством её работоспособности. Если исправление выпускается поэтапно, метаданные и документация должны отражать фактическую поддержку. | SystemPolicy actual Settings always-on/lockdown restoration PASS; manifest/docs aligned |

### ANDROID-M01: Защитить локальный SOCKS и убрать ненужный HTTP-вход

| Пункт | Требование | Проверка |
|---|---|---|
| ANDROID-M01.1 | Генерировать реквизиты внутреннего SOCKS в service через SecureRandom; не передавать их в пользовательский Dart-конфиг. Добавить отдельный контекст локального доступа, который получает runtime-конструктор. | LocalProxyAccessPolicyTest; native session authorization |
| ANDROID-M01.2 | В штатном VPN-режиме поднимать управляемый SOCKS с auth=password и accounts. Применять защиту также к уже присутствующему управляемому входу, а не только к автоматически добавленному. | XrayCoreManagerTest; native authorization + authenticated TUN traffic |
| ANDROID-M01.3 | Убрать безусловную вставку HTTP-inbound из обычного VPN-пути. По текущему коду задержки измеряются через SOCKS; подтвердить отсутствие другого внутреннего потребителя перед удалением. | XrayCoreManagerTest; default runtime listener tests |
| ANDROID-M01.4 | Если отдельному режиму HTTP-вход нужен, создавать его только для этого режима и с авторизацией. Не оставлять открытый HTTP как обход защищённого SOCKS. | LocalProxyAccessPolicyTest; separate-UID SOCKS/HTTP controls |
| ANDROID-M01.5 | Передать реквизиты tun2socks и обновить измерения задержки. Проверить поведение Java SOCKS-клиента для выбранной авторизации; не устанавливать глобальный Authenticator с библиотечными секретами на весь процесс приложения. | AuthenticatedSocksClientTest; real tun2socks TCP/UDP; SessionDelayDeviceTest IPC PASS |
| ANDROID-M01.6 | Для временного runtime getServerDelay создавать отдельные реквизиты и освобождать их вместе с процессом. Не повторно использовать секреты активной VPN-сессии. | SessionDelayDeviceTest: two independent temporary runtimes, separate credentials and cleanup PASS |
| ANDROID-M01.7 | Не печатать команду запуска с userinfo. Предпочесть поддерживаемый runtime механизм конфигурационного файла/FD; если выбранная версия его не поддерживает, описать и включить необходимое изменение запуска. Один только percent-encoding URI не скрывает секрет. | Private YAML launch path; real tun2socks runtime + safe diagnostics tests |
| ANDROID-M01.8 | Временные конфиги с локальными и удалёнными реквизитами хранить только в приватном, не резервируемом каталоге; удалять после остановки соответствующей сессии, не затрагивая файлы новой сессии. Не выдавать их через snapshot. | SessionRuntimeFilesTest; whole-service crash cleanup; actual key-loss cold start removes orphan xray/tun/validate files; stop/replacement PASS |
| ANDROID-M01.9 | Как на iOS, проверить дополнительные пользовательские HTTP/SOCKS-входы. В штатном VPN-режиме не допускать незамеченного noauth-обхода; несовместимую конфигурацию отклонять до изменения текущей сессии. | Mixed-case/duplicate alias regression; native rejection before session mutation |
| ANDROID-M01.10 | Для явного proxyOnly описать отдельную семантику пользовательских входов. Не ломать намеренно предоставляемый внешний локальный прокси молчаливой заменой реквизитов. | proxyOnly accounts/users tests; explicit exclusion/proxyOnly device test |
| ANDROID-M01.11 | Сохранить локальный StatsService и его маршрутизацию; не удалять API-inbound вместе с ненужным HTTP-inbound. | StatsService config tests; controlled routing native counter assertions |

### ANDROID-L10: Убрать подробное tun2socks-логирование по умолчанию

| Пункт | Требование | Проверка |
|---|---|---|
| ANDROID-L10.1 | Заменить фиксированный debug на error по умолчанию. Значение должно поддерживаться упакованной версией tun2socks. | diagnostics tests + full emulator PASS |
| ANDROID-L10.2 | Убрать безусловный вывод полной команды запуска и исходных строк tun2socks в Log.d. | diagnostics tests + full emulator PASS |
| ANDROID-L10.3 | Для logcat и сохранённой диагностики использовать один безопасный набор событий: запуск, остановка, код выхода, стадия ошибки, число повторов и числовые показатели. | diagnostics tests + full emulator PASS |
| ANDROID-L10.4 | Произвольную строку native stderr/stdout не считать безопасной только потому, что это error. Если невозможно надёжно выделить безопасный код события, выдавать общее сообщение без исходного текста. | diagnostics tests + full emulator PASS |
| ANDROID-L10.5 | Не сохранять исходный tun2socks-текст через обходной вызов XrayDiagnosticsStore.append. Существующее ограничение размера оставить, но дополнить контролем содержимого. | diagnostics tests + full emulator PASS |
| ANDROID-L10.6 | Выполнить ограниченную миграцию старого библиотечного диагностического файла, который мог содержать tun2socks debug. Очистку выполнять без гонки с активной новой сессией; старое содержимое не выводить в snapshot. | diagnostics tests + full emulator PASS |
| ANDROID-L10.7 | Не добавлять отдельный полноценный режим сбора чувствительных логов в эту задачу. Если такой режим потребуется позднее, он должен иметь отдельный явный контракт. | diagnostics tests + full emulator PASS |

### ANDROID-L04: Проверять доверенные нативные артефакты в сборках библиотеки

| Пункт | Требование | Проверка |
|---|---|---|
| ANDROID-L04.1 | В корневой Android-сборке, которой реально проверяется пример, добавить Gradle dependency verification с доверенными SHA-256 для AAR и необходимых метаданных. Для текущего примера место нового файла: `example/android/gradle/verification-metadata.xml`. | pinned inputs + real Gradle negative tests + official APK consumption PASS |
| ANDROID-L04.2 | Ожидаемые суммы брать из проверенного процесса выпуска и фиксировать в репозитории. Не генерировать и автоматически принимать новые значения в обычной CI-сборке. | pinned inputs + real Gradle negative tests + official APK consumption PASS |
| ANDROID-L04.3 | Включить проверку в задаче потребления опубликованного Maven runtime и добавить отрицательную проверку изменённого артефакта с теми же координатами. | pinned inputs + real Gradle negative tests + official APK consumption PASS |
| ANDROID-L04.4 | Разделить проверку опубликованного runtime и разработческую сборку локального AAR. Текущий CI намеренно использует flutterVlessAndroidRuntimeRepo для тестового local Maven repo; удаление override сломает полезный сценарий. | pinned inputs + real Gradle negative tests + official APK consumption PASS |
| ANDROID-L04.5 | Для сборки, проверяющей официальный артефакт, явно запрещать неожиданный override repository/version. Разрешённый разработческий путь должен быть обозначен отдельно и не засчитываться как проверка официального AAR. | pinned inputs + real Gradle negative tests + official APK consumption PASS |
| ANDROID-L04.6 | Локальный AAR может отличаться побайтно от опубликованного. Предусмотреть отдельную контролируемую проверку локального артефакта; не ослаблять глобальную verification wildcard-доверием ко всем файлам группы. | pinned inputs + real Gradle negative tests + official APK consumption PASS |
| ANDROID-L04.7 | В документации дать готовый образец подключения verification на уровне root build потребителя и порядок обновления доверенной версии/checksum. Указать, что публикация metadata внутри библиотеки автоматически не включает проверку в чужом приложении. | pinned inputs + real Gradle negative tests + official APK consumption PASS |
| ANDROID-L04.8 | Если в рамках M-01/M-02 меняется runtime, синхронно обновить его версию, release notes и verification. Файлы metadata должны соответствовать фактически потребляемому набору артефактов. | pinned inputs + real Gradle negative tests + official APK consumption PASS |

Дополнительный стресс-тест выявил гонку отложенного STOP с последующим START.
Исправлено завершение service: cleanup старой сессии выполняется последовательно,
а завершить сам service может только актуальный запрос через `stopSelfResult(startId)`.
Устаревшие START не проходят дорогую preflight-проверку; отсутствующий вход всегда
отвечает отказом. Повторный тест последнего START прошёл; проверена сохранность
файлов новой сессии и отсутствие повторного запуска после финального STOP.

## Сохранённые и общие контракты

- iOS C-05/H-03: IPv6 capture+block и очищенная диагностика; L-04: прежние доверенные iOS checksums.
- Android H-02: собственный UID не исключается; broker проверяет UID, настоящий FD и protect acknowledgement. Пользовательские BLOCKED_APPS/direct сохраняются.
- Общий API 3.1: необязательные параметры проходят root/interface/adapter; явно выбранная неподдерживаемая гарантия отвергается до start. Старые defaults не требуют нового native метода.
- Поставка 3.3: root/Android/interface/podspec обновлены до 1.2.0; нативные версии не изменены, поскольку закреплённые артефакты уже поддерживают нужную авторизацию.
- Исходные пункты приложения и исключённые работы из раздела 4 исходного задания не объявляются исправленными выпуском библиотеки.

## Проверки, которые нельзя подменять локальными результатами

Физическое iOS-устройство отсутствует: не выполнены подписанный совместный Keychain
app/extension, first unlock/reboot/lock, уничтожение всего extension, захват
физического интерфейса и попытка доступа от отдельного iOS-приложения. Это не
результаты simulator-тестов. Перед production-интеграцией выполнить
[device matrix](device_matrix.md#security-regression-observations), отдельно до
и после восстановления. На Android реальные мобильная/Wi-Fi сети и аппаратные
особенности Keystore также требуют проверки целевым приложением.

## Независимая проверка кандидата

Свежий reviewer без истории реализации нашёл три подтверждённых дефекта Android:
1. Case-insensitive поля native JSON (`Protocol`, `Inbounds`, `Log`) могли обходить
   проверку локального доступа/логирования. Исправлено: canonicalization и отклонение
   неоднозначных aliases; JVM regression и настоящий native HTTP 407 пройдены.
2. Удалённое приложение в BLOCKED_APPS делало сохранённый профиль невосстановимым.
   Исправлено: пропускается только NameNotFoundException; сохранённый профиль
   со stale exclusion прошёл восстановление на эмуляторе.
3. Допустимый alias `users` в proxyOnly разбирался после teardown и мог оставить
   start без ответа. Исправлено: извлечение и проверка accounts/users с native
   приоритетом до изменения сессии; отказ всегда отвечает ResultReceiver.

Других конкретных обходов в проверенных iOS/common/DNS/storage/diagnostics/supply
путях reviewer не нашёл. Три исправления проверены фокусными regression tests;
дополнительный независимый review не объявляется проведённым.

## Дополнительная проверка маршрутизации на предоставленных профилях

Приватные профили и их реквизиты не включаются в Git или CI artifacts.
`tool/test_ios_private_routing.py` принимает пути к локальным JSON и запускает
настоящий iOS Xray через актуальные proxyOnly runner и tunnel preparer.
Разметка сообщения нормализована в JSON; macOS log paths исключены, порты
перенесены на свободные тестовые loopback-порты, чтобы не затронуть VPN хоста.

Исходные два SOCKS-входа проверены в proxyOnly: правило `socks-direct → direct`
сохраняется. В штатном VPN такой второй открытый вход отвергается до изменения
сессии. Для проверки VPN созданы эквиваленты с одним управляемым входом:
`full:api.ipify.org → direct`, `full:api4.ipify.org → proxy`. Оба сайта отвечают
по HTTPS; native counters подтверждают выбранный outbound, запрос proxy-сайта
не увеличивает direct counter. Проверка повторена для двух поколений runtime
каждого профиля. Публичные IP могут меняться между запросами, поэтому равенство
старому IP не подменяет измерение реального outbound. `direct` на эмуляторе
означает обход тестируемого плагина через существующую сеть/VPN компьютера.

CI дополнительно проверяет domain routing на двух отдельных localhost origins
без приватных серверов и реквизитов пользователя.

На Android `ActualProfileRoutingTest` также прошёл для обоих предоставленных
профилей, до и после принудительного завершения Xray. Проверяется настоящий
захват трафика приложения через TUN. При измерениях обнаружена задержка публикации
счётчика direct downlink: после полного HTTPS-ответа он увеличился ещё до запроса
ко второму сайту. Тест ограниченно дожидается учёта полученного direct-ответа,
после чего строго требует нулевой прирост direct при запросе proxy-сайта.
Эта проверка прошла во всех четырёх поколениях; проверка не заменена сравнением IP.

## Уточнение приёмки Android после включения работающего DNS эмулятора

Первоначальный resolver эмулятора не работал через существующий VPN хоста.
Выделенный AVD перезапущен с явным DNS, доступным через этот VPN; настройки
компьютера не менялись. Положительная калибровка pcap также выявила, что захват
этого AVD видит cellular interface, поэтому DNS capture выполняется на cellular
после отдельной проверки Wi-Fi ↔ cellular. Пустой захват не засчитывается.

Один контрольный пакет раннего прогона попал на физический интерфейс примерно через
6–18 мс после объявления VPN-сети, за ~235 мс до передачи FD и ~1,35 с до
`CONNECTED`. Границы определены по lifecycle events и измеренному смещению
часов host/device с интервалом 12,2 мс. Калибровка выполнена спустя ~275 с
после пакета, поэтому миллисекундные значения являются оценкой, а не прямым
синхронным измерением. Это холодный запуск в состоянии
`CONNECTING`, а не восстановление готового туннеля. DNS test теперь ждёт
новую последовательность `CONNECTING → CONNECTED` и положительный запрос
через TUN. Фильтр pcap не ослаблен: ни один контрольный direct DNS пакет
не исключается из результата. Блокировка до готовности/после смерти всего
service относится к системному always-on/lockdown, проверяемому отдельно.

Отдельный APK и shell UID не достигают проверки peer UID внутри broker: Android
SELinux отклоняет соединение раньше. Это фиксируется как OS-layer denial,
`peer_uid_guard_exercised=false`, а не как выполненная ветка Java guard. Проверка
UID в коде сохранена, same-UID передача настоящего FD и ровно один protect
callback подтверждены. SELinux не ослаблялся.
