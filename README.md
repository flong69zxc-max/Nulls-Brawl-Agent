# Nulls Brawl Agent

Frida Gadget agent для iOS-билда Nulls Brawl, работающий через LiveContainer.

## Что это

Плоский Frida-скрипт (`agent.js`), который собирается из модульных исходников в `scripts/frida-scripts/` и загружается в игру через Frida Gadget, вшитый в `Frida.framework`.

## Структура

```
.
├── .github/workflows/
│   ├── build.yml          # сборка Frida.framework с gadget + agent.js
│   ├── frida-compile.yml  # сборка agent.js из модулей
│   └── extract_offsets.yml # извлечение офсетов для target-патчей
├── config/
│   └── agent_config.json  # рантайм-конфиг (пути, targets, alert)
├── scripts/
│   └── frida-scripts/
│       └── agent.js       # точка входа agent
├── frida/
│   └── W.dylib.zip        # dev-эталон для верификации
├── offsets.js             # сгенерированные офсеты
├── package.json
└── tsconfig.json
```

## Сборка

Два независимых артефакта, оба собираются через GitHub Actions:

### 1. `agent.js` (workflow `frida-compile.yml`)

Собирает `scripts/frida-scripts/agent.js` в один плоский файл без `node_modules`-путей, с вшитым `frida-objc-bridge`. Выход: `dist/agent.js`.

Запуск: **Actions → Frida Compile → Run workflow**.

### 2. `Frida.framework` (workflow `build.yml`)

Собирает готовый iOS framework из стокового `frida-gadget-17.2.11-ios-universal`:
1. `lipo -thin arm64`
2. `strip -Sx`
3. Упаковка в `Frida.framework/` с `Info.plist`, `W.config`, `agent.js`
4. Подпись `ldid -S`

Выход: `Frida.framework.zip`.

Запуск: **Actions → Build → Run workflow**.

## Установка в LiveContainer

1. Скачать оба артефакта (`agent.js` и `Frida.framework.zip`).
2. Распаковать `Frida.framework.zip`.
3. Заменить `Frida.framework/agent.js` на свой `agent.js`.
4. Положить `Frida.framework` в `nt.nb.ios.app/Frameworks/`.
5. Запустить игру.

## Конфиг

`config/agent_config.json` — рантайм-настройки агента:

| Поле | Описание |
|---|---|
| `patch` | Включить патчинг (иначе только probe) |
| `alert` | Показывать UIAlertController при загрузке |
| `alert_delay_ms` | Задержка перед показом alert |
| `targets` | Список target-патчей (rva + type + value) |
| `scan_strings` | Автоматический скан строк при старте |
| `reapply_ms` | Через сколько мс переприменять патчи |

## Разработка

Требуется Node.js 20+.

```
npm install
npm run build    # собрать agent.js локально (esbuild)
npm run watch    # watch-режим
```

## Отладка

Логи агента пишутся в `Documents/agent.log` **контейнера гостя** (не LiveContainer'а). Путь в реальном времени виден в системном логе iOS по тегу `[Nulls Brawl]` или через StikDebug.

## Лицензия

Приватный репозиторий. Использование на свой риск.
