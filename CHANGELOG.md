# Changelog

Все значимые изменения по проекту. Формат — [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added
- Модульная структура агента в `scripts/frida-scripts/`
- CI-сборка `Frida.framework` под Frida 17.2.11
- Отладочный лог агента в `Documents/agent.log`

### Changed
- Переход с `frida-compile@17` на `esbuild` для сборки flat agent.js
- Целевой рантайм обновлён до Frida 17.2.11

### Removed
- Устаревшие отладочные утилиты (`compare.yml`, `create.yml`)
- Сгенерированные артефакты из git (`offsets_report.txt`, `offsets_resolved.js`)

## [0.1.0] - 2026-09-29

### Added
- Первый рабочий агент под Nulls Brawl
- Патчинг `isDeveloperBuild` через rva-таргеты
- Автопереприменение патчей
