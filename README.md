# Nulls Brawl Agent

Frida Gadget agent для iOS через LiveContainer.

## Структура

- .github/workflows/build-frida-framework.yml — сборка Frida.framework
- .github/workflows/frida-compile.yml — сборка agent.js из модулей
- scripts/frida-scripts/agent.js — точка входа
- config/agent_config.json — рантайм-конфиг
- offsets.js — сгенерированные офсеты
- hints.md — заметки по сборке Frida.framework

## Установка

1. Скачать Frida.framework.zip из артефактов
2. Распаковать
3. Положить Frida.framework в nt.nb.ios.app/Frameworks/
4. Запустить игру
