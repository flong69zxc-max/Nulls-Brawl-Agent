# Frida.framework: сборка под iOS 27 + LiveContainer

## Ключевой факт

dev-W.dylib это сток Frida 17.2.11 + lipo -thin arm64 + ldid-procursus -S + обнуление LC_CODE_SIGNATURE blob + lipo -create.

Счётчики brk/nop/ret в dev, стоке и нашей сборке совпадают до единицы. Никакого gum-graft, никаких патчей кода.

## Почему 17.2.11

Последний релиз до появления сегментов __FRIDA_TEXT*/__FRIDA_DATA* (17.2.15+). Эти сегменты iOS 27 отвергает с CODESIGNING 2 Invalid Page.

Frida 17.2.11 использует LC_DYLD_INFO_ONLY, не LC_DYLD_CHAINED_FIXUPS.

## Почему ldid-procursus

Обычный ldid от Saurik пишет подпись ~238 КБ без DER-encoded entitlements. Файл получается на 17 КБ короче dev.

ldid-procursus (форк ProcursusTeam) добавляет DER entitlements для iOS 15.1+ и пишет подпись 256 КБ, как у dev.

Установка: brew uninstall ldid; brew install ldid-procursus

## Порядок операций

stock fat 17.2.11
  -> lipo -thin arm64 (19006768)
  -> ldid-procursus -S (19006592, LC_CODE_SIGNATURE.size=256496)
  -> обнулить blob подписи
  -> lipo -create -arch arm64 (19022976)

## Ключевые цифры

- fat size: 19022976
- arm64 slice: 19006592
- LC_CODE_SIGNATURE.offset: 18750096
- LC_CODE_SIGNATURE.size: 256496

## Что НЕ работает

- gum-graft: создаёт __FRIDA_TEXT* сегменты, iOS 27 отвергает
- ручная обрезка файла: __LINKEDIT.filesize вылезает за конец файла
- Frida 17.2.15+: brk #0x539 в инициализаторе dyld
- обычный ldid: подпись короче на 17 КБ

## Проверка на устройстве

python3 an.py NULLS.dylib OUR.dylib

Ожидается slice size diff: 0
