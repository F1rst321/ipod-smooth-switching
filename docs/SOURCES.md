# Источники для разбора

- [Rockbox `ipodpatcher.c`](https://github.com/mguentner/rockbox/blob/master/rbutil/ipodpatcher/ipodpatcher.c) — открытая реализация чтения таблицы и размещения образов прошивки iPod.
- [iPod Classic Firmware Research](https://github.com/giek2000/ipod-classic-firmware-research) — содержит отдельную спецификацию для RetailOS 25.1.3 и документацию по MeCCA. Это независимый сторонний разбор; перед использованием адреса сопоставляются с локальным компонентом OSOS, а описание аудиопути для других моделей не считается доказанным для нашего 5.5G.
- [Спецификация RetailOS 25.1.3](https://github.com/giek2000/ipod-classic-firmware-research/blob/main/specs/iPod_5_5G_Video_Enhanced_25_1_3.md) — полезна как индекс строк и гипотез. Указанный в ней бинарник отличается по размеру и SHA-256 от локально извлечённого OSOS, поэтому её адреса нельзя напрямую применять к патчеру.
- [Исследование RetailOS в эмуляторе iPod](https://github.com/siggifly/ipod-emulator) — публикует разбор PCM-задачи и двойного аудиобуфера. Участок `OSOS+0x25a720` был независимо просмотрен и дизассемблирован на локальном бинарнике; роль его callback ещё исследуется.
- [Эмуляция iPod Video 5G и Classic в QEMU](https://github.com/davidmonterocrespo24/qemu-ipod-classic) — отдельно описывает PP5022C и состояние Apple RetailOS на iPod Video 5G. Текущая версия помечает аудио 5G как нереализованное; опубликованные аудиотрассы Classic 6G относятся к S5L8702 и не переносятся на наш iPod.
- [Спецификация RetailOS 25.1.2.1](https://github.com/giek2000/ipod-classic-firmware-research/blob/main/specs/iPod_5_5G_Video_Enhanced_25_1_2_1.md) — справочник по смежной версии, применим только как ориентир для гипотез.
- [Обсуждение патча RetailOS 1.3 для iPod Video](https://www.reddit.com/r/IpodClassic/comments/1wy2cwz/dark_mode_album_artwork_on_patched_stock_os/) — опубликованы адреса трёх UI функций и общий способ добавить элемент Settings. Их первые байты сверены с нашим OSOS; полная реализация ещё не опубликована, а детали ещё требуют проверки.

Локальный пакет `iPod_25.1.3.ipsw` остаётся исходным источником истины для этого устройства. Его файлы не публикуются в репозитории.
