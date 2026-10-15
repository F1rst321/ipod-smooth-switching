# Источники для разбора

- [Rockbox `ipodpatcher.c`](https://github.com/mguentner/rockbox/blob/master/rbutil/ipodpatcher/ipodpatcher.c) — открытая реализация чтения таблицы и размещения образов прошивки iPod.
- [iPod Classic Firmware Research](https://github.com/giek2000/ipod-classic-firmware-research) — исследовательский репозиторий указывает, что среди дополнительно разобранных образов есть 5.5G 25.1.3. Опубликованная подробная спецификация относится к 25.1.2.1 на 80 GB; её адреса и выводы нельзя переносить в проект без сравнения бинарников.
- [Спецификация RetailOS 25.1.2.1](https://github.com/giek2000/ipod-classic-firmware-research/blob/main/specs/iPod_5_5G_Video_Enhanced_25_1_2_1.md) — справочник по смежной версии, применим только как ориентир для гипотез.
- [Обсуждение патча RetailOS 1.3 для iPod Video](https://www.reddit.com/r/IpodClassic/comments/1wy2cwz/dark_mode_album_artwork_on_patched_stock_os/) — опубликованы адреса трёх UI функций и общий способ добавить элемент Settings. Их первые байты сверены с нашим OSOS; полная реализация ещё не опубликована, а детали ещё требуют проверки.

Локальный пакет `iPod_25.1.3.ipsw` остаётся исходным источником истины для этого устройства. Его файлы не публикуются в репозитории.
