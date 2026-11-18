# Сбор и исходная таблица

- `__main__.py` собирает исходные данные в `../../data/vulnerabilities.csv`
- `config.py` читает настройки
- `sources.py` получает NVD, OSV, GitHub Advisory, EPSS и CISA KEV
- `http.py` выполняет HTTP-запросы с повторами
- `transform.py` объединяет записи
- `cli.py` сохраняет результат
- `../../data/raw` - ответы API
- `../../data/vulnerabilities.csv` - итоговая таблица выгрузки

Кандидаты обнаруживаются широким поиском NVD по `PyTorch`/`torch`, а также по пакетам `torch` в OSV и GitHub Advisory. 
Записи объединяются по CVE и aliases; поисковое совпадение само по себе не означает, что уязвимость относится к PyTorch. 
В таблицу попадают записи за период 2020-01-01 - 2026-11-18. 

Перед анализом каждую строку нужно вручную включить или исключить по правилам из [инструкции ручной проверки](../../data/manual_review.md).
Сбор запускается командой `uv run python scripts/1_collect_pytorch_vulns`, а после ручной разметки — `uv run python scripts/2_enrich_bdu_data`.