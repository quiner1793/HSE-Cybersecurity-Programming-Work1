# Ручная проверка строк

После первоначального сбора нужно проверить каждую строку `data/vulnerabilities.csv` отдельно. 
Совпадение по слову `torch` не являются достаточным основанием включения в финальный набор.

Включаем запись, если NVD прямо связывает уязвимость с PyTorch либо официальный бюллетень/issue PyTorch подтверждает уязвимый код компонента. 
Исключаем downstream-проект, использующий PyTorch, и случаи, которые политика PyTorch относит к обычным ошибкам. 

1. Открываем `https://nvd.nist.gov/vuln/detail/{cve_id}`. Сверяем `nvd_cpe`, название продукта, затронутые версии, `description` и ссылки. Продукт должен быть самим PyTorch, а не сторонним проектом, который его использует.
2. Открываем `https://osv.dev/vulnerability/{osv_id}` и `https://github.com/advisories/{ghsa_id}`. Проверяем aliases, имя пакета (`torch`/`pytorch`), экосистему PyPI и затронутые версии; сравниваем их с `affected` и `fixed_version`. Если ID отсутствует, переходим к следующему источнику.
3. По ссылкам из `source_urls` проверяем первоисточник: бюллетень, issue, pull request или commit в `pytorch/pytorch`. Нужно убедиться, что описана проблема в коде PyTorch и есть security impact. Сверяем вывод с [политикой безопасности PyTorch](https://github.com/pytorch/pytorch/security/policy): обычная ошибка, некорректный аргумент или ожидаемое поведение сами по себе не проходят критерий.
4. Фиксируем `review_status`: `included` или `excluded`. В `review_notes` указываем конкретное доказательство и причину.
5. Далее, для `review_status`: `included` заполняем данные по БДУ ФСТЭК по [выгрузке](bdu_vullist.xlsx), предварительно скачанной с [БДУ ФСТЭК](https://bdu.fstec.ru/vul). При совпадении `cve_id` заполняем `bdu_id`, `published_bdu`, `cvss_bdu` и `cvss_bdu_version`.

## Примеры

- **Включить — CVE-2022-45907.** В `nvd_cpe` указан `linuxfoundation:pytorch`; `description` называет `torch.jit.annotations.parse_type_line`; ссылки в `source_urls` ведут на issue, pull request и commit проекта PyTorch. Это проблема самого компонента, поэтому `review_status=included`.
- **Исключить — CVE-2021-4118.** В `nvd_cpe` указан `lightningai:pytorch_lightning`, `description` и `source_urls` относятся к PyTorch Lightning. Это отдельный проект, использующий PyTorch, поэтому `review_status=excluded`.
