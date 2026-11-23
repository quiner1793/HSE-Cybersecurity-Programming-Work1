"""Build the STIX 2.1 bundle for CVE-2026-24747 using stix2."""

from pathlib import Path

from stix2.v21 import AttackPattern, Bundle, CourseOfAction, Relationship, Vulnerability


ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "data/analysis/5_cve_2026_24747/cve-2026-24747.stix.json"
CREATED = "2026-11-23T16:24:25Z"


def main() -> None:
    vulnerability = Vulnerability(
        id="vulnerability--32e4796f-690f-4dd3-93fb-f46ff7a69f4c",
        created=CREATED,
        modified=CREATED,
        name="CVE-2026-24747",
        description=(
            "Недостаточная проверка типов при обработке SETITEM/SETITEMS и согласованности "
            "размеров хранилища при загрузке недоверенного checkpoint в "
            "torch.load(weights_only=True). Исправлено в PyTorch 2.10.0."
        ),
        external_references=[
            {
                "source_name": "cve",
                "external_id": "CVE-2026-24747",
                "url": "https://www.cve.org/CVERecord?id=CVE-2026-24747",
            },
            {
                "source_name": "pytorch-advisory",
                "external_id": "GHSA-63cw-57p8-fm3p",
                "url": "https://github.com/pytorch/pytorch/security/advisories/GHSA-63cw-57p8-fm3p",
            },
        ],
    )
    object_injection = AttackPattern(
        id="attack-pattern--5d53bfc3-b279-4f46-bf95-50d808ad31d0",
        created=CREATED,
        modified=CREATED,
        name="CAPEC-586 Object Injection",
        description="Внедрение некорректного содержимого в сериализованный объект, который приложение затем десериализует.",
        external_references=[
            {
                "source_name": "capec",
                "external_id": "CAPEC-586",
                "url": "https://capec.mitre.org/data/definitions/586.html",
            }
        ],
    )
    malicious_file = AttackPattern(
        id="attack-pattern--eed51254-6a50-4f19-80e9-77dd528971d0",
        created=CREATED,
        modified=CREATED,
        name="ATT&CK T1204.002 User Execution: Malicious File",
        description=(
            "Применимо к сценарию, в котором атакующий побуждает пользователя открыть и загрузить "
            "подготовленный checkpoint. Не описывает автоматическую загрузку файла сервисом."
        ),
        external_references=[
            {
                "source_name": "mitre-attack",
                "external_id": "T1204.002",
                "url": "https://attack.mitre.org/techniques/T1204/002/",
            }
        ],
    )
    upgrade = CourseOfAction(
        id="course-of-action--a7d628a0-495d-475f-ab4a-ad675d302450",
        created=CREATED,
        modified=CREATED,
        name="Обновить PyTorch до версии 2.10.0 или новее",
        description="Использовать исправленный выпуск PyTorch; не загружать недоверенные checkpoint в процессе с уязвимой версией.",
        external_references=[
            {
                "source_name": "pytorch-advisory",
                "url": "https://github.com/pytorch/pytorch/security/advisories/GHSA-63cw-57p8-fm3p",
            }
        ],
    )
    relationships = [
        Relationship(
            id="relationship--ab4da737-d90b-4d1c-80f1-d12ef2515b26",
            created=CREATED,
            modified=CREATED,
            relationship_type="targets",
            source_ref=object_injection.id,
            target_ref=vulnerability.id,
        ),
        Relationship(
            id="relationship--e8b630c1-c040-4564-b56d-4ad2c91060ef",
            created=CREATED,
            modified=CREATED,
            relationship_type="related-to",
            description=(
                "В пользовательском сценарии открытие подготовленного файла может предшествовать "
                "обработке некорректно сериализованного объекта."
            ),
            source_ref=malicious_file.id,
            target_ref=object_injection.id,
        ),
        Relationship(
            id="relationship--fae01266-923a-48aa-957c-b248da510f6f",
            created=CREATED,
            modified=CREATED,
            relationship_type="mitigates",
            source_ref=upgrade.id,
            target_ref=vulnerability.id,
        ),
    ]
    bundle = Bundle(
        vulnerability,
        object_injection,
        malicious_file,
        upgrade,
        *relationships,
        id="bundle--5a6489c1-dc16-4f13-ac73-94d0a3f69570",
    )
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(bundle.serialize(pretty=True) + "\n", encoding="utf-8")
    print(f"STIX 2.1: {OUTPUT}")


if __name__ == "__main__":
    main()
