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
                "source_name": "cwe",
                "external_id": "CWE-502",
                "url": "https://cwe.mitre.org/data/definitions/502.html",
                "description": "Основной класс слабости для аналитической цепочки CWE-502 → CAPEC-586.",
            },
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
    client_exploitation = AttackPattern(
        id="attack-pattern--878d990c-97de-42b2-8d1d-2a1ae5819e26",
        created=CREATED,
        modified=CREATED,
        name="ATT&CK T1203 Exploitation for Client Execution",
        description=(
            "Эксплуатация уязвимости загрузчика checkpoint в клиентском приложении "
            "для выполнения произвольного кода."
        ),
        external_references=[
            {
                "source_name": "mitre-attack",
                "external_id": "T1203",
                "url": "https://attack.mitre.org/techniques/T1203/",
            }
        ],
    )
    unsafe_artifact = AttackPattern(
        id="attack-pattern--e9aac8ae-790b-4f8f-ae31-58f31cb49a4a",
        created=CREATED,
        modified=CREATED,
        name="ATLAS AML.T0011.000 User Execution: Unsafe AI Artifacts",
        description="Основное сопоставление для сценария, в котором пользователь инициирует загрузку вредоносного checkpoint.",
        external_references=[
            {
                "source_name": "mitre-atlas",
                "external_id": "AML.T0011.000",
                "url": "https://atlas.mitre.org/techniques/AML.T0011.000",
            }
        ],
    )
    model_supply_chain = AttackPattern(
        id="attack-pattern--eb458510-aa65-482f-9436-08e4dd59c549",
        created=CREATED,
        modified=CREATED,
        name="ATLAS AML.T0010.003 Supply Chain Compromise: Model Repository",
        description="Вариант доставки вредоносной модели через репозиторий в использующую её систему; загрузка может быть ручной или автоматической.",
        external_references=[
            {
                "source_name": "mitre-atlas",
                "external_id": "AML.T0010.003",
                "url": "https://atlas.mitre.org/techniques/AML.T0010.003",
            }
        ],
    )
    public_application = AttackPattern(
        id="attack-pattern--ff7f9b79-c43e-40c8-a788-bcd22173fa3e",
        created=CREATED,
        modified=CREATED,
        name="ATT&CK T1190 Exploit Public-Facing Application",
        description="Вариант первоначального доступа через доступный из Интернета сервис, принимающий checkpoint и передающий его уязвимому загрузчику.",
        external_references=[
            {
                "source_name": "mitre-attack",
                "external_id": "T1190",
                "url": "https://attack.mitre.org/techniques/T1190/",
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
            id="relationship--ecb41644-f507-4da3-86b5-57a927116d5b",
            created=CREATED,
            modified=CREATED,
            relationship_type="related-to",
            description=(
                "Аналитическое сопоставление: CAPEC-586 описывает обработку подготовленного объекта, "
                "а T1203 — эксплуатацию уязвимости в клиентском приложении."
            ),
            source_ref=client_exploitation.id,
            target_ref=object_injection.id,
        ),
        Relationship(
            id="relationship--434f679c-0a1b-41af-bd83-243cbfc99cfb",
            created=CREATED,
            modified=CREATED,
            relationship_type="related-to",
            description="Аналитическое сопоставление пользовательского сценария из бюллетеня; не свидетельство наблюдавшейся атаки.",
            source_ref=unsafe_artifact.id,
            target_ref=object_injection.id,
        ),
        Relationship(
            id="relationship--69826e6b-aabd-48f8-9b58-095e644a96f7",
            created=CREATED,
            modified=CREATED,
            relationship_type="related-to",
            description="Аналитическое сопоставление при условии доставки подготовленного checkpoint через репозиторий моделей; не универсальная характеристика CVE.",
            source_ref=model_supply_chain.id,
            target_ref=object_injection.id,
        ),
        Relationship(
            id="relationship--d7d7ba24-588b-4ec2-8eb1-e5911948c812",
            created=CREATED,
            modified=CREATED,
            relationship_type="related-to",
            description="Аналитическое сопоставление только для первоначального доступа через публичный сервис загрузки моделей; автоматизация сама по себе недостаточна.",
            source_ref=public_application.id,
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
        unsafe_artifact,
        model_supply_chain,
        client_exploitation,
        public_application,
        upgrade,
        *relationships,
        id="bundle--5a6489c1-dc16-4f13-ac73-94d0a3f69570",
    )
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(bundle.serialize(pretty=True) + "\n", encoding="utf-8")
    print(f"STIX 2.1: {OUTPUT}")


if __name__ == "__main__":
    main()
