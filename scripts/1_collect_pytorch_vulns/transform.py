import datetime as dt
from typing import Any

from config import FIELDS, START_DATE


def aliases(record: dict[str, Any]) -> set[str]:
    return {value for value in [record.get("id", ""), *(record.get("aliases", []) or [])] if value}


def nvd_details(cve: dict[str, Any]) -> dict[str, Any]:
    weaknesses = [
        (description.get("value", ""), weakness.get("source", ""))
        for weakness in cve.get("weaknesses", [])
        for description in weakness.get("description", [])
        if str(description.get("value", "")).startswith("CWE-")
    ]
    cvss = {f"cvss{version}_{source}": "" for version in ("30", "31", "40") for source in ("nvd", "cna")}
    for metric_key, version in (("cvssMetricV30", "30"), ("cvssMetricV31", "31"), ("cvssMetricV40", "40")):
        for metric in cve.get("metrics", {}).get(metric_key, []):
            data = metric.get("cvssData", {})
            value = f"{data.get('baseScore', '')} {data.get('vectorString', '')}".strip()
            source = metric.get("source")
            if source == "nvd@nist.gov":
                field = f"cvss{version}_nvd"
            elif source and source == cve.get("sourceIdentifier"):
                field = f"cvss{version}_cna"
            else:
                continue
            cvss[field] = cvss[field] or value
    descriptions = [item.get("value", "") for item in cve.get("descriptions", []) if item.get("lang") == "en"]
    cpes = []
    for configuration in cve.get("configurations", []):
        nodes = list(configuration.get("nodes", []))
        while nodes:
            node = nodes.pop()
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable") or not match.get("criteria"):
                    continue
                bounds = [
                    f"{name}={match[name]}"
                    for name in (
                        "versionStartIncluding",
                        "versionStartExcluding",
                        "versionEndIncluding",
                        "versionEndExcluding",
                    )
                    if match.get(name)
                ]
                cpes.append(f"{match['criteria']} ({', '.join(bounds)})" if bounds else match["criteria"])
            nodes.extend(node.get("children", []))
    return {
        "published": cve.get("published", "")[:10],
        "weaknesses": weaknesses,
        "description": descriptions[0] if descriptions else "",
        "cpes": cpes,
        **cvss,
    }


def cve_from_advisory(item: dict[str, Any]) -> str:
    value = item.get("cve_id") or ""
    return value if value.startswith("CVE-") else ""


def _unique(values: list[str]) -> str:
    return ";".join(dict.fromkeys(value for value in values if value))


def _merge_descriptions(values: list[str]) -> str:
    unique = list(dict.fromkeys(value.strip() for value in values if value and value.strip()))
    distinct = [value for value in unique if not any(value != other and value in other for other in unique)]
    return "\n\n".join(distinct)


def _cvss_value(data: dict[str, Any]) -> str:
    if not data:
        return ""
    score = data.get("score") or data.get("baseScore") or ""
    vector = data.get("vector_string") or data.get("vectorString") or ""
    return f"{score} {vector}".strip()


def advisory_cvss(item: dict[str, Any], version: str) -> str:
    severities = item.get("cvss_severities") or {}
    key = "cvss_v4" if version == "4.0" else "cvss_v3"
    data = severities.get(key) or {}
    if not str(data.get("vector_string") or "").startswith(f"CVSS:{version}/"):
        return ""
    return _cvss_value(data)


def cve_list_assignments(record: dict[str, Any]) -> list[tuple[str, str, str, str]]:
    assignments = []
    containers = record.get("containers", {})
    for role, items in (("CNA", [containers.get("cna")]), ("ADP", containers.get("adp", []))):
        for container in items:
            if not container:
                continue
            provider = container.get("providerMetadata", {})
            name = provider.get("shortName") or provider.get("orgId", "")
            for problem in container.get("problemTypes", []):
                for description in problem.get("descriptions", []):
                    cwe = description.get("cweId", "")
                    if str(cwe).startswith("CWE-"):
                        assignments.append(("cwe", cwe, role, name))
            for metric in container.get("metrics", []):
                for key, field in (("cvssV3_0", "cvss30"), ("cvssV3_1", "cvss31"), ("cvssV4_0", "cvss40")):
                    value = _cvss_value(metric.get(key, {}))
                    if value:
                        assignments.append((field, value, role, name))
    return assignments


def _cwe_source(value: str, source: str, cna: str, adp_names: dict[str, str]) -> str:
    if source == "nvd@nist.gov":
        label = "NVD"
    elif source == cna:
        label = "CNA"
    elif source in adp_names:
        label = f"ADP {adp_names[source]}"
    else:
        label = "другой источник"
    return f"{value} — {label} ({source})"


def build_rows(
    nvd: list[dict[str, Any]],
    osv: list[dict[str, Any]],
    github: list[dict[str, Any]],
    epss: dict[str, dict[str, str]],
    kev: dict[str, dict[str, Any]],
    cve_records: dict[str, dict[str, Any]],
    end: dt.date,
) -> list[dict[str, str]]:
    groups: dict[str, dict[str, Any]] = {}
    alias_to_key: dict[str, str] = {}
    for cve in nvd:
        cve_id = cve.get("id", "")
        if cve_id:
            groups.setdefault(cve_id, {"cve": cve, "osv": [], "github": []})
            alias_to_key[cve_id] = cve_id
    for item in osv:
        cve_id = next((value for value in sorted(aliases(item)) if value.startswith("CVE-")), "")
        key = cve_id or item.get("id", "")
        if key:
            groups.setdefault(key, {"cve": None, "osv": [], "github": []})["osv"].append(item)
            for value in aliases(item):
                alias_to_key[value] = key
    for item in github:
        cve_id = cve_from_advisory(item)
        ghsa_id = item.get("ghsa_id", "")
        key = alias_to_key.get(cve_id, cve_id) if cve_id else alias_to_key.get(ghsa_id, ghsa_id)
        if key:
            groups.setdefault(key, {"cve": None, "osv": [], "github": []})["github"].append(item)
            alias_to_key[ghsa_id] = key
            if cve_id:
                alias_to_key[cve_id] = key

    rows: list[dict[str, str]] = []
    snapshot = dt.date.today().isoformat()
    for key, group in sorted(groups.items()):
        cve = group["cve"]
        osv_items, ghsa_items = group["osv"], group["github"]
        detail = nvd_details(cve) if cve else {}
        cve_id = key if key.startswith("CVE-") else ""
        ghsa_id = _unique([item.get("ghsa_id", "") for item in ghsa_items])
        osv_id = _unique([item.get("id", "") for item in osv_items])
        published_cve = cve_records.get(cve_id, {}).get("cveMetadata", {}).get("datePublished", "")[:10]
        date_published = published_cve or detail.get("published", "")
        if not date_published:
            dates = [item.get("published", "")[:10] for item in osv_items if item.get("published")]
            dates.extend(item.get("published_at", "")[:10] for item in ghsa_items if item.get("published_at"))
            date_published = min(dates) if dates else ""
        in_period = bool(date_published and START_DATE.isoformat() <= date_published <= end.isoformat())
        if not in_period:
            continue

        descriptions, cwes = [], []
        cpes = detail.get("cpes", [])
        if detail.get("description"):
            descriptions.append(detail["description"])
        for item in osv_items:
            if item.get("details"):
                descriptions.append(item["details"])
            cwes.extend(
                (cwe, f"OSV ({item.get('id', '')})") for cwe in (item.get("database_specific", {}).get("cwe_ids") or [])
            )
        for item in ghsa_items:
            if item.get("description"):
                descriptions.append(item["description"])
            cwes.extend((cwe.get("cwe_id", ""), f"GHSA ({item.get('ghsa_id', '')})") for cwe in item.get("cwes", []))

        kev_item = kev.get(cve_id, {})
        weaknesses = detail.get("weaknesses", [])
        list_assignments = cve_list_assignments(cve_records.get(cve_id, {}))
        cwes.extend(
            (value, f"CVE List/{role} ({name})") for field, value, role, name in list_assignments if field == "cwe"
        )
        cna_cvss = {
            field: next(
                (value for candidate, value, role, _ in list_assignments if candidate == field and role == "CNA"), ""
            )
            for field in ("cvss30", "cvss31", "cvss40")
        }
        adp_names = {
            provider.get("orgId", ""): provider.get("shortName", "ADP")
            for container in cve_records.get(cve_id, {}).get("containers", {}).get("adp", [])
            if (provider := container.get("providerMetadata", {})).get("orgId")
        }
        row = {field: "" for field in FIELDS}
        row.update(
            {
                "cve_id": cve_id,
                "ghsa_id": ghsa_id,
                "osv_id": osv_id,
                "published_cve": published_cve,
                "published_nvd": detail.get("published", ""),
                "published_osv": _unique([item.get("published", "")[:10] for item in osv_items]),
                "published_ghsa": _unique([item.get("published_at", "")[:10] for item in ghsa_items]),
                "cwe": _unique([*(value for value, _ in weaknesses), *(value for value, _ in cwes)]),
                "cwe_source": _unique(
                    [
                        *(
                            _cwe_source(value, source, cve.get("sourceIdentifier", ""), adp_names)
                            for value, source in weaknesses
                        )
                    ]
                    + [f"{value} — {source}" for value, source in cwes if value]
                ),
                "cvss30_nvd": detail.get("cvss30_nvd", ""),
                "cvss30_cna": cna_cvss["cvss30"] or detail.get("cvss30_cna", ""),
                "cvss30_adp": _unique(
                    [f"{name}: {value}" for field, value, role, name in list_assignments if field == "cvss30" and role == "ADP"]
                ),
                "cvss30_ghsa": _unique([advisory_cvss(item, "3.0") for item in ghsa_items]),
                "cvss31_nvd": detail.get("cvss31_nvd", ""),
                "cvss31_cna": cna_cvss["cvss31"] or detail.get("cvss31_cna", ""),
                "cvss31_adp": _unique(
                    [f"{name}: {value}" for field, value, role, name in list_assignments if field == "cvss31" and role == "ADP"]
                ),
                "cvss31_ghsa": _unique([advisory_cvss(item, "3.1") for item in ghsa_items]),
                "cvss40_nvd": detail.get("cvss40_nvd", ""),
                "cvss40_cna": cna_cvss["cvss40"] or detail.get("cvss40_cna", ""),
                "cvss40_adp": _unique(
                    [f"{name}: {value}" for field, value, role, name in list_assignments if field == "cvss40" and role == "ADP"]
                ),
                "cvss40_ghsa": _unique([advisory_cvss(item, "4.0") for item in ghsa_items]),
                "epss": epss.get(cve_id, {}).get("epss", ""),
                "epss_percentile": epss.get(cve_id, {}).get("percentile", ""),
                "epss_date": epss.get(cve_id, {}).get("date", ""),
                "in_kev": "yes" if kev_item else ("no" if cve_id else ""),
                "kev_date_added": kev_item.get("dateAdded", ""),
                "affected": "",
                "fixed_version": "",
                "snapshot_date": snapshot,
                "description": _merge_descriptions(descriptions),
                "nvd_cpe": _unique(cpes),
                "review_status": "",
                "review_notes": "",
            }
        )
        rows.append(row)
    return rows
