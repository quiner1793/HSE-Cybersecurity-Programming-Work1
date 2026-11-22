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
    cvss = {"cvss31_nvd": "", "cvss31_cna": "", "cvss40": ""}
    for metric_key, field in (("cvssMetricV31", "cvss31"), ("cvssMetricV40", "cvss40")):
        for metric in cve.get("metrics", {}).get(metric_key, []):
            data = metric.get("cvssData", {})
            value = f"{data.get('baseScore', '')} {data.get('vectorString', '')}".strip()
            if field == "cvss40":
                cvss[field] = cvss[field] or value
            elif metric.get("source") == "nvd@nist.gov":
                cvss["cvss31_nvd"] = value
            else:
                cvss["cvss31_cna"] = cvss["cvss31_cna"] or value
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


def _reference_url(reference: Any) -> str:
    if isinstance(reference, str):
        return reference
    if isinstance(reference, dict):
        return reference.get("url", "")
    return ""


def _cvss_value(data: dict[str, Any]) -> str:
    if not data:
        return ""
    score = data.get("score") or data.get("baseScore") or ""
    vector = data.get("vector_string") or data.get("vectorString") or ""
    return f"{score} {vector}".strip()


def _advisory_cvss40(item: dict[str, Any]) -> str:
    severities = item.get("cvss_severities") or {}
    return _cvss_value(severities.get("cvss_v4") or {})


def build_rows(
    nvd: list[dict[str, Any]],
    osv: list[dict[str, Any]],
    github: list[dict[str, Any]],
    epss: dict[str, dict[str, str]],
    kev: dict[str, dict[str, Any]],
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
        published_other = _unique(
            [
                f"OSV:{item.get('id', '')}:{item.get('published', '')[:10]}"
                for item in osv_items
                if item.get("id") and item.get("published")
            ]
            + [
                f"GHSA:{item.get('ghsa_id', '')}:{item.get('published_at', '')[:10]}"
                for item in ghsa_items
                if item.get("ghsa_id") and item.get("published_at")
            ]
        )
        date_published = detail.get("published", "")
        if not date_published:
            dates = [item.get("published", "")[:10] for item in osv_items + ghsa_items if item.get("published")]
            date_published = min(dates) if dates else ""
        in_period = bool(date_published and START_DATE.isoformat() <= date_published <= end.isoformat())
        if not in_period:
            continue

        affected, fixed, descriptions, source_urls, cwes = [], [], [], [], []
        cpes = detail.get("cpes", [])
        if detail.get("description"):
            descriptions.append(detail["description"])
        if cve:
            source_urls.extend(_reference_url(reference) for reference in cve.get("references", []))
        for item in osv_items:
            if item.get("details"):
                descriptions.append(item["details"])
            source_urls.extend(_reference_url(reference) for reference in item.get("references", []))
            cwes.extend(
                (cwe, item.get("id", "OSV")) for cwe in (item.get("database_specific", {}).get("cwe_ids") or [])
            )
            for affected_package in item.get("affected", []):
                package = affected_package.get("package") or {}
                if str(package.get("name", "")).lower() not in ("torch", "pytorch"):
                    continue
                for version_range in affected_package.get("ranges", []):
                    for event in version_range.get("events", []):
                        if event.get("fixed") and version_range.get("type") == "ECOSYSTEM":
                            fixed.append(event["fixed"])
                        for marker in ("introduced", "last_affected"):
                            if event.get(marker):
                                affected.append(f"{marker} {event[marker]}")
        for item in ghsa_items:
            if item.get("description"):
                descriptions.append(item["description"])
            source_urls.extend(
                [item.get("html_url", ""), *(_reference_url(reference) for reference in item.get("references", []))]
            )
            cwes.extend((cwe.get("cwe_id", ""), item.get("ghsa_id", "GHSA")) for cwe in item.get("cwes", []))
            if not detail.get("cvss40"):
                detail["cvss40"] = _advisory_cvss40(item)
            for vulnerability in item.get("vulnerabilities", []):
                package = vulnerability.get("package") or {}
                if str(package.get("name", "")).lower() in ("torch", "pytorch"):
                    affected.append(vulnerability.get("vulnerable_version_range", ""))
                    patched = vulnerability.get("first_patched_version")
                    if isinstance(patched, str):
                        fixed.append(patched)
                    elif isinstance(patched, dict) and patched.get("identifier"):
                        fixed.append(patched["identifier"])

        kev_item = kev.get(cve_id, {})
        weaknesses = detail.get("weaknesses", [])
        row = {field: "" for field in FIELDS}
        row.update(
            {
                "cve_id": cve_id,
                "ghsa_id": ghsa_id,
                "osv_id": osv_id,
                "published_cve": detail.get("published", "") if cve else "",
                "published_other": published_other or (date_published if not cve else ""),
                "cwe": _unique([*(value for value, _ in weaknesses), *(value for value, _ in cwes)]),
                "cwe_source": _unique([*(source for _, source in weaknesses), *(source for _, source in cwes)]),
                "cvss31_nvd": detail.get("cvss31_nvd", ""),
                "cvss31_cna": detail.get("cvss31_cna", ""),
                "cvss40": detail.get("cvss40", ""),
                "epss": epss.get(cve_id, {}).get("epss", ""),
                "epss_percentile": epss.get(cve_id, {}).get("percentile", ""),
                "epss_date": epss.get(cve_id, {}).get("date", ""),
                "in_kev": "yes" if kev_item else ("no" if cve_id else ""),
                "kev_date_added": kev_item.get("dateAdded", ""),
                "affected": _unique(affected),
                "fixed_version": _unique(fixed),
                "snapshot_date": snapshot,
                "source_ids": _unique(
                    [cve_id]
                    + [item.get("ghsa_id", "") for item in ghsa_items]
                    + [item.get("id", "") for item in osv_items]
                ),
                "description": _merge_descriptions(descriptions),
                "nvd_cpe": _unique(cpes),
                "source_urls": _unique(source_urls),
                "review_status": "",
                "review_notes": "",
            }
        )
        rows.append(row)
    return rows
