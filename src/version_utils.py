"""Version parsing and comparison utilities for network OS versions.

Supports vendor-specific formats:
- Cisco ASA: 9.20(3), 9.18(3)40, 9.18(4)22, 9.16.2, 9.14.1(10)
- Cisco IOS XE: 17.3.3, 17.15.1a, 16.12.1a, 16.10.1, 17.3.4b
- Cisco IOS Classic: 15.2(4)M, 15.4(3)M2
- Fortinet FortiOS: 7.2.5, v7.2.4, 7.0.0, 7.4.1
- Palo Alto PAN-OS: 10.1.6-h3, 10.2.3-h4, 11.0.2, 9.1.12-h3
- Standard SemVer: 1.2.3, 2.0.0-rc.1, 1.0.0-alpha
"""

import re
from typing import Optional, Tuple


def normalize_version(
    version_str: str,
    os_type: Optional[str] = None,
) -> Tuple[int, ...]:
    """Normalize a network OS version string into a comparable tuple of integers.

    Args:
        version_str: Version string (e.g., '9.20(3)', '9.18(3)40', '17.3.3',
                     '16.12.1a', '7.2.5', '10.1.6-h3').
        os_type: Optional hint for OS family ('cisco_asa', 'ios_xe', 'panos',
                 'fortios', 'semver').

    Returns:
        A tuple of integers suitable for mathematical comparison.
    """
    if not version_str or not isinstance(version_str, str):
        return ()

    s = version_str.strip().lstrip("vV")
    if not s:
        return ()

    os_lower = os_type.lower() if os_type else ""

    # 1. SemVer with prerelease (-alpha, -beta, -rc, -dev, -preview, etc. excluding -h)
    m_sem = re.match(r"^(\d+)\.(\d+)\.(\d+)-([a-zA-Z][0-9a-zA-Z.-]*)$", s)
    if (
        ("semver" in os_lower or not os_lower)
        and m_sem
        and not m_sem.group(4).startswith(("h", "H"))
    ):
        maj, minr, patch, pre = m_sem.groups()
        pre_parts = []
        for p in re.split(r"[-._]", pre):
            if p.isdigit():
                pre_parts.append(int(p))
            else:
                p_l = p.lower()
                if p_l == "alpha":
                    pre_parts.append(10)
                elif p_l == "beta":
                    pre_parts.append(20)
                elif p_l.startswith("rc"):
                    num = re.findall(r"\d+", p_l)
                    pre_parts.append(30 + (int(num[0]) if num else 0))
                else:
                    pre_parts.append(sum(ord(c) for c in p_l))
        # -1 tag indicates prerelease (< 0 release)
        return (int(maj), int(minr), int(patch), -1, *pre_parts)

    # 2. Cisco ASA: Major.Minor.Maintenance(Build/Interim) e.g. 9.14.1(10), 9.14.2(4)
    m_asa_maint = re.match(r"^(\d+)\.(\d+)\.(\d+)[_\.]?\((\d+)\)(\d+)?$", s)
    if ("asa" in os_lower or not os_lower) and m_asa_maint:
        maj, minr, maint, build, _ = m_asa_maint.groups()
        b_val = int(build) if build else 0
        return (int(maj), int(minr), int(maint), b_val)

    # 3. Cisco ASA: Major.Minor(Maintenance)[Build] e.g. 9.18(4)22, 9.20(3), 9.18(3)40
    m_asa = re.match(r"^(\d+)\.(\d+)[_\.]?\((\d+)\)(\d+)?$", s)
    if ("asa" in os_lower or not os_lower) and m_asa:
        major, minor, maint, build = m_asa.groups()
        return (int(major), int(minor), int(maint), int(build) if build else 0)

    # 4. Palo Alto PAN-OS: Major.Minor.Patch[-hHotfix] e.g. 10.1.6-h3, 10.2.3-h4, 11.0.2
    m_pan = re.match(r"^(\d+)\.(\d+)\.(\d+)(?:[-_\.]h(\d+))?$", s, re.IGNORECASE)
    if m_pan and (m_pan.group(4) or "pan" in os_lower):
        major, minor, patch, hf = m_pan.groups()
        return (int(major), int(minor), int(patch), int(hf) if hf else 0)

    # 5. Cisco IOS XE / FortiOS with Letter: 17.15.1a, 16.12.1a, 17.3.4b
    m_ios_xe = re.match(r"^(\d+)\.(\d+)\.(\d+)([a-zA-Z])?(?:\.(\d+))?$", s)
    if m_ios_xe and (m_ios_xe.group(4) or m_ios_xe.group(5)):
        major, minor, patch, letter, rebuild = m_ios_xe.groups()
        let_val = (ord(letter.lower()) - ord("a") + 1) if letter else 0
        reb_val = int(rebuild) if rebuild else 0
        return (
            (int(major), int(minor), int(patch), let_val, reb_val)
            if reb_val
            else (int(major), int(minor), int(patch), let_val)
        )

    # 6. Cisco IOS Classic: Major.Minor(Maint)Train[Rebuild] e.g. 15.2(4)M, 15.4(3)M2
    m_classic = re.match(r"^(\d+)\.(\d+)\((\d+)\)([a-zA-Z]+)?(\d+)?$", s)
    if m_classic:
        maj, minr, maint, train, reb = m_classic.groups()
        train_val = ord(train[0].upper()) if train else 0
        reb_val = int(reb) if reb else 0
        return (int(maj), int(minr), int(maint), train_val, reb_val)

    # 7. Standard 3-part dotted numeric version: e.g. 17.3.3, 7.2.5, 9.16.2, 10.2.3
    m_3dot = re.match(r"^(\d+)\.(\d+)\.(\d+)$", s)
    if m_3dot:
        major, minor, patch = m_3dot.groups()
        return (int(major), int(minor), int(patch), 0)

    # 8. Standard dotted numeric: e.g. 9.14.1.10, 10.1, 7.0
    m_dots = re.match(r"^(\d+)(?:\.(\d+))*$", s)
    if m_dots:
        return tuple(int(x) for x in s.split("."))

    # 9. Generic dotted numeric with letters
    m_dots_gen = re.match(r"^(\d+)(?:\.(\d+))*(?:[a-zA-Z](\d+)?)?$", s)
    if m_dots_gen:
        raw_parts = re.split(r"[._-]+", s)
        res = []
        for p in raw_parts:
            sub = re.findall(r"(\d+|[a-zA-Z]+)", p)
            for item in sub:
                if item.isdigit():
                    res.append(int(item))
                else:
                    for ch in item.lower():
                        res.append(ord(ch) - ord("a") + 1)
        return tuple(res)

    # 10. Fallback generic regex extraction
    parts = re.findall(r"(\d+|[a-zA-Z]+)", s)
    res = []
    for p in parts:
        if p.isdigit():
            res.append(int(p))
        else:
            for ch in p.lower():
                res.append(ord(ch) - ord("a") + 1)
    return tuple(res)


def compare_versions(
    v1: str,
    v2: str,
    os_type: Optional[str] = None,
) -> int:
    """Compare two version strings mathematically.

    Args:
        v1: First version string.
        v2: Second version string.
        os_type: Optional OS family hint.

    Returns:
        -1 if v1 < v2
         0 if v1 == v2
         1 if v1 > v2
    """
    t1 = normalize_version(v1, os_type=os_type)
    t2 = normalize_version(v2, os_type=os_type)

    # Align lengths by zero-padding the shorter tuple
    max_len = max(len(t1), len(t2))
    p1 = t1 + (0,) * (max_len - len(t1))
    p2 = t2 + (0,) * (max_len - len(t2))

    if p1 < p2:
        return -1
    elif p1 > p2:
        return 1
    return 0


def is_version_in_range(
    version_str: str,
    v_start_inc: Optional[str] = None,
    v_start_exc: Optional[str] = None,
    v_end_inc: Optional[str] = None,
    v_end_exc: Optional[str] = None,
    exact_version: Optional[str] = None,
    os_type: Optional[str] = None,
    target_ver: Optional[str] = None,
    min_ver: Optional[str] = None,
    max_ver: Optional[str] = None,
    include_min: bool = True,
    include_max: bool = False,
    *args,
    **kwargs,
) -> bool:
    """Check if version_str falls within specified version range bounds.

    Supports both NVD CPE range format (v_start_inc, v_start_exc, v_end_inc, v_end_exc)
    and legacy range parameters (min_ver, max_ver, include_min, include_max).

    Args:
        version_str: Target version string to evaluate.
        v_start_inc: Inclusive lower bound (>=).
        v_start_exc: Exclusive lower bound (>).
        v_end_inc: Inclusive upper bound (<=).
        v_end_exc: Exclusive upper bound (<).
        exact_version: Exact matching version (==).
        os_type: Optional OS family identifier.
        target_ver: Legacy target version parameter alias.
        min_ver: Legacy minimum version bound.
        max_ver: Legacy maximum version bound.
        include_min: Legacy flag for min inclusion.
        include_max: Legacy flag for max inclusion.

    Returns:
        True if version_str satisfies all active bounds, False otherwise.
    """
    v_str = version_str or target_ver or ""
    if not v_str or not isinstance(v_str, str) or not v_str.strip():
        return False

    # Detect legacy 5-argument positional call: is_version_in_range(v, "7.4.0", "7.4.2", True, True)
    if isinstance(v_end_inc, bool):
        legacy_min = v_start_inc
        legacy_max = v_start_exc
        legacy_inc_min = v_end_inc
        legacy_inc_max = bool(v_end_exc)

        v_start_inc = legacy_min if legacy_inc_min else None
        v_start_exc = legacy_min if not legacy_inc_min else None
        v_end_inc = legacy_max if legacy_inc_max else None
        v_end_exc = legacy_max if not legacy_inc_max else None
        exact_version = None
    elif min_ver is not None or max_ver is not None:
        if min_ver is not None:
            v_start_inc = min_ver if include_min else None
            v_start_exc = min_ver if not include_min else None
        if max_ver is not None:
            v_end_inc = max_ver if include_max else None
            v_end_exc = max_ver if not include_max else None

    # Check exact_version if specified
    if exact_version is not None:
        if compare_versions(v_str, exact_version, os_type=os_type) == 0:
            return True
        if not any([v_start_inc, v_start_exc, v_end_inc, v_end_exc]):
            return False

    # If no bounds and no exact_version specified at all
    if not any([v_start_inc, v_start_exc, v_end_inc, v_end_exc, exact_version]):
        return True

    # 1. Lower bound (inclusive >=)
    if v_start_inc is not None:
        if compare_versions(v_str, v_start_inc, os_type=os_type) < 0:
            return False

    # 2. Lower bound (exclusive >)
    if v_start_exc is not None:
        if compare_versions(v_str, v_start_exc, os_type=os_type) <= 0:
            return False

    # 3. Upper bound (inclusive <=)
    if v_end_inc is not None:
        if compare_versions(v_str, v_end_inc, os_type=os_type) > 0:
            return False

    # 4. Upper bound (exclusive <)
    if v_end_exc is not None:
        if compare_versions(v_str, v_end_exc, os_type=os_type) >= 0:
            return False

    return True
