"""Version parsing and comparison utilities for network OS versions.

Supports vendor-specific formats:
- Cisco ASA: 9.20(3), 9.18(4)22, 9.16.2
- Cisco IOS XE: 17.15.1a, 16.10.1, 17.3.4b
- Cisco IOS Classic: 15.2(4)M, 15.4(3)M2
- Fortinet FortiOS: v7.2.4, 7.0.0, 7.4.1
- Palo Alto PAN-OS: 10.2.3-h4, 11.0.2, 9.1.12-h3
"""

import re
from typing import Optional, Tuple


def normalize_version(version_str: str) -> Tuple[int, ...]:
    """Normalize a network OS version string into a comparable tuple of integers.

    Args:
        version_str: Version string (e.g., '9.20(3)', '17.15.1a', '10.2.3-h4').

    Returns:
        A tuple of integers suitable for mathematical comparison.
    """
    if not version_str or not isinstance(version_str, str):
        return ()

    s = version_str.strip().lstrip("vV")
    if not s:
        return ()

    # 1. Cisco ASA: Major.Minor(Maintenance)[Build] e.g. 9.18(4)22, 9.20(3)
    m_asa = re.match(r"^(\d+)\.(\d+)\((\d+)\)(\d+)?$", s)
    if m_asa:
        major, minor, maint, build = m_asa.groups()
        return (int(major), int(minor), int(maint), int(build) if build else 0)

    # 2. Palo Alto PAN-OS: Major.Minor.Patch[-hHotfix] e.g. 10.2.3-h4, 11.0.2
    m_pan = re.match(r"^(\d+)\.(\d+)\.(\d+)(?:-h(\d+))?$", s)
    if m_pan:
        major, minor, patch, hf = m_pan.groups()
        return (int(major), int(minor), int(patch), int(hf) if hf else 0)

    # 3. Cisco IOS XE / FortiOS: Major.Minor.Patch[Letter] e.g. 17.15.1a, 7.2.4
    m_ios_xe = re.match(r"^(\d+)\.(\d+)\.(\d+)([a-zA-Z])?$", s)
    if m_ios_xe:
        major, minor, patch, letter = m_ios_xe.groups()
        let_val = (ord(letter.lower()) - ord("a") + 1) if letter else 0
        return (int(major), int(minor), int(patch), let_val)

    # 4. Cisco IOS Classic: Major.Minor(Maint)Train[Rebuild] e.g. 15.2(4)M, 15.4(3)M2
    m_classic = re.match(r"^(\d+)\.(\d+)\((\d+)\)([a-zA-Z]+)?(\d+)?$", s)
    if m_classic:
        maj, minr, maint, train, reb = m_classic.groups()
        train_val = ord(train[0].upper()) if train else 0
        reb_val = int(reb) if reb else 0
        return (int(maj), int(minr), int(maint), train_val, reb_val)

    # 5. Generic dotted numeric version: e.g. 9.16.2, 10.1, 7.0
    m_dots = re.match(r"^(\d+)(?:\.(\d+))*(?:[a-zA-Z](\d+)?)?$", s)
    if m_dots:
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

    # 6. Fallback generic regex extraction
    parts = re.findall(r"(\d+|[a-zA-Z]+)", s)
    res = []
    for p in parts:
        if p.isdigit():
            res.append(int(p))
        else:
            for ch in p.lower():
                res.append(ord(ch) - ord("a") + 1)
    return tuple(res)


def compare_versions(v1: str, v2: str) -> int:
    """Compare two version strings.

    Args:
        v1: First version string.
        v2: Second version string.

    Returns:
        -1 if v1 < v2
         0 if v1 == v2
         1 if v1 > v2
    """
    t1 = normalize_version(v1)
    t2 = normalize_version(v2)

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
    target_ver: str,
    min_ver: Optional[str] = None,
    max_ver: Optional[str] = None,
    include_min: bool = True,
    include_max: bool = False,
) -> bool:
    """Check if target_ver falls within the specified range [min_ver, max_ver).

    Args:
        target_ver: Target version string to evaluate.
        min_ver: Minimum version bound (or None if no lower bound).
        max_ver: Maximum version bound (or None if no upper bound).
        include_min: True to include min_ver (>=), False for strict (>).
        include_max: True to include max_ver (<=), False for strict (<).

    Returns:
        True if target_ver is within the range, False otherwise.
    """
    if not target_ver:
        return False

    if min_ver is not None:
        cmp_min = compare_versions(target_ver, min_ver)
        if include_min and cmp_min < 0:
            return False
        if not include_min and cmp_min <= 0:
            return False

    if max_ver is not None:
        cmp_max = compare_versions(target_ver, max_ver)
        if include_max and cmp_max > 0:
            return False
        if not include_max and cmp_max >= 0:
            return False

    return True
