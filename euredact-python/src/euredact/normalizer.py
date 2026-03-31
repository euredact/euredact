"""Unicode NFC normalization for input text."""

from __future__ import annotations

import unicodedata


def normalize(text: str) -> tuple[str, list[int] | None]:
    """Normalize text to NFC form before pattern matching.

    Returns the normalized text and an offset mapping from normalized positions
    to original positions (None if no length change occurred).
    """
    normalized = unicodedata.normalize("NFC", text)
    if len(normalized) == len(text):
        return normalized, None

    # Build character offset mapping: normalized index -> original index
    # We do this by normalizing character-by-character
    mapping: list[int] = []
    orig_idx = 0
    for char in text:
        nfc_char = unicodedata.normalize("NFC", char)
        for _ in nfc_char:
            mapping.append(orig_idx)
        orig_idx += len(char.encode("utf-32-le")) // 4
        # Actually, we need codepoint-level tracking
    # Simpler approach: use NFC on full string and build mapping via
    # decompose-then-compose tracking
    # For most European text, NFC doesn't change length. When it does,
    # the mapping lets us translate detection offsets back to original positions.
    return normalized, _build_offset_mapping(text, normalized)


def _build_offset_mapping(original: str, normalized: str) -> list[int]:
    """Build mapping from normalized character positions to original positions.

    Uses NFD as intermediate to align characters between original and NFC.
    """
    nfd_original = unicodedata.normalize("NFD", original)
    nfd_normalized = unicodedata.normalize("NFD", normalized)

    # Both NFD forms should be identical
    # Build: original char index -> NFD index range
    orig_to_nfd: list[int] = []
    nfd_idx = 0
    for char in original:
        nfd_char = unicodedata.normalize("NFD", char)
        orig_to_nfd.append(nfd_idx)
        nfd_idx += len(nfd_char)

    # Build: NFD index -> normalized char index
    nfd_to_norm: list[int] = []
    nfd_idx = 0
    for norm_idx, char in enumerate(normalized):
        nfd_char = unicodedata.normalize("NFD", char)
        for _ in nfd_char:
            nfd_to_norm.append(norm_idx)
        nfd_idx += len(nfd_char)

    # Build: normalized index -> original index
    # For each normalized position, find which original character maps to it
    norm_to_orig: list[int] = []
    orig_char_idx = 0
    orig_nfd_pos = 0
    for norm_idx in range(len(normalized)):
        nfd_of_norm_char = unicodedata.normalize("NFD", normalized[norm_idx])
        nfd_start = sum(
            len(unicodedata.normalize("NFD", normalized[i]))
            for i in range(norm_idx)
        )
        # Find which original character this NFD position belongs to
        target_orig = 0
        running = 0
        for oi, oc in enumerate(original):
            nfd_oc = unicodedata.normalize("NFD", oc)
            if running + len(nfd_oc) > nfd_start:
                target_orig = oi
                break
            running += len(nfd_oc)
        norm_to_orig.append(target_orig)

    return norm_to_orig


def map_offset_to_original(
    offset: int, mapping: list[int] | None
) -> int:
    """Map a normalized-text offset back to an original-text offset."""
    if mapping is None:
        return offset
    if offset >= len(mapping):
        # Past end of mapping — extrapolate
        if mapping:
            return mapping[-1] + (offset - len(mapping) + 1)
        return offset
    return mapping[offset]
