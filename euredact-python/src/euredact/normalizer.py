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
    Runs in O(n) using cumulative prefix sums and a two-pointer scan.
    """
    # Precompute cumulative NFD lengths for normalized characters
    norm_nfd_cum = [0]
    for ch in normalized:
        norm_nfd_cum.append(norm_nfd_cum[-1] + len(unicodedata.normalize("NFD", ch)))

    # Precompute cumulative NFD lengths for original characters
    orig_nfd_cum = [0]
    for ch in original:
        orig_nfd_cum.append(orig_nfd_cum[-1] + len(unicodedata.normalize("NFD", ch)))

    # Two-pointer scan: map each normalized position to its original position
    norm_to_orig: list[int] = []
    orig_ptr = 0
    for norm_idx in range(len(normalized)):
        nfd_start = norm_nfd_cum[norm_idx]
        while orig_ptr + 1 < len(original) and orig_nfd_cum[orig_ptr + 1] <= nfd_start:
            orig_ptr += 1
        norm_to_orig.append(orig_ptr)

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
