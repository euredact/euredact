"""Unicode normalization for input text: NFC, and digits folded to ASCII."""

from __future__ import annotations

import unicodedata

#: The zero of every run of decimal digits in the Basic Multilingual Plane
#: outside ASCII (Unicode 16; each run is 0-9 in order). The TypeScript SDK
#: carries the same list, so both fold the same characters whatever Unicode
#: version their runtime has.
_DIGIT_ZEROS = (
    0x0660, 0x06F0, 0x07C0, 0x0966, 0x09E6, 0x0A66, 0x0AE6, 0x0B66, 0x0BE6,
    0x0C66, 0x0CE6, 0x0D66, 0x0DE6, 0x0E50, 0x0ED0, 0x0F20, 0x1040, 0x1090,
    0x17E0, 0x1810, 0x1946, 0x19D0, 0x1A80, 0x1A90, 0x1B50, 0x1BB0, 0x1C40,
    0x1C50, 0xA620, 0xA8D0, 0xA900, 0xA9D0, 0xA9F0, 0xAA50, 0xABF0, 0xFF10,
)

#: Each of those digits to its ASCII digit: one character for one, so offsets
#: do not move.
_ASCII_DIGITS = {zero + k: 0x30 + k for zero in _DIGIT_ZEROS for k in range(10)}


def normalize(text: str) -> tuple[str, list[int] | None]:
    """Normalize text to NFC form, digits to ASCII, before pattern matching.

    Returns the normalized text and an offset mapping from normalized positions
    to original positions (None when NFC left the text as it was).

    The mapping is built whenever NFC changed the text, not only when it
    changed its length: a composition (two characters to one) and an
    expansion (U+0958 to two) cancel out in the length and still move every
    character between them, and the masks landed one character off
    (rules-engine#150).

    Digits are folded to ASCII, one character for one, so offsets stay put.
    The patterns are written with ASCII digits in mind: a phone number in
    full-width digits ("０６１２３４５６７８") was left whole by the TypeScript
    SDK, whose ``\\d`` is ASCII, and cut in two by the Python one, whose ``\\d``
    is not but whose word boundaries are (rules-engine#150).
    """
    normalized = unicodedata.normalize("NFC", text)
    mapping = None if normalized == text else _build_offset_mapping(text, normalized)
    if not normalized.isascii():
        normalized = normalized.translate(_ASCII_DIGITS)
    return normalized, mapping


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
    # The end of the text maps to the end of the original. Extrapolating one
    # past the last character landed inside a decomposed cluster: a detection
    # ending on "é" written e + U+0301 left the accent outside the mask
    # (rules-engine#159).
    norm_to_orig.append(len(original))

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
