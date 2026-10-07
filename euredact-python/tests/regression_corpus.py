"""Regression records for the corpus: the layouts the generated corpus lacked.

Every fix in rules-engine#82, #90, #91, #93 and #94 left the 152,300-document
corpus exactly as it was, before and after. Not because the fixes did nothing --
the pipeline documents gained 1,800 masked values from them -- but because the
corpus contained none of the layouts involved: no AVS number with a bad check
digit, no KRS, no Polish domestic account number or personal NIP grouping, and
no identifier sitting above a bulleted line. A regression in any of them would
have passed `make eval`, `make sweep` and `make parity` in silence.

This module writes those layouts as corpus records, deterministically, in the
corpus's own format (`source_text` plus `PII`), so all three corpus tools see
them once the file is in `EUREDACT_CORPUS`. Two extra keys ride along and are
ignored by the corpus tools: `regression`, the issue a record guards, and
`must_not_detect`, values that must stay unmasked. Each negative sits in a
record that also carries real PII, because `make eval` skips a record with
none, and only then does a wrong detection count as a false positive.

The same records are a hard gate here: `check()` fails on any value not masked
whole with an accepted type, and on any detection touching a `must_not_detect`
value, in both of the modes `make eval` runs (with and without country hints).
A few hundred records in a corpus of 152,000 move the aggregate recall by
less than its rounding, so the aggregate alone would not catch a regression.

    python tests/regression_corpus.py --check            # gate, exit 1 on failure
    python tests/regression_corpus.py --write "$EUREDACT_CORPUS"
"""
from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import euredact  # noqa: E402
from euredact.rules.validators import VALIDATORS  # noqa: E402
from eval_full import CATEGORY_MAP, _recall_outcome  # noqa: E402

FILENAME = "euromask_regressions.json"
SEED = 20261007
#: Variants generated per template. Small, because each template already pins
#: one layout; the variants only vary the digits, names and surrounding words.
PER_TEMPLATE = 6


# ── Values ──────────────────────────────────────────────────────────────


def _digits(rng: random.Random, n: int) -> str:
    return "".join(rng.choice("0123456789") for _ in range(n))


def _sample(rng: random.Random, make, validator: str):
    """Draw from *make* until the engine's own validator accepts it."""
    check = VALIDATORS[validator]
    while True:
        value = make(rng)
        if check(value):
            return value


def ahv(rng: random.Random, *, valid: bool) -> str:
    """A 13-digit AHV, compact. *valid* chooses whether its EAN-13 digit holds."""
    good = _sample(rng, lambda r: "756" + _digits(r, 10), "swiss_ahv")
    if valid:
        return good
    return good[:-1] + str((int(good[-1]) + 1 + rng.randrange(9)) % 10)


def dotted_ahv(compact: str) -> str:
    return f"{compact[:3]}.{compact[3:7]}.{compact[7:11]}.{compact[11:]}"


def krs(rng: random.Random) -> str:
    return "0000" + _digits(rng, 6)


def regon(rng: random.Random) -> str:
    return _sample(rng, lambda r: _digits(r, 9), "polish_regon")


def nip(rng: random.Random) -> str:
    return _sample(rng, lambda r: _digits(r, 10), "polish_nip")


def nip_company(n: str) -> str:
    return f"{n[:3]}-{n[3:6]}-{n[6:8]}-{n[8:]}"


def nip_personal(n: str) -> str:
    return f"{n[:3]}-{n[3:5]}-{n[5:7]}-{n[7:]}"


def nrb(rng: random.Random, *, valid: bool = True) -> str:
    """A Polish NRB: the PL IBAN's check digits and 24-digit BBAN, no "PL"."""
    bban = _digits(rng, 24)
    check = 98 - int(bban + "252100") % 97
    if not valid:
        check = (check + 1 + rng.randrange(90)) % 100
    return f"{check:02d}{bban}"


def nrb_spaced(n: str) -> str:
    return " ".join([n[:2]] + [n[i:i + 4] for i in range(2, 26, 4)])


def bsn(rng: random.Random) -> str:
    return _sample(rng, lambda r: _digits(r, 9), "bsn")


def belgian_nn(rng: random.Random) -> str:
    yy, mm, dd = rng.randrange(50, 99), rng.randrange(1, 13), rng.randrange(1, 29)
    seq = rng.randrange(1, 998)
    first = f"{yy:02d}{mm:02d}{dd:02d}{seq:03d}"
    check = 97 - int(first) % 97
    return f"{first[:2]}.{first[2:4]}.{first[4:6]}-{first[6:]}.{check:02d}"


def nl_mobile(rng: random.Random) -> str:
    return f"06 {_digits(rng, 8)}"


def at_mobile(rng: random.Random) -> str:
    return f"+43 664 {rng.randrange(1, 10)}{_digits(rng, 6)}"


def uk_mobile(rng: random.Random) -> str:
    return f"+44 7{_digits(rng, 3)} {_digits(rng, 6)}"


_FIRST = ["anna", "lukas", "marta", "piotr", "sophie", "jan", "elena", "noah", "chiara", "tomasz"]
_LAST = ["meier", "kowalski", "de-vries", "peeters", "nowak", "brunner", "rossi", "janssen"]
_DOMAINS = ["example.ch", "example.pl", "example.nl", "example.be", "example.at", "example.co.uk"]


def email(rng: random.Random) -> str:
    return f"{rng.choice(_FIRST)}.{rng.choice(_LAST)}@{rng.choice(_DOMAINS)}"


def pii(value: str, category: str, country: str) -> dict:
    return {"PII_identifier": value, "PII_category": category, "PII_country": country}


# ── Templates ───────────────────────────────────────────────────────────
#
# Each returns (source_text, PII, must_not_detect). One template, one layout.


def _avs(label_and_value: str, valid: bool, compact: bool = False):
    def build(rng):
        a = ahv(rng, valid=valid)
        v = a if compact else dotted_ahv(a)
        e = email(rng)
        text = label_and_value.format(v=v) + f" Kontakt: {e}"
        return text, [pii(v, "NATIONAL_ID", "CH"), pii(e, "EMAIL", "CH")], []
    return build


def _avs_unlabelled(rng):
    v = dotted_ahv(ahv(rng, valid=False))
    e = email(rng)
    return f"Referenz {v} im Archiv. Kontakt: {e}", [pii(e, "EMAIL", "CH")], [v]


def _krs(template: str):
    def build(rng):
        k, r, n = krs(rng), regon(rng), nip(rng)
        text = template.format(krs=k, regon=r, nip=nip_company(n))
        found = [pii(k, "CHAMBER_OF_COMMERCE", "PL")]
        if "{regon}" in template:
            found.append(pii(r, "CHAMBER_OF_COMMERCE", "PL"))
        if "{nip}" in template:
            found.append(pii(nip_company(n), "TAX_ID", "PL"))
        return text, found, []
    return build


def _nrb(label: str, spaced: bool):
    def build(rng):
        n = nrb(rng)
        v = nrb_spaced(n) if spaced else n
        return f"{label}{v}. Tytuł przelewu: faktura 14/2026.", [pii(v, "BANK_ACCOUNT", "PL")], []
    return build


def _nrb_bad_check(rng):
    v = nrb_spaced(nrb(rng, valid=False))
    e = email(rng)
    return (f"Nr rachunku: {v}\nKontakt: {e}", [pii(e, "EMAIL", "PL")], [v])


def _nip(label: str, personal: bool):
    def build(rng):
        n = nip(rng)
        v = nip_personal(n) if personal else nip_company(n)
        return f"{label}{v}, podatnik VAT czynny.", [pii(v, "TAX_ID", "PL")], []
    return build


def _bullets(rows, country: str):
    """A bulleted block: each row is (label, value-maker, category)."""
    def build(rng):
        lines, found = [], []
        for label, make, category in rows:
            v = make(rng)
            lines.append(f"- {label}: {v}")
            found.append(pii(v, category, country))
        lines.append("- Notitie: terugbellen na 14:00")
        return "Gegevens\n" + "\n".join(lines), found, []
    return build


def _rule_after(label: str, make, category: str, country: str):
    def build(rng):
        v = make(rng)
        return (f"{label}: {v}\n\n---\n\nBeschreibung des Vorgangs folgt.",
                [pii(v, category, country)], [])
    return build


def _asterisk_after(rng):
    v = belgian_nn(rng)
    return (f"Rijksregisternummer: {v}\n* volgende punt: adreswijziging",
            [pii(v, "NATIONAL_ID", "BE")], [])


def _timeline(rng):
    """Bulleted timeline dates are not phones: guards against widening #91."""
    e = email(rng)
    d1 = f"{rng.randrange(1, 28):02d}.0{rng.randrange(1, 9)}.2026 {rng.randrange(10, 23)}:{rng.randrange(10, 59)}"
    d2 = f"{rng.randrange(1, 28):02d}.0{rng.randrange(1, 9)}.2026 0{rng.randrange(1, 9)}:{rng.randrange(10, 59)}"
    text = (f"## Zeitachse\n\n- {d1} — Push nach öffentlichem Repo\n"
            f"- {d2} — Schlüssel rotiert\n\nMeldung an {e}")
    return text, [pii(e, "EMAIL", "DE")], [d1, d2]


def _references(rng):
    """Hyphenated references are not phones: guards against widening #91."""
    e = email(rng)
    r1 = f"V-20{rng.randrange(10, 27)}-{_digits(rng, 7)}"
    r2 = f"PV-LS-2026-{_digits(rng, 6)}"
    text = f"IND-referentie {r1} (verleend), proces-verbaal {r2}. Contact: {e}"
    return text, [pii(e, "EMAIL", "NL")], [r1, r2]


TEMPLATES: list[tuple[str, object]] = [
    # #82: AVS/AHV with a bad check digit, named as such.
    ("rules-engine#82: label touching", _avs("Numéro AVS {v}.", valid=False)),
    ("rules-engine#82: AHV-Nr.", _avs("AHV-Nr. {v}.", valid=False)),
    ("rules-engine#82: AHV-Nummer, compact", _avs("AHV-Nummer: {v}.", valid=False, compact=True)),
    ("rules-engine#82: n° AVS", _avs("n° AVS: {v}.", valid=False)),
    ("rules-engine#82: in parentheses", _avs("Numéro AVS ({v}), adresse inchangée.", valid=False)),
    ("rules-engine#82: in backticks", _avs("Bitte die AHV-Nummer `{v}` abfragen.", valid=False)),
    ("rules-engine#82: after a phrase", _avs("Le numéro AVS de l'assurée : {v}.", valid=False)),
    ("rules-engine#82: valid, behind its label", _avs("Numéro AVS {v}.", valid=True)),
    ("rules-engine#82: unlabelled bad number stays unmasked", _avs_unlabelled),
    # #90: KRS is a register number, not a phone.
    ("rules-engine#90: KRS label", _krs("KRS: {krs}.")),
    ("rules-engine#90: KRS in prose", _krs("Spółka wpisana do rejestru przedsiębiorców pod numerem KRS {krs}.")),
    ("rules-engine#90: KYC paragraph", _krs("NIP: {nip}. REGON: {regon}. KRS: {krs}.")),
    # #91: a bullet or rule on the next line is not arithmetic.
    ("rules-engine#91: NL bullets", _bullets([("BSN", bsn, "NATIONAL_ID"), ("Telefoon", nl_mobile, "PHONE")], "NL")),
    ("rules-engine#91: NL phone then bullet", _bullets([("Telefoon", nl_mobile, "PHONE")], "NL")),
    ("rules-engine#91: AHV then bullet", _bullets([("AHV-Nummer", lambda r: dotted_ahv(ahv(r, valid=True)), "NATIONAL_ID")], "CH")),
    ("rules-engine#91: AT phone before a rule", _rule_after("Kontakt", at_mobile, "PHONE", "AT")),
    ("rules-engine#91: UK phone before a rule", _rule_after("Tel", uk_mobile, "PHONE", "UK")),
    ("rules-engine#91: BE number before an asterisk", _asterisk_after),
    ("rules-engine#91: timeline dates stay unmasked", _timeline),
    ("rules-engine#91: references stay unmasked", _references),
    # #93: the Polish domestic account number.
    ("rules-engine#93: Nr rachunku, spaced", _nrb("Nr rachunku: ", spaced=True)),
    ("rules-engine#93: Numer konta, compact", _nrb("Numer konta: ", spaced=False)),
    ("rules-engine#93: payment request, spaced", _nrb("Proszę o wpłatę na konto ", spaced=True)),
    ("rules-engine#93: Rachunek bankowy nr, compact", _nrb("Rachunek bankowy nr ", spaced=False)),
    ("rules-engine#93: bad check digits stay unmasked", _nrb_bad_check),
    # #94: the NIP in both groupings.
    ("rules-engine#94: personal grouping", _nip("NIP: ", personal=True)),
    ("rules-engine#94: personal grouping, in prose", _nip("numer NIP podatnika ", personal=True)),
    ("rules-engine#94: company grouping", _nip("NIP: ", personal=False)),
]


def build(per_template: int = PER_TEMPLATE) -> list[dict]:
    rng = random.Random(SEED)
    records = []
    for name, template in TEMPLATES:
        for _ in range(per_template):
            text, found, absent = template(rng)
            records.append({"source_text": text, "PII": found,
                            "regression": name, "must_not_detect": absent})
    return records


# ── Gate ────────────────────────────────────────────────────────────────


def check(records: list[dict]) -> list[str]:
    """Every failure, as a readable line; empty when the engine holds."""
    failures = []
    for rec in records:
        text = rec["source_text"]
        countries = sorted({p["PII_country"] for p in rec["PII"]})
        for hint in (countries, None):
            dets = euredact.redact(text, countries=hint, detect_dates=True, cache=False).detections
            mode = "hints" if hint else "blind"
            for p in rec["PII"]:
                acceptable = CATEGORY_MAP.get(p["PII_category"], {p["PII_category"]})
                outcome = _recall_outcome(text, dets, p["PII_identifier"], acceptable)
                if outcome != "hit":
                    failures.append(f"{rec['regression']} [{mode}]: {p['PII_category']} "
                                    f"{p['PII_identifier']!r} {outcome} in {text!r}")
            for value in rec["must_not_detect"]:
                start = text.find(value)
                end = start + len(value)
                for d in dets:
                    if d.start < end and d.end > start:
                        failures.append(f"{rec['regression']} [{mode}]: {d.entity_type.value} "
                                        f"{d.text!r} detected inside {value!r}")
    return failures


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--write", metavar="DIR", help=f"write {FILENAME} into DIR")
    ap.add_argument("--check", action="store_true", help="fail on any regression")
    args = ap.parse_args()
    records = build()
    if args.write:
        path = Path(args.write) / FILENAME
        path.write_text(json.dumps(records, indent=1, ensure_ascii=False) + "\n")
        print(f"wrote {len(records)} records to {path}")
    if args.check or not args.write:
        failures = check(records)
        for line in failures:
            print(line)
        print(f"{len(records)} regression records, {len(failures)} failures")
        return 1 if failures else 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
