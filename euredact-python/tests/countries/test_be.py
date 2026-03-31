"""Belgium-specific pattern tests."""

import euredact
from euredact.types import EntityType


class TestBelgianNationalID:
    def test_valid_nn_detected(self):
        # Valid: 850412123, check = 97 - (850412123 % 97) = 69
        result = euredact.redact(
            "Zijn rijksregisternummer is 85.04.12-123.69.",
            countries=["BE"],
        )
        assert any(d.entity_type == EntityType.NATIONAL_ID for d in result.detections)

    def test_valid_nn_no_formatting(self):
        result = euredact.redact(
            "RR: 85041212369", countries=["BE"]
        )
        assert any(d.entity_type == EntityType.NATIONAL_ID for d in result.detections)

    def test_invalid_nn_not_detected(self):
        result = euredact.redact(
            "Het nummer is 85041212399.", countries=["BE"]
        )
        assert not any(d.entity_type == EntityType.NATIONAL_ID for d in result.detections)


class TestBelgianIBAN:
    def test_valid_iban(self):
        result = euredact.redact(
            "Mijn IBAN is BE68 5390 0754 7034.", countries=["BE"]
        )
        assert any(d.entity_type == EntityType.IBAN for d in result.detections)
        assert "[IBAN]" in result.redacted_text

    def test_valid_iban_compact(self):
        result = euredact.redact(
            "IBAN: BE68539007547034", countries=["BE"]
        )
        assert any(d.entity_type == EntityType.IBAN for d in result.detections)

    def test_invalid_iban(self):
        result = euredact.redact(
            "IBAN: BE00539007547034", countries=["BE"]
        )
        assert not any(d.entity_type == EntityType.IBAN for d in result.detections)


class TestBelgianVAT:
    def test_valid_vat(self):
        result = euredact.redact("BTW: BE0123456749", countries=["BE"])
        assert any(d.entity_type == EntityType.VAT for d in result.detections)

    def test_valid_vat_formatted(self):
        result = euredact.redact("BTW: BE 0123.456.749", countries=["BE"])
        assert any(d.entity_type == EntityType.VAT for d in result.detections)


class TestBelgianPhone:
    def test_national_landline(self):
        result = euredact.redact(
            "Bel ons op 02/123.45.67.", countries=["BE"]
        )
        assert any(d.entity_type == EntityType.PHONE for d in result.detections)

    def test_national_mobile(self):
        result = euredact.redact(
            "Mijn GSM is 0478/12.34.56.", countries=["BE"]
        )
        assert any(d.entity_type == EntityType.PHONE for d in result.detections)

    def test_international(self):
        result = euredact.redact(
            "Call +32 2 123 45 67.", countries=["BE"]
        )
        assert any(d.entity_type == EntityType.PHONE for d in result.detections)


class TestBelgianLicensePlate:
    def test_current_format(self):
        result = euredact.redact(
            "Nummerplaat: 1-ABC-234.", countries=["BE"]
        )
        assert any(d.entity_type == EntityType.LICENSE_PLATE for d in result.detections)

    def test_no_dashes(self):
        result = euredact.redact(
            "Plaat 1ABC234.", countries=["BE"]
        )
        assert any(d.entity_type == EntityType.LICENSE_PLATE for d in result.detections)


class TestBelgianEmail:
    def test_email_detected(self):
        result = euredact.redact(
            "E-mail: jan.desmedt@example.be", countries=["BE"]
        )
        assert any(d.entity_type == EntityType.EMAIL for d in result.detections)


class TestBelgianDOB:
    def test_dob_with_context(self):
        result = euredact.redact(
            "Geboren op 12/04/1985 te Antwerpen.",
            countries=["BE"], detect_dates=True,
        )
        assert any(d.entity_type == EntityType.DOB for d in result.detections)

    def test_date_without_context_not_detected(self):
        result = euredact.redact(
            "De vergadering is op 12/04/1985.",
            countries=["BE"], detect_dates=True,
        )
        assert not any(d.entity_type == EntityType.DOB for d in result.detections)

    def test_dob_excluded_by_default(self):
        result = euredact.redact(
            "Geboren op 12/04/1985 te Antwerpen.", countries=["BE"]
        )
        assert not any(d.entity_type == EntityType.DOB for d in result.detections)


class TestBelgianCreditCard:
    def test_visa(self):
        result = euredact.redact(
            "Kaart: 4532 0151 1283 0366", countries=["BE"]
        )
        assert any(d.entity_type == EntityType.CREDIT_CARD for d in result.detections)
