"""Synthetic guards/bytes only; no private projects or official authority."""
from copy import deepcopy
from dataclasses import FrozenInstanceError
import hashlib
import struct
import unittest

from gx3_fx5_profile.hsc_observed import (
    HscObservedError, MAX_UNIT_BYTES, MAX_W3PA_BYTES, PROFILE_FORMAT,
    decode_hsc_observed_settings,
)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def nested(count, width, value):
    return struct.pack("<I", count) + b"".join(
        struct.pack("<III", 1, 0x80000000 + index, width) + value
        for index in range(count))


def record(tag, payload):
    attributes = b"".join(struct.pack("<IIIH", 0xFFFFFFFF, index + 1, 2,
                                    1 if index == 0 else 0) for index in range(4))
    return struct.pack("<5I", 76 + len(payload), tag, 1, 1, 4) + payload + attributes


def fixture(overrides=None):
    overrides = overrides or {}
    unit = b"synthetic unit member; no engineering meaning"
    pairs = [(14809, b"\x00" * 4), (14780, nested(8, 1, b"\x00")),
             (14712, nested(16, 4, b"\x20\x00\x00\x00"))]
    pairs.extend((1000 + index, struct.pack("<I", index)) for index in range(227))
    pairs = [(tag, overrides.get(tag, payload)) for tag, payload in pairs]
    profile = {"format": PROFILE_FORMAT, "version": 1, "unit_sha256": digest(unit),
               "records": [{"tag": tag, "size": 76 + len(payload), "primary": 4,
                            "payload_sha256": digest(payload)} for tag, payload in pairs]}
    return unit, b"".join(record(tag, payload) for tag, payload in pairs), profile


_DEFAULT = object()


class HscObservedTests(unittest.TestCase):
    def setUp(self):
        self.unit, self.raw, self.profile = fixture()

    def decode(self, unit=_DEFAULT, raw=_DEFAULT, profile=_DEFAULT):
        return decode_hsc_observed_settings(
            self.unit if unit is _DEFAULT else unit, self.raw if raw is _DEFAULT else raw,
            self.profile if profile is _DEFAULT else profile)

    def unsupported(self, result, code, entry="w3pa", tag=None):
        self.assertEqual(result.status, "UNSUPPORTED")
        self.assertIsNone(result.specification_method)
        self.assertIsNone(result.channel_use_vector)
        self.assertEqual(result.raw_channel_flags, ())
        self.assertFalse(result.project_complete)
        self.assertEqual(result.counter_device_status, "UNKNOWN")
        self.assertIsNone(result.counter_device)
        self.assertEqual(result.findings[0].code, code)
        self.assertEqual(result.findings[0].entry, entry)
        self.assertEqual(result.findings[0].tag, tag)

    def test_observed_form_has_fixed_meaning_and_no_authority(self):
        result = self.decode()
        self.assertEqual(result.status, "OBSERVED_FORM")
        self.assertEqual(result.specification_method, "NORMAL")
        self.assertEqual(result.channel_use_vector, "ALL_NOT_USE_OBSERVED_VECTOR")
        self.assertEqual(result.raw_channel_flags, (0,) * 8)
        self.assertEqual(result.qualification, "CALLER_GUARDED_OBSERVED_FORM_ONLY")
        self.assertEqual(result.semantic_authority, "NOT_ESTABLISHED")
        self.assertEqual(result.counter_device_status, "UNKNOWN")
        self.assertFalse(result.project_complete)
        self.assertEqual(result.findings, ())
        with self.assertRaises(FrozenInstanceError):
            result.status = "UNSUPPORTED"

    def test_deterministic_unchanged_input_and_profile(self):
        before = deepcopy(self.profile)
        first, second = self.decode(), self.decode()
        self.assertEqual(first, second)
        self.assertEqual(self.profile, before)
        self.assertEqual(first.unit_sha256, digest(self.unit))
        self.assertEqual(first.w3pa_sha256, digest(self.raw))
        reversed_keys = dict(reversed(list(self.profile.items())))
        reversed_keys["records"] = [dict(reversed(list(row.items()))) for row in self.profile["records"]]
        self.assertEqual(first.guard_profile_sha256, self.decode(profile=reversed_keys).guard_profile_sha256)

    def test_profile_cannot_inject_meaning_offsets_or_project_allowlist(self):
        for key in ("meaning", "offset", "source_sha256", "project_name"):
            profile = deepcopy(self.profile)
            profile[key] = "untrusted"
            with self.subTest(key=key), self.assertRaisesRegex(HscObservedError, "PROFILE_SCHEMA"):
                self.decode(profile=profile)
        profile = deepcopy(self.profile)
        profile["records"][3]["meaning"] = "NORMAL"
        with self.assertRaisesRegex(HscObservedError, "PROFILE_RECORD_SCHEMA at /records/3"):
            self.decode(profile=profile)

    def test_version_and_integer_fields_reject_bool_float_and_string(self):
        for field in ("version", "tag", "size", "primary"):
            for value in (True, 1.0, "1"):
                profile = deepcopy(self.profile)
                target = profile if field == "version" else profile["records"][3]
                target[field] = value
                with self.subTest(field=field, value=value), self.assertRaises(HscObservedError):
                    self.decode(profile=profile)

    def test_unknown_version_format_and_non_dictionary_profile(self):
        for profile in (None, [], {**self.profile, "version": 2}, {**self.profile, "format": "unknown"}):
            with self.subTest(profile_type=type(profile).__name__), self.assertRaises(HscObservedError):
                self.decode(profile=profile)

    def test_record_count_duplicate_and_missing_required_tag(self):
        for mutation, code in (("count", "PROFILE_RECORD_COUNT"),
                               ("duplicate", "PROFILE_DUPLICATE_TAG"),
                               ("required", "PROFILE_REQUIRED_TAG")):
            profile = deepcopy(self.profile)
            if mutation == "count":
                profile["records"].pop()
            elif mutation == "duplicate":
                profile["records"][4]["tag"] = profile["records"][3]["tag"]
            else:
                profile["records"][0]["tag"] = 999999
            with self.subTest(mutation=mutation), self.assertRaisesRegex(HscObservedError, code):
                self.decode(profile=profile)

    def test_invalid_profile_digest_and_semantic_size(self):
        for mutation, code in (("digest", "PROFILE_DIGEST"), ("size", "PROFILE_OBSERVED_STRUCTURE")):
            profile = deepcopy(self.profile)
            if mutation == "digest":
                profile["records"][4]["payload_sha256"] = "A" * 64
            else:
                profile["records"][0]["size"] += 1
            with self.subTest(mutation=mutation), self.assertRaisesRegex(HscObservedError, code):
                self.decode(profile=profile)

    def test_profile_byte_budget(self):
        profile = deepcopy(self.profile)
        profile["records"][4]["size"] = MAX_W3PA_BYTES
        with self.assertRaisesRegex(HscObservedError, "PROFILE_BYTE_LIMIT"):
            self.decode(profile=profile)

    def test_immutable_bytes_and_argument_budgets(self):
        for unit in (None, bytearray(self.unit), memoryview(self.unit), "text"):
            with self.subTest(type=type(unit).__name__), self.assertRaisesRegex(HscObservedError, "IMMUTABLE_BYTES_REQUIRED"):
                self.decode(unit=unit)
        with self.assertRaisesRegex(HscObservedError, "IMMUTABLE_BYTES_REQUIRED"):
            self.decode(raw=None)
        with self.assertRaisesRegex(HscObservedError, "INPUT_BYTE_LIMIT"):
            self.decode(unit=b"x" * (MAX_UNIT_BYTES + 1))
        with self.assertRaisesRegex(HscObservedError, "INPUT_BYTE_LIMIT"):
            self.decode(raw=b"x" * (MAX_W3PA_BYTES + 1))

    def test_empty_or_mixed_unit_returns_unsupported(self):
        for unit in (b"", b"different synthetic UNIT"):
            with self.subTest(unit=unit):
                self.unsupported(self.decode(unit=unit), "UNIT_CONTEXT_MISMATCH", "UNIT.PRM")

    def test_header_truncation_empty_and_last_record_truncation(self):
        self.unsupported(self.decode(raw=b""), "RECORD_TRUNCATED", tag=14809)
        self.unsupported(self.decode(raw=self.raw[:19]), "RECORD_TRUNCATED", tag=14809)
        self.unsupported(self.decode(raw=self.raw[:-1]), "RECORD_BOUNDARY", tag=1226)

    def test_record_marker_primary_and_size_damage(self):
        for at, value, code in ((8, 2, "RECORD_MARKER"), (16, 1, "RECORD_MARKER"),
                                (0, 79, "RECORD_BOUNDARY")):
            raw = bytearray(self.raw)
            struct.pack_into("<I", raw, at, value)
            with self.subTest(at=at):
                self.unsupported(self.decode(raw=bytes(raw)), code, tag=14809)

    def test_record_order_and_duplicate_not_signature_search(self):
        raw = bytearray(self.raw)
        struct.pack_into("<I", raw, 4, 14780)
        self.unsupported(self.decode(raw=bytes(raw)), "RECORD_ORDER", tag=14809)
        raw = bytearray(self.raw)
        struct.pack_into("<I", raw, 80 + 4, 14809)
        self.unsupported(self.decode(raw=bytes(raw)), "RECORD_DUPLICATE_TAG", tag=14780)

    def test_attributes_are_validated_and_located(self):
        raw = bytearray(self.raw)
        struct.pack_into("<H", raw, 24 + 12, 0)
        result = self.decode(raw=bytes(raw))
        self.unsupported(result, "RECORD_ATTRIBUTES", tag=14809)
        self.assertEqual(result.findings[0].offset, 24)

    def test_trailing_data_and_opaque_payload_change(self):
        self.unsupported(self.decode(raw=self.raw + b"extra"), "RECORD_TRAILING")
        raw = bytearray(self.raw)
        raw[80 + 184 + 336 + 20] ^= 1
        self.unsupported(self.decode(raw=bytes(raw)), "PAYLOAD_CONTEXT_MISMATCH", tag=1000)

    def test_other_one_cannot_be_approved_by_profile_digest(self):
        unit, raw, profile = fixture({14809: struct.pack("<I", 1)})
        result = decode_hsc_observed_settings(unit, raw, profile)
        self.unsupported(result, "OTHER_CONTEXT_UNSUPPORTED", tag=14809)
        self.assertEqual(result.findings[0].offset, 20)

    def test_nonzero_vector_cannot_be_approved_by_profile_digest(self):
        body = bytearray(nested(8, 1, b"\x00"))
        body[-1] = 1
        unit, raw, profile = fixture({14780: bytes(body)})
        self.unsupported(decode_hsc_observed_settings(unit, raw, profile),
                         "CHANNEL_VECTOR_UNSUPPORTED", tag=14780)

    def test_coupled_value_is_fixed_not_profile_mapping(self):
        unit, raw, profile = fixture({14712: nested(16, 4, struct.pack("<I", 33))})
        self.unsupported(decode_hsc_observed_settings(unit, raw, profile),
                         "COUPLED_CONTEXT_UNSUPPORTED", tag=14712)

    def test_nested_count_key_order_duplicate_and_width(self):
        for tag, count, width, value in ((14780, 8, 1, b"\x00"),
                                          (14712, 16, 4, struct.pack("<I", 32))):
            for mutation, code in (("count", "NESTED_COUNT"), ("order", "NESTED_KEY_ORDER"),
                                   ("duplicate", "NESTED_KEY_ORDER"), ("width", "NESTED_LENGTH")):
                body = bytearray(nested(count, width, value))
                if mutation == "count":
                    struct.pack_into("<I", body, 0, count - 1)
                elif mutation == "order":
                    struct.pack_into("<I", body, 8, 0x80000001)
                elif mutation == "duplicate":
                    struct.pack_into("<I", body, 4 + 12 + width + 4, 0x80000000)
                else:
                    struct.pack_into("<I", body, 12, width + 1)
                unit, raw, profile = fixture({tag: bytes(body)})
                with self.subTest(tag=tag, mutation=mutation):
                    self.unsupported(decode_hsc_observed_settings(unit, raw, profile), code, tag=tag)


if __name__ == "__main__":
    unittest.main()
