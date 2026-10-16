"""Generated synthetic bytes only; these tests establish no native authority."""
from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
import hashlib
import json
import struct
import unittest

from gx3_fx5_profile.cpu_observed import (
    CpuObservedError, CpuObservedMember, MAX_CPU_BYTES, MAX_MEMBERS,
    MAX_MEMBER_BYTES, MAX_W3PA_BYTES, PROFILE_FORMAT,
    decode_cpu_observed_settings,
)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


CPU_PREFIX = b"generated opaque CPU context: "
CPU_SUFFIX = b" :generated opaque CPU suffix"
W3PA_SUFFIX = b"generated opaque parameter suffix" * 12
IDENTITY = "10000000000000000001"
QPG = "ConvertData/101/Program.qpg"
UNLINKED = "ConvertData/202/Program.qpg"
LINK = "ConvertData/101/PouLinkOrder.info"
STEP = IDENTITY + "_StepInfo.db"
PCODE = "ConvertData/" + IDENTITY + "/PouPCode.pcode"
W3PA = "generated-cpu.w3pa"
QPG_PREFIX = struct.pack("<HIIIH", 0xFFFF, 0x4C, 0x60, 0xFFFFFFFF, 16)
_DEFAULT = object()


def fixture(name="Demo"):
    encoded = name.encode("utf-16le") + b"\0\0"
    units = len(encoded) // 2
    length, internal = {5: (20, 14), 9: (24, 18)}[units]
    cpu = CPU_PREFIX + struct.pack("<HIIHHH", 0xFFFF, length, 0x01003700,
                                   1, internal, units) + encoded + CPU_SUFFIX
    w3pa = struct.pack("<9I", 386 if units == 5 else 394, 0x0E11, 1, 1, 4,
                      1, 1, 0x10000, len(encoded)) + encoded + W3PA_SUFFIX
    qpg = b"generated carrier prefix" + QPG_PREFIX + "SampleP\0".encode("utf-16le") + b"opaque tail"
    members = (CpuObservedMember(QPG, qpg),
               CpuObservedMember(UNLINKED, b"generated unnamed/unlinked opaque carrier"),
               CpuObservedMember(LINK, (IDENTITY + "\n").encode("ascii")),
               CpuObservedMember(STEP, b"generated step identity payload"),
               CpuObservedMember(PCODE, b"generated pcode identity payload"),
               CpuObservedMember("CPU.PRM", cpu),
               CpuObservedMember(W3PA, w3pa),
               CpuObservedMember("unrelated/member.txt", b"uninterpreted inventory member"))
    profile = {"format": PROFILE_FORMAT, "version": 1,
               "cpu_context": {"prefix_sha256": digest(CPU_PREFIX), "suffix_sha256": digest(CPU_SUFFIX)},
               "w3pa_context": {"prefix_sha256": digest(b""), "suffix_sha256": digest(W3PA_SUFFIX)},
               "member_guards": [{"entry": m.entry, "byte_count": len(m.body), "sha256": digest(m.body)}
                                 for m in members if m.entry not in ("CPU.PRM", W3PA, "unrelated/member.txt")]}
    return cpu, w3pa, members, profile


def change_member(members, entry, body):
    return tuple(replace(m, body=body) if m.entry == entry else m for m in members)


def reguard(profile, members):
    """Allow adversarial bytes through opaque guards to test fixed code checks."""
    result = deepcopy(profile)
    result["member_guards"] = [{"entry": m.entry, "byte_count": len(m.body), "sha256": digest(m.body)}
                               for m in members if m.entry not in ("CPU.PRM", W3PA, "unrelated/member.txt")]
    return result


class CpuObservedTests(unittest.TestCase):
    def setUp(self):
        self.cpu, self.w3pa, self.members, self.profile = fixture()

    def decode(self, cpu=_DEFAULT, w3pa=_DEFAULT, members=_DEFAULT, profile=_DEFAULT):
        if members is _DEFAULT:
            members = self.members
            # Grammar mutations remain same-artifact inputs. Contradictory
            # inventories are passed explicitly in the dedicated negative test.
            if type(cpu) is bytes:
                members = change_member(members, "CPU.PRM", cpu)
            if type(w3pa) is bytes:
                members = change_member(members, W3PA, w3pa)
        return decode_cpu_observed_settings(
            self.cpu if cpu is _DEFAULT else cpu,
            self.w3pa if w3pa is _DEFAULT else w3pa,
            members,
            self.profile if profile is _DEFAULT else profile)

    def unsupported(self, result, code):
        self.assertEqual(result.status, "UNSUPPORTED")
        self.assertIsNone(result.observed_program_name)
        self.assertIsNone(result.observed_pou_name)
        self.assertIsNone(result.linked_pou_id)
        self.assertIsNone(result.observed_execution_context)
        self.assertEqual(result.binding_status, "UNKNOWN")
        self.assertEqual(result.findings[0].code, code)
        self.assertFalse(result.project_complete)
        return result.findings[0]

    def test_two_name_forms_share_guards_and_preserve_unknowns(self):
        for name in ("Demo", "Demo_AB1"):
            with self.subTest(name=name):
                cpu, w3pa, members, _ = fixture(name)
                result = self.decode(cpu=cpu, w3pa=w3pa, members=members)
                self.assertEqual(result.status, "OBSERVED_FORM")
                self.assertEqual(result.observed_program_name, name)
                self.assertEqual(result.observed_pou_name, "SampleP")
                self.assertEqual(result.linked_pou_id, IDENTITY)
                self.assertEqual(result.step_info_entry, STEP)
                self.assertEqual(result.pcode_entry, PCODE)
                self.assertEqual(result.w3pa_entry, W3PA)
                self.assertEqual(result.binding_status, "OBSERVED_SINGLETON_CONTEXT")
                self.assertEqual(result.observed_execution_context, "SCAN_OBSERVED_CONTEXT_ONLY")
                for key in ("numeric_cpu_edge_status", "general_execution_type_status",
                            "execution_order_status", "qpg_record_size_semantics"):
                    self.assertEqual(getattr(result, key), "UNKNOWN")
                self.assertEqual(result.semantic_authority, "NOT_ESTABLISHED")
                self.assertEqual(result.qualification, "CALLER_GUARDED_OBSERVED_FORM_ONLY")
                self.assertFalse(result.project_complete)

    def test_complete_inventory_and_unlinked_carrier_are_not_dropped(self):
        result = self.decode()
        self.assertEqual(len(result.member_digests), len(self.members))
        self.assertEqual(len(result.qpg_census), 2)
        unlinked = next(q for q in result.qpg_census if not q.linked)
        self.assertEqual(unlinked.entry, UNLINKED)
        self.assertIsNone(unlinked.observed_name)
        self.assertIsNone(unlinked.name_offset)
        self.assertEqual(unlinked.name_status, "UNKNOWN")
        self.assertEqual(result.findings[0].code, "UNLINKED_QPG_UNKNOWN")

    def test_deterministic_canonical_profile_hash_and_no_mutation(self):
        before = deepcopy(self.profile)
        first = self.decode()
        reordered = deepcopy(self.profile)
        reordered["member_guards"].reverse()
        self.assertEqual(first, self.decode(profile=reordered, members=tuple(reversed(self.members))))
        canonical = deepcopy(self.profile)
        canonical["member_guards"].sort(key=lambda row: row["entry"])
        expected = digest(json.dumps(canonical, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=True).encode("ascii"))
        self.assertEqual(first.guard_profile_sha256, expected)
        self.assertEqual(self.profile, before)
        with self.assertRaises(FrozenInstanceError):
            first.project_complete = True

    def test_names_are_structured_fields_not_token_search(self):
        raw = CPU_PREFIX + "Demo\0".encode("utf-16le") + CPU_SUFFIX
        self.unsupported(self.decode(cpu=raw), "CPU_NAME_BLOCK_CARDINALITY")
        cpu = self.cpu + self.cpu[len(CPU_PREFIX):]
        self.unsupported(self.decode(cpu=cpu), "CPU_NAME_BLOCK_CARDINALITY")
        # A malformed second same-tag candidate must not be hidden in context.
        raw = self.cpu + struct.pack("<HIIHHH", 0xFFFF, 99, 0x01003700, 1, 14, 5)
        self.unsupported(self.decode(cpu=raw), "CPU_NAME_BLOCK_CARDINALITY")

    def test_cpu_header_tuple_cannot_be_injected_by_profile(self):
        for relative, width, value in ((2, 4, 24), (10, 2, 2), (12, 2, 18), (14, 2, 9)):
            raw = bytearray(self.cpu)
            at = len(CPU_PREFIX) + relative
            raw[at:at + width] = value.to_bytes(width, "little")
            self.unsupported(self.decode(cpu=bytes(raw)), "CPU_HEADER_FORM")

    def test_w3pa_fixed_header_and_name_agreement(self):
        for index in range(9):
            raw = bytearray(self.w3pa)
            value = int.from_bytes(raw[index * 4:index * 4 + 4], "little")
            struct.pack_into("<I", raw, index * 4, value + 1)
            finding = self.unsupported(self.decode(w3pa=bytes(raw)), "W3PA_HEADER_FORM")
            self.assertEqual(finding.entry, W3PA)
            self.assertEqual(finding.offset, 0)
        raw = self.w3pa[:36] + "Else\0".encode("utf-16le") + W3PA_SUFFIX
        self.unsupported(self.decode(w3pa=raw), "CPU_W3PA_NAME_MISMATCH")

    def test_prefix_suffix_mix_and_truncation_rejected(self):
        self.unsupported(self.decode(cpu=b"other" + self.cpu), "PREFIX_CONTEXT_MISMATCH")
        self.unsupported(self.decode(cpu=self.cpu + b"trailing"), "SUFFIX_CONTEXT_MISMATCH")
        self.unsupported(self.decode(w3pa=self.w3pa + b"trailing"), "SUFFIX_CONTEXT_MISMATCH")
        self.unsupported(self.decode(w3pa=self.w3pa[:35]), "W3PA_HEADER_TRUNCATED")
        self.unsupported(self.decode(cpu=self.cpu[:len(CPU_PREFIX) + 18]), "NAME_TRUNCATED")

    def test_utf16_and_single_terminal_nul(self):
        at = len(CPU_PREFIX) + 16
        for payload, code in ((b"\x00\xd8" + b"a\0" * 3 + b"\0\0", "NAME_UTF16"),
                              ("D\0mo\0".encode("utf-16le"), "NAME_OBSERVED_ALPHABET"),
                              ("DemoX".encode("utf-16le"), "NAME_TERMINATOR")):
            self.unsupported(self.decode(cpu=self.cpu[:at] + payload + CPU_SUFFIX), code)

    def test_profile_digest_checks_all_related_members(self):
        for member in self.members[:5]:
            members = change_member(self.members, member.entry, member.body + b"x")
            finding = self.unsupported(self.decode(members=members), "MEMBER_CONTEXT_MISMATCH")
            self.assertEqual(finding.entry, member.entry)

    def test_separate_arguments_cannot_contradict_full_inventory(self):
        cpu_b, w3pa_b, members_b, _ = fixture("Demo_AB1")
        self.unsupported(self.decode(members=members_b), "CPU_INVENTORY_MISMATCH")
        members = change_member(self.members, W3PA, w3pa_b)
        self.unsupported(self.decode(members=members), "W3PA_INVENTORY_MATCH_CARDINALITY")
        members = self.members + (CpuObservedMember("duplicate.w3pa", self.w3pa),)
        self.unsupported(self.decode(members=members), "W3PA_INVENTORY_MATCH_CARDINALITY")
        members = tuple(m for m in self.members if m.entry != "CPU.PRM")
        self.unsupported(self.decode(members=members), "CPU_INVENTORY_MISMATCH")
        members = tuple(replace(m, entry="generated-cpu.W3PA") if m.entry == W3PA else m
                        for m in self.members)
        self.unsupported(self.decode(members=members), "W3PA_INVENTORY_MATCH_CARDINALITY")

    def test_link_requires_exact_one_canonical_twenty_digit_id_and_lf(self):
        for raw in ((IDENTITY + "\r\n").encode(), (IDENTITY + "\n\n").encode(),
                    IDENTITY.encode(), (IDENTITY + "\n7").encode(), b"0" * 20 + b"\n",
                    b"123\n", b" " + IDENTITY.encode() + b"\n"):
            members = change_member(self.members, LINK, raw)
            self.unsupported(self.decode(members=members, profile=reguard(self.profile, members)),
                             "LINK_ID_OBSERVED_FORM")

    def test_link_identity_targets_missing_or_orphaned(self):
        for entry in (STEP, PCODE):
            members = tuple(m for m in self.members if m.entry != entry)
            self.unsupported(self.decode(members=members, profile=reguard(self.profile, members)),
                             "LINK_TARGET_MISSING")
        extra = CpuObservedMember("10000000000000000002_StepInfo.db", b"unreferenced identity")
        members = self.members + (extra,)
        self.unsupported(self.decode(members=members, profile=reguard(self.profile, members)),
                         "LINK_TARGET_CARDINALITY")

    def test_full_qpg_and_link_census_cardinality(self):
        for members in (tuple(m for m in self.members if m.entry != UNLINKED),
                        self.members + (CpuObservedMember("ConvertData/303/Program.qpg", b"extra"),),
                        self.members + (CpuObservedMember("ConvertData/303/PouLinkOrder.info", b"extra"),)):
            result = self.decode(members=members)
            self.unsupported(result, "SINGLETON_CENSUS_UNSUPPORTED")
            self.assertEqual(len(result.qpg_census), sum(m.entry.endswith("Program.qpg") for m in members))

    def test_qpg_fixed_block_no_fallback_or_record_size_claim(self):
        qpg = next(m.body for m in self.members if m.entry == QPG)
        for raw, code in ((b"only SampleP text", "QPG_NAME_BLOCK_CARDINALITY"),
                          (qpg + QPG_PREFIX + b"\0" * 16, "QPG_NAME_BLOCK_CARDINALITY"),
                          (QPG_PREFIX + b"short", "NAME_TRUNCATED"),
                          (QPG_PREFIX + "SampleX!".encode("utf-16le"), "NAME_TERMINATOR")):
            members = change_member(self.members, QPG, raw)
            self.unsupported(self.decode(members=members, profile=reguard(self.profile, members)), code)
        # The observed constant is not consumed as a record size: opaque tails
        # remain guarded, and no 76-byte boundary or next-record grammar exists.
        members = change_member(self.members, QPG, qpg + b"long synthetic opaque tail" * 9)
        result = self.decode(members=members, profile=reguard(self.profile, members))
        self.assertEqual(result.status, "OBSERVED_FORM")
        self.assertEqual(result.qpg_record_size_semantics, "UNKNOWN")

    def test_noncanonical_topology_path_is_censused_then_rejected(self):
        members = tuple(replace(m, entry="ConvertData/202/PROGRAM.QPG") if m.entry == UNLINKED else m
                        for m in self.members)
        result = self.decode(members=members)
        self.unsupported(result, "NONCANONICAL_TOPOLOGY_ENTRY")
        self.assertEqual(len(result.qpg_census), 2)
        for extra in ("nested/10000000000000000002_StepInfo.db", "ConvertData/303/POUPCODE.PCODE"):
            self.unsupported(self.decode(members=self.members + (CpuObservedMember(extra, b"alias"),)),
                             "NONCANONICAL_TOPOLOGY_ENTRY")

    def test_exact_profile_schema_no_offsets_meanings_names_or_id_mapping(self):
        for key in ("offset", "execution_type", "names", "cpu_to_pou", "official_accepted"):
            profile = deepcopy(self.profile)
            profile[key] = 0
            with self.assertRaises(CpuObservedError) as context:
                self.decode(profile=profile)
            self.assertEqual(context.exception.code, "PROFILE_SCHEMA")
        profile = deepcopy(self.profile)
        profile["cpu_context"]["offset"] = len(CPU_PREFIX)
        with self.assertRaises(CpuObservedError):
            self.decode(profile=profile)

    def test_profile_versions_types_and_integer_bools_rejected(self):
        for invalid in (None, [], (), "guards"):
            with self.assertRaises(CpuObservedError):
                self.decode(profile=invalid)
        for key, values in (("version", (True, 1.0, "1", 2)),):
            for value in values:
                profile = deepcopy(self.profile)
                profile[key] = value
                with self.assertRaises(CpuObservedError):
                    self.decode(profile=profile)
        for value in (True, 1.0, "1", 0, MAX_MEMBER_BYTES + 1):
            profile = deepcopy(self.profile)
            profile["member_guards"][0]["byte_count"] = value
            with self.assertRaises(CpuObservedError):
                self.decode(profile=profile)

    def test_profile_guard_census_duplicate_digest_and_entry_validation(self):
        profile = deepcopy(self.profile)
        profile["member_guards"].pop()
        self.unsupported(self.decode(profile=profile), "MEMBER_GUARD_CENSUS")
        profile = deepcopy(self.profile)
        profile["member_guards"].append(deepcopy(profile["member_guards"][0]))
        with self.assertRaises(CpuObservedError) as context:
            self.decode(profile=profile)
        self.assertEqual(context.exception.code, "PROFILE_DUPLICATE_ENTRY")
        for key, value in (("entry", "../Program.qpg"), ("sha256", "F" * 64)):
            profile = deepcopy(self.profile)
            profile["member_guards"][0][key] = value
            with self.assertRaises(CpuObservedError):
                self.decode(profile=profile)

    def test_immutable_inputs_safe_paths_and_budgets(self):
        for kwargs in ({"cpu": None}, {"cpu": bytearray(self.cpu)}, {"w3pa": None},
                       {"members": list(self.members)}, {"members": ()},
                       {"cpu": b"x" * (MAX_CPU_BYTES + 1)},
                       {"w3pa": b"x" * (MAX_W3PA_BYTES + 1)},
                       {"members": self.members * (MAX_MEMBERS + 1)}):
            with self.assertRaises(CpuObservedError):
                self.decode(**kwargs)
        for entry in ("/absolute", "../escape", "a//b", "a/./b", "C:/path", "a\\b", "a\n"):
            with self.assertRaises(CpuObservedError):
                self.decode(members=self.members + (CpuObservedMember(entry, b"x"),))
        for member in (CpuObservedMember("other", bytearray(b"x")),
                       CpuObservedMember("other", b"x" * (MAX_MEMBER_BYTES + 1))):
            with self.assertRaises(CpuObservedError):
                self.decode(members=self.members + (member,))
        with self.assertRaises(CpuObservedError) as context:
            self.decode(members=self.members + (replace(self.members[0], entry=QPG.upper()),))
        self.assertEqual(context.exception.code, "DUPLICATE_MEMBER_ENTRY")

    def test_explicit_empty_directories_preserve_full_inventory(self):
        directories = tuple(CpuObservedMember(entry, b"") for entry in (".meta/", ".meta/sub/", "ConvertData/"))
        result = self.decode(members=self.members + directories)
        self.assertEqual(result.status, "OBSERVED_FORM")
        self.assertEqual(len(result.member_digests), len(self.members) + len(directories))
        by_entry = {row.entry: row for row in result.member_digests}
        for directory in directories:
            self.assertEqual(by_entry[directory.entry].byte_count, 0)
            self.assertEqual(by_entry[directory.entry].sha256, digest(b""))
        self.assertEqual(len(result.qpg_census), 2)

    def test_directory_validation_and_file_directory_aliases(self):
        for entry in ("/", "//", "a//", "a//b/", "./", "a/../", "a/./", "/absolute/"):
            with self.subTest(entry=entry), self.assertRaises(CpuObservedError) as context:
                self.decode(members=self.members + (CpuObservedMember(entry, b""),))
            self.assertEqual(context.exception.code, "MEMBER_ENTRY")
        with self.assertRaises(CpuObservedError) as context:
            self.decode(members=self.members + (CpuObservedMember("nonempty/", b"payload"),))
        self.assertEqual(context.exception.code, "DIRECTORY_BODY_NOT_EMPTY")
        for aliases in (("alias", "alias/"), ("ALIAS/", "alias"), ("alias/", "alias/")):
            members = self.members + tuple(CpuObservedMember(entry, b"") for entry in aliases)
            with self.subTest(aliases=aliases), self.assertRaises(CpuObservedError) as context:
                self.decode(members=members)
            self.assertEqual(context.exception.code, "DUPLICATE_MEMBER_ENTRY")
        profile = deepcopy(self.profile)
        profile["member_guards"][0]["entry"] = "ConvertData/101/Program.qpg/"
        with self.assertRaises(CpuObservedError) as context:
            self.decode(profile=profile)
        self.assertEqual(context.exception.code, "PROFILE_MEMBER_ENTRY")


if __name__ == "__main__":
    unittest.main()
