'Source-derived parser observation.'

from __future__ import annotations

from typing import Final


LDA = "mc{op=lct{op=#:lt=l:ct=a:as=[as{vt=Abl}]}:as=[d{s=#:a=#:vt=nn}]}"
LDP = "mc{op=lct{op=#:lt=l:ct=p:as=[as{vt=Abl}]}:as=[d{s=#:a=#:vt=nn}]}"
LDF = "mc{op=lct{op=#:lt=l:ct=f:as=[as{vt=Abl}]}:as=[d{s=#:a=#:vt=nn}]}"
ANDA = "mc{op=lct{op=#:lt=a:ct=a:as=[as{vt=Abl}]}:as=[d{s=#:a=#:vt=nn}]}"
ORA = "mc{op=lct{op=#:lt=o:ct=a:as=[as{vt=Abl}]}:as=[d{s=#:a=#:vt=nn}]}"
COILA = "mc{op=cl{op=#:ct=a:as=[as{vt=Abl}]}:as=[d{s=#:a=#:vt=nn}]}"
COILP = "mc{op=cl{op=#:ct=p:as=[as{vt=Abl}]}:as=[d{s=#:a=#:vt=nn}]}"
COILF = "mc{op=cl{op=#:ct=f:as=[as{vt=Abl}]}:as=[d{s=#:a=#:vt=nn}]}"
MOV16 = "mc{op=cl{op=#:ct=a:as=[as{vt=A16}:as{vt=A16}]}:as=[d{s=#:a=#:vt=nn}:d{s=#:a=#:vt=nn}]}"
MOV32 = "mc{op=cl{op=#:ct=a:as=[as{vt=A32}:as{vt=A32}]}:as=[d{s=#:a=#:vt=nn}:d{s=#:a=#:vt=nn}]}"
MOV3D = "mc{op=cl{op=#:ct=a:as=[as{vt=A16}:as{vt=A16}:as{vt=A16}]}:as=[d{s=#:a=#:vt=nn}:d{s=#:a=#:vt=nn}:c{s=#:v=#:si=s}]}"
FMOV3 = "mc{op=cl{op=#:ct=a:as=[as{vt=A16}:as{vt=A16}:as{vt=A16}]}:as=[c{s=#:v=#:si=s}:d{s=#:a=#:vt=nn}:c{s=#:v=#:si=s}]}"
SCT = "mc{op=sct{op=#:ct=a}}"
TERMINAL = "mc{op=cl{op=#:ct=a}}"


def _entry(identifier: str, header: str, segments: tuple[str, ...], instructions: tuple[tuple[str, tuple[str, ...]], ...]) -> dict[str, object]:
    return {"id": identifier, "canonical": header + ":ms{el=[" + ":".join(segments) + "]}", "instructions": instructions}


SIGNATURES: Final[tuple[dict[str, object], ...]] = (
    _entry("LD_OUT", "V1:4:1:1:3:1:A:M:OUT:M", (LDA, COILA), (("LD", ("M",)), ("OUT", ("M",)))),
    _entry("END", "V1:1:3:END", (TERMINAL,), (("END", ()),)),
    _entry("LDI_OUT", "V1:4:1:1:3:1:B:M:OUT:M", (LDA, COILA), (("LDI", ("M",)), ("OUT", ("M",)))),
    _entry("LD_AND_OUT", "V1:6:1:1:1:1:3:1:A:M:A:M:OUT:M", (LDA, ANDA, COILA), (("LD", ("M",)), ("AND", ("M",)), ("OUT", ("M",)))),
    _entry("LD_ANI_OUT", "V1:6:1:1:1:1:3:1:A:M:B:M:OUT:M", (LDA, ANDA, COILA), (("LD", ("M",)), ("ANI", ("M",)), ("OUT", ("M",)))),
    _entry("LD_OR_OUT", "V1:6:1:1:1:1:3:1:A:M:A:M:OUT:M", (LDA, ORA, COILA), (("LD", ("M",)), ("OR", ("M",)), ("OUT", ("M",)))),
    _entry("LD_ORI_OUT", "V1:6:1:1:1:1:3:1:A:M:B:M:OUT:M", (LDA, ORA, COILA), (("LD", ("M",)), ("ORI", ("M",)), ("OUT", ("M",)))),
    _entry("LDP_OUT", "V1:4:1:1:3:1:A:M:OUT:M", (LDP, COILA), (("LDP", ("M",)), ("OUT", ("M",)))),
    _entry("LDF_OUT", "V1:4:1:1:3:1:A:M:OUT:M", (LDF, COILA), (("LDF", ("M",)), ("OUT", ("M",)))),
    _entry("LD_PLS", "V1:4:1:1:3:1:A:M:OUT:M", (LDA, COILP), (("LD", ("M",)), ("PLS", ("M",)))),
    _entry("LD_PLF", "V1:4:1:1:3:1:A:M:OUT:M", (LDA, COILF), (("LD", ("M",)), ("PLF", ("M",)))),
    _entry("LD_SET", "V1:4:1:1:3:1:A:M:SET:M", (LDA, COILA), (("LD", ("M",)), ("SET", ("M",)))),
    _entry("LD_RST", "V1:4:1:1:3:1:A:M:RST:M", (LDA, COILA), (("LD", ("M",)), ("RST", ("M",)))),
    _entry("LD_MOV", "V1:5:1:1:3:1:1:A:M:MOV:D:D", (LDA, MOV16), (("LD", ("M",)), ("MOV", ("D", "D")))),
    _entry("LD_DMOV", "V1:5:1:1:3:1:1:A:M:MOV:D:D", (LDA, MOV32), (("LD", ("M",)), ("DMOV", ("D", "D")))),
    _entry("LD_BMOV", "V1:6:1:1:4:1:1:3:A:M:BMOV:D:D:K_#", (LDA, MOV3D), (("LD", ("M",)), ("BMOV", ("D", "D", "K")))),
    _entry("LD_FMOV", "V1:6:1:1:4:3:1:3:A:M:FMOV:K_#:D:K_#", (LDA, FMOV3), (("LD", ("M",)), ("FMOV", ("K", "D", "K")))),
    _entry("ANB", "V1:11:1:1:1:1:1:1:1:1:3:3:1:A:M:A:M:A:M:A:M:ANB:OUT:M", (LDA, ORA, LDA, ORA, SCT, COILA), (("LD", ("M",)), ("OR", ("M",)), ("LD", ("M",)), ("OR", ("M",)), ("ANB", ()), ("OUT", ("M",)))),
    _entry("ORB", "V1:11:1:1:1:1:1:1:1:1:3:3:1:A:M:A:M:A:M:A:M:ORB:OUT:M", (LDA, ANDA, LDA, ANDA, SCT, COILA), (("LD", ("M",)), ("AND", ("M",)), ("LD", ("M",)), ("AND", ("M",)), ("ORB", ()), ("OUT", ("M",)))),
    _entry("MPS_MRD_MPP", "V1:17:1:1:3:1:1:3:1:3:1:1:3:1:3:1:1:3:1:A:M:MPS:A:M:OUT:M:MRD:A:M:OUT:M:MPP:A:M:OUT:M", (LDA, SCT, ANDA, COILA, SCT, ANDA, COILA, SCT, ANDA, COILA), (("LD", ("M",)), ("MPS", ()), ("AND", ("M",)), ("OUT", ("M",)), ("MRD", ()), ("AND", ("M",)), ("OUT", ("M",)), ("MPP", ()), ("AND", ("M",)), ("OUT", ("M",)))),
    _entry("FEND", "V1:1:4:FEND", (TERMINAL,), (("FEND", ()),)),
)

CANONICAL_SIGNATURES: Final[dict[str, tuple[tuple[str, tuple[str, ...]], ...]]] = {item["canonical"]: item["instructions"] for item in SIGNATURES}  # type: ignore[misc]
AUTHORITY_HEADERS: Final[frozenset[str]] = frozenset(str(item["canonical"]).split(":ms{", 1)[0] for item in SIGNATURES)
ACCEPTED_OPCODES: Final[frozenset[str]] = frozenset(opcode for item in SIGNATURES for opcode, _ in item["instructions"])  # type: ignore[misc]

# Runtime uses these 24 individual forms.  The block-level table above is
# retained solely to regress the independent 5-GX3 authority extraction.
FORM_SIGNATURES: Final[dict[str, dict[str, object]]] = {
    "LD": {"marker": "A", "segment": LDA, "operands": ("M",)},
    "LDI": {"marker": "B", "segment": LDA, "operands": ("M",)},
    "LDP": {"marker": "A", "segment": LDP, "operands": ("M",)},
    "LDF": {"marker": "A", "segment": LDF, "operands": ("M",)},
    "AND": {"marker": "A", "segment": ANDA, "operands": ("M",)},
    "ANI": {"marker": "B", "segment": ANDA, "operands": ("M",)},
    "OR": {"marker": "A", "segment": ORA, "operands": ("M",)},
    "ORI": {"marker": "B", "segment": ORA, "operands": ("M",)},
    "OUT": {"header": "OUT", "segment": COILA, "operands": ("M",)},
    "PLS": {"header": "OUT", "segment": COILP, "operands": ("M",)},
    "PLF": {"header": "OUT", "segment": COILF, "operands": ("M",)},
    "SET": {"header": "SET", "segment": COILA, "operands": ("M",)},
    "RST": {"header": "RST", "segment": COILA, "operands": ("M",)},
    "MOV": {"header": "MOV", "segment": MOV16, "operands": ("D", "D")},
    "DMOV": {"header": "MOV", "segment": MOV32, "operands": ("D", "D")},
    "BMOV": {"header": "BMOV", "segment": MOV3D, "operands": ("D", "D", "K")},
    "FMOV": {"header": "FMOV", "segment": FMOV3, "operands": ("K", "D", "K")},
    "ANB": {"header": "ANB", "segment": SCT, "operands": ()},
    "ORB": {"header": "ORB", "segment": SCT, "operands": ()},
    "MPS": {"header": "MPS", "segment": SCT, "operands": ()},
    "MRD": {"header": "MRD", "segment": SCT, "operands": ()},
    "MPP": {"header": "MPP", "segment": SCT, "operands": ()},
    "FEND": {"header": "FEND", "segment": TERMINAL, "operands": ()},
    "END": {"header": "END", "segment": TERMINAL, "operands": ()},
}
