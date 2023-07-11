import socket
from dataclasses import dataclass, field
from enum import Enum
from random import randrange
from struct import Struct
from typing import Iterator, Self


def _unpack_from(struct: Struct, buffer: bytes, offset: int) -> tuple[tuple, int]:
    return struct.unpack_from(buffer, offset), offset + struct.size


def _encode_name(name: str) -> Iterator[bytes]:
    for part in name.encode("ascii").split(b"."):
        yield b"%c" % len(part)
        yield part
    yield b"\x00"


def _decode_name(buffer: bytes, offset: int = 0) -> tuple[str, int]:
    parts: list[str] = []
    seen: set[int] = set()

    def decode(offset: int) -> int:
        seen.add(offset)
        while n := buffer[offset]:
            offset += 1
            if n & 0b1100_0000:
                pos = ((n & 0b0011_1111) << 8) + buffer[offset]
                if pos in seen:
                    raise ValueError("Recusion while decoding DNS name")
                decode(pos)
                break
            start = offset
            offset += n
            parts.append(buffer[start:offset].decode("ascii"))
        return offset + 1

    offset = decode(offset)
    return ".".join(parts), offset


class DnsType(Enum):
    A = 1
    NS = 2
    CNAME = 5
    SOA = 6
    PTR = 12
    MX = 15
    TXT = 16
    RP = 17
    AAAA = 28
    SRV = 33


class DnsClass(Enum):
    IN = 1


@dataclass(slots=True)
class Question:
    name: str
    type_: DnsType = DnsType.A
    class_: DnsClass = DnsClass.IN

    _STRUCT = Struct("!HH")

    def _encode(self) -> Iterator[bytes]:
        yield from _encode_name(self.name)
        yield self._STRUCT.pack(self.type_.value, self.class_.value)

    @classmethod
    def _decode(cls, buffer: bytes, *, offset: int) -> tuple[Self, int]:
        name, offset = _decode_name(buffer, offset)
        (typ, clas), offset = _unpack_from(cls._STRUCT, buffer, offset)
        self = cls(name, DnsType(typ), DnsClass(clas))
        return self, offset


@dataclass(slots=True)
class Record:
    name: str
    ttl: int

    _STRUCT = Struct("!HHIH")

    @staticmethod
    def _decode(buffer: bytes, *, offset: int) -> tuple["Record", int]:
        name, offset = _decode_name(buffer, offset)
        (typ, clas, ttl, data_len), offset = _unpack_from(
            Record._STRUCT, buffer, offset
        )
        end = offset + data_len
        if clas == DnsClass.IN.value:
            if typ == DnsType.A.value and data_len == 4:
                addr = socket.inet_ntop(socket.AF_INET, buffer[offset:end])
                return RecordInetA(name, ttl, addr), end
            if typ == DnsType.AAAA.value and data_len == 16:
                addr = socket.inet_ntop(socket.AF_INET6, buffer[offset:end])
                return RecordInetAAAA(name, ttl, addr), end
            if typ == DnsType.CNAME.value:
                target, _ = _decode_name(buffer, offset)
                return RecordInetCNAME(name, ttl, target), end
            if typ == DnsType.PTR.value:
                target, _ = _decode_name(buffer, offset)
                return RecordInetPTR(name, ttl, target), end
            if typ == DnsType.SOA.value:
                fields, _ = RecordInetSOA._decode_fields(buffer, offset)
                return RecordInetSOA(name, ttl, *fields), end
            if typ == DnsType.SRV.value:
                fields, _ = RecordInetSRV._decode_fields(buffer, offset)
                return RecordInetSRV(name, ttl, *fields), end
            if typ == DnsType.TXT.value:
                strings = RecordInetTXT._decode_strings(buffer, offset, end)
                return RecordInetTXT(name, ttl, strings), end
            if typ == DnsType.MX.value:
                fields, _ = RecordInetMX._decode_fields(buffer, offset)
                return RecordInetMX(name, ttl, *fields), end
        self = RecordOther(name, ttl, DnsType(typ), DnsClass(clas), buffer[offset:end])
        return self, end


@dataclass(slots=True)
class RecordOther(Record):
    type_: DnsType
    class_: DnsClass
    data: bytes


@dataclass(slots=True)
class RecordInetA(Record):
    address: str


@dataclass(slots=True)
class RecordInetAAAA(Record):
    address: str


@dataclass(slots=True)
class RecordInetCNAME(Record):
    target: str


@dataclass(slots=True)
class RecordInetTXT(Record):
    text: list[str]

    @staticmethod
    def _decode_strings(buffer: bytes, offset: int, end: int) -> list[str]:
        result = []
        while offset < end:
            start = offset + 1
            offset = start + buffer[offset]
            result.append(buffer[start:offset].decode("ascii"))
        return result


@dataclass(slots=True)
class RecordInetPTR(Record):
    target: str


@dataclass(slots=True)
class RecordInetSRV(Record):
    priority: int
    weight: int
    port: int
    target: str

    _STRUCT = Struct("!HHH")

    @classmethod
    def _decode_fields(cls, buffer: bytes, offset: int) -> tuple[tuple, int]:
        fields, offset = _unpack_from(cls._STRUCT, buffer, offset)
        target, offset = _decode_name(buffer, offset)
        return [*fields, target], offset


@dataclass(slots=True)
class RecordInetMX(Record):
    exchange: str
    preference: int

    _STRUCT = Struct("!H")

    @classmethod
    def _decode_fields(cls, buffer: bytes, offset: int) -> tuple[tuple, int]:
        fields, offset = _unpack_from(cls._STRUCT, buffer, offset)
        exchange, offset = _decode_name(buffer, offset)
        return (exchange, *fields), offset


@dataclass(slots=True)
class RecordInetSOA(Record):
    master_name: str
    responsible_name: str
    serial_num: int
    refresh_num: int
    retry_num: int
    expire_num: int
    minimum_num: int

    _STRUCT = Struct("!IIIII")

    @classmethod
    def _decode_fields(cls, buffer: bytes, offset: int) -> tuple[tuple, int]:
        mname, offset = _decode_name(buffer, offset)
        rname, offset = _decode_name(buffer, offset)
        fields, offset = _unpack_from(cls._STRUCT, buffer, offset)
        return (mname, rname, *fields), offset


RECURSION_DESIRED = 1 << 8


@dataclass(slots=True)
class Header:
    id: int
    flags: int
    questions: list[Question] = field(default_factory=list)
    answers: list[Record] = field(default_factory=list)
    authorities: list[Record] = field(default_factory=list)
    additionals: list[Record] = field(default_factory=list)

    _STRUCT = Struct("!HHHHHH")

    def encode(self) -> bytes:
        "encode a question to network bytes"
        return b"".join(self._encode())

    def _encode(self) -> Iterator[bytes]:
        assert len(self.questions) == 1, "only one question supported by DNS"
        assert not self.answers
        assert not self.authorities
        assert not self.additionals

        yield self._STRUCT.pack(
            self.id,
            self.flags,
            len(self.questions),
            0,
            0,
            0,
        )
        for qn in self.questions:
            yield from qn._encode()

    @classmethod
    def _decode(cls, buffer: bytes, offset: int) -> tuple[Self, int]:
        (
            id,
            flags,
            num_qns,
            num_ans,
            num_auth,
            num_extra,
        ), offset = _unpack_from(cls._STRUCT, buffer, offset)

        self = cls(id, flags)
        for _ in range(num_qns):
            qn, offset = Question._decode(buffer, offset=offset)
            self.questions.append(qn)
        for _ in range(num_ans):
            ans, offset = Record._decode(buffer, offset=offset)
            self.answers.append(ans)
        for _ in range(num_auth):
            ans, offset = Record._decode(buffer, offset=offset)
            self.authorities.append(ans)
        for _ in range(num_extra):
            ans, offset = Record._decode(buffer, offset=offset)
            self.additionals.append(ans)

        return self, offset


def make_question(
    name: str,
    qtype: str = "A",
    *,
    id: int | None = None,
    flags: int = RECURSION_DESIRED,
) -> Header:
    if id is None:
        id = randrange(65536)
    qn = Question(
        name,
        type_=getattr(DnsType, qtype),
    )
    return Header(id=id, flags=flags, questions=[qn])


def decode_response(buffer: bytes) -> Header:
    result, offset = Header._decode(buffer, 0)
    if offset != len(buffer):
        print("extra bytes after packet")
    return result
