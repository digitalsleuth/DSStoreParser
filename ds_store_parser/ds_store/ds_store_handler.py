# -*- coding: utf-8 -*-
"""DsStoreHandler and DsStoreRecord Classes"""
from datetime import timedelta, datetime as dt
from binascii import hexlify, unhexlify
import collections
import struct
from ds_store_parser.ds_store import store as ds_store


class DsStoreHandler:
    """Wrapper class for handling the DS Store artifact."""
    def __init__(self, file_io, location):
        self._file_io = file_io
        self.location = location
        self.ds_store = ds_store.DSStore.open(
            self._file_io, "rb"
        )


    def __iter__(self):
        """
        Iterate the entries within the store.

        Yields
            <DsStoreRecord>: The ds store entry record
        """
        for ds_store_entry in sorted(self.ds_store):
            yield DsStoreRecord(ds_store_entry)


class DsStoreRecord:
    """A wrapper class for the DSStoreEntry."""
    def __init__(self, ds_store_entry):
        self.ds_store_entry = ds_store_entry

    def as_dict(self):
        """
        Turn the internal DSStoreEntry into a OrderedDict.

        Returns
            <OrderedDict>: The ordered dictionary representing the internal DSStoreEntry.
        """

        record_dict = collections.OrderedDict([
            ("filename", self.ds_store_entry.filename),
            ("type", self.ds_store_entry.type),
            ("code", (self.ds_store_entry.code).decode()),
            ("value", self.ds_store_entry.value),
        ])
        if hasattr(self.ds_store_entry.type, "__name__"):
            record_dict["type"] = self.ds_store_entry.type.__name__
        if record_dict["type"] in ("blob", b"blob") and record_dict["code"].lower() == 'modd':
            record_dict["value"] = hexlify(record_dict["value"])
            a = record_dict["value"][:16]
            a = (''.join([a.decode()[i:i+2] for i in range(0, len(a), 2)][::-1])).encode()
            a = struct.unpack('>d', unhexlify(a))[0]
            parsed_dt = dt.utcfromtimestamp(a + 978307200)
            record_dict["value"] = parsed_dt
        elif record_dict["type"] in ("blob", b"blob"):
            record_dict["value"] = hexlify(record_dict["value"])
        elif record_dict["type"] in ("dutc", b"dutc"):
            epoch_dt = dt(1904, 1, 1)
            parsed_dt = epoch_dt + timedelta(
                seconds=int(self.ds_store_entry.value) / 65536
            )
            record_dict["value"] = parsed_dt
        return record_dict, self.ds_store_entry.node
