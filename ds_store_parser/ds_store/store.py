# -*- coding: utf-8 -*-

import struct
import biplist
import mac_alias
import re
import io
import hashlib
import sys
from binascii import hexlify, unhexlify
from ds_store_parser.ds_store import buddy

try:
    next
except NameError:
    next = lambda x: x.__next__()


class IlocCodec(object):
    @staticmethod
    def decode(bytesData):
        if isinstance(bytesData, bytearray):
            x, y, z, a = struct.unpack_from(b'>IIII', bytes(bytesData[:16]))
        else:
            x, y, z, a = struct.unpack(b'>IIII', bytesData[:16])
        h_str = hexlify(bytesData)
        r_value_hor = x
        r_value_ver = y
        r_value_idx = z
        if r_value_hor == 4294967295:
            r_value_hor = "Null"
        if r_value_ver == 4294967295:
            r_value_ver = "Null"
        if r_value_idx == 4294967295:
            r_value_idx = "Null"

        val = f'Location: ({str(r_value_hor)}, {str(r_value_ver)}), '\
              f'Selected Index: {str(r_value_idx)}, Unknown: {h_str[24:32]}'

        return val

class IcvoCodec(object):
    @staticmethod
    def decode(bytesData):
#        h_str = str(bytesData).encode('hex')
#        i_type = h_str[:8].decode('hex')
        h_str = hexlify(bytesData)
        i_type = unhexlify(h_str[:8])
        p_size = str(int(h_str[8:12], 16))
        g_align = unhexlify(h_str[12:20])
#        g_align = h_str[12:20].decode('hex')
#        g_align_loc = h_str[20:28].decode('hex')
        g_align_loc = unhexlify(h_str[20:28])
        unknown = str(h_str[28:])

        val = f'Type: {i_type}, IconPixelSize: {p_size}, GridAlign: {g_align}, '\
              f'GridAlignTo: {g_align_loc}, Unknown: {unknown}'
        return val

class Fwi0Codec(object):
    @staticmethod
    def decode(bytesData):
        if isinstance(bytesData, bytearray):
            w, x, y, z = struct.unpack_from(b'>HHHH', bytes(bytesData[:16]))
        else:
            w, x, y, z = struct.unpack(b'>HHHH', bytesData[:16])

        h_str = hexlify(bytesData)
#        h_str = str(bytesData).encode('hex')

        h_array = (
            f'top: {str(w)}',
            f'left: {str(x)}',
            f'bottom: {str(y)}',
            f'right: {str(z)}',
            f'view_type: {unhexlify(h_str[16:24])}',
            f'Unknown: {h_str[24:32]}'
        )
        val = str(h_array).replace("', u'", ", ").replace("'", "").replace("(u", "(")
        return val

class DilcCodec(object):
    @staticmethod
    def decode(bytesData):
        if isinstance(bytesData, bytearray):
            u, v, w, x, y, z, a, b = struct.unpack_from(b'>IIIIIIII', bytes(bytesData[:32]))
        else:
            u, v, w, x, y, z, a, b = struct.unpack(b'>IIIIIIII', bytesData[:32])
        h_str = hexlify(bytesData)
        if int(h_str[16:24], 16) > 65535:
            h_pos = f"IconPosFromRight: {str(4294967295 - int(h_str[16:24], 16))}"
        else:
            h_pos = f"IconPosFromLeft: {str(int(h_str[16:24], 16))}"

        if int(h_str[24:32], 16) > 65535:
            v_pos = f"IconPosFromBottom: {str(4294967295 - int(h_str[24:32], 16))}"
        else:
            v_pos = f"IconPosFromTop: {str(int(h_str[24:32], 16))}"
        h_array = (
            f"Unk1: {h_str[:8].decode()}",
            f"GridQuadrant: {str(int(h_str[8:12], 16))}",        # short?: Indicates the quadrant on the screen the icon is located. 1=top right, 2=bottom right, 3=bottom left, 4=top left
            f"Unk2: {h_str[12:16].decode()}",       # short?: Unknown. Values other than 0 have been observed
            h_pos,       # position from right/left of screen. 0xFF indicates right position
            v_pos,       # position from top/bottom of screen. 0xFF indicates bottom position
            f"GridIconPosFromLeft: {str(int(h_str[32:40], 16))}",       # position from left
            f"GridIconPosFromTop: {str(int(h_str[40:48], 16))}",       # position from top
            f"Unk3: {h_str[48:56].decode()}",
            f"Unk4: {h_str[56:64].decode()}"
        )

        val = str(h_array).replace("', u'", ", ").replace("'", "").replace("(u", "(")

        return val

class PlistCodec(object):
    @staticmethod
    def decode(byteval):
        try:
            return biplist.readPlistFromString(byteval)
        except Exception as exp:
            return f'{str(exp)}: {hexlify(byteval).decode()}'

class BookmarkCodec(object):
    @staticmethod
    def decode(byteval):
        try:
            return mac_alias.Bookmark.from_bytes(byteval)
        except Exception as exp:
            return f'{str(exp)}: {hexlify(byteval).decode()}'

# This list tells the code how to decode particular kinds of entry in the
# .DS_Store file.  This is really a convenience, and we currently only
# support a tiny subset of the possible entry types.
codecs = {
    b'Iloc': IlocCodec,
    b'icvo': IcvoCodec,
    b'fwi0': Fwi0Codec,
    b'dilc': DilcCodec,
    b'bwsp': PlistCodec,
    b'lsvp': PlistCodec,
    b'glvp': PlistCodec,
    b'lsvP': PlistCodec,
    b'icvp': PlistCodec,
    b'lsvC': PlistCodec,
    b'pBBk': BookmarkCodec,
    b'pBB0': BookmarkCodec
    }

codes = {
    "BKGD": "Finder Folder Background Picture",
    "ICVO": "Icon View Options",
    "Iloc": "Icon Location",              # Location and Index
    "LSVO": "List View Options",
    "bwsp": "Browser Window Properties",
    "cmmt": "Finder Comments",
    "clip": "Text Clipping",
    "dilc": "Desktop Icon Location",
    "dscl": "Directory is Expanded in List View",
    "fdsc": "Directory is Expanded in Limited Finder Window",
    "extn": "File Extension",
    "fwi0": "Finder Window Information",
    "fwsw": "Finder Window Sidebar Width",
    "fwvh": "Finder Window Sidebar Height",
    "glvp": "Gallery View Properties",
    "GRP0": "Group Items By",
    "icgo": "icgo. Unknown. Icon View Options?",
    "icsp": "icsp. Unknown. Icon View Properties?",
    "icvo": "Icon View Options",
    "icvp": "Icon View Properties",
    "icvt": "Icon View Text Size",
    "info": "info: Unknown. Finder Info?:",
    "logS": "Logical Size",
    "lg1S": "Logical Size",
    "lssp": "List View Scroll Position",
    "lsvC": "List View Columns",
    "lsvo": "List View Options",
    "lsvt": "List View Text Size",
    "lsvp": "List View Properties",
    "lsvP": "List View Properties",
    "modD": "Modified Date",
    "moDD": "Modified Date",
    "phyS": "Physical Size",
    "ph1S": "Physical Size",
    "pict": "Background Image",
    "vSrn": "Opened Folder in new tab",
    "bRsV": "Browse in Selected View",
    "pBBk": "Finder Folder Background Image Bookmark",
    "pBB0": "Finder Folder Background Image Bookmark",
    "vstl": "View Style Selected",
    "ptbL": "Trash Put Back Location",
    "ptbN": "Trash Put Back Name"
}

types = (
    'long',
    'shor',
    'blob',
    'dutc',
    'type',
    'bool',
    'ustr',
    'comp'
)


class DSStoreEntry(object):
    """Holds the data from an entry in a ``.DS_Store`` file.  Note that this is
    not meant to represent the entry itself---i.e. if you change the type
    or value, your changes will *not* be reflected in the underlying file.

    If you want to make a change, you should either use the :class:`DSStore`
    object's :meth:`DSStore.insert` method (which will replace a key if it
    already exists), or the mapping access mode for :class:`DSStore` (often
    simpler anyway).
    """
    def __init__(self, filename, code, typecode, value=None, node=None):
        if str != bytes and type(filename) == bytes:
            filename = filename.decode('utf-8')

        if not isinstance(code, bytes):
            code = code.encode('latin-1')
        self.filename = filename
        self.code = code
        self.type = typecode
        self.value = value
        self.node = node

    def __repr__(self):
        return repr((self.filename, self.code, self.type, self.value, self.node))

    @classmethod
    def read(cls, block, node):
        """Read a ``.DS_Store`` entry from the containing Block"""
        # First read the filename
        nlen = block.read(b'>I')[0]
        filename = block.read(2 * nlen).decode('utf-16be')

        # Next, read the code and type
        code, typecode = block.read(b'>4s4s')

        # Finally, read the data
        if typecode == b'bool':
            value = block.read(b'>?')[0]
        elif typecode == b'long' or typecode == b'shor':
            value = block.read(b'>I')[0]
        elif typecode == b'blob':
            vlen = block.read(b'>I')[0]
            value = block.read(vlen)

            codec = codecs.get(code, None)
            if codec:
                value = codec.decode(value)
                typecode = codec
        elif typecode == b'ustr':
            vlen = block.read(b'>I')[0]
            value = block.read(2 * vlen).decode('utf-16be')
        elif typecode == b'type':
            value = block.read(b'>4s')[0]
        elif typecode == b'comp' or typecode == b'dutc':
            value = block.read(b'>Q')[0]
        else:
            raise ValueError(f'Unknown type code "{typecode}"')

        return DSStoreEntry(filename, code.decode(), typecode, value, node)

    def __lt__(self, other):
        if not isinstance(other, DSStoreEntry):
            raise TypeError('Can only compare against other DSStoreEntry objects')
        sfl = self.filename.lower()
        ofl = other.filename.lower()
        return (sfl < ofl
                or (self.filename == other.filename
                    and self.code < other.code))

    def __le__(self, other):
        if not isinstance(other, DSStoreEntry):
            raise TypeError('Can only compare against other DSStoreEntry objects')
        sfl = self.filename.lower()
        ofl = other.filename.lower()
        return (sfl < ofl
                or (sfl == ofl
                    and self.code <= other.code))


class DSStore(object):
    """Python interface to a ``.DS_Store`` file.  Works by manipulating the file
    on the disk---so this code will work with ``.DS_Store`` files for *very*
    large directories.

    A :class:`DSStore` object can be used as if it was a mapping, e.g.::

      d['foobar.dat']['Iloc']

    will fetch the "Iloc" record for "foobar.dat", or raise :class:`KeyError` if
    there is no such record.  If used in this manner, the :class:`DSStore` object
    will return (type, value) tuples, unless the type is "blob" and the module
    knows how to decode it.

    Currently, we know how to decode "Iloc", "bwsp", "lsvp", "lsvP" and "icvp"
    blobs.  "Iloc" decodes to an (x, y) tuple, while the others are all decoded
    using ``biplist``.

    Assignment also works, e.g.::

      d['foobar.dat']['note'] = ('ustr', u'Hello World!')

    as does deletion with ``del``::

      del d['foobar.dat']['note']

    This is usually going to be the most convenient interface, though
    occasionally (for instance when creating a new ``.DS_Store`` file) you
    may wish to drop down to using :class:`DSStoreEntry` objects directly."""
    def __init__(self, store):
        self._store = store

        self.entries = {}
        self.dict_list = {}

        self._superblk = self._store['DSDB']
        with self._get_block(self._superblk) as s:
            self._rootnode, self._levels, self._records, \
            self._nodes, self._page_size = s.read(b'>IIIII')

        self._min_usage = 2 * self._page_size // 3
        self._dirty = False

    @classmethod
    def open(cls, file_or_name, mode='r+', initial_entries=None):
        """Open a ``.DS_Store`` file; pass either a Python file object, or a
        filename in the ``file_or_name`` argument and a file access mode in
        the ``mode`` argument.  If you are creating a new file using the "w"
        or "w+" modes, you may also specify a list of entries with which
        to initialise the file."""
        store = buddy.Allocator.open(file_or_name, mode)
        return DSStore(store)

    def _get_block(self, number):
        return self._store.get_block(number)

    # Iterate over the tree, starting at `node'
    def _traverse(self, node):
        counter = 0
        self.src_name = self._store._file.name

        if node is None:
            node = self._rootnode
        with self._get_block(node) as block:
            next_node, count = block.read(b'>II')

            if next_node:
                for n in range(count):
                    counter = counter + 1
                    ptr = block.read(b'>I')[0]

                    for t in self._traverse(ptr):
                        yield t

                    e = DSStoreEntry.read(block, node)
                    chk = e.filename.encode('ascii', 'replace') + str(e.type).encode() + e.code + self.src_name.encode('ascii', 'replace') + hexlify(str(e.value).encode())
                    e_hash = hashlib.md5(chk).hexdigest()

                    if e_hash not in self.dict_list:
                        self.entries[e_hash] = e
                        self.entries[e_hash].node = f'allocated {str(node)}'
                        self.dict_list[e_hash] = f'{chk.decode()}allocated {str(node)}'

                    elif e_hash in self.dict_list and 'unallocated' in self.dict_list[e_hash]:
                        self.entries[e_hash] = e
                        self.entries[e_hash].node = self.dict_list[e_hash].split('unallocated')[1] + f'hello, reallocated in {node}'
                        self.dict_list[e_hash] = self.dict_list[e_hash] + f', reallocated in {node}'
                    else:
                        sys.exit()

                if counter == count and block.tell() < len(block):
                    slack = str(block)[block.tell() * 2:]
                    self.read_slack(slack, node)

                for t in self._traverse(next_node):
                    yield t

                if self.entries:
                    for key in self.entries:
                        yield self.entries[key]

                counter = 0
                self.entries = {}

            else:
                for n in range(count):
                    counter = counter + 1
                    e = DSStoreEntry.read(block, node)
                    chk = e.filename.encode('ascii', 'replace') + str(e.type).encode() + e.code + self.src_name.encode('ascii', 'replace') + hexlify(str(e.value).encode())
                    e_hash = hashlib.md5(chk).hexdigest()

                    if e_hash not in self.dict_list:
                        self.entries[e_hash] = e
                        self.entries[e_hash].node = f'allocated {node}'
                        self.dict_list[e_hash] = f'{chk.decode()}allocated {node}'

                    elif e_hash in self.dict_list and 'unallocated' in self.dict_list[e_hash]:
                        self.entries[e_hash] = e
                        self.entries[e_hash].node = self.dict_list[e_hash].split('unallocated')[1] + f'unallocated, reallocated in {node}'
                        self.dict_list[e_hash] = self.dict_list[e_hash] + f', reallocated in {node}'
                    else:
                        sys.exit()
                '''
                if counter == count and block.tell() < len(block):
                    slack = unicode(block)[block.tell() * 2:]
                    self.read_slack(slack, node)
                '''
                if self.entries:
                    for key in self.entries:
                        yield self.entries[key]

                counter = 0
                self.entries = {}


    def __iter__(self):
        return self._traverse(self._rootnode)


    def read_slack(self, slack, node):
        slack = unhexlify(slack)
        search_exp = '('
        for k in list(codes.keys()):
            for t in types:
                search_exp = search_exp + k + t + '|'

        search_exp = search_exp[:-1] + ')'

        p = re.compile(f'\x00\x00\x00[\x01-\xff](\x00[\x01-\xff]){1,}{search_exp}')
        s_offset = p.search(slack)
        if s_offset:
            s_offset = s_offset.span()[0]
        sub_search = re.finditer(f'\x00\x00\x00[\x01-\xff](\x00[\x01-\xff]){1,}{search_exp}', slack)
        counter = 0
        for match in sub_search:
            counter = counter + 1
            if match.regs[0][0] == s_offset:
                prev = s_offset
                s_offset = None
            else:
                e_off = match.regs[0][0]
                s_off = prev
                prev = e_off
                hex_str = slack[s_off:].encode('utf-8')
                block = io.StringIO()
                block.write(hex_str.decode())
                block.seek(0)
                try:
                    nlen = struct.unpack('>I', block.read(4))[0]
                    filename = block.read(2 * nlen).decode('utf-16be')

                    # Next, read the code and type
                    code, typecode = struct.unpack('>4s4s', block.read(8))

                    # Finally, read the data
                    if typecode == 'bool':
                        value = struct.unpack('>?', block.read(4))[0]
                    elif typecode == 'long' or typecode == 'shor':
                        value = struct.unpack('>I', block.read(4))[0]
                    elif typecode == 'blob':
                        vlen = struct.unpack('>I', block.read(4))[0]
                        value = block.read(vlen)
                        codec = codecs.get(code, None)
                        if codec:
                            value = codec.decode(value)
                            typecode = codec
                    elif typecode == b'ustr':
                        vlen = struct.unpack('>I', block.read(4))[0]
                        value = block.read(2 * vlen).decode('utf-16be')
                    elif typecode == b'type':
                        value = struct.unpack('>4s', block.read(4))[0]
                    elif typecode == b'comp' or typecode == b'dutc':
                        value = struct.unpack('>Q', block.read(8))[0]
                    else:
                        raise ValueError(f'Unknown type code "{typecode}"')
                except Exception as e:
                    print(f'File: {self.src_name}. unable to parse entry. Error: {str(e)}')
                    continue

                e = DSStoreEntry(filename, code, typecode, value, 'unallocated')
                chk = e.filename.encode('ascii', 'replace') + str(e.type) + str(e.code) + self.src_name.encode('ascii', 'replace') + hexlify(str(e.value))
                #chk = e.filename.encode('ascii', 'replace') + str(e.type).encode() + e.code + self.src_name.encode('ascii', 'replace') + hexlify(str(e.value).encode())
                e_hash = hashlib.md5(chk).hexdigest()

                if e_hash not in self.dict_list:
                    self.entries[e_hash] = e
                    self.dict_list[e_hash] = f'{chk}unallocated'
                    #self.dict_list[e_hash] = f'{chk.decode()}unallocated'

                elif e_hash in self.dict_list and 'unallocated' not in self.dict_list[e_hash]:
                    self.entries[e_hash] = e
                    self.entries[e_hash].node = f'{str(self.entries[e_hash].node)} reallocated in {node}'
                    self.dict_list[e_hash] = f'{chk} reallocated'
                    #self.dict_list[e_hash] = f'{chk.decode()} reallocated'

                else:
                    print(f'File: {self.src_name}. unknown exception in store.py')
                    pass
