#!/usr/bin/env python3
"""
ObjC/Swift Metadata Recovery
Extract class/method/protocol info from __objc_* sections, Swift metadata.
"""

import sys
import struct
from dataclasses import dataclass, field
from typing import List, Dict, Optional, BinaryIO
from pathlib import Path

# Reuse Mach-O parser
sys.path.insert(0, str(Path(__file__).parent))
from macho_parser import MachOParser, Section, SectionFlags


@dataclass
class ObjCClass:
    name: str
    superclass: str = ""
    metaclass: int = 0
    instance_size: int = 0
    ivars: List[Dict] = field(default_factory=list)
    methods: List[Dict] = field(default_factory=list)
    properties: List[Dict] = field(default_factory=list)
    protocols: List[str] = field(default_factory=list)


@dataclass
class ObjCProtocol:
    name: str
    protocols: List[str] = field(default_factory=list)
    instance_methods: List[Dict] = field(default_factory=list)
    class_methods: List[Dict] = field(default_factory=list)
    optional_instance_methods: List[Dict] = field(default_factory=list)
    optional_class_methods: List[Dict] = field(default_factory=list)
    properties: List[Dict] = field(default_factory=list)


@dataclass
class ObjCCategory:
    name: str
    class_name: str
    instance_methods: List[Dict] = field(default_factory=list)
    class_methods: List[Dict] = field(default_factory=list)
    protocols: List[str] = field(default_factory=list)
    properties: List[Dict] = field(default_factory=list)


@dataclass
class SwiftMetadata:
    type_name: str
    kind: str  # struct, class, enum, protocol
    size: int = 0
    flags: int = 0
    fields: List[Dict] = field(default_factory=list)
    protocol_conformances: List[str] = field(default_factory=list)
    generic_params: List[str] = field(default_factory=list)


class ObjCParser:
    def __init__(self, macho_parser: MachOParser):
        self.macho = macho_parser
        self.classes: List[ObjCClass] = []
        self.protocols: List[ObjCProtocol] = []
        self.categories: List[ObjCCategory] = []
        self.selectors: Dict[int, str] = {}
        self._parse()
    
    def _parse(self):
        # Find __objc_* sections
        objc_sections = {}
        for sect in self.macho.get_sections():
            if sect.sectname.startswith('__objc_'):
                objc_sections[sect.sectname] = sect
        
        if not objc_sections:
            return
        
        # Parse selectors first (__objc_selrefs, __objc_methname)
        self._parse_selectors(objc_sections)
        
        # Parse classes (__objc_classlist, __objc_nlclslist)
        self._parse_classes(objc_sections)
        
        # Parse protocols (__objc_protolist, __objc_nlprotolist)
        self._parse_protocols(objc_sections)
        
        # Parse categories (__objc_catlist, __objc_nlcatlist)
        self._parse_categories(objc_sections)
    
    def _read_at(self, offset: int, fmt: str) -> tuple:
        """Read struct at offset."""
        self.macho.f.seek(offset)
        size = struct.calcsize(fmt)
        data = self.macho.f.read(size)
        return struct.unpack(fmt, data)
    
    def _read_string(self, offset: int) -> str:
        """Read null-terminated string at offset."""
        self.macho.f.seek(offset)
        data = bytearray()
        while True:
            b = self.macho.f.read(1)
            if not b or b == b'\x00':
                break
            data.extend(b)
        return data.decode('utf-8', errors='replace')
    
    def _parse_selectors(self, sections: Dict[str, Section]):
        """Parse selector references and method names."""
        # __objc_selrefs - array of selector pointers
        if '__objc_selrefs' in sections:
            sect = sections['__objc_selrefs']
            self.macho.f.seek(sect.offset)
            count = sect.size // (8 if self.macho.header.is_64bit else 4)
            ptr_fmt = '<Q' if self.macho.header.is_64bit else '<I'
            for _ in range(count):
                sel_ptr = struct.unpack(ptr_fmt, self.macho.f.read(struct.calcsize(ptr_fmt)))[0]
                if sel_ptr:
                    # Selector is a string pointer
                    self.macho.f.seek(sel_ptr)
                    name = self._read_string(sel_ptr)
                    self.selectors[sel_ptr] = name
        
        # __objc_methname - actual selector strings
        if '__objc_methname' in sections:
            sect = sections['__objc_methname']
            self.macho.f.seek(sect.offset)
            # These are just strings, harder to parse without references
            pass
    
    def _parse_classes(self, sections: Dict[str, Section]):
        """Parse class lists."""
        for list_name in ['__objc_classlist', '__objc_nlclslist']:
            if list_name not in sections:
                continue
            sect = sections[list_name]
            self.macho.f.seek(sect.offset)
            ptr_size = 8 if self.macho.header.is_64bit else 4
            ptr_fmt = '<Q' if self.macho.header.is_64bit else '<I'
            count = sect.size // ptr_size
            
            for _ in range(count):
                class_ptr = struct.unpack(ptr_fmt, self.macho.f.read(ptr_size))[0]
                if class_ptr:
                    self._parse_class(class_ptr)
    
    def _parse_class(self, class_ptr: int):
        """Parse a single class_t structure (ObjC 2.0, 64-bit).
        
        struct objc_class : objc_object {
            Class isa;              // +0
            Class superclass;       // +8
            cache_t cache;          // +16 (16 bytes)
            class_data_bits_t bits; // +32
        }
        class_ro_t is obtained via bits & FAST_DATA_MASK (0x00007ffffffffff8).
        """
        if not self.macho.header.is_64bit:
            return  # 32-bit layout differs; skip for now

        ptr_size = 8
        isa = self._read_ptr(class_ptr)
        superclass_ptr = self._read_ptr(class_ptr + 8)
        bits = self._read_ptr(class_ptr + 32)

        FAST_DATA_MASK = 0x00007ffffffffff8
        ro_ptr = bits & FAST_DATA_MASK
        if ro_ptr == 0:
            return

        # Parse class_ro_t
        # struct class_ro_t {
        #   uint32_t flags; uint32_t instanceStart;
        #   uint32_t instanceSize; uint32_t reserved;
        #   const uint8_t *ivarLayout; const char *name;
        #   method_list_t *baseMethodList; protocol_list_t *baseProtocols;
        #   const ivar_list_t *ivars; const uint8_t *weakIvarLayout;
        #   property_list_t *baseProperties;
        # }
        try:
            name_ptr = self._read_ptr(ro_ptr + 24)
            name = self._read_string(name_ptr) if name_ptr else '<unnamed>'
        except Exception:
            return

        superclass_name = ''
        if superclass_ptr:
            try:
                super_bits = self._read_ptr(superclass_ptr + 32)
                super_ro = super_bits & FAST_DATA_MASK
                if super_ro:
                    super_name_ptr = self._read_ptr(super_ro + 24)
                    if super_name_ptr:
                        superclass_name = self._read_string(super_name_ptr)
            except Exception:
                pass

        cls = ObjCClass(name=name, superclass=superclass_name)
        try:
            cls.instance_size = self._read_u32(ro_ptr + 8)
        except Exception:
            pass

        # Methods
        try:
            methods_ptr = self._read_ptr(ro_ptr + 40)
            if methods_ptr:
                cls.methods = self._parse_method_list(methods_ptr)
        except Exception:
            pass

        # Protocols
        try:
            protocols_ptr = self._read_ptr(ro_ptr + 48)
            if protocols_ptr:
                cls.protocols = self._parse_protocol_list_names(protocols_ptr)
        except Exception:
            pass

        # Ivars
        try:
            ivars_ptr = self._read_ptr(ro_ptr + 56)
            if ivars_ptr:
                cls.ivars = self._parse_ivar_list(ivars_ptr)
        except Exception:
            pass

        # Properties
        try:
            props_ptr = self._read_ptr(ro_ptr + 72)
            if props_ptr:
                cls.properties = self._parse_property_list(props_ptr)
        except Exception:
            pass

        self.classes.append(cls)

    def _read_ptr(self, offset: int) -> int:
        """Read a 64-bit pointer at file offset."""
        self.macho.f.seek(offset)
        data = self.macho.f.read(8)
        if len(data) < 8:
            raise EOFError(f"EOF reading pointer at {offset}")
        return struct.unpack('<Q', data)[0]

    def _read_u32(self, offset: int) -> int:
        self.macho.f.seek(offset)
        data = self.macho.f.read(4)
        if len(data) < 4:
            raise EOFError(f"EOF reading u32 at {offset}")
        return struct.unpack('<I', data)[0]

    def _parse_method_list(self, list_ptr: int) -> List[Dict]:
        """Parse method_list_t.
        
        struct method_list_t {
            uint32_t entsizeAndFlags;  // low 16 = entsize, high = flags
            uint32_t count;
            struct method_t first;     // 24 bytes each (64-bit)
        }
        """
        methods = []
        try:
            entsize_flags = self._read_u32(list_ptr)
            count = self._read_u32(list_ptr + 4)
            entsize = entsize_flags & 0xffff
            if entsize == 0:
                entsize = 24  # default 64-bit method_t
            if count > 10000:
                return methods  # sanity check

            for i in range(count):
                m_off = list_ptr + 8 + i * entsize
                name_ptr = self._read_ptr(m_off)
                types_ptr = self._read_ptr(m_off + 8)
                imp_ptr = self._read_ptr(m_off + 16)
                mname = self._read_string(name_ptr) if name_ptr else '?'
                mtypes = self._read_string(types_ptr) if types_ptr else ''
                methods.append({'name': mname, 'types': mtypes, 'imp': imp_ptr})
        except Exception:
            pass
        return methods

    def _parse_ivar_list(self, list_ptr: int) -> List[Dict]:
        """Parse ivar_list_t.
        
        struct ivar_list_t { uint32_t entsize; uint32_t count; ivar_t first; }
        ivar_t (64-bit): offset ptr(8), name ptr(8), type ptr(8), align(4), size(4)
        """
        ivars = []
        try:
            entsize = self._read_u32(list_ptr)
            count = self._read_u32(list_ptr + 4)
            if entsize == 0:
                entsize = 32
            if count > 10000:
                return ivars
            for i in range(count):
                iv_off = list_ptr + 8 + i * entsize
                name_ptr = self._read_ptr(iv_off + 8)
                type_ptr = self._read_ptr(iv_off + 16)
                iname = self._read_string(name_ptr) if name_ptr else '?'
                itype = self._read_string(type_ptr) if type_ptr else '?'
                ivars.append({'name': iname, 'type': itype})
        except Exception:
            pass
        return ivars

    def _parse_property_list(self, list_ptr: int) -> List[Dict]:
        """Parse property_list_t (64-bit: entsize u32, count u32, then 16-byte entries)."""
        props = []
        try:
            entsize = self._read_u32(list_ptr)
            count = self._read_u32(list_ptr + 4)
            if entsize == 0:
                entsize = 16
            if count > 10000:
                return props
            for i in range(count):
                p_off = list_ptr + 8 + i * entsize
                name_ptr = self._read_ptr(p_off)
                attrs_ptr = self._read_ptr(p_off + 8)
                pname = self._read_string(name_ptr) if name_ptr else '?'
                pattrs = self._read_string(attrs_ptr) if attrs_ptr else ''
                props.append({'name': pname, 'attributes': pattrs})
        except Exception:
            pass
        return props

    def _parse_protocol_list_names(self, list_ptr: int) -> List[str]:
        """Parse protocol_list_t (count pointer-size + array of protocol ptrs)."""
        names = []
        try:
            count = self._read_ptr(list_ptr)
            if count > 1000:
                return names
            for i in range(count):
                proto_ptr = self._read_ptr(list_ptr + 8 + i * 8)
                if proto_ptr:
                    name = self._parse_protocol_name(proto_ptr)
                    if name:
                        names.append(name)
        except Exception:
            pass
        return names

    def _parse_protocol_name(self, proto_ptr: int) -> str:
        """protocol_t layout (64-bit): isa(0), mangledName(8), ..."""
        try:
            name_ptr = self._read_ptr(proto_ptr + 8)
            return self._read_string(name_ptr) if name_ptr else ''
        except Exception:
            return ''

    def _parse_protocols(self, sections: Dict[str, Section]):
        """Parse protocol list sections."""
        for list_name in ['__objc_protolist', '__objc_nlprotolist']:
            if list_name not in sections:
                continue
            sect = sections[list_name]
            self.macho.f.seek(sect.offset)
            ptr_size = 8 if self.macho.header.is_64bit else 4
            ptr_fmt = '<Q' if self.macho.header.is_64bit else '<I'
            count = sect.size // ptr_size
            for _ in range(count):
                proto_ptr = struct.unpack(ptr_fmt, self.macho.f.read(ptr_size))[0]
                if proto_ptr:
                    self._parse_protocol(proto_ptr)

    def _parse_protocol(self, proto_ptr: int):
        """Parse a full protocol_t (64-bit layout).
        
        struct protocol_t {
            Class isa;                        // +0
            const char *mangledName;          // +8
            protocol_list_t *protocols;       // +16
            method_list_t *instanceMethods;   // +24
            method_list_t *classMethods;      // +32
            method_list_t *optionalInstanceMethods;  // +40
            method_list_t *optionalClassMethods;     // +48
            property_list_t *instanceProperties;     // +56
            uint32_t size; uint32_t flags;    // +64, +68
            const char **extendedMethodTypes; // +72
            const char *demangledName;        // +80
            property_list_t *classProperties; // +88
        }
        """
        if not self.macho.header.is_64bit:
            return
        try:
            name_ptr = self._read_ptr(proto_ptr + 8)
            name = self._read_string(name_ptr) if name_ptr else '<unnamed>'
        except Exception:
            return

        proto = ObjCProtocol(name=name)
        try:
            # Inherited protocols
            protos_ptr = self._read_ptr(proto_ptr + 16)
            if protos_ptr:
                proto.protocols = self._parse_protocol_list_names(protos_ptr)
            # Methods
            inst_m = self._read_ptr(proto_ptr + 24)
            if inst_m:
                proto.instance_methods = self._parse_method_list(inst_m)
            class_m = self._read_ptr(proto_ptr + 32)
            if class_m:
                proto.class_methods = self._parse_method_list(class_m)
            opt_inst = self._read_ptr(proto_ptr + 40)
            if opt_inst:
                proto.optional_instance_methods = self._parse_method_list(opt_inst)
            opt_class = self._read_ptr(proto_ptr + 48)
            if opt_class:
                proto.optional_class_methods = self._parse_method_list(opt_class)
            # Properties
            props = self._read_ptr(proto_ptr + 56)
            if props:
                proto.properties = self._parse_property_list(props)
        except Exception:
            pass

        self.protocols.append(proto)

    def _parse_categories(self, sections: Dict[str, Section]):
        """Parse category list sections.
        
        struct category_t (64-bit):
            const char *name;             // +0
            classref_t cls;               // +8
            method_list_t *instanceMethods;  // +16
            method_list_t *classMethods;     // +24
            protocol_list_t *protocols;      // +32
            property_list_t *instanceProperties;  // +40
            property_list_t *_classProperties;    // +48 (newer runtimes)
        """
        for list_name in ['__objc_catlist', '__objc_nlcatlist']:
            if list_name not in sections:
                continue
            sect = sections[list_name]
            self.macho.f.seek(sect.offset)
            ptr_size = 8 if self.macho.header.is_64bit else 4
            ptr_fmt = '<Q' if self.macho.header.is_64bit else '<I'
            count = sect.size // ptr_size
            for _ in range(count):
                cat_ptr = struct.unpack(ptr_fmt, self.macho.f.read(ptr_size))[0]
                if cat_ptr:
                    self._parse_category(cat_ptr)

    def _parse_category(self, cat_ptr: int):
        """Parse a single category_t."""
        if not self.macho.header.is_64bit:
            return
        try:
            name_ptr = self._read_ptr(cat_ptr)
            name = self._read_string(name_ptr) if name_ptr else '<unnamed>'
            cls_ref = self._read_ptr(cat_ptr + 8)
        except Exception:
            return

        cat = ObjCCategory(name=name, class_name='')
        # cls_ref points to the class_t; resolve its name
        try:
            cls_bits = self._read_ptr(cls_ref + 32)
            FAST_DATA_MASK = 0x00007ffffffffff8
            cls_ro = cls_bits & FAST_DATA_MASK
            if cls_ro:
                cls_name_ptr = self._read_ptr(cls_ro + 24)
                if cls_name_ptr:
                    cat.class_name = self._read_string(cls_name_ptr)
        except Exception:
            pass

        try:
            inst_m = self._read_ptr(cat_ptr + 16)
            if inst_m:
                cat.instance_methods = self._parse_method_list(inst_m)
            class_m = self._read_ptr(cat_ptr + 24)
            if class_m:
                cat.class_methods = self._parse_method_list(class_m)
            protos = self._read_ptr(cat_ptr + 32)
            if protos:
                cat.protocols = self._parse_protocol_list_names(protos)
            props = self._read_ptr(cat_ptr + 40)
            if props:
                cat.properties = self._parse_property_list(props)
        except Exception:
            pass

        self.categories.append(cat)
    
    def dump_classes(self):
        print("--- ObjC Classes ---")
        for cls in self.classes:
            print(f"  {cls.name} : {cls.superclass}")
            for m in cls.methods:
                print(f"    - {m}")
    
    def dump_protocols(self):
        print("--- ObjC Protocols ---")
        for proto in self.protocols:
            print(f"  {proto.name}")
    
    def dump_categories(self):
        print("--- ObjC Categories ---")
        for cat in self.categories:
            print(f"  {cat.class_name}({cat.name})")


class SwiftParser:
    """Parse Swift metadata from __swift* sections."""
    
    def __init__(self, macho_parser: MachOParser):
        self.macho = macho_parser
        self.types: List[SwiftMetadata] = []
        self._parse()
    
    def _parse(self):
        # Find Swift sections
        swift_sections = {}
        for sect in self.macho.get_sections():
            if sect.sectname.startswith('__swift'):
                swift_sections[sect.sectname] = sect
        
        if not swift_sections:
            return
        
        # Parse type metadata references
        if '__swift_types' in swift_sections or '__swift5_types' in swift_sections:
            self._parse_type_refs(swift_sections)
        
        # Parse protocol conformances
        if '__swift_proto' in swift_sections or '__swift5_proto' in swift_sections:
            self._parse_protocol_conformances(swift_sections)
        
        # Parse field metadata
        if '__swift_field' in swift_sections or '__swift5_field' in swift_sections:
            self._parse_field_metadata(swift_sections)
        
        # Parse generic metadata
        if '__swift_generic' in swift_sections or '__swift5_generic' in swift_sections:
            self._parse_generic_metadata(swift_sections)
    
    def _parse_type_refs(self, sections: Dict[str, Section]):
        """Parse type metadata references."""
        pass
    
    def _parse_protocol_conformances(self, sections: Dict[str, Section]):
        """Parse protocol conformance records."""
        pass
    
    def _parse_field_metadata(self, sections: Dict[str, Section]):
        """Parse field reflection metadata."""
        pass
    
    def _parse_generic_metadata(self, sections: Dict[str, Section]):
        """Parse generic type metadata."""
        pass
    
    def dump_types(self):
        print("--- Swift Types ---")
        for t in self.types:
            print(f"  {t.type_name} ({t.kind}) size={t.size} flags=0x{t.flags:x}")
            for conf in t.protocol_conformances:
                print(f"    conforms: {conf}")


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <mach-o-file>")
        sys.exit(1)
    
    macho = MachOParser(sys.argv[1])
    
    print(f"=== ObjC/Swift Metadata: {sys.argv[1]} ===")
    print(f"Architecture: {macho.header.cpu_arch}")
    print()
    
    # List ObjC sections
    objc_sections = [s for s in macho.get_sections() if s.sectname.startswith('__objc')]
    if objc_sections:
        print("--- ObjC Sections ---")
        for s in objc_sections:
            print(f"  {s.sectname:32} addr=0x{s.addr:x} sz=0x{s.size:x} off=0x{s.offset:x}")
    else:
        print("No __objc_* sections found")
    
    swift_sections = [s for s in macho.get_sections() if s.sectname.startswith('__swift')]
    if swift_sections:
        print("\n--- Swift Sections ---")
        for s in swift_sections:
            print(f"  {s.sectname:32} addr=0x{s.addr:x} sz=0x{s.size:x} off=0x{s.offset:x}")
    else:
        print("\nNo __swift* sections found")
    
    # Try parsing
    objc = ObjCParser(macho)
    objc.dump_classes()
    objc.dump_protocols()
    objc.dump_categories()
    
    swift = SwiftParser(macho)
    swift.dump_types()


if __name__ == '__main__':
    main()