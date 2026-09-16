#!/usr/bin/env python3
"""
dyld Shared Cache Extractor
Locate and parse dyld shared cache (macOS/iOS), extract individual dylibs.
"""

import sys
import struct
import mmap
import os
from dataclasses import dataclass
from typing import List, Optional, BinaryIO
from pathlib import Path


@dataclass
class DyldCacheHeader:
    magic: bytes
    version: str
    mapping_count: int
    mapping_offset: int
    images_count: int
    images_offset: int
    dyld_base: int
    code_signature_offset: int
    code_signature_size: int
    local_symbols_offset: int
    local_symbols_size: int
    uuid: bytes
    branch_pools_offset: int
    branch_pools_count: int
    patch_table_offset: int
    patch_table_count: int
    cache_type: int


@dataclass
class DyldCacheMapping:
    address: int
    size: int
    file_offset: int
    max_prot: int
    init_prot: int


@dataclass
class DyldCacheImage:
    address: int
    mod_time: int
    inode: int
    path_offset: int
    path: str = ""


def parse_dyld_cache_header(f: BinaryIO) -> DyldCacheHeader:
    """Parse dyld shared cache header."""
    # Read magic (16 bytes)
    magic = f.read(16)
    
    # Version string (16 bytes, null-terminated)
    version_bytes = f.read(16)
    version = version_bytes.rstrip(b'\x00').decode('ascii', errors='replace')
    
    # Rest of header (varies by version)
    # Common fields for iOS 14+ / macOS 11+
    header_fmt = '<QQQQQQQQQQ16sQQQQI'
    header_size = struct.calcsize(header_fmt)
    data = f.read(header_size)
    
    if len(data) < header_size:
        # Try older format
        f.seek(32)
        old_fmt = '<IIIIIIIIII16sIIII'
        old_data = f.read(struct.calcsize(old_fmt))
        vals = struct.unpack(old_fmt, old_data)
        return DyldCacheHeader(
            magic=magic,
            version=version,
            mapping_count=vals[0],
            mapping_offset=vals[1],
            images_count=vals[2],
            images_offset=vals[3],
            dyld_base=vals[4],
            code_signature_offset=vals[5],
            code_signature_size=vals[6],
            local_symbols_offset=vals[7],
            local_symbols_size=vals[8],
            uuid=vals[9],
            branch_pools_offset=vals[10],
            branch_pools_count=vals[11],
            patch_table_offset=vals[12],
            patch_table_count=vals[13],
            cache_type=vals[14]
        )
    
    vals = struct.unpack(header_fmt, data)
    return DyldCacheHeader(
        magic=magic,
        version=version,
        mapping_count=vals[0],
        mapping_offset=vals[1],
        images_count=vals[2],
        images_offset=vals[3],
        dyld_base=vals[4],
        code_signature_offset=vals[5],
        code_signature_size=vals[6],
        local_symbols_offset=vals[7],
        local_symbols_size=vals[8],
        uuid=vals[9],
        branch_pools_offset=vals[10],
        branch_pools_count=vals[11],
        patch_table_offset=vals[12],
        patch_table_count=vals[13],
        cache_type=vals[14]
    )


def parse_mappings(f: BinaryIO, header: DyldCacheHeader) -> List[DyldCacheMapping]:
    """Parse cache mappings."""
    f.seek(header.mapping_offset)
    mappings = []
    for _ in range(header.mapping_count):
        fmt = '<QQQII'
        data = f.read(struct.calcsize(fmt))
        if len(data) < struct.calcsize(fmt):
            break
        vals = struct.unpack(fmt, data)
        mappings.append(DyldCacheMapping(*vals))
    return mappings


def parse_images(f: BinaryIO, header: DyldCacheHeader) -> List[DyldCacheImage]:
    """Parse cache images (dylibs)."""
    f.seek(header.images_offset)
    images = []
    for _ in range(header.images_count):
        fmt = '<QQQI'
        data = f.read(struct.calcsize(fmt))
        if len(data) < struct.calcsize(fmt):
            break
        vals = struct.unpack(fmt, data)
        img = DyldCacheImage(vals[0], vals[1], vals[2], vals[3])
        images.append(img)
    return images


def read_image_paths(f: BinaryIO, images: List[DyldCacheImage], strings_offset: int):
    """Read image paths from string table."""
    for img in images:
        f.seek(strings_offset + img.path_offset)
        path_bytes = bytearray()
        while True:
            b = f.read(1)
            if not b or b == b'\x00':
                break
            path_bytes.extend(b)
        img.path = path_bytes.decode('utf-8', errors='replace')


def find_dyld_cache_paths() -> List[str]:
    """Find dyld shared cache paths on macOS."""
    paths = []
    
    # macOS system cache
    macos_paths = [
        '/System/Library/dyld/dyld_shared_cache_arm64',
        '/System/Library/dyld/dyld_shared_cache_x86_64',
        '/System/Library/dyld/dyld_shared_cache_arm64e',
    ]
    
    # Check for split caches (macOS 12+)
    dyld_dir = Path('/System/Library/dyld')
    if dyld_dir.exists():
        for f in dyld_dir.glob('dyld_shared_cache_*'):
            if f.is_file():
                paths.append(str(f))
    
    # Add default paths if they exist
    for p in macos_paths:
        if Path(p).exists():
            paths.append(p)
    
    return paths


def extract_dylib_from_cache(cache_path: str, image_path: str, output_dir: str) -> bool:
    """Extract a single dylib from the shared cache."""
    try:
        with open(cache_path, 'rb') as f:
            # Parse header
            header = parse_dyld_cache_header(f)
            mappings = parse_mappings(f, header)
            images = parse_images(f, header)
            
            # Find string table offset (after images array)
            strings_offset = header.images_offset + header.images_count * 24  # approx
            
            read_image_paths(f, images, strings_offset)
            
            # Find target image
            target_img = None
            for img in images:
                if img.path == image_path or img.path.endswith('/' + image_path):
                    target_img = img
                    break
            
            if not target_img:
                print(f"Image not found: {image_path}")
                print(f"Available images: {[img.path for img in images[:10]]}...")
                return False
            
            # Find mapping containing this image
            target_mapping = None
            for mapping in mappings:
                if mapping.address <= target_img.address < mapping.address + mapping.size:
                    target_mapping = mapping
                    break
            
            if not target_mapping:
                print(f"No mapping found for image at 0x{target_img.address:x}")
                return False
            
            # Calculate file offset
            offset_in_mapping = target_img.address - target_mapping.address
            file_offset = target_mapping.file_offset + offset_in_mapping
            
            # Determine dylib size (approximate - would need Mach-O parsing for exact)
            # For now, extract from image address to next image or mapping end
            next_addr = target_mapping.address + target_mapping.size
            for img in images:
                if img.address > target_img.address and img.address < next_addr:
                    next_addr = img.address
            
            dylib_size = next_addr - target_img.address
            
            # Extract
            f.seek(file_offset)
            dylib_data = f.read(dylib_size)
            
            # Write output
            os.makedirs(output_dir, exist_ok=True)
            output_name = os.path.basename(image_path)
            output_path = os.path.join(output_dir, output_name)
            with open(output_path, 'wb') as out:
                out.write(dylib_data)
            
            print(f"Extracted: {output_path} ({len(dylib_data)} bytes)")
            return True
            
    except Exception as e:
        print(f"Error extracting {image_path}: {e}")
        return False


def list_cache_images(cache_path: str) -> List[str]:
    """List all images in a dyld shared cache."""
    images = []
    try:
        with open(cache_path, 'rb') as f:
            header = parse_dyld_cache_header(f)
            mappings = parse_mappings(f, header)
            imgs = parse_images(f, header)
            
            strings_offset = header.images_offset + header.images_count * 24
            read_image_paths(f, imgs, strings_offset)
            
            for img in imgs:
                images.append(img.path)
    except Exception as e:
        print(f"Error reading cache: {e}")
    return images


def print_cache_info(cache_path: str):
    """Print dyld cache information."""
    with open(cache_path, 'rb') as f:
        header = parse_dyld_cache_header(f)
        mappings = parse_mappings(f, header)
        images = parse_images(f, header)
        
        strings_offset = header.images_offset + header.images_count * 24
        read_image_paths(f, images, strings_offset)
        
        print(f"=== dyld Shared Cache: {cache_path} ===")
        print(f"Magic: {header.magic.hex()}")
        print(f"Version: {header.version}")
        print(f"Cache Type: {header.cache_type}")
        print(f"UUID: {header.uuid.hex()}")
        print(f"Dyld Base: 0x{header.dyld_base:x}")
        print(f"Mappings: {header.mapping_count}")
        print(f"Images: {header.images_count}")
        print()
        
        print("--- Mappings ---")
        for i, m in enumerate(mappings):
            print(f"  [{i}] addr=0x{m.address:x} sz=0x{m.size:x} fileoff=0x{m.file_offset:x} prot={m.init_prot:#x}/{m.max_prot:#x}")
        
        print(f"\n--- Images (showing first 20 of {len(images)}) ---")
        for img in images[:20]:
            print(f"  0x{img.address:x} {img.path}")
        if len(images) > 20:
            print(f"  ... and {len(images) - 20} more")


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <cache-file> [image-path] [output-dir]")
        print(f"       {sys.argv[0]} --list-caches")
        print(f"       {sys.argv[0]} --list <cache-file>")
        print(f"       {sys.argv[0]} --info <cache-file>")
        sys.exit(1)
    
    if sys.argv[1] == '--list-caches':
        paths = find_dyld_cache_paths()
        if paths:
            print("Found dyld caches:")
            for p in paths:
                print(f"  {p}")
        else:
            print("No dyld caches found")
        return
    
    if sys.argv[1] == '--list':
        if len(sys.argv) < 3:
            print("Need cache file")
            sys.exit(1)
        images = list_cache_images(sys.argv[2])
        for img in images:
            print(img)
        return
    
    if sys.argv[1] == '--info':
        if len(sys.argv) < 3:
            print("Need cache file")
            sys.exit(1)
        print_cache_info(sys.argv[2])
        return
    
    # Extract mode
    cache_path = sys.argv[1]
    image_path = sys.argv[2] if len(sys.argv) > 2 else None
    output_dir = sys.argv[3] if len(sys.argv) > 3 else './extracted'
    
    if not image_path:
        print("Need image path to extract")
        sys.exit(1)
    
    extract_dylib_from_cache(cache_path, image_path, output_dir)


if __name__ == '__main__':
    main()