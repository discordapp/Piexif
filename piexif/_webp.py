
import struct


def split(data):
    if data[0:4] != b"RIFF" or data[8:12] != b"WEBP":
        raise ValueError("Not WebP")

    webp_length_bytes = data[4:8]
    webp_length = struct.unpack("<L", webp_length_bytes)[0]
    RIFF_HEADER_SIZE = 8
    file_size = RIFF_HEADER_SIZE + webp_length

    start = 12
    pointer = start
    CHUNK_FOURCC_LENGTH = 4
    LENGTH_BYTES_LENGTH = 4

    chunks = []
    while pointer + CHUNK_FOURCC_LENGTH + LENGTH_BYTES_LENGTH < file_size:
        fourcc = data[pointer:pointer + CHUNK_FOURCC_LENGTH]
        pointer += CHUNK_FOURCC_LENGTH
        chunk_length_bytes = data[pointer:pointer + LENGTH_BYTES_LENGTH]
        chunk_length = struct.unpack("<L", chunk_length_bytes)[0]
        pointer += LENGTH_BYTES_LENGTH

        chunk_data = data[pointer:pointer + chunk_length]
        chunks.append({"fourcc":fourcc, "length_bytes":chunk_length_bytes, "data":chunk_data})

        padding = 1 if chunk_length % 2 else 0

        pointer += chunk_length + padding
    return chunks

def merge_chunks(chunks):
    merged = b"".join([chunk["fourcc"] 
                       + chunk["length_bytes"]
                       + chunk["data"]
                       + (len(chunk["data"]) % 2) * b"\x00"
                        for chunk in chunks])
    return merged


def _get_size_from_vp8x(chunk):
    width_minus_one_bytes = chunk["data"][-6:-3] + b"\x00"
    width_minus_one = struct.unpack("<L", width_minus_one_bytes)[0]
    width = width_minus_one + 1
    height_minus_one_bytes = chunk["data"][-3:] + b"\x00"
    height_minus_one = struct.unpack("<L", height_minus_one_bytes)[0]
    height = height_minus_one + 1
    return (width, height)

def _get_size_from_vp8(chunk):
    BEGIN_CODE = b"\x9d\x01\x2a"
    begin_index = chunk["data"].find(BEGIN_CODE)
    if begin_index == -1:
        ValueError("wrong VP8")
    else:
        BEGIN_CODE_LENGTH = len(BEGIN_CODE)
        LENGTH_BYTES_LENGTH = 2
        length_start = begin_index + BEGIN_CODE_LENGTH
        width_bytes = chunk["data"][length_start:length_start + LENGTH_BYTES_LENGTH]
        width = struct.unpack("<H", width_bytes)[0]
        height_bytes = chunk["data"][length_start + LENGTH_BYTES_LENGTH:length_start + 2 * LENGTH_BYTES_LENGTH]
        height = struct.unpack("<H", height_bytes)[0]
        return (width, height)

def _vp8L_contains_alpha(chunk_data):
    flag = ord(chunk_data[4:5]) >> 5-1 & ord(b"\x01")
    contains = 1 * flag
    return contains

def _get_size_from_vp8L(chunk):
    b1 = chunk["data"][1:2]
    b2 = chunk["data"][2:3]
    b3 = chunk["data"][3:4]
    b4 = chunk["data"][4:5]

    width_minus_one = (ord(b2) & ord(b"\x3F")) << 8 | ord(b1)
    width = width_minus_one + 1

    height_minus_one = (ord(b4) & ord(b"\x0F")) << 10 | ord(b3) << 2 | (ord(b2) & ord(b"\xC0")) >> 6
    height = height_minus_one + 1

    return (width, height)

def _get_size_from_anmf(chunk):
    width_minus_one_bytes = chunk["data"][6:9] + b"\x00"
    width_minus_one = struct.unpack("<L", width_minus_one_bytes)[0]
    width = width_minus_one + 1
    height_minus_one_bytes = chunk["data"][9:12] + b"\x00"
    height_minus_one = struct.unpack("<L", height_minus_one_bytes)[0]
    height = height_minus_one + 1
    return (width, height)
    

def _get_sub_chunks_from_anmf(anmf_chunk):
    """
    Extracts and returns sub-chunks from the ANMF chunk data.

    :param anmf_chunk: Dictionary containing the 'fourcc', 'length_bytes', and 'data' for the ANMF chunk.
    :return: List of dictionaries representing sub-chunks found within the ANMF chunk.
    """
    data = anmf_chunk['data']
    sub_chunks = []
    offset = 0

    # Fixed size for the ANMF header (Frame X, Frame Y, Width, Height, Duration, Reserved, B, D)
    anmf_header_size = 16

    # Skip the ANMF header to get to the Frame Data
    offset += anmf_header_size

    data_length = len(data)
    while offset < data_length:
        # Ensure there's enough data left for a new chunk (4 bytes for fourcc + 4 bytes for length)
        if offset + 8 > data_length:
            break

        # Read the fourcc code (4 bytes)
        fourcc = data[offset:offset + 4]
        offset += 4

        # Read the length of the chunk (4 bytes, little-endian)
        length = struct.unpack('<I', data[offset:offset + 4])[0]
        offset += 4

        # Ensure there's enough data left for the chunk data
        if offset + length > data_length:
            break

        # Read the chunk data
        chunk_data = data[offset:offset + length]
        offset += length

        # Append the sub-chunk to the list
        sub_chunks.append({
            'fourcc': fourcc,
            'length_bytes': struct.pack('<I', length),
            'data': chunk_data
        })

        # Ensure chunks are padded to even length
        if length % 2 == 1:
            offset += 1

    return sub_chunks

def set_vp8x(chunks):
    max_width = 0
    max_height = 0
    flags = [b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0']  # [0, 0, ICC, Alpha, EXIF, XMP, Anim, 0]

    def process_chunk(chunk):
        nonlocal max_width, max_height
        if chunk['fourcc'] == b'VP8X':
            width, height = _get_size_from_vp8x(chunk)
            max_width = max(max_width, width)
            max_height = max(max_height, height)
        elif chunk['fourcc'] == b'VP8 ':
            width, height = _get_size_from_vp8(chunk)
            max_width = max(max_width, width)
            max_height = max(max_height, height)
        elif chunk['fourcc'] == b'VP8L':
            is_rgba = _vp8L_contains_alpha(chunk['data'])
            if is_rgba:
                flags[3] = b'1'
            width, height = _get_size_from_vp8L(chunk)
            max_width = max(max_width, width)
            max_height = max(max_height, height)
        elif chunk['fourcc'] == b'ANMF':
            sub_chunks = _get_sub_chunks_from_anmf(chunk)
            for sub_chunk in sub_chunks:
                process_chunk(sub_chunk)
            frame_width, frame_height = _get_size_from_anmf(chunk)
            max_width = max(max_width, frame_width)
            max_height = max(max_height, frame_height)
        elif chunk['fourcc'] == b'ICCP':
            flags[2] = b'1'
        elif chunk['fourcc'] == b'ALPH':
            flags[3] = b'1'
        elif chunk['fourcc'] == b'EXIF':
            flags[4] = b'1'
        elif chunk['fourcc'] == b'XMP ':
            flags[5] = b'1'
        elif chunk['fourcc'] == b'ANIM':
            flags[6] = b'1'

    for chunk in chunks:
        process_chunk(chunk)

    max_width_minus_one = max_width - 1
    max_height_minus_one = max_height - 1

    if chunks[0]['fourcc'] == b'VP8X':
        chunks.pop(0)

    header_bytes = b'VP8X'
    length_bytes = b'\x0a\x00\x00\x00'
    flags_bytes = struct.pack('B', int(b''.join(flags), 2))
    padding_bytes = b'\x00\x00\x00'
    width_bytes = struct.pack('<L', max_width_minus_one)[:3]
    height_bytes = struct.pack('<L', max_height_minus_one)[:3]

    data_bytes = flags_bytes + padding_bytes + width_bytes + height_bytes

    vp8x_chunk = {'fourcc': header_bytes, 'length_bytes': length_bytes, 'data': data_bytes}
    chunks.insert(0, vp8x_chunk)

    return chunks

def get_file_header(chunks):
    WEBP_HEADER_LENGTH = 4
    FOURCC_LENGTH = 4
    LENGTH_BYTES_LENGTH = 4

    length = WEBP_HEADER_LENGTH
    for chunk in chunks:
        data_length = struct.unpack("<L", chunk["length_bytes"])[0]
        data_length += 1 if data_length % 2 else 0
        length += FOURCC_LENGTH + LENGTH_BYTES_LENGTH + data_length
    length_bytes = struct.pack("<L", length)
    riff = b"RIFF"
    webp_header = b"WEBP"
    file_header = riff + length_bytes + webp_header
    return file_header



def get_exif(data):
    if data[0:4] != b"RIFF" or data[8:12] != b"WEBP":
        raise ValueError("Not WebP")

    if data[12:16] != b"VP8X":
        raise ValueError("doesnot have exif")

    webp_length_bytes = data[4:8]
    webp_length = struct.unpack("<L", webp_length_bytes)[0]
    RIFF_HEADER_SIZE = 8
    file_size = RIFF_HEADER_SIZE + webp_length

    start = 12
    pointer = start
    CHUNK_FOURCC_LENGTH = 4
    LENGTH_BYTES_LENGTH = 4

    chunks = []
    exif = b""
    while pointer < file_size:
        fourcc = data[pointer:pointer + CHUNK_FOURCC_LENGTH]
        pointer += CHUNK_FOURCC_LENGTH
        chunk_length_bytes = data[pointer:pointer + LENGTH_BYTES_LENGTH]
        chunk_length = struct.unpack("<L", chunk_length_bytes)[0]
        if chunk_length % 2:
            chunk_length += 1
        pointer += LENGTH_BYTES_LENGTH
        if fourcc == b"EXIF":
            return data[pointer:pointer + chunk_length]
        pointer += chunk_length
    return None  # if there isn't exif, return None.


def insert_exif_into_chunks(chunks, exif_bytes):
    EXIF_HEADER = b"EXIF"
    exif_length_bytes = struct.pack("<L", len(exif_bytes))
    exif_chunk = {"fourcc":EXIF_HEADER, "length_bytes":exif_length_bytes, "data":exif_bytes}

    xmp_index = None
    animation_index = None

    for index, chunk in enumerate(chunks):
        if chunk["fourcc"] == b"EXIF":
            chunks.pop(index)

    for index, chunk in enumerate(chunks):
        if chunk["fourcc"] == b"XMP ":
            xmp_index = index
        elif chunk["fourcc"] == b"ANIM":
            animation_index = index
    if xmp_index is not None:
        chunks.insert(xmp_index, exif_chunk)
    elif animation_index is not None:
        chunks.insert(animation_index, exif_chunk)
    else:
        chunks.append(exif_chunk)
    return chunks


def insert(webp_bytes, exif_bytes):
    chunks = split(webp_bytes)
    chunks = insert_exif_into_chunks(chunks, exif_bytes)
    chunks = set_vp8x(chunks)
    file_header = get_file_header(chunks)
    merged = merge_chunks(chunks)
    new_webp_bytes = file_header + merged
    return new_webp_bytes


def remove(webp_bytes):
    chunks = split(webp_bytes)
    for index, chunk in enumerate(chunks):
        if chunk["fourcc"] == b"EXIF":
            chunks.pop(index)
    chunks = set_vp8x(chunks)
    file_header = get_file_header(chunks)
    merged = merge_chunks(chunks)
    new_webp_bytes = file_header + merged
    return new_webp_bytes
