import hashlib
from PIL import Image


#Capacity check

def get_lsb_mask(num_bits: int) -> int:
    #Mask for the lowest N bits, e.g. num_bits=3 -> 0b00000111.
    return (1 << num_bits) - 1


def check_capacity(cover_width: int, cover_height: int, channels: int,
                    payload_size_bytes: int, bits_per_channel: int) -> tuple[bool, str]:

    #Check if payload (+ 4-byte length header) fits in the cover image
    #at the given bit-depth. Returns (fits: bool, message: str).

    total_bytes = payload_size_bytes + 4  # +4 for the length header
    payload_bits = total_bytes * 8
    available_bits = cover_width * cover_height * channels * bits_per_channel

    if payload_bits > available_bits:
        return False, (
            f"Payload too large: needs {payload_bits} bits "
            f"(payload {payload_size_bytes}B + 4B header), "
            f"image only provides {available_bits} bits at {bits_per_channel}-bit LSB."
        )
    return True, f"OK: {payload_bits}/{available_bits} bits used."


#Byte-level LSB read/write


def embed_bits_in_byte(cover_byte: int, secret_bits: int, num_bits: int) -> int:
    #Replace the lowest `num_bits` of cover_byte with secret_bits.
    mask = get_lsb_mask(num_bits)
    cleared = cover_byte & ~mask & 0xFF
    return cleared | (secret_bits & mask)


def extract_bits_from_byte(stego_byte: int, num_bits: int) -> int:
    #Read back the lowest `num_bits` of stego_byte.
    return stego_byte & get_lsb_mask(num_bits)

#Start location derivation (FR7)
def derive_start_location(key: str, width: int, height: int, channels: int) -> int:
    """
    Derive a flat channel-index start location from a secret key.
    Deterministic: same key + same image dimensions -> same location,
    so the extractor can independently recompute it without it being
    stored anywhere in the stego file itself.

    Reserves room at the end for the length header + a reasonably sized
    payload by keeping the derived start within the first 80% of the
    image, so embedding rarely runs off the end for typical payloads.
    """
    digest = hashlib.sha256(key.encode()).digest()
    seed = int.from_bytes(digest[:8], "big")

    total_channels = width * height * channels
    usable_range = max(1, int(total_channels * 0.8))
    start_channel_index = seed % usable_range
    return start_channel_index


#Embed

def embed_payload(image_path: str, output_path: str, payload: bytes,
                   key: str, bits_per_channel: int = 1) -> None:
    """
    Embed `payload` bytes into the PNG at image_path, starting at a
    key-derived location, using `bits_per_channel` LSBs per channel.
    Saves the result (lossless) to output_path.
    """
    img = Image.open(image_path).convert("RGB")
    width, height = img.size
    channels = 3
    pixels = bytearray(img.tobytes())

    total_channels = width * height * channels

    # length header: 4 bytes, big-endian, so extractor knows payload length
    length_header = len(payload).to_bytes(4, "big")
    data_to_embed = length_header + payload
    bit_string = "".join(f"{byte:08b}" for byte in data_to_embed)

    fits, msg = check_capacity(width, height, channels, len(payload), bits_per_channel)
    if not fits:
        raise ValueError(msg)

    start_index = derive_start_location(key, width, height, channels)

    bit_pos = 0
    channel_index = start_index
    total_bits = len(bit_string)

    while bit_pos < total_bits:
        chunk = bit_string[bit_pos: bit_pos + bits_per_channel]
        if len(chunk) < bits_per_channel:
            chunk = chunk.ljust(bits_per_channel, "0")
        secret_bits = int(chunk, 2)

        idx = channel_index % total_channels
        pixels[idx] = embed_bits_in_byte(pixels[idx], secret_bits, bits_per_channel)

        channel_index += 1
        bit_pos += bits_per_channel

    stego_img = Image.frombytes("RGB", (width, height), bytes(pixels))
    stego_img.save(output_path, "PNG")  # PNG save is lossless, preserves exact pixel values

#Extract

def extract_payload(image_path: str, key: str, bits_per_channel: int = 1) -> bytes:

    #Extract and return payload bytes from a stego PNG, using the same key and bit-depth that were used to embed it.
   
    img = Image.open(image_path).convert("RGB")
    width, height = img.size
    channels = 3
    pixels = img.tobytes()

    total_channels = width * height * channels
    start_index = derive_start_location(key, width, height, channels)

    #read the 4-byte (32-bit) length header first
    header_bits_needed = 32
    bits = []
    channel_index = start_index
    while len(bits) * bits_per_channel < header_bits_needed:
        idx = channel_index % total_channels
        bits.append(extract_bits_from_byte(pixels[idx], bits_per_channel))
        channel_index += 1

    header_bit_string = "".join(f"{b:0{bits_per_channel}b}" for b in bits)[:header_bits_needed]
    header_bytes = int(header_bit_string, 2).to_bytes(4, "big")
    payload_length = int.from_bytes(header_bytes, "big")

    #read the payload itself
    payload_bits_needed = payload_length * 8
    bits = []
    while len(bits) * bits_per_channel < header_bits_needed + payload_bits_needed:
        idx = channel_index % total_channels
        bits.append(extract_bits_from_byte(pixels[idx], bits_per_channel))
        channel_index += 1

    full_bit_string = "".join(f"{b:0{bits_per_channel}b}" for b in bits)
    payload_bit_string = full_bit_string[:payload_bits_needed]

    payload_bytes = bytearray()
    for i in range(0, len(payload_bit_string), 8):
        byte_chunk = payload_bit_string[i:i + 8]
        payload_bytes.append(int(byte_chunk, 2))

    return bytes(payload_bytes)



#Quick test (run: python image_stego.py) for now, dont commit the generated png files please!

if __name__ == "__main__":
    # Create a small dummy cover image for testing
    test_img = Image.new("RGB", (50, 50), color=(120, 130, 140))
    test_img.save("test_cover.png")

    secret_message = b"Hello from INF2005 image stego test!"
    secret_key = "team-p1-4-secret-key"

    print("Capacity check:", check_capacity(50, 50, 3, len(secret_message), bits_per_channel=1))

    embed_payload("test_cover.png", "test_stego.png", secret_message, secret_key, bits_per_channel=1)
    print("Embedded ->", "test_stego.png")

    recovered = extract_payload("test_stego.png", secret_key, bits_per_channel=1)
    print("Recovered:", recovered)
    print("Match:", recovered == secret_message)

    #tamper test
    tampered = Image.open("test_stego.png").convert("RGB")
    pixels = bytearray(tampered.tobytes())
    pixels[0] = pixels[0] ^ 0xFF  #flip a byte outside the payload's likely region
    Image.frombytes("RGB", tampered.size, bytes(pixels)).save("test_stego_tampered.png")

    try:
        recovered_tampered = extract_payload("test_stego_tampered.png", secret_key, bits_per_channel=1)
        print("Tampered extraction result:", recovered_tampered)
        print("Still matches original?:", recovered_tampered == secret_message)
    except Exception as e:
        print("Tampered extraction failed as expected:", e)