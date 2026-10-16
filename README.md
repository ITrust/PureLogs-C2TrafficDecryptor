# PureLogs C2 Traffic Decryptor

Decrypts and deserializes the C2 traffic of PureLogs Stealer (stage 3 / `tray01.exe`) directly from a pcap capture.

Based on the analysis published by **ITrust CERT**: [PureLogs Stealer -- Analyse Malware](https://www.itrust.fr/purelogs-stealer-analyse-malware)

## How it works

The stage 3 binary uses **AES-128-CBC with PKCS7 padding** for its C2 communications. The static encryption key is embedded in the PE at a known offset (`<PrivateImplementationDetails>` field, RVA `0x2048`, file offset `0x248`), loaded via `InitializeArray` and stored in `tx67.axis340`.

Each C2 frame follows this structure:

```
[ length : uint32 LE ][ IV : 16 bytes cleartext ][ AES-128-CBC(payload) ]
```

The tool:

1. Parses the pcap and reassembles TCP streams (with retransmission handling).
2. Splits each stream into length-prefixed frames.
3. Decrypts each frame using the known static key.
4. Detects session key negotiation (handshake) and automatically uses derived session keys (AES-256) for subsequent frames.
5. Deserializes the custom binary protocol (tagged TLV: strings, integers, byte arrays, nested objects, dictionaries, lists, etc.).

## Requirements

- Python 3.8+
- `cryptography` library

```
pip install cryptography
```

## Usage

```
python decrypt_pcap.py <pcap_file> [options]
```

### Basic examples

Decrypt all C2 traffic from a capture:

```
python decrypt_pcap.py capture.pcap
```

Filter on a specific C2 port:

```
python decrypt_pcap.py capture.pcap --port 8080
```

Dump decrypted payloads to disk:

```
python decrypt_pcap.py capture.pcap --dump-dir ./output
```

Show raw hexdump instead of deserialized output:

```
python decrypt_pcap.py capture.pcap --raw
```

Extract the key from a different sample:

```
python decrypt_pcap.py capture.pcap --key-from-binary tray01.exe
```

### Options

| Option | Description |
|---|---|
| `pcap` | Path to the pcap file (required). pcapng is not supported; convert with `editcap -F pcap in.pcapng out.pcap`. |
| `--key HEX` | AES-128 key as a hex string. Default: `7B41C330B576FA8D0CE909C2B1E4D150` (extracted from the known sample). |
| `--key-from-binary PE` | Read the key directly from a PE binary instead of using the hardcoded value. |
| `--key-offset OFFSET` | File offset where the key is located in the binary. Default: `0x248`. Accepts hex (`0x...`) or decimal. |
| `--port PORT` | Only process TCP streams involving this port. Can be specified multiple times. |
| `--raw` | Display a hex dump of the decrypted plaintext instead of deserializing the payload. |
| `--dump-dir DIR` | Write each decrypted frame to a separate `.bin` file in the specified directory. |

## Output

For each TCP stream, the tool prints:

- Stream identification (source/destination IP and ports).
- Reassembly warnings if gaps are detected (which will likely corrupt decryption).
- Per-frame: IV, plaintext size, which key was used (static or session), and the deserialized payload structure.
- A final summary of successfully decrypted frames.

## Limitations

- Only reads classic pcap format. pcapng must be converted first.
- TCP reassembly is basic: it handles retransmissions and detects gaps, but does not handle out-of-order segments beyond sorting by sequence number.
- The hardcoded key corresponds to a specific PureLogs sample. Other samples may use a different key at a different offset; use `--key` or `--key-from-binary` accordingly.

## Authors

- **Samuel Raebisch** ([@SamuelRaebisch](https://github.com/sraebisch-itrust))
- **Alexis Duverneix** @AlexisDuverneix

**ITrust CERT** -- [itrust.fr](https://www.itrust.fr)

## License

See [LICENSE](LICENSE) for details.
