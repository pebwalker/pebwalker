+++
title = "Mean Girls: High School Showdown"
description = "Reverse engineering of an abandonware game whose only available copy is suspected of being used as a malware distribution vector. Unpacking, validating, debunking. And on Wednesdays we wear pink."
date = 2025-10-03
template = "article.html"

[extra]
image = "images/mean-girls.png"
logline = "Stop trying to make malware happen. It's not going to happen."
+++

## Introduction

**Mean Girls: High School Showdown** is a 2009 top-down RPG based on the classic teen comedy. It was developed by Ladyluck Digital Media and Legacy Interactive, and published by Paramount Digital Entertainment. Like many casual games from that era, it was built on Adobe Flash, wrapped in a native Windows executable using SWF Studio.

I love the movie Mean Girls. The game, on the other hand, looked plain bad even by 2009 casual game standards. I had no intention of playing it. So why download it?

The publisher is gone, the official download links are dead, and the only place to find it is [MyAbandonware](https://www.myabandonware.com/game/mean-girls-high-school-showdown-ius#download). The download is flagged on VirusTotal, and the filename itself is a warning: `Mean-Girls-High-School-Showdown_Win_EN_Infected-Setup-Use-Virtual-Machine.zip`. Someone, at some point, decided this file was suspicious enough to label it infected. That's what caught my attention.

Inspired by [Nathan Baggs](https://www.youtube.com/@NathanBaggs)' work on abandonware preservation, I wanted to find out: is the file actually infected? 

Proving that an executable is malicious is relatively straightforward. You find the bad behavior, you document it, you're done. Proving that an executable is *clean* is much harder. You have to demonstrate the absence of something, which means examining everything. That's what this article is about.

---

## The Installer

The zip contains a single file: `Mean Girls.exe`, a 107MB PE32 executable.

```
SHA256: c92128c1b1c274a987c39f3cb322876390864158e430a0fd926a97c5c27495d4
```

Opening it in IDA, the first thing that stands out is the PE structure:

```
Sections: 1
  kkrunchy  VA=0x00001000  VSize=0x00066E14  RawSize=0x0000F1F6  [CODE|INIT_DATA|EXEC|READ|WRITE]

Imports:
  KERNEL32.dll
    LoadLibraryA
    GetProcAddress
```

A single section with a 7:1 virtual-to-raw size ratio, and exactly two imports. This is textbook packer behavior.

> A **packer** compresses or encrypts an executable and prepends a stub that decompresses it at runtime. Malware uses them to evade AV signatures, but they're just as common in the game repacking scene, where tools like UPX and kkrunchy are used to shrink downloads.

Two imports means everything else is resolved dynamically at runtime. The virtual size is much larger than the raw size because the compressed data expands in memory. Static analysis of the unpacked code is impossible from this view alone.

### Identifying the packer

The section name gives it away: [kkrunchy](http://www.farbrausch.de/~fg/kkrunchy/) is a well-known executable packer from the demo scene, created by Farbrausch. It was designed to compress small demos and intros into tiny executables for competitions where file size matters. A string search confirms this further: at `0x3DFDD4`, there is an embedded XML manifest:

```xml
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity version="1.0.0.0" processorArchitecture="X86"
                    name="THETA.SFX.Manifest" type="win32"/>
  <description>THETA SFX</description>
  <!-- ... -->
</assembly>
```

THETA SFX is a self-extracting archive tool built on top of the kkrunchy packer. So the installer is not just packed, it's a self-extracting archive.

### What's inside

The PE image itself is only 66KB. The remaining 107MB is overlay data appended after the PE sections. A hexdump of the overlay start reveals the format:

```
$ hexdump -C overlay.bin | head
00000000  50 4b 03 04 00 00 00 00  00 00 52 61 72 21 1a 07  |PK........Rar!..|
00000010  00 3b d0 73 08 00 0d 00  00 00 00 00 00 00 4a 42  |.;.s..........JB|
00000020  7a 00 80 23 00 f0 02 00  00 88 09 00 00 02 79 0b  |z..#..........y.|
00000030  67 8e 00 00 00 00 1d 33  03 00 01 00 00 00 43 4d  |g......3......CM|
```

The `PK\x03\x04` at offset 0 is a ZIP local file header, but the `Rar!\x1a\x07` at offset 0x0A reveals the actual format: this is a RAR4 solid archive wrapped in a thin SFX header.

The RAR archive contains an HTML comment linking to `www.2baksa.net` and `www.Nowa.cc`, both Russian warez and repack sites.

Extracting the RAR yields the actual game files:

```
MeanGirls.exe   237 KB   Launcher
  SHA256: e29d5621142e020e31b88c8cb594608840433e0bc3453c0e98914d371c4ae419

MeanGirls.dat   27.9 MB  Game runtime (SWF Studio)
  SHA256: 1c979968335ef16d91a962b36567c9b748b7516fbf692c54f75fb71982407d8f

MeanGirls.ico   143 KB   Icon
  SHA256: ded77db6d68c0e3ca134c415ac10e373489de6c5f46d3e600fa200279f77c974

Uninstall.exe   38 KB    Uninstaller
  SHA256: fe4e000ca39f212f1dc0c5ff9155c63d0daaaee199822b845a3f4c20e2a68ca0

Assets/         ~80 MB   SWF game content (characters, movies, sounds, etc.)
```

### Decompiling the packer stub

The entry point at `0x3DE792` is the standard kkrunchy decompression stub. Decompiling it in IDA gives us the full picture:

```c
HMODULE *start()
{
  // ... kkrunchy decompression into loc_3EE1EC ...

  v16 = byte_3EE545;  // encoded import table
  while ( 1 )
  {
    v17 = (HMODULE **)(v16 + 1);
    result = *v17;             // pointer into IAT
    v16 = (const CHAR *)(v17 + 1);
    if ( !result )
      break;
    v19 = result;
    LibraryA = LoadLibraryA(v16);  // load DLL by name
    if ( !LibraryA )
      return (HMODULE *)((char *)LibraryA + 1);
    v21 = LibraryA;
    while ( 1 )
    {
      v16 += strlen(v16) + 1;
      if ( !*v16 )
        break;
      // resolve by ordinal or by name
      if ( *v16 < 0 )
        LibraryA = (HMODULE)GetProcAddress(v21, (LPCSTR)*(WORD*)(v16+1));
      else
        LibraryA = (HMODULE)GetProcAddress(v21, v16);
      *v19++ = LibraryA;  // fill IAT slot
      if ( !LibraryA )
        return (HMODULE *)((char *)LibraryA + 1);
    }
  }
  return result;
}
```

The structure is clear: iterate through a packed table of DLL names and function names at `byte_3EE545`, call `LoadLibraryA` for each DLL, resolve each function with `GetProcAddress`, and write the address into the Import Address Table. This is the standard kkrunchy import resolution loop and nothing more.

The packer stub does nothing beyond decompression and import resolution. There is no network activity, no file creation outside the expected extraction path, no registry manipulation.

### The uninstaller

`Uninstall.exe` (38 KB, PE timestamp February 8, 2008) uses the same kkrunchy packer as the installer: single PE section named `kkrunchy`, two-import IAT (`LoadLibraryA`, `GetProcAddress`), kkrunchy decompression stub. Its embedded XML manifest identifies it as `THETA.DU.Manifest` (THETA Dynamic Uninstaller), the companion to the THETA SFX installer.

The 17 KB overlay begins with the `DEADBEEF` magic number and `NullsoftInst` identifier, confirming it contains an [NSIS](https://nsis.sourceforge.io/) (Nullsoft Scriptable Install System) uninstall script. NSIS is an open-source, widely-used installer framework. The embedded script data is NSIS-compressed and handles standard file deletion: removing the extracted game files and the installation directory. There is no registry manipulation, no networking, and no persistence beyond what NSIS provides for standard uninstallation.

---

## The Launcher

`MeanGirls.exe` is a small Win32 GUI application compiled with Visual C++. Its import table includes `kernel32.dll` and `user32.dll`, with functions like `CreateProcessW`, `WaitForSingleObject`, `SetTimer`, and `CreateWindowExW`. There are no networking, registry, or injection APIs.

A string search reveals two interesting things:

- `svchostmngrlslnchr` at `0x40513C`
- `e:\svn\Mean Girls Launcher\Release\Clueless.pdb` at `0x405E18`

The PDB path tells us the project was originally named "Clueless" (another teen movie), developed in SVN, and compiled in Release mode. Legacy Interactive made several casual games based on TV and movie licenses, so this is likely a generic launcher template reused across titles.

### Decompilation

Decompiling `wWinMain` reveals everything the launcher does:

```c
int __stdcall wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                       LPWSTR lpCmdLine, int nShowCmd)
{
  GetFullPathNameW(L"Meangirls.dat", 0x1000u, &ApplicationName, &FilePart);
  memset(&StartupInfo, 0, sizeof(StartupInfo));
  memset(&ProcessInformation, 0, sizeof(ProcessInformation));
  StartupInfo.cb = 68;
  StartupInfo.wShowWindow = 5;        // SW_SHOW
  StartupInfo.dwFlags = 1;            // STARTF_USESHOWWINDOW
  CreateProcessW(&ApplicationName, L"Meangirls.dat",
                 0, 0, 0, 0, 0, 0,    // no special flags
                 &StartupInfo, &ProcessInformation);
  hHandle = ProcessInformation.hProcess;
  wcscpy(Destination, L"svchostmngrlslnchr");
  // ... register window class, create window, message loop ...
}
```

No suspicious creation flags. No `CREATE_SUSPENDED`. No debug privileges. Just a straightforward `CreateProcessW`.

The window creation is equally straightforward:

```c
HWND __cdecl sub_401000(HINSTANCE hInstance)
{
  HWND result = CreateWindowExW(0, &ClassName, Destination,
                                0xCF0000, // WS_OVERLAPPEDWINDOW
                                0x80000000, 0, 0x80000000, 0,
                                0, 0, hInstance, 0);
  if ( result )
  {
    ShowWindow(result, 0);             // SW_HIDE, window is invisible
    UpdateWindow(result);
    SetTimer(result, 1, 0x64, 0);      // 100ms timer
  }
  return result;
}
```

And the window procedure is where we find the watchdog logic:

```c
LRESULT __stdcall WndProc(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
{
  if ( Msg == WM_TIMER ) {             // 275
    if ( !WaitForSingleObject(hHandle, 0) ) {  // child exited?
      KillTimer(hWnd, 1);
      PostQuitMessage(0);              // launcher exits too
    }
    return 0;
  }
  if ( Msg == WM_CLOSE || Msg == WM_DESTROY ) {
    if ( hHandle )
      TerminateProcess(hHandle, 0);    // kill child on close
    PostQuitMessage(0);
    return 0;
  }
  return DefWindowProcW(hWnd, Msg, wParam, lParam);
}
```

That's it. The launcher is a process watchdog. It exists because the game runtime (MeanGirls.dat) apparently needs a parent process alive to function correctly. The hidden window serves only as a message pump for the timer, and `svchostmngrlslnchr` is its window title, not a process name. It never appears in the task manager or process list.

Still, the name is unfortunate. Any AV scanning window titles would see a string containing "svchost" and flag it as suspicious. A poor choice by the developer, but not malicious.

---

## The Game Runtime

Despite the `.dat` extension, `MeanGirls.dat` is the actual game. It is a 27.9 MB PE32 executable that contains the entire runtime: the application logic, the Flash Player engine, and all the protection layers. The launcher is just a watchdog; this is the binary that does everything. Parsing its PE sections reveals something unusual:

```
Image base: 0x400000
Entry point: 0x5A1353
Sections: 6
  0 ext   VA=0x00001000  VSize=0x0012BD80  RawSize=0x00046000  [EXEC|READ]
  1 ata   VA=0x0012D000  VSize=0x000094F8  RawSize=0x00000000  [EXEC|READ|WRITE]
  2 src   VA=0x00137000  VSize=0x00067508  RawSize=0x00068000  [EXEC|READ|WRITE]
  3 ext   VA=0x0019F000  VSize=0x00011870  RawSize=0x0000C000  [EXEC|READ|WRITE]
  4 data  VA=0x001B1000  VSize=0x00001102  RawSize=0x00002000  [EXEC|READ|WRITE]
  5 ata   VA=0x001B3000  VSize=0x00007A24  RawSize=0x00002000  [EXEC|READ|WRITE]

PE code ends at:  0xBF000 (782 KB)
Overlay data:     27.1 MB (97.2% of file)
```

Despite its size, only 2.8% of the file is actual code. The rest is overlay data containing embedded Flash runtime DLLs, SWF game files, and assets. IDA identifies only 45 functions.

> **SWF Studio** wraps Flash games into standalone Windows executables. The native binary is a thin shell: it embeds the Flash Player runtime as DLLs, hosts it as an ActiveX control, and bridges OS calls to the Flash VM through `ExternalInterface`. The game logic is stored in SWF files, compiled ActionScript bytecode bundled as overlay data.

This is a textbook example: 45 native functions driving a 27MB binary, because almost everything happens inside Flash. The section names are truncated fragments (`0 ext`, `1 ata`, `2 src`), which hints at a PE packer or virtualizer stripping the original names. This is where things get interesting.

### The static imports

The PE import table includes some APIs that immediately catch the eye:

- `WriteProcessMemory` and `ResumeThread` from `kernel32.dll`
- `RegCreateKeyA` and `RegSetValueA` from `advapi32.dll`
- `CoRegisterClassObject` from `ole32.dll`

WriteProcessMemory and ResumeThread together are classic indicators of process injection: create a suspended process, write code into it, then resume execution. If these were actively used, this would be a problem.

Tracing cross-references to their IAT entries in IDA shows **zero xrefs**: no code in the visible (unencrypted) portions of the binary calls these functions. That alone is not conclusive, since most of the PE sections are still encrypted at this point. The encrypted code could theoretically reference them after decryption. To know for sure, I need to find how the runtime actually resolves its APIs.

### The dynamic imports

The real import table is hidden. The entry point function `sub_5A0C10` (the entry point `0x5A1353` lies within it) decrypts an entire PE section using a linear congruential generator. Here is the XOR loop in assembly:

```nasm
loc_5A0C7C:
  imul    esi, 19660Dh           ; esi = 1664525 * esi
  mov     ebx, [ecx]             ; read encrypted dword
  add     esi, 3C6EF375h         ; esi += 1013904245
  xor     ebx, esi               ; decrypt
  mov     [ecx], ebx             ; write decrypted dword
  add     ecx, 4                 ; next dword
  cmp     ecx, eax               ; end of section?
  jb      short loc_5A0C7C       ; loop
```

The constants `0x19660D` (1664525) and `0x3C6EF375` (1013904245) are the LCG parameters from Knuth's *The Art of Computer Programming*. After decryption, the integers decode to null-terminated ASCII strings:

```
00000000  42 41 52 49 45 52 00 56  69 72 74 75 61 6c 41 6c  |BARIER.VirtualAl|
00000010  6c 6f 63 00 43 72 65 61  74 65 54 68 72 65 61 64  |loc.CreateThread|
00000020  00 50 6f 73 74 4d 65 73  73 61 67 65 41 00 44 65  |.PostMessageA.De|
00000030  66 57 69 6e 64 6f 77 50  72 6f 63 41 00 45 6e 75  |fWindowProcA.Enu|
00000040  6d 57 69 6e 64 6f 77 73  00 44 65 73 74 72 6f 79  |mWindows.Destroy|
```

113 API names covering file I/O, window management, memory allocation, graphics, process management, and COM. Standard functionality for a desktop application runtime. `OpenProcess` is present but commonly used for legitimate process management.

This table is also exhaustive. The XOR decryption routine (`sub_5A0C10`, detailed below) is the only import resolution path in the binary: it decrypts the table, resolves every name via `GetProcAddress`, and writes the results into a fixed-size function pointer array. There is no secondary resolution loop, no hash-based API lookup, and no fallback mechanism. The routine also verifies the integrity of the decrypted section with a checksum; any modification to the table causes `RaiseException(0xEF0000FA)` and a crash. Combined with the zero xrefs to the static IAT entries for `WriteProcessMemory` and `ResumeThread`, this closes both resolution paths: neither the static imports nor the dynamic imports provide access to injection APIs.

The table also contains internal strings that reveal the actual protection layer:

```
molebox2/bootup/mbx_DLL.cpp
MBX@%X@*.###
MBX@%X@%X.###
:BOX:ReadCompressedSection: decompresion failed with code %d
:API:NopeFunc
BARIER
kernel32
ntdll.dll
```

The source path `molebox2/bootup/mbx_DLL.cpp` identifies this as [MoleBox v2](https://sudachen.github.io/Molebox/), a commercial PE virtualizer by Teggo Systems. SWF Studio v3 uses MoleBox to protect its runtime binary: the sections are encrypted and compressed, DLLs are embedded in the overlay, and everything is unpacked at startup through a multi-layer bootstrap. The `MBX` prefix in the DLL naming pattern (`MBX@{PID}@{ADDR}.###`) stands for **M**ole**B**o**x**. The `BARIER` sentinel marks the start of the API name table.

---

## Cracking the protection

### The XOR decryption

MoleBox means the sections of `MeanGirls.dat` are encrypted. To determine what the runtime actually does, I need to decrypt them. The entry point function (`sub_5A0C10`) applies the same LCG-XOR loop (identified in the dynamic imports section) to two PE sections, then decompresses each with LZSS and verifies integrity with a checksum. The full sequence reimplemented in Python:

```python
import struct

def lcg_xor_decrypt(data, offset, size, seed):
    """XOR-decrypt a PE section using the MoleBox LCG."""
    result = bytearray(data[offset:offset + size])
    for i in range(0, len(result) & ~3, 4):
        seed = (1664525 * seed + 1013904245) & 0xFFFFFFFF
        dword = struct.unpack_from('<I', result, i)[0]
        struct.pack_into('<I', result, i, dword ^ seed)
    return bytes(result)

def verify_and_decompress(decrypted):
    """
    After decryption, the section header contains:
      +0x00: expected decompressed size
      +0x04: compressed size
      +0x08: expected checksum
      +0x0C: compressed data starts here
    """
    expected_size = struct.unpack_from('<I', decrypted, 0)[0]
    compressed_size = struct.unpack_from('<I', decrypted, 4)[0]
    expected_crc = struct.unpack_from('<I', decrypted, 8)[0]
    decompressed = lzss_decompress(decrypted[12:12 + compressed_size], expected_size)
    if crc32(decompressed) != expected_crc:
        raise RuntimeError("0xEF0000FA: checksum mismatch")
    return decompressed

# Phase 1: decrypt the .data section (yields the import table shown above)
data_section = lcg_xor_decrypt(raw, data_offset, data_size, image_base + rva)

# Phase 2: decrypt and decompress the .text section (yields 64 KB of bootstrap code)
text_section = lcg_xor_decrypt(raw, text_offset, text_size, caller_addr)
bootstrap = verify_and_decompress(text_section)
```

The exception codes used for integrity checks (`0xEF0000FE`, `0xEF0000F8`, `0xEF0000FA`) are custom values in the MoleBox-reserved range. These are anti-tampering checks: they prevent modified binaries from running, which is standard commercial software protection.

### The IDEA cipher

After `sub_5A0C10` decrypts and decompresses the bootstrap, it calls `FlushInstructionCache` and transfers control to the MoleBox initialization function `loc_5A1650`. This function stores a second set of LCG constants, `0x19660D` and `0x3C6EF35F`, distinct from the Knuth constants used in the previous XOR phase. It then copies 64 bytes from the now-decompressed bootstrap and decrypts them using a block cipher. The key schedule at `sub_5A4C20` reads 8 big-endian 16-bit words and expands them via 25-bit rotation of the 128-bit key state:

```nasm
; sub_5A4C20 — IDEA key expansion (25-bit rotation via word pairs)
5A4C33  movzx    di, byte ptr [eax]      ; high byte of key word
5A4C37  movzx    bx, byte ptr [eax + 1]  ; low byte
5A4C3C  shl      edi, 8
5A4C3F  add      edi, ebx                ; word = big-endian 16-bit value
```

The block cipher at `sub_5A4EE0` operates on 64-bit blocks using multiplication mod 2^16+1, addition mod 2^16, and XOR, with 8 rounds and a 4-operation output transformation. The characteristic modular multiplication confirms this is **IDEA** (International Data Encryption Algorithm):

```nasm
; sub_5A4EE0 — IDEA multiplication mod 2^16+1
5A4F4F  imul     edx, edi           ; 32-bit multiply
5A4F54  shr      edi, 10h           ; high 16 bits
5A4F57  cmp      dx, di             ; low vs high
5A4F5A  sbb      ebx, ebx           ; borrow flag → carry
5A4F5C  neg      ebx
5A4F5E  sub      ebx, edi           ; result = low - high + carry
5A4F60  add      ebx, edx
```

> **IDEA** is a symmetric block cipher designed by Xuejia Lai and James Massey in 1991. It was used in early versions of PGP and was considered a strong alternative to DES throughout the 1990s.

The decrypted 64-byte metadata block contains the MoleBox header:

```
[0x00] 0x004013D8    Original Entry Point
[0x04] 0x00400000    Image base
[0x08] 0x0012CAA4    Decompressed runtime size
[0x10] 0x00000001    Compression flags (bitmask per section)
[0x14] 0x00000003    Encryption flags (bitmask per section)
[0x2C] 0x005A13E4    MoleBox directory pointer
```

The pointer at offset 0x2C drives a final XOR pass using the MoleBox LCG, decrypting a 512-byte directory. This directory contains a single virtual file entry:

```
[0x20]  05 E1 55 FE 72 E5 BB 3A CC F6 78 40 54 F1 2E B9   ← 16-byte IDEA key
[0x30]  70 6C 61 79 65 72 2E 42 4F 58 00                   ← "player.BOX"
```

### The section pipeline

The metadata flags at offsets 0x10 and 0x14 indicate which PE sections need zlib decompression and IDEA decryption. Two IDEA code paths exist, distinguished by their subkey selection:

```nasm
; sub_5A4EB0 — metadata decryption (ENCRYPT subkeys at context base)
5A4EC2  push     edi                    ; context + 0x00 (encrypt subkeys)

; sub_5A5170 — section/overlay decryption (DECRYPT subkeys at context + 0x68)
5A5182  lea      eax, [edi + 0x68]      ; context + 0x68 (decrypt subkeys)
5A5185  push     eax
```

The metadata uses forward IDEA (encrypt subkeys on ciphertext). Sections and overlay data use inverse IDEA (decrypt subkeys). The IDEA key for both comes from the directory entry's 16-byte hash (`05e155fe...`). After IDEA decryption, the main `.text` section is zlib-inflated (standard `78 9C` header) to produce 1,228,800 bytes of decompressed runtime code.

### The overlay

The overlay (27.1 MB at file offset 0xBF000) has three regions. At the front is the MoleBox-packaged Flash Player DLL (`player.BOX`): about 1.6 MB of IDEA-encrypted, zlib-compressed chunks that inflate to the ~3 MB DLL. Near the tail are two MoleBox helper executables and the application icon, stored as unencrypted zlib streams. Between them sits the bulk of the overlay, roughly 25 MB: SWF Studio's attached-files container, which holds the game's own content under its own encryption. That scheme is separate from MoleBox and resisted every static attack I threw at it; I open it later, [under a debugger](#inside-the-encrypted-container). The overlay header describes the `player.BOX` chunking:

```
[0x00]  2,886,950     Total decompressed size
[0x04]  41            TOC entry count
[0x08]  41 DWORDs     TOC (entries 0-1: trailing chunk sizes,
                           entries 2-5: 16-byte IDEA key hash,
                           entries 6-40: 35 main chunk sizes)
[0xAC]  11 DWORDs     Continuation chunk sizes
[0xD8]  ...           IDEA-encrypted chunk data
```

### Extracting the Flash Player DLL

My initial approach, applying IDEA ECB as one continuous stream across the entire overlay, produced only 9 valid zlib chunks (576 KB). The breakthrough came from reversing the MoleBox bootstrap function `sub_5A37F0`, which revealed that each chunk is decrypted with a **fresh IDEA context**:

```nasm
; sub_5A37F0 — overlay chunk reader
5A3909  mov      eax, [0x5B5734]         ; IDEA metadata buffer
5A390E  mov      ecx, [eax + 0x2C]      ; directory pointer
5A3911  add      ecx, 0x20              ; IDEA key at directory + 0x20
5A3914  push     ecx
5A391B  call     sub_5A4BF0             ; ← fresh IDEA key init PER CHUNK
5A3920  mov      edx, [ebx]
5A3927  shr      edx, 3                 ; size / 8 = IDEA block count
5A3932  call     sub_5A5170             ; IDEA decrypt (inverse subkeys)
```

With per-chunk IDEA and the TOC-defined chunk boundaries, the first 35 entries (TOC indices 6-40) immediately decoded. But 35 chunks only covered the `.text` section. The remaining PE sections were missing.

Tracing the call sites of `sub_5A5170` (IDEA decrypt) in the bootstrap confirmed there is **no key rotation**: all three callers use the same key (`[metadata+0x2C]+0x20`). The issue was not cryptographic but structural. `player.BOX` is split across two chunk groups, followed by a third group that turns out not to belong to the DLL:

```
Group 1:  35 main chunks        TOC entries 6-40      1,260,425 bytes compressed
Group 2:  11 continuation chunks   DWORDs at 0xAC       330,033 bytes compressed
Group 3:   2 trailing chunks    TOC entries 0-1         24,801 bytes compressed
```

Per-chunk IDEA ECB decryption followed by zlib decompression across Groups 1 and 2 (**46 chunks**) reconstructs the **complete** Flash Player DLL. Group 3's two chunks decrypt to non-zlib data; they are not part of `player.BOX` but the leading bytes of the ~25 MB attached-files container that fills the rest of the overlay. The 46 chunks yield:

```
flash_player.dll  2,991,890 bytes  Adobe Flash Player 9.0.124.0
  SHA256: 2f109a342bac580c1440526f63b794ee5d43b16a8f4d18c5bf3ab1f2d73d6047

  .text    2,355,200 bytes  FULL
  .rdata     286,720 bytes  FULL
  .data      200,704 bytes  FULL
  .rodata      4,096 bytes  FULL
  .rsrc       53,248 bytes  FULL
  .reloc      81,920 bytes  FULL

  PE timestamp: 2008-03-25 02:32:30 UTC
  Version: WIN 9,0,124,0
  Certificate: Adobe Systems Incorporated
```

The complete extraction pipeline chains seven layers:

1. **LCG-XOR** (Knuth constants) on the `.text` and `.data` sections
2. **LZSS** decompression of the XOR-decrypted sections
3. **IDEA** encryption (forward subkeys) on the 64-byte metadata block
4. **MoleBox LCG-XOR** (modified constant `0x3C6EF35F`) on the 512-byte directory
5. **IDEA** decryption (inverse subkeys) on PE section raw data + **zlib inflate**
6. **Per-chunk IDEA** decryption (inverse subkeys, fresh context) on overlay data + **zlib inflate**
7. **Unencrypted zlib** streams in the overlay tail (icon, MoleBox runtime DLLs)

All seven layers are implemented in a Python script that executes statically on the raw binary with no debugger required:

```
$ python3 dump_swfstudio.py MeanGirls.dat dumped/

--- Layer 1: Embedded section table ---
  [0] .text   VA=0x001000  Raw=0x046000
  [1] .data   VA=0x12D000  Raw=0x000000
  [2] .rsrc   VA=0x000000  Raw=0x068000
  [3] .text   VA=0x19F000  Raw=0x00C000
  [4] .rdata  VA=0x1B1000  Raw=0x002000
  [5] .data   VA=0x1B3000  Raw=0x002000

--- Layer 2: Decrypt .data section (import table) ---
  479 strings (113 Win32 API names, DLL names, sentinels, debug messages)

--- Layer 3: Decrypt .text section (bootstrap) ---
  64,590 bytes decompressed

--- Layer 4: IDEA decrypt metadata ---
  OEP: 0x004013D8, Image base: 0x00400000
  Compression flags: 0x1, Encryption flags: 0x3

--- Layer 5: Decrypt MoleBox directory ---
  Virtual file: player.BOX
  IDEA key: 05e155fe72e5bb3accf6784054f12eb9

--- Layer 6: Decompress PE sections ---
  .text [IDEA+zlib]: 1,228,800 bytes
  .rsrc:               425,984 bytes

--- Layer 7: Overlay extraction ---
  player.BOX: 46 chunks, 2,991,890 bytes (Flash Player 9.0.124.0)
  tail_file_0.ico:   143,245 bytes (icon)
  tail_file_1.exe:    41,600 bytes (MoleBox launcher)
  tail_file_2.exe:    53,888 bytes (MoleBox cleanup handler)
```

### The MoleBox runtime DLLs

The overlay also contains two MoleBox helper executables and the application icon, stored as unencrypted zlib streams near the overlay tail.

The first helper (41 KB) is a trivial process launcher: its entire `main` function concatenates argv, calls `CreateProcessA`, and waits. The second (53 KB) handles MoleBox cleanup, and its exit routine deserves close inspection because it uses process injection.

On exit, `sub_4019D0` creates `explorer.exe` as a suspended process, writes an 84-byte shellcode stub into the child's stack, redirects EIP to it, and resumes execution. The shellcode (`sub_401BE0`) is small enough to read in full:

```nasm
; MoleBox self-deletion shellcode (injected into explorer.exe)
push    esi
mov     esi, [esp + 8]              ; esi = data structure with function pointers
push    -1                          ; INFINITE
mov     eax, [esi + 0x204]          ; process handle (of the MoleBox process)
push    eax
call    [esi + 0x208]               ; WaitForSingleObject(hProcess, INFINITE)
push    ecx                         ;   → waits until MoleBox process exits
call    [esi + 0x20C]               ; CloseHandle(hProcess)
lea     edi, [esi + 0x228]          ; edi = path to MBX@*.### temp file
retry:
push    edi
call    [esi + 0x210]               ; DeleteFileA(path)
test    eax, eax
jne     done                        ; deleted successfully
push    0x3E8                       ; 1000 ms
call    [esi + 0x214]               ; Sleep(1000) — file might still be locked
push    edi
call    [esi + 0x210]               ; DeleteFileA(path) — retry
test    eax, eax
je      retry                       ; keep trying until deleted
done:
push    0
call    [esi + 0x218]               ; ExitProcess(0)
```

Injecting code into `explorer.exe` is an aggressive technique, and it is understandable that AV heuristics flag it. But the purpose here is mundane: the MoleBox DLL cannot delete itself while loaded in the game's process, so it delegates cleanup to another process. The injected code calls only `WaitForSingleObject`, `CloseHandle`, `DeleteFileA`, `Sleep`, and `ExitProcess`. It waits for the game to exit, deletes the temporary files, and terminates. There is no networking, no persistence, no privilege escalation. A less alarming approach would have been to write a batch file or use `MoveFileEx` with `MOVEFILE_DELAY_UNTIL_REBOOT`, but MoleBox chose process injection instead.

At runtime, MoleBox extracts these helpers to `%APPDATA%\.#\` as `MBX@{PID}@{ADDR}.###`, with `FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM` to prevent accidental deletion during the session.

### The VB6 runtime

The decompressed `.text` section contains zero native x86 functions. Instead, it holds 1,176 twelve-byte trampolines and their associated method descriptors. Each trampoline loads a pointer to a method descriptor into EDX and jumps into the VB6 bytecode interpreter:

```nasm
BA <desc_addr>   ; MOV EDX, method_descriptor   (5 bytes)
B9 70 13 40 00   ; MOV ECX, 0x00401370          (5 bytes)
FF E1            ; JMP ECX                      (2 bytes)
```

None of these trampolines contain application logic. They are dispatch stubs: the jump target `0x401370` is an IAT stub for **MSVBVM60.DLL** (the Visual Basic 6 runtime), which reads the method descriptor from EDX, locates the corresponding p-code bytecodes, and interprets them. The actual application logic is encoded as p-code, stored immediately before each method descriptor in the same section. SWF Studio is a VB6 p-code application. The VB5! header at `0x40243C` (passed to `ThunRTMain` at the OEP) points to an object table with 10 top-level objects, but the actual runtime contains **70 VB6 classes** with 1,176 methods total.

I obtained MSVBVM60.DLL from a Windows VM and analyzed `ProcCallEngine` (the p-code interpreter, exported at RVA 0x108BF1). The setup code revealed how ESI (the p-code instruction pointer) is derived from EDX (the method descriptor pointer set by the thunk):

```nasm
; ProcCallEngine setup — ESI derivation
66108C25  mov      ebx, edx               ; ebx = method descriptor (from thunk)
66108CE0  movzx    esi, word ptr [ebx + 8] ; esi = pcode_offset (desc field at +0x08)
66108CE4  neg      esi                    ; negate
66108CE6  add      esi, ebx              ; ESI = descriptor - pcode_offset
66108CF0  mov      al, [esi]             ; read first opcode
66108CF2  inc      esi                   ; advance ESI
66108CF3  jmp      [eax*4 + 0x6610AA24]  ; dispatch through 256-entry table
```

The p-code is stored **immediately before** each method descriptor in memory: `ESI = descriptor_addr - WORD(descriptor + 8)`. The `WORD` at descriptor offset 8 gives the distance in bytes from the p-code start to the descriptor.

The dispatch table has 256 entries, but the last five (`0xFB` through `0xFF`) are **lead bytes**: each prefixes a second byte to form a 2-byte opcode, dispatched through its own sub-table. This gives the VB6 VM over 1,500 possible opcodes across five extended pages. Using the [VB-Decompiler.org opcode reference](https://www.vb-decompiler.org/vb_pcode_table.htm) for mnemonic names and operand sizes, I built a disassembler that decodes all 1,176 methods into readable mnemonics. Here is XBitOps method 0 (a bit-masking function):

```
ILdI2              12      ; load int16 variable at stack offset 12
LitI2             255      ; push literal 255
AndI4                      ; bitwise AND
CUI1I2                     ; convert unsigned byte to int16
FStUI1           -134      ; store unsigned byte at stack offset -134
ExitProcUI1                ; return
```

The disassembler decodes 108,100 instructions across all 1,176 methods.

#### What the p-code does

Across all 1,176 methods, every instruction falls into one of six categories: variable loads and stores (`ILdRf`, `FStStr`, `FStR4`), literal values (`LitI4`, `LitStr`), COM method dispatch (`ImpAdCallI2`, `VCallHresult`), type conversions (`CI2I4`, `CStrVar`), control flow (`BranchF`, `Branch`, `OnErrorGoto`), and arithmetic/string operations (`AddI4`, `ConcatStr`). Every single method call goes through COM dispatch opcodes that route through the VB6 runtime's virtual method table, not direct Win32 API calls. There are no `DllFunctionCall` patterns (VB6's `Declare Function` mechanism for calling Win32 APIs directly), no inline assembly, no shellcode construction.

The import table constrains what APIs are reachable (no networking, no code injection), and the decoded p-code confirms the mechanism: every method call is mediated through the VB6 COM dispatch layer, not through direct Win32 calls.

#### The 70 VB6 classes

Using the ObjectInfo back-pointers embedded in each method descriptor, I mapped all 1,176 methods to their parent classes. The class names are stored in the object public descriptor array at `0x4176E0`. The complete class inventory:

- **Flash/Media** (5 classes, 129 methods):
  - `MFlash`
  - `XFlash`
  - `MXPlayer`
  - `MPlayer`
  - `MMCI`
- **Window/UI** (14 classes, 255 methods):
  - `XWindow`
  - `MWin`
  - `MLayout`
  - `MPopup`
  - `MTray`
  - `MTooltip`
  - `MKeyboard`
  - `MMouse`
  - `MDesktop`
  - `MSplash`
  - `MTransparent`
  - `MMask`
  - `MGuides`
  - `MWndProcs`
- **File/IO** (9 classes, 177 methods):
  - `XFileSys`
  - `XString`
  - `XBitOps`
  - `XByteStr`
  - `MConsole`
  - `MStdOut`
  - `MScript`
  - `XRegistry`
  - `MRegistry`
- **System** (8 classes, 111 methods):
  - `MSysInfo`
  - `MSysTools`
  - `XWinVer`
  - `XProcess`
  - `MShell`
  - `XShellLnk`
  - `MLaunch`
  - `MReboot`
- **Application core** (7 classes, 186 methods):
  - `MMain`
  - `MDispatch`
  - `MEvents`
  - `MApp`
  - `MCore`
  - `MObjects`
  - `MActiveX`
- **Security/Anti-tamper** (7 classes, 60 methods):
  - `MAntiHack`
  - `MHack`
  - `MSentry`
  - `MSecurity`
  - `MCrypto`
  - `XCrypto`
  - `MHooks`
- **Graphics** (2 classes, 31 methods):
  - `XPEFile`
  - `XFont`
- **Networking** (3 classes, 19 methods):
  - `MServer`
  - `XProxy`
  - `MMonikers`
- **Utility** (15 classes, 208 methods):
  - `XUtility`
  - `MUtil`
  - `XMarshall`
  - `MCustom`
  - `MPlugins`
  - `MTest`
  - `MScratch`
  - `XTree`
  - `XShim`
  - `XUnicode`
  - `MPrinter`
  - `MIntervals`
  - `MClipboard`
  - `XZLib`
  - `MCompress`

Several of these class names look suspicious in isolation. `XProcess`, `MShell`, `MLaunch`, and `MServer` sound like they could be used for malicious purposes, and `MAntiHack`, `MHack`, and `MSentry` sound like active exploitation tools. I decoded every method of all seven classes. In context, they are standard SWF Studio v3 framework classes: their p-code contains only property access, type conversions, COM dispatch calls, string operations, and error handling.

`MServer` is a local HTTP server for serving SWF content to the embedded Flash Player ActiveX control. `XProcess`, `MShell`, and `MLaunch` are wrappers around `CreateProcessA` for features like "open URL in browser" or "launch external application," exposed to ActionScript game developers through the `ssCore` API. `MAntiHack`, `MHack`, and `MSentry` are anti-tampering protection for the commercial wrapper itself, preventing reverse engineering of SWF Studio.

Whether any of these classes are actually invoked depends on the Flash game content.

The largest method belongs to `MDispatch` (5,592 bytes of p-code, 2,120 instructions): a central event dispatcher with branch logic that routes SWF Studio API calls to the appropriate handler class.

### COM registration

At runtime, the binary registers COM interfaces for the Flash Player ActiveX control:

```
RegCreateKeyA(HKCU, "Software\Classes\Interface\{d27cdb6d-ae6d-11cf-96b8-444553540000}")
RegSetValueA("ProxyStubClsid32", "{00020420-0000-0000-C000-000000000046}")
```

> **COM registration** writes GUID-to-DLL mappings into the Windows registry so the OS can locate and instantiate COM components. Any application embedding an ActiveX control, like Flash Player, needs to register the control's interfaces before using it. These registry writes are routine plumbing, not persistence.

The first GUID is the Flash control's `_IShockwaveFlashEvents` interface (registered under `Interface\`; the `Shockwave Flash Object` coclass itself is the sibling GUID ending `…6E`). The second is the standard OLE Automation (IDispatch) proxy stub, set as that interface's `ProxyStubClsid32`. This registration happens under `HKEY_CURRENT_USER`, not `HKLM`, so it doesn't require elevation. This is completely standard behavior for any application embedding Flash Player as an ActiveX control.

---

## Dynamic behavior

Static analysis can only tell us what the code *could* do. To see what it *actually* does, I ran it in a VM and hooked the Windows API calls at runtime.

In IDA's debugger, I set conditional logging breakpoints on key Win32 API functions: `CreateDirectoryA`, `SetFileAttributesA`, `RegCreateKeyA`, `RegSetValueA`, `CreateFileA`, `CreateFileW`, `GetProcAddress`, `LoadLibraryA`, and `GetModuleFileNameW`. Each breakpoint logs its arguments and return value without pausing execution, so the game runs normally while I record every interesting system call it makes:

```
GetProcAddress(77140000,"CreateFileW")
GetProcAddress(77140000,"CreateFileMappingW")
GetProcAddress(77140000,"LoadLibraryA")
GetProcAddress(77140000,"MapViewOfFile")
GetProcAddress(77140000,"ReadFile")
GetProcAddress(77140000,"VirtualAlloc")
GetProcAddress(77140000,"VirtualProtect")
GetProcAddress(77140000,"WriteFile")
CreateDirectoryA("C:\Users\...\AppData\Roaming\.#")
SetFileAttributesA("C:\Users\...\AppData\Roaming\.#", attr=00000006)
6A9D0000: loaded C:\USERS\...\APPDATA\ROAMING\.#\MBX@13B8@A092828.###
RegCreateKeyA(h=80000001, subkey="...\{d27cdb6d-ae6d-11cf-96b8-444553540000}")
RegSetValueA(data="{00020420-0000-0000-C000-000000000046}")
30000000: loaded C:\USERS\...\APPDATA\ROAMING\.#\MBX@13B8@A0927F8.###
6E0F0000: loaded C:\WINDOWS\SyCHPE32\WININET.dll
74070000: loaded C:\WINDOWS\SysWOW64\WS2_32.dll
```

This approach has a limitation: it only captures calls that the application makes directly through the hooked APIs. Activity inside loaded DLLs (Flash Player, OLE runtime), kernel-level operations, and any API not explicitly hooked is invisible. A syscall-level trace using API Monitor, ETW, or Procmon would be more comprehensive. I chose selective hooking because these specific APIs are the ones whose use (or absence) determines whether the behavioral AV flags are justified.

Two entries stand out. First, `CreateDirectoryA("C:\Users\...\AppData\Roaming\.#")` followed by `SetFileAttributesA` with `FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM`. A hidden directory in AppData with the SYSTEM flag is exactly the kind of thing AV behavioral heuristics flag. But the naming pattern `MBX@{PID}@{ADDRESS}.###` is MoleBox's convention for its runtime DLLs, analyzed in full in "The MoleBox runtime DLLs" section above. These are session-scoped temp files, not persistence mechanisms.

Second, `WININET.dll` and `WS2_32.dll` appear in the loaded modules list, which is alarming for a game with no network capability. But these are transitive dependencies: `OLEAUT32.dll` pulls in `urlmon.dll`, which pulls in `WININET.dll`. Flash Player's COM registration uses OLE Automation, which triggers this chain. No application code ever calls a network function.

---

## The Flash content

Static analysis of the native code only covers the C/C++ shell. The actual game logic lives in the SWF files in the `Assets/` directory. If malware were hiding here, this is a natural place for it. To rule this out, I need to validate the Flash content independently.

### Heuristic scan

The extracted `Assets/` directory contains 73 SWF files across characters, cutscene movies, and particle effects. As a first pass, I wrote a tag-level scanner that decompresses each SWF, walks the binary tag stream, and checks for known attack patterns: PE/ELF headers in `DefineBinaryData` tags, x86 NOP sleds and shellcode prologues, malformed `DefineBitsJPEG3` alpha offsets (CVE-2013-0634 and similar), and suspicious ActionScript API references in `DoABC2` bytecode. It flagged nothing: 73/73 clean, zero `DefineBinaryData` tags across the entire set.

But heuristic scanning can only catch what it already knows to look for. Obfuscated ActionScript, custom-encoded payloads, or novel exploit techniques would sail right through. To actually understand what this code does, I need to read it.

### Parsing the ABC constant pools

Every `DoABC2` tag contains AVM2 bytecode, and every AVM2 bytecode block starts with a constant pool. The constant pool holds *every* string the bytecode can reference: class names, method names, string literals, namespace URIs. If the code calls `Socket.connect()`, the string `Socket` must appear in the pool. If it constructs a `URLRequest`, that string must be there. There is no way around this; the AVM2 instruction set references strings by pool index. Parsing the constant pool gives us the complete vocabulary of the code.

70 of the 73 SWFs contain a `DoABC2` tag (the other 3 are pure graphics with no code).

> `DoABC2` is a SWF file tag (tag type 82) that embeds compiled ActionScript 3 bytecode for the AVM2 virtual machine. It replaced the older `DoABC` tag in Flash Player 9.0.124.0, adding a name field and a lazy-initialization flag. Every ActionScript class, function, and expression in a Flash application is compiled into one of these tags.

The bytecodes are small: 692 to 785 bytes for characters, 438 to 1348 bytes for movies, 275 to 4598 bytes for particles. Small enough to enumerate every string in every file.

```python
def read_u30(data, pos):
    """Read AVM2 variable-length encoded integer."""
    result, shift = 0, 0
    for _ in range(5):
        b = data[pos]; pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80): break
        shift += 7
    return result, pos

def parse_abc_constant_pool(abc_data):
    """Extract all strings from an AVM2 ABC constant pool."""
    pos = 4  # skip version (u16 minor + u16 major)
    # Skip integer, uinteger, double pools
    for _ in range(3):
        count, pos = read_u30(abc_data, pos)
        if _ < 2:
            for __ in range(max(0, count - 1)):
                _, pos = read_u30(abc_data, pos)
        else:
            pos += max(0, count - 1) * 8
    # String pool
    string_count, pos = read_u30(abc_data, pos)
    strings = []
    for _ in range(max(0, string_count - 1)):
        strlen, pos = read_u30(abc_data, pos)
        strings.append(abc_data[pos:pos+strlen].decode('utf-8', errors='replace'))
        pos += strlen
    return strings
```

Running this across all 73 files and aggregating the results by category:

**Characters** (50 files, 49 with code): 301 unique strings total. Every single one is either a Flash display class (`MovieClip`, `Sprite`, `DisplayObjectContainer`), a character-specific FLA symbol name (`Aaron_fla:aaronmouth_2`, `CadyRebel_fla:CADY_REBEL_1`), a frame label (`frame1`, `frame15`), or one of two methods: `stop` and `addFrameScript`. That's it. 50 files of nothing but timeline animation frame scripts.

**Movies** (17 files, all with code): 115 unique strings. Same Flash display classes, plus movie-specific scene names (`REGINA_HIT_BUS_2`, `BLACK_FADE_IN_4`, `theEnd_artfreak_3`), `addEventListener`, and `ENTER_FRAME` for driving animations. The `Credits.swf` at 1348 bytes is the most complex, and even it is just a frame script with an `onBackButtonClick` handler.

**Particles** (6 files, 4 with code): 129 unique strings. This is the only category with actual logic: a particle system library with `Effect`, `Emitter`, and `Particle` classes. The strings include physics variables (`velocity`, `gravity`, `friction`, `rotation`), math functions (`cos`, `sin`, `sqrt`), and two local asset paths (`Assets/ParticleSprites/circle.swf`, `Assets/ParticleSprites/smoke.swf`). The `flash.net` namespace is present, but the only `URLRequest` usage loads these local sprite SWFs.

Across all 70 ABC constant pools, the referenced namespaces are:

- `flash.display`
- `flash.events`
- `flash.geom`
- `flash.net` (particles only, for local sprite loading)

Notably absent:

- **Networking**:
  - `flash.net.Socket`
  - `flash.net.XMLSocket`
  - `flash.net.URLLoader`
  - `navigateToURL`
  - `sendToURL`
  - `getURL`
- **Security**:
  - `flash.system.Security.allowInsecureDomain`
- **Host interaction**:
  - `flash.external` (present in the bootstrap SWF, but not in any game asset)
- **Code execution**:
  - `eval`
  - `loadVariables`

The constant pool is exhaustive. If a string isn't in the pool, the bytecode cannot reference it. There is nothing here but a Flash game.

### The bootstrap SWF

The overlay also contains two SWF Studio internal files. `__main.swf` is a 65-byte decoy with a valid `CWS` magic byte followed by plain ASCII:

```
$ xxd __main.swf
00000000: 4357 5307 706c 6561 7365 2064 6f6e 2774  CWS.please don't
00000010: 2061 7474 656d 7074 2074 6f20 7374 6561   attempt to stea
00000020: 6c20 7468 696e 6773 2074 6861 7420 646f  l things that do
00000030: 6e27 7420 6265 6c6f 6e67 2074 6f20 796f  n't belong to yo
00000040: 75                                       u
```

An anti-piracy trap. Anyone who extracts the SWFs and tries to load `__main.swf` directly gets a scolding instead of a game.

The real bootstrap is `5e9823bd6ad54a5585d8d47dae4cd6be.swf` (3KB, CWS v9). Its embedded XMP metadata identifies it as `Northcode Inc. - SWF Studio V3 - AS3 API - Stub`, dated `Oct 22, 2008`. Decompiling it produces `coreAS3Stub.as`, which has several patterns that look suspicious in isolation:

```actionscript
private function init() : void
{
  Security.allowDomain("*");        // looks like a security bypass
  _stage = stage;
  fscommand("Flash9");              // looks like command execution
  if(ExternalInterface.available)
  {
    // looks like remote control
    ExternalInterface.addCallback("coreLoadMovie", loadMovie);
  }
  _coreLdr = new Loader();
  _ldr = new Loader();
  // ...
}

private function onMainInit(param1:Event) : void
{
  if(_req)
  {
    // looks like anti-forensic file deletion
    _core.core.Core.deleteFile({"path":_req.url});
  }
}
```

In context, these are all standard SWF Studio v3 patterns: `allowDomain("*")` is required for the native-to-Flash bridge to work across security sandboxes. `ExternalInterface.addCallback` registers the function that the native host calls to pass SWF data to the Flash VM. `fscommand("Flash9")` is a version handshake. And `deleteFile` cleans up the temporary SWF file after loading it into memory, not anti-forensics, just temp file cleanup.

---

## Inside the encrypted container

One region of `MeanGirls.dat` refused to open under static analysis: the ~25 MB encrypted container that makes up most of the overlay. This is the game's own content, embedded in the runtime and separate from the loose `Assets/` files. None of the MoleBox keys decrypt it, and the data is flat, high-entropy noise with no usable structure. To get inside, I stopped reading the binary and started running it.

I loaded `MeanGirls.dat` into IDA and drove it under a remote Windows debugger in a VM. The plan was to let the runtime decrypt its own content and lift the plaintext out of memory as it appeared.

SWF Studio stages attached files through temporary files on their way to the Flash player, so a logging breakpoint on `kernel32!WriteFile` is enough to watch them go by. The decrypted files dropped straight out:

```
WriteFile  len=3055    43 57 53 09 ...   (bootstrap SWF, CWS v9)
WriteFile  len=143245  00 00 01 00 ...   (application icon, ICO)
```

Both come out as valid, recognizable files, lifted straight from memory as the engine wrote them: a CWS Flash movie and a Windows icon. The decryption works, and what it produces is plain game content.

### The engine

Those `WriteFile` calls returned into a DLL the runtime had unpacked to `%APPDATA%\.#` and loaded at `0x10000000`. Its export name is `utility.dll`: SWF Studio's native engine. Walking back up the call stack, the file-extraction routine makes two `thiscall`s right before it writes:

- `0x10009510`, which receives the file's name and its length
- `0x1000a500`, which receives a source buffer, a destination, and a length

`0x10009510` copies an 18-entry P-array and four 256-entry S-boxes from fixed tables and runs them through a key schedule. The tables are the fractional digits of pi:

```
P-array:  243f6a88 85a308d3 13198a2e 03707344 ...
S-box 0:  d1310ba6 98dfb5ac 2ffd72db d01adfb7 ...
```

That is **Blowfish**. `0x1000a500` is the **CBC** driver: it reads 8-byte blocks big-endian, runs each through the Blowfish round function at `0x10009a00`, and XOR-chains with the previous block. The IV is zero.

The key was the part I did not expect. `0x10009510` keys Blowfish with the **file's own name**, and inside the container those names are 110-character hex strings:

```
1BBF0E91A4614501A44688CF8A7101783D513AB25A99D31344388E4EE25343CD3 ...
```

clamped to Blowfish's 56-byte maximum. Every file is therefore encrypted under a different key, each one a name that the container keeps encrypted in its own directory.

### Pinning it down

A lookalike cipher is easy to misidentify, so I did not want to take the pi constants on faith. I set a breakpoint that let the engine finish its key schedule, then read the **expanded Blowfish context straight out of the running process** (the engine keeps it as a stack local) and reimplemented Blowfish with those exact subkeys. They reproduce, to the byte, the key schedule that standard Blowfish derives from `filename[:56]`. Cipher, mode, IV, and key are all confirmed against the live process, not inferred.

Getting that far meant going around the wrapper's own defenses. `utility.dll` is one of the `MAntiHack` components: it self-checksums and silently restores any software breakpoint planted in its own code, so a breakpoint on the decrypt routine never fires. The way through is to never touch `utility.dll` at all. Reach the decrypt through a `kernel32` breakpoint, then recover the Blowfish context by reading it out of the extraction routine's stack frame at a fixed offset from the file-name pointer.

So the last and most alarming region of the binary, 25 MB of solid entropy that looks exactly like a concealed encrypted payload, is the game. Every attached file is Blowfish-CBC encrypted under its own name, and the bytes that come out are ordinary SWFs and assets.

---

## VirusTotal sandbox report

VirusTotal runs submitted files in multiple sandboxes (CAPA, CAPE, Cuckoo, Jujubox, Zenbox) and aggregates the observed behaviors into MITRE ATT&CK mappings and Malware Behavior Catalog (MBC) tags. The [report for MeanGirls.exe](https://www.virustotal.com/gui/file/e29d5621142e020e31b88c8cb594608840433e0bc3453c0e98914d371c4ae419/behavior) flags several behavioral indicators. Since the sandbox runs `MeanGirls.exe`, which spawns `MeanGirls.dat` as a child process, the report captures behavior from both binaries.

Every finding maps directly to code already analyzed in this article:

| VT finding | ID | Actual cause |
|---|---|---|
| Software Packing | F0001 | MoleBox v2's XOR-encrypted PE sections in MeanGirls.dat, which the sandbox observes being decrypted at runtime |
| Obfuscated Files or Information | T1027 | The LCG-based XOR decryption loop at `0x5A0C7C` using constants `0x19660D` / `0x3C6EF375` to decrypt the import table |
| Command and Scripting Interpreter | T1059 | Flash Player's ActionScript Virtual Machine (AVM2), initialized by SWF Studio to execute `.swf` game content |
| Shared Modules | T1129 | MoleBox's dynamic loading of `MBX@*.###` runtime DLLs from `%APPDATA%\.#` via `LoadLibraryA` |
| Hide Artifacts | T1564 | The launcher's `ShowWindow(result, 0)` creating a hidden watchdog window, and MoleBox's hidden `.#` temp directory with `FILE_ATTRIBUTE_HIDDEN \| FILE_ATTRIBUTE_SYSTEM` |
| System Information Discovery | T1082 | `GetVersionExA` in the launcher's CRT startup code (see below) |
| Create Process | C0017 | `CreateProcessW(L"Meangirls.dat")` in the launcher's `wWinMain` |
| Terminate Process | C0018 | `TerminateProcess(hHandle, 0)` in the launcher's window procedure on `WM_CLOSE` / `WM_DESTROY` |
| Writes File | C0052 | MoleBox extracting runtime DLLs to `%APPDATA%\.#\MBX@{PID}@{ADDR}.###` |
| HTTP Communication / WinINet | C0002 / C0005 | Not from application code. DNS query attributed to Zenbox sandbox infrastructure (see below) |

### System Information Discovery

The sandbox flags the binary for querying host information (MITRE T1082). This comes from the MSVC C Runtime startup code, not from the application itself. The launcher's `start` function at `0x401482` contains the standard CRT initialization sequence:

```c
// MSVC CRT startup (compiler-generated, not application code)
GetVersionExA(&VersionInfo);                       // 0x4014a2
dword_40D780 = VersionInfo.dwPlatformId;
dword_40D78C = VersionInfo.dwMajorVersion;
dword_40D790 = VersionInfo.dwMinorVersion;
```

Every MSVC-compiled binary contains this code. The CRT queries the OS version to configure internal behavior (heap implementation, string handling, exception dispatch). It runs before `wWinMain` is even called. The sandbox correctly observes the `GetVersionExA` call but cannot distinguish compiler-generated boilerplate from intentional host fingerprinting.

### Contacted domain

The VirusTotal Relations tab reports that the sandbox contacted `cl-glcb907925.globalcdn.co`. This is the one finding I did *not* observe in my own dynamic analysis, so it warrants investigation.

The Network Communication section narrows this down: the only traffic is a single DNS query (`UDP 162.159.36.2:53`). No TCP connection, no HTTP request. A domain name was resolved, and nothing was done with the result.

Neither binary contains network API calls in its own code. The dynamic import table extracted from MeanGirls.dat has no socket functions, no WinINet, no WinHTTP, and no URL-related APIs. My runtime trace confirms this: `WININET.dll` is loaded as a transitive dependency through the OLE/urlmon chain, but no `InternetConnectA`, `HttpSendRequestA`, or any other WinINet function is ever called by the application.

[`cl-glcb907925.globalcdn.co`](https://www.virustotal.com/gui/domain/cl-glcb907925.globalcdn.co/relations) has 183,600 communicating files on VirusTotal: Win32 EXEs, PDFs, ISO images, HTML files, Android APKs, ranging from confirmed malware (68/72 detections) to completely clean documents (0/64). The Passive DNS resolvers are all "VirusTotal" or "Zenbox".

There is no plausible scenario where 183K unrelated files all independently connect to the same endpoint. This domain is part of the Zenbox sandbox infrastructure. When Zenbox executes a submitted file, its environment resolves this domain as part of its own operation, and the DNS query is attributed to whichever file is being analyzed. The network indicator is a sandbox artifact, not application behavior.

---

## Execution summary

From double-clicking the installer to gameplay:

1. **Installer unpacks.**
   - `Mean Girls.exe` (kkrunchy/THETA SFX) decompresses its kkrunchy-packed stub
   - Extracts a RAR4 archive containing:
     - The launcher
     - The game runtime
     - The uninstaller
     - The icon
     - ~80 MB of SWF assets
2. **Launcher starts the runtime.**
   - `MeanGirls.exe` calls `CreateProcessW(L"Meangirls.dat")`
   - Creates a hidden watchdog window
   - Polls every 100 ms
3. **MoleBox unpacks.**
   - `MeanGirls.dat` decrypts its PE sections through seven layers:
     - LCG-XOR
     - LZSS
     - IDEA
     - MoleBox LCG-XOR
     - Per-section IDEA+zlib
     - Per-chunk IDEA+zlib
     - Unencrypted zlib
   - Produces:
     - The VB6 runtime code
     - The Flash Player DLL
     - Two helper executables
     - The application icon
4. **VB6 runtime starts.**
   - The decompressed `.text` section contains 1,176 p-code method trampolines dispatching to `MSVBVM60.DLL`
   - `ProcCallEngine` begins interpreting 70 VB6 classes of SWF Studio application logic
5. **MoleBox extracts DLLs.**
   - Flash Player 9.0.124.0 and two MoleBox helpers are written to `%APPDATA%\.#\` as `MBX@{PID}@{ADDR}.###`
   - Directory marked with hidden+system attributes
6. **Flash Player initializes.**
   - SWF Studio registers the Flash Player ActiveX control via COM under `HKEY_CURRENT_USER`
   - Networking DLLs (`WININET.dll`, `WS2_32.dll`) load as transitive OLE dependencies
   - No application code calls them
7. **The game runs.**
   - SWF Studio loads the bootstrap SWF
   - Initializes `ExternalInterface`
   - Loads game SWFs from `Assets/`
   - The Flash VM executes ActionScript game logic
8. **Cleanup on exit.**
   - The MoleBox cleanup handler injects an 84-byte shellcode into `explorer.exe`
   - Waits for the game process to exit
   - Deletes the temp DLLs
   - No trace remains

---

## Conclusion

The `Mean Girls: High School Showdown` repack is not malware. It is a legitimate Flash game from 2009, built with SWF Studio v3 on MoleBox v2, repacked by a warez site using kkrunchy, and distributed through abandonware channels.

I statically cracked seven layers of protection, extracted the Flash Player runtime and the MoleBox helper components, decoded all 1,176 VB6 p-code methods into readable mnemonics, parsed every ActionScript constant pool across the 73 SWF files in `Assets/`, and decrypted the embedded game container. Every component has been traced, and every byte that looked like a hidden payload turned out to be the game.

The AV detections are likely false positives, triggered by a perfect storm of heuristic indicators that individually raise suspicion but, when traced back to the code, have a benign explanation.

Part of me is disappointed: I went in hoping to find a niche malware sample hiding inside a teen movie game, and all I got was a Flash wrapper with too many protection layers. But I am glad that the abandonware preservation scene, for all its rough edges, has enough integrity to not weaponize nostalgia.

Even so, always take precautions. Run unknown binaries in a virtual machine, and don't trust random bloggers.
