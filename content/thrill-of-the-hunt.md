+++
title = "The Thrill of the Hunt"
description = "An ode to malware hunting and dissection through a Lumma Stealer case study, from YouTube cheat bait to in-depth configuration and protocol breakdown."
date = 2025-08-03
template = "article.html"

[extra]
image = "images/thrill.png"
logline = "An ode to malware hunting starring Lumma Stealer."
+++

## Introduction

As an offensive security specialist, I often analyze malware to stay up to date with current trends. Extracting TTPs from the latest samples is a good way to understand the shifts in modern tradecraft and keep adversary simulations relevant.

But while grabbing a cool APT sample from a malware repository or a threat hunting platform can be practical and efficient, it doesn't carry the same satisfaction for me as exploring shady websites to organically find and dissect suspicious executables.

While I rarely stumble upon completely new malware families since many of the samples are just repacked variants of known threats, I enjoy the process of finding them myself. I like collecting them from the wild, picking them apart, and understanding every bit and byte until the sample has no secrets left.

There is joy in the hunt.

---

## Hunting Grounds

In many gaming communities, rank is status. When that status feels at risk, some players look for shortcuts.

While one can't deny the existence of a thriving underground cheat market where players and streamers spend hundreds of dollars for exclusive unpatched cheats in competitive games, this article focuses on a different world: one of free cheats advertised on YouTube and link aggregators, packaged as easy tutorials like "NEW Working Cheat Undetected 2025" and propped up by comment walls of fake validation.

Free cheats create the perfect expectations. Unofficial software breaks often and triggers antivirus, so users are primed to ignore warnings and "try again". Cheat distributors even coach them to disable protections or run as administrator. If a loader launches and nothing visible happens, most simply assume it failed and move on, often after credentials are already on their way out.

---


## Sample Acquisition

### Youtube

Finding the sample started with a simple YouTube search for recent Roblox cheats. Sorting by Upload date, I clicked a video posted a couple of hours earlier advertising the capabilities of a new cheat loader.

![Youtube search](/images/youtube-roblox.png)
{% figure() %}Youtube search results{% end %}


The video included troubleshooting tips (`if it doesn't work, try disabling antivirus` or `run as administrator`), priming users to expect security warnings and ignore them. This is not surprising, even for "real" cheats, as some techniques they often use are flagged by antivirus, but it leads to something analogous to alert fatigue where users get used to turning protections off.

---

### Malicious Website

The description of the video linked to a relatively decent-looking AI-generated landing page:


![Distributor's website](/images/lumma-distributor.png)
{% figure() %}The distributor's website{% end %}

---

### Sample Download

The downloads were hosted on MediaFire, wrapped in password-protected ZIP archives. This is a popular approach, as multiple sources can link to the same ZIP and no malicious content is kept on the actual website.

It is also harder to analyze the content when we can't trace it back to the source where the password is revealed.


![Mediafire](/images/lumma-mediafire.png)
{% figure() %}Sample is hosted on a third party website{% end %}

---

## First Look

After downloading and unpacking the archive, I opened the executable in IDA Pro. The disassembly was a mess: hundreds of small, branching functions, junk code, and inflated function sizes.

To get a better high-level understanding of what a normal execution is like, I usually upload the sample to an online sandbox. In this instance, I uploaded the file to `ANY.RUN`

Running the sample in `ANY.RUN` confirmed my suspicion: it was flagged as Lumma Stealer, a well-known MaaS (Malware-as-a-Service) credential stealer.


![ANY.RUN results](/images/lumma-anyrun.png)
{% figure() %}ANY.RUN identifies the sample as Lumma{% end %}


The process tree showed something unusual: the malicious payload ran under `MSBuild.exe`, a "living off the land" binary (LOLBin).

LOLBins are signed Windows tools that attackers abuse to blend in and bypass controls. In this case, it was not used for typical LOLBin behavior like executing a project file or an inline build script.

Instead, it served as a trusted host for process hollowing: a technique where a benign process is started in a suspended state and has its original image replaced with a malicious PE. This aligns with the absence of any `.sln`/`.proj` parsing or MSBuild command-line arguments you would expect in a legitimate MSBuild invocation.

>By contrast, common LOLBin `certutil.exe` is often abused to download payloads. Here, MSBuild did not download or build anything, it only provided a reputable host process for injection.

I downloaded the injected process dump from the sandbox for deeper analysis.

After crudely fixing the mapped sections' offsets in `PEBear`, the dumped PE could launch, but would quit before performing malicious actions, which often happens when you run a rebuilt dump outside the original injection context or when it contains anti-vm measures.

Time to dive into the disassembly.

---

## Constant Unscrambling

The sample makes heavy use of stack strings with unique unscrambling functions to hide its constants. While the actual unscrambling functions are unique, their calling setup in always the same, which makes them easy to identify:

```nasm
mov     [esp+69Ch+var_594], 175715B0h
mov     [esp+69Ch+var_590], 13B61151h
mov     [esp+69Ch+var_58C], 1FAE1D43h
mov     [esp+69Ch+var_588], 1B1A19A8h
push    esi
call    mw_decode_mutex_prefix
```

The content of the function is always a tiny loop that performs simple byte substitutions based on a hard-coded constant and the current index:


![Lumma Unscrambler](/images/lumma-unscrambler.png)
{% figure() %}A typical unscrambling routine{% end %}


As the unscrambling functions always return the address of the decoded data in eax and don't use any input other than the value to decode, it is possible to add a breakpoint at the return to automatically dump the decoded data during dynamic analysis.

---

## Syscall Table

One of the first things the sample does when launched is to build its own syscall table and save a function pointer to a direct syscall stub, a popular technique used by malicious software to evade detection by avoiding potentially hooked ntdll functions.

To do that, the malware must access common DLLs:

```C
  scrambled_module_name[0] = 0x1B86198A; // Stack string set to scrambled module name
  ...
  scrambled_module_name[4] = 0xB0A099C;
  ntdll_str = mw_unscrambler((int)scrambled_module_name); // Unscramble stack string
  ntdll_module = mw_get_module_base_by_name_obf(ntdll_str); // Get ntdll handle
  success = 0;
  switch ( ntdll_module == 0 )
  {
    case 0:
      scrambled_module_name[0] = 0x4387418B; // Stack string set to scrambled name
      ...
      LOWORD(scrambled_module_name[6]) = 0x5958;
      kernel32_str = mw_unscrambler_0((int)scrambled_module_name); // Unscramble stack string
      kernel32_module = mw_get_module_base_by_name_obf(kernel32_str); // Get kernel32 handle
      success = 0;
      switch ( kernel32_module == 0 )
      {
        case 0:
          scrambled_module_name[0] = 0x53E151FD; // Stack string set to scrambled module name
          ...
          LOWORD(scrambled_module_name[5]) = 0x4544;
          user32_str_1 = mw_unscrambler_1((int)scrambled_module_name); // Unscramble stack string
          user32_module = mw_get_module_base_by_name_obf(user32_str_1); // Get user32 handle
          success = mw_build_syscall_table(); // Build syscall table
          break;
        case 1:
          return success;
      }

```

Their names are obfuscated, but placing a breakpoint on the decode functions' return reveal the names of the usual suspects:

- `KERNEL32.DLL`
- `ntdll.dll`
- `USER32.DLL`

The syscall table is created by parsing `ntdll.dll` and extracting the syscall numbers it uses.

>Syscall numbers vary from one Windows build to another. They can't be hardcoded without absolute knowledge of the target.

The function responsible for the syscall table creation is called, and receives a pointer to the base of ntdll:

```nasm
push    ebp
push    ebx
push    edi
push    esi
sub     esp, 244h
push    ntdll_module
call    mw_syscall_table_init_from_ntdll
```

The sample then performs PE sanity checks on ntdll: offsets are compared against obfuscated constants. These constants are the DOS magic MZ (`0x5A4D`) and PE (`0x00004550`):

```C
  mz_magic_ntdll = *ntdll_ptr;
  ...
  match = *decode_mz_magic(mz_magic) != mz_magic_ntdll;
  ...
  switch ( match )
  {
    case 0:
      pe_header_offset = *((_DWORD *)ntdll_ptr + 15);
      pe_signature_ntdll = *(_DWORD *)((char *)ntdll_ptr + pe_header_offset);
      scrambled_value = 0xEBEA5458;
      pe_magic = unscramble_PE_magic((int)&scrambled_value);
      ...
      switch ( pe_signature_ntdll != *pe_magic )
```

The export directory table is located:

```C
export_dir_rva = *(DWORD*)((char*)ntdll_ptr + pe_header_offset + 120);
if (*(DWORD*)((char*)ntdll_ptr + pe_header_offset + 124) == 0 || export_dir_rva == 0) return 0;
```

It reads the `IMAGE_EXPORT_DIRECTORY` RVA/Size from `OptionalHeader.DataDirectory[0]`, then computes the three key arrays inside the export directory:

```C
addr_of_names     = base + *(DWORD*)(base + export_dir_rva + 32); // AddressOfNames
addr_of_ordinals  = base + *(DWORD*)(base + export_dir_rva + 36); // AddressOfNameOrdinals
addr_of_functions = base + *(DWORD*)(base + export_dir_rva + 28); // AddressOfFunctions
```

Finally, it loops over the found exported names. Each function has their hash computed and their index parsed as long as it fits the following conditions:

1. The function name starts with `Nt`
2. The function contains these bytes within the first 0x20 bytes of the function:

- `0xB8`: mov eax, imm32 → the syscall number follows.
- Either:
  - `0xC3`: ret
  - `0xC2`: ret imm16

The result is a dynamically built table that can be used in direct syscall invocation.

---

### ntdll reload

After building the initial syscall table against the process's loaded `ntdll.dll`, the sample checks the system architecture, maps a fresh copy of `ntdll.dll` from the OS "KnownDLLs" section (`\KnownDlls\ntdll.dll` or `\KnownDlls32\ntdll.dll`), and immediately reruns the same build routine against that image.

KnownDLLs are loader-managed shared sections that expose baseline DLL images, which makes them a convenient source if you want an unmodified `ntdll.dll`. While intent cannot be proven from code alone, rerunning the build against a KnownDLLs-sourced image likely aims to derive syscall numbers and stubs from an unhooked `ntdll.dll`, reducing the chance that user-mode hooks skew results.


---


## Execution Conditions

Following the initialization of the syscall table, the malware enters a series of validations that establish conditions for the execution:

1. Anti-sandbox DLL validation
2. Language validation
3. Payload is encrypted on disk

---

### 1. Anti-sandbox DLL validation

The first condition relies on a method that validates the name of every loaded DLL against a list of hash known to be part of a sandbox product.

Using basic IDA automation, we can add a short IDC script to a breakpoint on the comparison instruction and dump the list of hashed DLL names.

#### IDC:

```C
auto p = Dword(EBX);
auto s = GetString(p, -1, ASCSTR_UNICODE);
Message("Target=%08X  Computed=%08X  Name=%s\n", EDX, EAX, s );
0;
```

#### Output:

```
Target=B16F6427  Computed=A0BFB930  Name=ntdll.dll
Target=B16F6427  Computed=D4F81F6A  Name=KERNEL32.DLL
Target=B16F6427  Computed=43F30262  Name=KERNELBASE.dll
Target=B16F6427  Computed=1DB424F9  Name=SHELL32.dll
Target=B16F6427  Computed=CDDFB5A5  Name=ucrtbase.dll
Target=B16F6427  Computed=9513C46C  Name=USER32.dll
Target=B16F6427  Computed=A400F6D2  Name=msvcp_win.dll
Target=B16F6427  Computed=19B11EB5  Name=GDI32.dll
...

```

After reimplementing the hashing function in python and using it to launch a bruteforce attack against a list of common DLLs, I was able to identify the sample's targets:

| Target Hash    | DLL name |
|---------|-------|
| 027999D3  | sbiedll.dll |
| 0F5995D5  | vmcheck.dll |
| 2BDD265E  | wpespy.dll |
| 781F5709  | dir_watch.dll |
| 8920B9F8  | snxhk.dll |
| 8FDA311C  | pstorec.dll |
| 99292F03  | api_log.dll |
| B16F6427  | avghookx.dll |
| B45D8108  | avghooka.dll |
| EA71728C  | cmdvrt64.dll |
| F6C2C2AF  | cmdvrt32.dll |

---


### 2. Language Validation

The second condition, now ubiquitous in most Malware-as-a-Service executables, validates the language of the system to make sure the execution is stopped if `GetUserDefaultUILanguage` returns `0x419`, the langid for the russian language.

```nasm
mov     eax, kernel32_module
sub     esp, 8
mov     [esp+8+var_8], eax
mov     [esp+8+var_4], 8CED6615h
call    mw_resolve_export_by_hash_checked ; KERNEL32.DLL:kernel32_GetUserDefaultUILanguage
add     esp, 8
call    eax
movzx   edi, ax
mov     al, [ebx]
mov     [ebp-44h], al
mov     byte ptr [ebp-28h], 53h ; 'S'
mov     byte ptr [ebp-27h], 0B9h
mov     byte ptr [ebp-26h], 0B6h
mov     byte ptr [ebp-25h], 0B7h
sub     esp, 4
lea     eax, [ebp-28h]
mov     [esp+4+var_4], eax
call    mw_inline_const_u32_decode ; 0x00000419 -> Russian LANGID
add     esp, 4
mov     eax, [eax]
xor     ecx, ecx
sub     edi, eax
setz    cl
mov     [ebp-280h], ecx
mov     eax, [ebp-284h]
mov     ecx, [ebp-280h]
mov     eax, [eax+ecx*4]
jmp     eax
```

---

### 3. Payload is encrypted on disk

Finally, the sample loads its own image from the disk and compares values at a precise offset to ensure they don't match the values in memory. This is likely a way of ensuring the image was not distributed in its unencrypted form.

If this check fails, the victim receives a not-so-stealthy pop-up asking them if they really want to execute malware:


![Lumma Warning](/images/lumma-warning.png)
{% figure() %}Pop up triggered by the detection of the unencrypted sample on disk{% end %}


If all these conditions are true, the malware can continue its execution.

---


## C2 List Decryption

After finishing its initialization phase, the malware has to connect to a Command & Control server (C2). This requires the malware to keep a hardcoded list of domains within the executable.

>As C2 lists constitute the main source of network-based indicators of compromise, they are usually encrypted as a way to evade string matching and slow down the reverse engineering process.

Looking for a config decryption routine led me to a suspicious function that looked like a cipher. The routine matched ChaCha20 (20 rounds, 16-word state, quarter-round pattern).

By comparing the function's xrefs to the expected decryption behavior, I was able to identify the code block responsible for the C2 extraction:

```nasm
mov     [esp+0A0h+encoded_block_size], 575655D4h ; Block size is encoded like most constants
mov     eax, esp
push    eax
call    decode_block_size	; Decodes the block size as 0x80
add     esp, 4
movzx   ecx, c2_list_index	; The current domain index has to be unscrambled
mov     edx, ecx
add     dl, cl
and     dl, 0C0h
sub     cl, dl
add     cl, 60h ; '`'
movzx   ecx, cl
shl     ecx, 7
lea     ecx, c2_ciphertext[ecx]	; Next domain entry
lea     esi, [esp+0A0h+c2_output_buffer]
push    dword ptr [eax]
push    esi
push    ecx
push    offset chacha20_state
call    mw_chacha20	; Decrypt function
add     esp, 10h
push    0
push    esi
push    80h
push    offset utf16_destination
call    utf8_to_utf16
add     esp, 10h
mov     al, 1
jmp     loc_40F6AA
```

And from there, identify the key setup block:

```nasm
loc_40DB69:             ; jumptable 0040DB49 case 1
mov     eax, offset chacha20_key
mov     edi, offset chacha20_key_copy
mov     ecx, 8
xchg    eax, esi
rep movsd
xchg    eax, esi
mov     eax, offset chacha20_nonce
mov     edi, offset dword_452E68
xor     ecx, ecx
xchg    eax, esi
```

With the key, nonce, and ciphertext offsets revealed, I was able to reimplement the decryption algorithm in python and create a config dumper that extracted the list of C2:

```
$ python ./chacha-dumper.py ./2903bd6b00db807518439a03423c402ce8043bd8567f2284360ae816d9fa049d
```
```JSON
{
  "C2": [
    "mocadia[.]com/iuew",
    "mastwin[.]in/qsaz",
    "precisionbiomeds[.]com/ikg",
    "physicianusepeptides[.]com/opu",
    "vishneviyjazz[.]ru/neco",
    "yrokistorii[.]ru/uqya",
    "xurekodip[.]com/qpdl",
    "utvp1[.]net/zkaj",
    "orienderi[.]com/xori"
  ],
  "key": "b43215b2a0fce918c4c2237602a2eafde0d727b043f1e10aa2221acb82284be5",
  "nonce": "00000000d1a7bd6aaa618069"
}
```

The sample also contained a fallback C2 that is dynamically obtained from a Steam profile.

---

## Network Protocol


With the list of C2 domains now decrypted, the malware can establish a connection over HTTPS.

To analyze the network traffic, I created a python flask API to impersonate a C2, then added a DNS entry and root certificate on the VM for easy HTTPS communication.

---

### Protocol description

All communications between the sample and the C2 are encrypted/decrypted using the same ChaCha20 implementation used to decrypt the list of C2 domains, with a fresh key and nonce generated for every request and response. Because these values are random and there's no prior handshake/KDF, both sides append them to the end of each ciphertext as a 40-byte trailer: `[32-byte key][8-byte nonce-tail]`.

The client sends its data as `multipart/form-data` parts of type `application/octet-stream`. The server auto-extracts the trailer to decrypt, then replies with a NULL-terminated JSON configuration encrypted in the same way and with the same trailer layout appended, allowing the client to decrypt symmetrically.

---

### String Encryption

The strings found in the JSON configuration are all encrypted using a simple process.

1. If utf-8, the string is converted to utf-16
2. A random 8 bytes key is generated 
3. The utf-16 string is XOR encrypted using the key generated on step 2
4. The 8 bytes key is appended at the beginning of the encryption result
5. The result from step 4 is base64 encoded

This translates roughly to the following operation:

```python
base64.b64encode( XOR_KEY + xor_encrypt( XOR_KEY, UTF16_PLAINTEXT ) )
```

The sample performs the reversed operation to cleanly obtain string values, such as path strings passed within the `p` parameter.

>To simplify the analysis, I hardcoded the XOR key to 8 nullbytes, as performing an XOR encryption with a null key returns the original value which can be helpful when debugging.

---

## JSON Keys Description

Basic overview of the JSON structure using example values:


```JSON
{
  // General Flags
  "se" : false,       // Screenshot
  "ad" : false,       // Auto-delete
  "vm" : false,       // Virtual Machine
  "dbg": false,       // Debug
	
  // Collector List
  "c" : [
    {
      "t" : 0,        // Collector ID 0 -> File Collector
      "p" : "",       // Path
      "z" : "",       // Zip output
      "m" : [""],     // Mask list
      "d": 1,         // Recursive depth
      "fs": 999999,   // Max File Size
      "fl": true      // Follow links
      
    },
    
    {
      "t" : 1,        // Collector ID 1 -> Chromium Collector
      "p" : "",       // Path
      "z" : "",       // Zip output
      "r": "",        // Relative subpath for User Data
      "n": "",        // Profile name
      "l": "",        // Extra subpath
      "h": false,     // Browser history exfiltration
      
    },
    
    {
      "t" : 2,        // Collector ID 2 -> Mozilla Collector
      "p" : "",       // Path
      "z" : "",       // Zip output
      "h" : false,    // Browser history exfiltration
      
    },
    
    {
      "t" : 3,        // Collector ID 3 -> Running Process Dumper
      "p" : "",       // Path
      "z" : "",       // Zip output
      "g" : "",       // Process name
      "m" : [""],     // Mask list
      "d" : "",       // Recursive depth
      "fs": 999999    // Max File Size
      
    },
    
    {
      "t" : 4,        // Collector ID 4 -> Registry Dumper
      "p" : "",       // HKCU subkey path
      "z" : "",       // Zip output
      "v" : "",       // Value name
      
    }
  ],
    
  // Chromium Extensions List
  "ex" : [
    {
      "en" : "",      // Extension name/path
      "ez" : "",      // Zip output
      "ldb" : false,  // Enables LevelDB harvesting
      "ses" : false,  // Sync Extension Settings harvesting
    }
  ],
    
  // Mozilla Extensions List
  "mx" : [
    {
      "en" : "",      // Extension name/path
      "ez" : "",      // Zip output
    }
  ],

}
```

---

### General Flags

The general flags are optional. They indicate if an action must be performed by the sample.

- `se`
  - **S**creenshot **E**nabled
  - Grabs a screenshot during general harvesting
- `ad`
  - **A**uto **D**elete
  - Sample self-deletes at the end of the execution
- `vm`
  - **V**irtual **M**achine check
  - Executes `cpuid` and compares the output with a list of constants associated to these vendors:
    - KVM
    - QEMU
    - VMware
    - VirtualBox
    - Xen 
- `dbg`
  - When looking at the code, the `dbg` flag branches to a block of NOP instructions
  - The NOP block probably contained **d**e**b**u**g** instructions that were removed in the final build

___

### Collectors

A list of collectors is passed in the root element `c`. This list of collector is the core  of the configuration.

The type of collector and its associated parameters are selected based on the `t` parameter:

---

#### Collector 0: **File Stealer**

A simple collector that opens the directory `p` and steals every files matching an entry in the list `m`.

- `t`: **T**ype set to 0
- `p`: Root **p**ath where to start enumeration 
- `m`: List of **m**asks, usually file extensions in the form `*.txt`
- `z`: Output directory in the **Z**IP file
- `d`: Recursive **d**epth
- `fs`: Max **f**ile **s**ize
- `fl`: **F**ollow **l**inks

---

#### Collector 1: **Chromium Dumper**

A specialized collector for chromium-based browsers.

- `t`: **T**ype set to 1
- `p`: Root **p**ath where to start enumeration 
- `z`: Output directory in the **Z**IP file
- `r`: **R**elative subpath for User Data
- `n`: Profile **n**ame
- `l`: Extra subpath. Purpose unknown.
- `h`: Collect **h**istory

---

#### Collector 2: **Mozilla Dumper**

A specialized collector for mozilla-based browsers.

- `t`: **T**ype set to 2
- `p`: Root **p**ath where to start enumeration
- `z`: Output directory in the **Z**IP file
- `h`: Collect **h**istory

---

#### Collector 3: **Running Process Dumper**

A collector that might be used for non-standard installation paths. Instead of using `p` as the root directory where to begin enumeration, it uses the directory where the image of a running process is located.

- `t`: **T**ype set to 3
- `g`: Name of the running process
- `p`: Sub **p**ath where to append to the root path
- `m`: List of **m**asks, usually file extensions
- `z`: Output directory in the **Z**IP file
- `d`: Recursive **d**epth
- `fs`: Max **f**ile **s**ize

---

#### Collector 4: **Registry Dumper**

Simple Registry key stealer

- `t` : **T**ype set to 4
- `p` : HKCU subkey **p**ath
- `v` : **V**alue name
- `z` : Output file in the **Z**IP file

---

### Extension Lists

In addition to the general browser collector, the JSON configuration also contains lists of extensions that should be harvested by the stealer:

- `ex` : Chromium **Ex**tensions
  - `en` : **E**xtension **n**ame / path
  - `ez` : **E**xtension output path in the **Z**IP file
  - `ldb` : Enables **L**evel**DB** harvesting
  - `ses` : Enables **S**ync **E**xtension **S**ettings path harvesting

- `mx` : **M**ozilla E**x**tensions
  - `en` : **E**xtension **n**ame / path
  - `ez` : **E**xtension output path in the **Z**IP file


---


### General Harvesters

After the list of collectors in the JSON configuration is exhausted, the malware executes a series of hardcoded harvesters designed to steal:

- Emails
- Calendar
- Steam data
- Notepad++ Session

---

#### System

The malware finally extracts basic system information which is sent upstream in a series of text files:

- `System.txt`
  - Sample's Build Date
  - System's configuration
	  - Executable Path
	  - OS Version
	  - Local Date
	  - Time Zone
	  - Install Date
	  - Elevated
	  - Computer
	  - User
	  - Domain
	  - Hostname
	  - NetBIOS
	  - Language
	  - Anti Virus
	  - HWID
	  - RAM Size
	  - CPU Vendor
	  - CPU Name
	  - CPU Threads
	  - CPU Cores
	  - GPU List
	  - Display resolution
- `Software.txt`
  - List of Software found on the system
- `Processes.txt`
  - List of running processes


---

## YARA and Hunting

With the analysis completed, the next step was to hunt for similar samples to extract their embedded C2s and create a bigger list of domain IoC.

To do that, I created a YARA rule based on Lumma's ChaCha20 implementation and its key setup: 

```
  strings:
    // Copy 32B key, then 8B nonce
    $copy_stub = {
      B8 ?? ?? ?? ?? BF ?? ?? ?? ?? B9 08 00 00 00 96 F3 A5 96
      B8 ?? ?? ?? ?? BF ?? ?? ?? ?? 31 C9 96 F3 66 A5 96
    }

    // Short ChaCha core: sub esp,110h ... mov ecx,10h ; rep movsd ... xor ecx,ecx ; rep movsw
    $chacha_core_short = {
      81 EC 10 01 00 00         // sub esp, 0x110
      [0-64]
      B9 10 00 00 00            // mov ecx, 16
      [0-16]
      F3 A5                     // rep movsd
      [0-64]
      31 C9                     // xor ecx, ecx
      [0-16]
      F3 66 A5                  // rep movsw
    }
```

I then [published it on YARAify](https://yaraify.abuse.ch/yarahub/rule/Lumma_ChaCha20_KeyStub_v2/) for hunting and community use.


---

## Conclusion


Pulling samples from the wild is not the fastest way to learn a family. It skips the big-picture trends and the neat threat landscape charts. It is narrow, and it is messy, but it is also fun.

There will always be joy in the hunt.

---

## Appendix A - IoC Table

| Type    | Value |
|---------|-------|
| SHA256  | c3452e0484d1985280565c5f8827e798f4623cf7b05ce624b394303376b108a2 |
| C2      | mocadia[.]com/iuew |
| C2      | mastwin[.]in/qsaz |
| C2      | precisionbiomeds[.]com/ikg |
| C2      | physicianusepeptides[.]com/opu |
| C2      | vishneviyjazz[.]ru/neco |
| C2      | yrokistorii[.]ru/uqya |
| C2      | xurekodip[.]com/qpdl |
| C2      | utvp1[.]net/zkaj |
| C2      | orienderi[.]com/xori |


---



