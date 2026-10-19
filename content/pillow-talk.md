+++
title = "Pillow Talk"
description = "How a 1990s image format turns a single Image.open() into a shell. Auditing the native stack, finding the bug where nobody looks, and walking a heap overflow through a fake Python type into system()."
date = 2026-11-15
template = "article.html"

[extra]
image = "images/pillow-talk.png"
logline = "Open the wrong picture and Pillow opens a shell."
+++

## Introduction

I spent the last DEF CON Qualifier CTF trying to solve [stork](https://bbbctf.com/challenges/stork), a challenge built around a custom Lua VM. The organizers had written their own scripting engine, and the goal was to break out of it through a memory bug.

I did not solve it before the competition ended, probably because I didn't have much practice finding and exploiting memory corruption bugs through a scripting language. Fuzzing a C parser directly is familiar territory. Reaching a memory bug from inside a managed runtime and turning it into arbitrary execution is not something I had done often.

The obvious place to build that skill is browser exploitation, but the v8 write-ups have always felt out of reach to me. So I picked a smaller version of the same problem: Python libraries that wrap C parsers.

I audited a handful of the popular ones and found memory corruption bugs in most. This article is about those I found in Pillow.

[Pillow](https://github.com/python-pillow/Pillow) is the de facto imaging library for Python. If a Python program opens, resizes, or converts an image, chances are Pillow is the library doing it: thumbnail pipelines, avatar uploads, document converters, ML data loaders. Under the Python API sits a large amount of C, some of it Pillow's own, most of it the usual decoders for JPEG, PNG, TIFF, and the rest.

---

## A Python memory-corruption primer

A heap overflow in a C extension is a different animal from one in a standalone C program. The interpreter's objects share the same heap as the buffers native code allocates, so an overflow will usually target a live Python object.

Every CPython object begins with the same header: a reference count and a pointer to the object's *type*.

<svg viewBox="0 0 720 292" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="A CPython object begins with ob_refcnt at offset 0 and ob_type at offset 8; ob_type points to its PyTypeObject, a table of function-pointer slots such as tp_dealloc, tp_call and tp_getattro." style="width:100%;height:auto;max-width:720px;display:block;margin:1.6rem auto;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace">
  <defs><marker id="p1" markerWidth="9" markerHeight="9" refX="7.5" refY="4.5" orient="auto"><path d="M0,0 L9,4.5 L0,9 Z" fill="#e19b2a"/></marker></defs>
  <rect x="44" y="54" width="252" height="200" rx="6" fill="#1b1c19" stroke="#3c3836"/>
  <text x="60" y="78" fill="#c7bf91" font-size="14">a Python object</text>
  <line x1="44" y1="90" x2="296" y2="90" stroke="#3c3836"/>
  <line x1="44" y1="134" x2="296" y2="134" stroke="#2c2a26"/>
  <line x1="44" y1="178" x2="296" y2="178" stroke="#2c2a26"/>
  <text x="60" y="117" fill="#7c6f57" font-size="11">0x00</text>
  <text x="98" y="117" fill="#a89984" font-size="13">ob_refcnt</text>
  <text x="184" y="117" fill="#c7bf91" font-size="13">2</text>
  <text x="60" y="161" fill="#7c6f57" font-size="11">0x08</text>
  <text x="98" y="161" fill="#e19b2a" font-size="13">ob_type</text>
  <text x="184" y="161" fill="#e19b2a" font-size="13">&amp;PyTypeObject</text>
  <text x="60" y="212" fill="#7c6f57" font-size="11">0x10</text>
  <text x="98" y="212" fill="#a89984" font-size="13">… the object's data …</text>
  <rect x="452" y="44" width="236" height="232" rx="6" fill="#1b1c19" stroke="#e19b2a"/>
  <text x="468" y="67" fill="#c7bf91" font-size="14">PyTypeObject</text>
  <text x="468" y="85" fill="#a89984" font-size="11">a table of function pointers</text>
  <line x1="452" y1="96" x2="688" y2="96" stroke="#3c3836"/>
  <line x1="452" y1="126" x2="688" y2="126" stroke="#2c2a26"/>
  <line x1="452" y1="156" x2="688" y2="156" stroke="#2c2a26"/>
  <line x1="452" y1="186" x2="688" y2="186" stroke="#2c2a26"/>
  <line x1="452" y1="216" x2="688" y2="216" stroke="#2c2a26"/>
  <line x1="452" y1="246" x2="688" y2="246" stroke="#2c2a26"/>
  <text x="468" y="116" fill="#7c6f57" font-size="10.5">0x30</text>
  <text x="512" y="116" fill="#a89984" font-size="11">tp_dealloc</text>
  <text x="606" y="116" fill="#c7bf91" font-size="11">fn ptr</text>
  <text x="468" y="146" fill="#7c6f57" font-size="10.5">0x80</text>
  <text x="512" y="146" fill="#a89984" font-size="11">tp_call</text>
  <text x="606" y="146" fill="#c7bf91" font-size="11">fn ptr</text>
  <text x="468" y="176" fill="#7c6f57" font-size="10.5">0x90</text>
  <text x="512" y="176" fill="#a89984" font-size="11">tp_getattro</text>
  <text x="606" y="176" fill="#c7bf91" font-size="11">fn ptr</text>
  <text x="468" y="206" fill="#7c6f57" font-size="10.5">0xa0</text>
  <text x="512" y="206" fill="#a89984" font-size="11">tp_as_buffer</text>
  <text x="606" y="206" fill="#c7bf91" font-size="11">fn ptr</text>
  <text x="468" y="236" fill="#7c6f57" font-size="10.5">0xc8</text>
  <text x="512" y="236" fill="#a89984" font-size="11">tp_iternext</text>
  <text x="606" y="236" fill="#c7bf91" font-size="11">fn ptr</text>
  <text x="512" y="266" fill="#a89984" font-size="11">… dozens more …</text>
  <path d="M298,156 C360,150 400,116 448,104" fill="none" stroke="#e19b2a" stroke-width="1.5" marker-end="url(#p1)"/>
  <text x="360" y="126" fill="#a89984" font-size="11">its type</text>
</svg>

To illustrate that, `bytes` is about the simplest object to look at. On a 64-bit build, this line:

```python
x = b"AAAAAAAA"
```

puts a `PyBytesObject` on the heap: the shared header, then a length, a cached hash, and the eight bytes laid out inline right after.

<svg viewBox="0 0 700 230" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="The bytes object x = b'AAAAAAAA' on the heap as a PyBytesObject: ob_refcnt 1 at offset 0, ob_type at offset 8 pointing to PyBytes_Type, ob_size 8 at offset 16, ob_shash -1 at offset 24, and ob_sval holding the bytes 41 41 41 41 41 41 41 41 00 at offset 32. An arrow runs from ob_type to the PyBytes_Type object beside it." style="width:100%;height:auto;max-width:700px;display:block;margin:1.6rem auto;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace">
  <defs><marker id="pb" markerWidth="9" markerHeight="9" refX="7.5" refY="4.5" orient="auto"><path d="M0,0 L9,4.5 L0,9 Z" fill="#e19b2a"/></marker></defs>
  <rect x="16" y="42" width="384" height="180" rx="6" fill="#1b1c19" stroke="#3c3836"/>
  <text x="28" y="62" fill="#c7bf91" font-size="13.5">PyBytesObject</text>
  <line x1="16" y1="72" x2="400" y2="72" stroke="#3c3836"/>
  <line x1="16" y1="102" x2="400" y2="102" stroke="#2c2a26"/>
  <line x1="16" y1="132" x2="400" y2="132" stroke="#2c2a26"/>
  <line x1="16" y1="162" x2="400" y2="162" stroke="#2c2a26"/>
  <line x1="16" y1="192" x2="400" y2="192" stroke="#2c2a26"/>
  <text x="28" y="91" fill="#7c6f57" font-size="10.5">0x00</text>
  <text x="74" y="91" fill="#a89984" font-size="11.5">ob_refcnt</text>
  <text x="176" y="91" fill="#c7bf91" font-size="11">1</text>
  <text x="28" y="121" fill="#7c6f57" font-size="10.5">0x08</text>
  <text x="74" y="121" fill="#e19b2a" font-size="11.5">ob_type</text>
  <text x="176" y="121" fill="#e19b2a" font-size="11">&amp;PyBytes_Type</text>
  <text x="28" y="151" fill="#7c6f57" font-size="10.5">0x10</text>
  <text x="74" y="151" fill="#a89984" font-size="11.5">ob_size</text>
  <text x="176" y="151" fill="#c7bf91" font-size="11">8</text>
  <text x="28" y="181" fill="#7c6f57" font-size="10.5">0x18</text>
  <text x="74" y="181" fill="#a89984" font-size="11.5">ob_shash</text>
  <text x="176" y="181" fill="#c7bf91" font-size="11">-1</text>
  <text x="206" y="181" fill="#7c6f57" font-size="9.5">(hash cache, unset)</text>
  <text x="28" y="211" fill="#7c6f57" font-size="10.5">0x20</text>
  <text x="74" y="211" fill="#a89984" font-size="11.5">ob_sval</text>
  <text x="176" y="211" fill="#c7bf91" font-size="10.5">41 41 41 41 41 41 41 41 00</text>
  <rect x="474" y="48" width="212" height="168" rx="6" fill="#1b1c19" stroke="#e19b2a"/>
  <text x="486" y="68" fill="#e19b2a" font-size="13">PyBytes_Type</text>
  <text x="486" y="85" fill="#a89984" font-size="9.5">shared, in libpython</text>
  <line x1="474" y1="94" x2="686" y2="94" stroke="#3c3836"/>
  <line x1="474" y1="124" x2="686" y2="124" stroke="#2c2a26"/>
  <line x1="474" y1="154" x2="686" y2="154" stroke="#2c2a26"/>
  <line x1="474" y1="184" x2="686" y2="184" stroke="#2c2a26"/>
  <text x="486" y="113" fill="#7c6f57" font-size="10">0x30</text>
  <text x="524" y="113" fill="#a89984" font-size="10">tp_dealloc</text>
  <text x="592" y="113" fill="#c7bf91" font-size="10">&amp;bytes_dealloc</text>
  <text x="486" y="143" fill="#7c6f57" font-size="10">0x58</text>
  <text x="524" y="143" fill="#a89984" font-size="10">tp_repr</text>
  <text x="592" y="143" fill="#c7bf91" font-size="10">&amp;bytes_repr</text>
  <text x="486" y="173" fill="#7c6f57" font-size="10">0x78</text>
  <text x="524" y="173" fill="#a89984" font-size="10">tp_hash</text>
  <text x="592" y="173" fill="#c7bf91" font-size="10">&amp;bytes_hash</text>
  <text x="524" y="203" fill="#a89984" font-size="10">… dozens more …</text>
  <path d="M404,120 C436,120 452,124 470,126" fill="none" stroke="#e19b2a" stroke-width="1.5" marker-end="url(#pb)"/>
</svg>

The first two fields, `ob_refcnt` at offset 0 and `ob_type` at offset 8, are the header every object start with; everything after them is particular to `bytes`.

>`ob_type` is the most important field. It points to a `PyTypeObject`, which is essentially a table of function pointers: one slot per operation the interpreter might perform on the object. Deallocating it, calling it, hashing it, fetching an attribute, releasing a buffer it lent out, each is a slot. Almost everything done to an object is an indirect call through one of these slots, reached by following `ob_type`.

That is what makes this class of bug exploitable. To act on an object, the interpreter reads its `ob_type`, picks a slot, and calls that function pointer with the object itself as the first argument:

<svg viewBox="0 0 720 214" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="To act on an object the interpreter reads ob_type, selects a slot such as tp_dealloc in the PyTypeObject, and calls it with the object as the first argument (rdi on x86-64)." style="width:100%;height:auto;max-width:720px;display:block;margin:1.6rem auto;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace">
  <defs><marker id="p2" markerWidth="9" markerHeight="9" refX="7.5" refY="4.5" orient="auto"><path d="M0,0 L9,4.5 L0,9 Z" fill="#e19b2a"/></marker></defs>
  <text x="12" y="22" fill="#a89984" font-size="12.5">To act on the object, the interpreter calls a slot from its type:</text>
  <rect x="16" y="58" width="152" height="92" rx="6" fill="#1b1c19" stroke="#3c3836"/>
  <text x="30" y="82" fill="#c7bf91" font-size="13">the object</text>
  <text x="30" y="118" fill="#e19b2a" font-size="13">ob_type &#8594;</text>
  <rect x="256" y="46" width="212" height="120" rx="6" fill="#1b1c19" stroke="#3c3836"/>
  <text x="270" y="70" fill="#c7bf91" font-size="13">PyTypeObject</text>
  <rect x="264" y="82" width="150" height="26" rx="3" fill="#241f16" stroke="#e19b2a"/>
  <text x="274" y="100" fill="#e19b2a" font-size="12.5">tp_dealloc</text>
  <text x="274" y="130" fill="#a89984" font-size="12">tp_call</text>
  <text x="274" y="152" fill="#a89984" font-size="12">tp_getattro</text>
  <rect x="524" y="72" width="182" height="66" rx="16" fill="#18201a" stroke="#8ec07c"/>
  <text x="615" y="98" text-anchor="middle" fill="#8ec07c" font-size="13">call</text>
  <text x="615" y="118" text-anchor="middle" fill="#8ec07c" font-size="13">tp_dealloc(obj)</text>
  <path d="M168,108 L252,102" fill="none" stroke="#e19b2a" stroke-width="1.5" marker-end="url(#p2)"/>
  <path d="M416,96 L520,102" fill="none" stroke="#e19b2a" stroke-width="1.5" marker-end="url(#p2)"/>
  <text x="360" y="200" text-anchor="middle" fill="#a89984" font-size="11.5">the object is passed as the first argument (rdi on x86-64)</text>
</svg>

The pointers are trusted by the interpreter, and usually easy to reach from an overflow. Overwriting `ob_type` lets you point to an arbitrary type. So I aim it at memory I already control, the overflowing buffer itself, and shape those bytes into a counterfeit `PyTypeObject`. The next time the interpreter touches the object it reads my fake type, pulls a slot from it, and calls the address I placed there:

<svg viewBox="0 0 720 372" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Memory laid out top to bottom with addresses increasing downward: the controlled buffer holds the command string, a fake PyTypeObject, and a fake tp_dealloc slot set to the address of system (a fixed PLT address in a non-PIE binary), and across the end-of-buffer boundary sits the adjacent victim object. The overflow writes downward past the end of the buffer into the object's ob_type, overwriting it with a pointer to the fake type; a wide arrow curves back up to that fake type. Redirecting ob_type into the buffer needs the buffer's heap address, a heap leak." style="width:100%;height:auto;max-width:720px;display:block;margin:1.6rem auto;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace">
  <defs>
    <marker id="r3" markerWidth="9" markerHeight="9" refX="7.5" refY="4.5" orient="auto"><path d="M0,0 L9,4.5 L0,9 Z" fill="#fb4934"/></marker>
  </defs>
  <text x="12" y="22" fill="#a89984" font-size="12.5">Memory is contiguous, so the overflow runs off the end of the buffer into the next object:</text>
  <rect x="250" y="56" width="220" height="150" rx="4" fill="#1e1a18" stroke="#fb4934" stroke-width="1.5"/>
  <line x1="250" y1="92" x2="470" y2="92" stroke="#4a3b34"/>
  <line x1="250" y1="128" x2="470" y2="128" stroke="#4a3b34"/>
  <line x1="250" y1="164" x2="470" y2="164" stroke="#4a3b34"/>
  <text x="262" y="80" fill="#c7bf91" font-size="12">"id\0" bytes</text>
  <text x="460" y="80" text-anchor="end" fill="#a89984" font-size="9.5">obj+0 &#8594; rdi</text>
  <text x="262" y="116" fill="#c7bf91" font-size="12">fake PyTypeObject</text>
  <text x="262" y="152" fill="#e19b2a" font-size="11.5">tp_dealloc = <tspan fill="#8ec07c">&amp;system</tspan></text>
  <text x="460" y="152" text-anchor="end" fill="#a89984" font-size="9">fixed PLT</text>
  <text x="262" y="190" fill="#a89984" font-size="11">… rest of your bytes …</text>
  <line x1="250" y1="214" x2="470" y2="214" stroke="#d3869b" stroke-width="1.25" stroke-dasharray="5 3"/>
  <text x="478" y="218" fill="#d3869b" font-size="9.5">end of buffer</text>
  <rect x="250" y="222" width="220" height="112" rx="4" fill="#1b1c19" stroke="#3c3836"/>
  <rect x="250" y="222" width="220" height="76" fill="#fb4934" fill-opacity="0.08"/>
  <line x1="250" y1="258" x2="470" y2="258" stroke="#2c2a26"/>
  <line x1="250" y1="296" x2="470" y2="296" stroke="#2c2a26"/>
  <text x="262" y="246" fill="#a89984" font-size="11.5">ob_refcnt</text>
  <text x="262" y="282" fill="#fb4934" font-size="12">ob_type</text>
  <text x="460" y="282" text-anchor="end" fill="#fb4934" font-size="11">&amp;fake_type</text>
  <text x="262" y="319" fill="#a89984" font-size="11.5">ob_size, …</text>
  <path d="M238,64 L238,278 L246,278" fill="none" stroke="#fb4934" stroke-width="1.5" marker-end="url(#r3)"/>
  <text x="36" y="218" fill="#fb4934" font-size="12">&#9312; overflow</text>
  <text x="36" y="235" fill="#a89984" font-size="10.5">the write runs off</text>
  <text x="36" y="249" fill="#a89984" font-size="10.5">the end of the buffer</text>
  <text x="36" y="263" fill="#a89984" font-size="10.5">into ob_type</text>
  <path d="M474,278 C616,248 616,150 474,116" fill="none" stroke="#fb4934" stroke-width="1.5" marker-end="url(#r3)"/>
  <text x="596" y="185" fill="#fb4934" font-size="11.5">&#9313; ob_type points</text>
  <text x="596" y="202" fill="#a89984" font-size="10">into the buffer:</text>
  <text x="596" y="215" fill="#e19b2a" font-size="10.5">needs a heap leak</text>
  <text x="556" y="108" fill="#8ec07c" font-size="11">&#9314; system: a fixed</text>
  <text x="556" y="124" fill="#a89984" font-size="10">PLT address (non-PIE),</text>
  <text x="556" y="137" fill="#a89984" font-size="10">so no leak needed</text>
  <text x="360" y="356" text-anchor="middle" fill="#a89984" font-size="11.5">rdi holds obj, the "id" bytes, so the hijacked call becomes system("id")</text>
</svg>

Two values have to be real addresses for this to fire, each with its own requirement:

- **The buffer's address.** The overwritten `ob_type` has to hold the real address of my bytes on the heap, so we need to know where is the buffer we are overflowing. This usually requires a leak. Without it I can corrupt `ob_type` but I cannot aim it.
- **What to call.** We need to know the address we want to call when we take control of the execution. Most of the time, this means finding the address of `system`. Against a binary built without PIE, `system` is reachable through a fixed PLT entry baked into the executable, so this one costs nothing. Against a position-independent build it is a second leak, of the text or libc base. But it's 2026, most python binaries deployed in a production environment must be PIE-enabled right? Right? ...Actually no. **All** the prebuilt docker images I analyzed during this research were not shipping with a position independant build of python.

The object pointer is the slot's first argument, `rdi` on x86-64, and that pointer is usually the start of the buffer (lucky!), so whatever is placed at the front is the argument. A command string there, like `id\0`, turns the hijacked call into `system("id\0")`.

The bugs ahead loosely follow this map, reaching an adjacent object's `ob_type`, redirecting it into attacker-controlled bytes shaped like a type, and landing a call on a chosen address with a chosen argument. What differs between them is how each one reaches the overflow.

Start to finish, that is the whole move in one place: the buffer fills with a fake type, the write runs off its end into `ob_type`, and the pointer that used to find the real type swings to the fake one.

<svg class="hj" viewBox="0 0 760 404" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="An animation of the hijack. First the overflowable buffer is empty and the intact object's ob_type points to the real PyBytes_Type, whose tp_dealloc slot is highlighted in aqua. The buffer then fills line by line with the command string and a fake PyTypeObject whose tp_dealloc is set to system. The write overruns the end of the buffer and corrupts the object's ob_refcnt and ob_type; ob_type now holds a pointer to the fake type, so the arrow swings from the real PyBytes_Type to the fake type, and the aqua highlight moves to the fake tp_dealloc.">
  <style>
    .hj-id{animation:hjIn6 12s ease-in-out infinite}
    .hj-hdr{animation:hjIn13 12s ease-in-out infinite}
    .hj-sys{animation:hjIn20 12s ease-in-out infinite}
    .hj-rest{animation:hjIn27 12s ease-in-out infinite}
    .hj-rc{animation:hjIn36 12s ease-in-out infinite}
    .hj-ot{animation:hjIn44 12s ease-in-out infinite}
    .hj-fakeval{animation:hjIn44 12s ease-in-out infinite}
    .hj-normval{animation:hjOut44 12s ease-in-out infinite}
    .hj-normarrow{animation:hjOut44 12s ease-in-out infinite}
    .hj-fakearrow{animation:hjIn44 12s ease-in-out infinite,hjDraw 12s ease-in-out infinite}
    .hj-normq{animation:hjOut58 12s ease-in-out infinite}
    .hj-fakeq{animation:hjIn58 12s ease-in-out infinite}
    @keyframes hjIn6{0%,6%{opacity:0}9%,90%{opacity:1}96%,100%{opacity:0}}
    @keyframes hjIn13{0%,13%{opacity:0}16%,90%{opacity:1}96%,100%{opacity:0}}
    @keyframes hjIn20{0%,20%{opacity:0}23%,90%{opacity:1}96%,100%{opacity:0}}
    @keyframes hjIn27{0%,27%{opacity:0}30%,90%{opacity:1}96%,100%{opacity:0}}
    @keyframes hjIn36{0%,36%{opacity:0}39%,90%{opacity:1}96%,100%{opacity:0}}
    @keyframes hjIn44{0%,44%{opacity:0}47%,90%{opacity:1}96%,100%{opacity:0}}
    @keyframes hjOut44{0%,44%{opacity:1}47%,92%{opacity:0}97%,100%{opacity:1}}
    @keyframes hjIn58{0%,58%{opacity:0}61%,90%{opacity:1}96%,100%{opacity:0}}
    @keyframes hjOut58{0%,58%{opacity:1}61%,92%{opacity:0}97%,100%{opacity:1}}
    @keyframes hjDraw{0%,44%{stroke-dashoffset:100}56%,94%{stroke-dashoffset:0}96%,100%{stroke-dashoffset:100}}
    @media (prefers-reduced-motion:reduce){.hj *{animation:none!important}}
  </style>
  <defs>
    <marker id="hjo" markerWidth="9" markerHeight="9" refX="7.5" refY="4.5" orient="auto"><path d="M0,0 L9,4.5 L0,9 Z" fill="#e19b2a"/></marker>
    <marker id="hjr" markerWidth="9" markerHeight="9" refX="7.5" refY="4.5" orient="auto"><path d="M0,0 L9,4.5 L0,9 Z" fill="#fb4934"/></marker>
  </defs>
  <text x="16" y="24" fill="#a89984" font-size="12.5">The overflow fills the buffer, corrupts ob_type, and swings the type pointer to the fake type:</text>
  <text x="44" y="62" fill="#fb4934" font-size="10.5">the overflowable buffer</text>
  <rect x="40" y="70" width="250" height="150" rx="4" fill="#1e1a18" stroke="#fb4934" stroke-width="1.5"/>
  <line x1="40" y1="107" x2="290" y2="107" stroke="#4a3b34"/>
  <line x1="40" y1="144" x2="290" y2="144" stroke="#4a3b34"/>
  <line x1="40" y1="181" x2="290" y2="181" stroke="#4a3b34"/>
  <rect class="hj-fakeq" opacity="0" x="44" y="149" width="242" height="28" rx="3" fill="#18201a" stroke="#8ec07c"/>
  <text class="hj-id" opacity="0" x="52" y="94" fill="#c7bf91" font-size="11.5">"id\0" bytes</text>
  <text class="hj-id" opacity="0" x="278" y="94" text-anchor="end" fill="#a89984" font-size="9">obj+0 &#8594; rdi</text>
  <text class="hj-hdr" opacity="0" x="52" y="131" fill="#c7bf91" font-size="11.5">fake PyTypeObject</text>
  <text class="hj-sys" opacity="0" x="52" y="168" fill="#e19b2a" font-size="11.5">tp_dealloc = <tspan fill="#8ec07c">&amp;system</tspan></text>
  <text class="hj-sys" opacity="0" x="278" y="168" text-anchor="end" fill="#a89984" font-size="9">fixed PLT</text>
  <text class="hj-rest" opacity="0" x="52" y="205" fill="#a89984" font-size="11">… rest of the bytes …</text>
  <line x1="40" y1="228" x2="250" y2="228" stroke="#d3869b" stroke-width="1.25" stroke-dasharray="5 3"/>
  <text x="258" y="232" fill="#d3869b" font-size="9.5">end of buffer</text>
  <rect x="40" y="236" width="250" height="115" rx="4" fill="#1b1c19" stroke="#3c3836"/>
  <rect class="hj-rc" opacity="0" x="41" y="237" width="248" height="36" fill="#fb4934" fill-opacity="0.14"/>
  <rect class="hj-ot" opacity="0" x="41" y="274" width="248" height="37" fill="#fb4934" fill-opacity="0.14"/>
  <line x1="40" y1="274" x2="290" y2="274" stroke="#2c2a26"/>
  <line x1="40" y1="312" x2="290" y2="312" stroke="#2c2a26"/>
  <text x="52" y="260" fill="#a89984" font-size="11.5">ob_refcnt</text>
  <text x="152" y="260" fill="#c7bf91" font-size="11">1</text>
  <text x="52" y="298" fill="#e19b2a" font-size="11.5">ob_type</text>
  <text class="hj-normval" x="152" y="298" fill="#e19b2a" font-size="11">&amp;PyBytes_Type</text>
  <text class="hj-fakeval" opacity="0" x="152" y="298" fill="#fb4934" font-size="11">&amp;fake_type</text>
  <text x="52" y="336" fill="#a89984" font-size="11.5">ob_size</text>
  <text x="152" y="336" fill="#c7bf91" font-size="11">8</text>
  <rect x="500" y="96" width="236" height="210" rx="6" fill="#1b1c19" stroke="#e19b2a"/>
  <text x="512" y="118" fill="#e19b2a" font-size="13">PyBytes_Type</text>
  <text x="512" y="135" fill="#a89984" font-size="9.5">the object's real type</text>
  <line x1="500" y1="144" x2="736" y2="144" stroke="#3c3836"/>
  <line x1="500" y1="184" x2="736" y2="184" stroke="#2c2a26"/>
  <line x1="500" y1="224" x2="736" y2="224" stroke="#2c2a26"/>
  <line x1="500" y1="264" x2="736" y2="264" stroke="#2c2a26"/>
  <rect class="hj-normq" x="504" y="149" width="228" height="31" rx="3" fill="#18201a" stroke="#8ec07c"/>
  <text x="512" y="169" fill="#7c6f57" font-size="10">0x30</text>
  <text x="548" y="169" fill="#a89984" font-size="11">tp_dealloc</text>
  <text x="622" y="169" fill="#c7bf91" font-size="10">&amp;bytes_dealloc</text>
  <text x="512" y="209" fill="#7c6f57" font-size="10">0x58</text>
  <text x="548" y="209" fill="#a89984" font-size="11">tp_repr</text>
  <text x="622" y="209" fill="#c7bf91" font-size="10">&amp;bytes_repr</text>
  <text x="512" y="249" fill="#7c6f57" font-size="10">0x78</text>
  <text x="548" y="249" fill="#a89984" font-size="11">tp_hash</text>
  <text x="622" y="249" fill="#c7bf91" font-size="10">&amp;bytes_hash</text>
  <text x="548" y="289" fill="#a89984" font-size="11">… dozens more …</text>
  <path class="hj-normarrow" d="M292,294 C392,290 420,182 498,170" fill="none" stroke="#e19b2a" stroke-width="1.5" marker-end="url(#hjo)"/>
  <path class="hj-fakearrow" opacity="0" pathLength="100" stroke-dasharray="100" stroke-dashoffset="100" d="M292,300 C374,296 374,150 293,133" fill="none" stroke="#fb4934" stroke-width="1.5" marker-end="url(#hjr)"/>
  <text class="hj-normq" x="196" y="388" fill="#a89984" font-size="11">When tp_dealloc is called, it runs <tspan fill="#8ec07c">bytes_dealloc</tspan><tspan fill="#c7bf91">(obj)</tspan></text>
  <text class="hj-fakeq" opacity="0" x="196" y="388" fill="#a89984" font-size="11">When tp_dealloc is called, it runs <tspan fill="#8ec07c">system</tspan><tspan fill="#c7bf91">(obj)</tspan></text>
</svg>


---

## How `Image.open()` picks a decoder

Most people picture `Image.open(file)` as "decode the PNG, or the JPEG, or whatever it is". The real behavior is more permissive. Pillow does not trust the extension or the caller. It reads the first bytes of the file and offers them to every registered format plugin, in order, until one claims it.

A plugin claims a file through a small `_accept` callback. Dozens are registered by default, including formats you would expect and several you would not. What matters for an attacker is that the reachable set of decoders is the set Pillow *ships*, not the set the application thinks it enabled. A file uploaded as `avatar.png` is decoded by whichever plugin recognizes its actual content.

One of those plugins is `FpxImagePlugin`, the FlashPix decoder.

---

## FlashPix, briefly

A FlashPix file is not an image file in the way a JPEG is. It is an **OLE2 compound document**: the container Microsoft used for legacy `.doc` and `.xls` files, a small filesystem packed into one file as a directory tree of named streams. Every OLE2 file starts with the same eight magic bytes, `D0 CF 11 E0 A1 B1 1A E1`, and the FlashPix plugin claims anything that begins with them:

```python
# src/PIL/FpxImagePlugin.py
def _accept(prefix):
    return prefix[:8] == olefile.MAGIC
```

Two details decide reachability. First, the match is on the magic bytes, so any upload starting with the OLE2 magic is routed into the FlashPix code regardless of its name. Second, the plugin needs the optional `olefile` package to read the container; without it, FlashPix is disabled. That sounds like a real barrier, but plenty of the imaging and document-processing ecosystem already pulls `olefile` in for other reasons. Where it is installed, the path is reachable.

Inside the document, a FlashPix file describes one or more subimages, and a subimage can store its pixels as JPEG. The JPEG path is where the bug is.

---


## The bug: a buffer sized for the wrong mode

When the FlashPix plugin meets a JPEG-compressed subimage, it builds a decode tile and tells Pillow's JPEG decoder two things: the `rawmode`, which is the pixel layout it expects back, and the `jpegmode`, which is what it thinks is in the stream. Both come from a lookup table keyed by FlashPix color identifiers, and those identifiers come straight out of the file:

```python
# src/PIL/FpxImagePlugin.py
MODES = {
    ...
    (0x00018000, 0x00017FFE): ("RGBA", "LA"),                # rawmode "LA"  (2 bytes/pixel)
    ...
    (0x00020000, 0x00020001, 0x00020002): ("RGB", "YCC;P"),  # rawmode "YCC;P"
}
```

Choose the color identifier that maps to `"LA"` and the decoder is told to expect two bytes per pixel. Pillow sizes the output buffer to match, one row wide, from the bit depth the `rawmode` implies:

```c
// src/decode.c
state->bytes  = (state->bits * state->xsize + 7) / 8;   // "LA" is 16 bits -> 2 * xsize bytes/row
state->buffer = (UINT8 *)calloc(1, state->bytes);
```

For an image of width `W` in `"LA"` mode, that row buffer is `2 * W` bytes.

Then, the JPEG decoder translates that `rawmode` string into a libjpeg output color space. It walks the modes it understands, `RGB`, `CMYK`, `YCbCr`, and a few more, and falls through to an `else` for anything it does not. `"LA"` is not on the list:

```c
// src/libImaging/JpegDecode.c
if (context->rawmode == IMAGING_RAWMODE_L) {
    context->cinfo.out_color_space = JCS_GRAYSCALE;
} else if (context->rawmode == IMAGING_RAWMODE_RGB) {
    context->cinfo.out_color_space = JCS_RGB;
}
...
} else {
    /* Disable decoder conversions. */
    context->cinfo.jpeg_color_space = JCS_UNKNOWN;
    context->cinfo.out_color_space  = JCS_UNKNOWN;
}
```

`JCS_UNKNOWN` tells libjpeg to skip color conversion and emit the raw components as the JPEG stores them. The bytes per pixel then come straight from the embedded JPEG's frame header, which the attacker writes. It declares four components.

So the second layer fills the buffer at four bytes per pixel:

```c
// src/libImaging/JpegDecode.c
ok = jpeg_read_scanlines(&context->cinfo, &state->buffer, 1);   // writes 4*W into a 2*W buffer
```

`jpeg_read_scanlines` writes `4 * W` bytes into a buffer sized for `2 * W`. The result is a heap overflow with attacker-controlled length (`W` is a field in the file) and attacker-controlled content (the pixels of a JPEG the attacker wrote).

> A *heap buffer overflow* is a write that runs past the end of a heap allocation into whatever the allocator placed after it.

---

## Building a file that triggers it

A bug you can only trigger by calling Pillow's internal decoder by hand is not worth much. It has to fire from one ordinary `Image.open()`, which means hand-building a valid FlashPix file that drags Pillow all the way to that scanline write.

I had to forge the container properly: a valid header, a sector allocation table, and a directory tree with the entries the plugin looks for. The pieces that matter for the bug are three streams:

- An **Image Contents** property set that declares one subimage, gives it the width `W` I want, and tags it with the FlashPix color identifier that maps to `"LA"`.
- A **subimage header** that marks the subimage as JPEG-compressed, so the plugin takes the JPEG path.
- A **data** stream holding the crafted JPEG itself, a four-component frame of width `W`.

The color identifier is a few bytes in the property blob:

```python
# the color-spec blob in the Image Contents property set
blob = o32(1) + o32(2) + o32(0x00018000) + o32(0x00017FFE)   # -> MODES key -> rawmode "LA"
```

With the container built correctly, opening the file is enough. Pillow recognizes the OLE2 magic, hands it to `FpxImagePlugin`, the plugin reads the property set, picks `"LA"`, builds a two-byte-per-pixel buffer, and feeds the four-component JPEG to libjpeg. Everything after this point is deciding what to write into the overflow.

---

## Confirming the overflow

Before building anything elaborate, it is worth running a few heuristics to make sure the primitive is exploitable. The cheapest possible test floods the overflow with a single repeated byte and opens the file.

There is one small wrinkle to account for. Pillow's CMYK JPEG path stores its data inverted, so a source byte of `0xBD` comes back as `0x42`. Flood the source with `0xBD`, and every byte that lands past the buffer is `0x42`. Among the things sitting just past the buffer is a live Python object, and `0x42` bytes turn its CPython type pointer into `0x4242424242424242`. The next thing Pillow does after decoding the tile dereferences that pointer:

```console
$ python3 vulnerable.py crash.fpx
Segmentation fault
```

```
# kernel log
segfault at 4242424242424242 ...
```

That settles it, the pointer being dereferenced is mine. Now, let's turn `0x4242424242424242` into something useful.

---

## From overflow to a controlled call

The object sitting past the buffer is the `bytes` object holding the file's data, the buffer Pillow is decoding. On a deterministic heap it lands at a fixed distance from the decode buffer, and its CPython type pointer, `ob_type`, sits at offset `130024` for the width I picked.

The overflow reaches a useful operation quickly because of how CPython releases a borrowed buffer. When Pillow is done with the file data it calls `PyBuffer_Release`, which reaches through the object's type to find the teardown callback:

```c
// CPython, simplified
void PyBuffer_Release(Py_buffer *view) {
    PyObject *obj = view->obj;
    PyBufferProcs *pb = Py_TYPE(obj)->tp_as_buffer;   // [ob_type + 0xa0]
    if (pb != NULL && pb->bf_releasebuffer != NULL)   // [pb + 8]
        pb->bf_releasebuffer(obj, view);              // indirect call
    ...
}
```

Read as a chain of dereferences off the pointer I overwrote, that is:

```
rax = obj->ob_type      ; the pointer we control
rax = [rax + 0xa0]       ; tp_as_buffer
rax = [rax + 8]          ; bf_releasebuffer
call rax                 ; with rdi = obj, rsi = view
```

This is a clean type-confusion primitive. I already control a large region of memory, the decode buffer, which is full of my decoded pixels.

Now bear with me: I need to lay the buffer out as a fake `PyTypeObject` whose `tp_as_buffer` points at a fake `PyBufferProcs` whose `bf_releasebuffer` is the address I want to call! Then, pointing `ob_type` at the fake type will make `PyBuffer_Release` calls that address with the object in `rdi`.

So the layout is three planted pointers inside the decoded image:

```
obj->ob_type        = &fake_type      (the overwrite, at offset 130024)
[fake_type + 0xa0]  = &fake_bufprocs  (tp_as_buffer)
[fake_bufprocs + 8] = TARGET          (bf_releasebuffer, the call destination)
```

To stay reliable across small shifts in heap layout, I do not bet on one exact offset. I spray the fake-type pointer across a wide stretch of the buffer and the target across another, so wherever `ob_type` lands, the `+0xa0` read still finds a fake type and the `+8` read still finds the target. That trades a precise offset for a wide window, a few kilobytes of slack.

---

## Writing exact bytes through JPEG

There is a catch in "lay the region out as a fake type". The region is the *output of a JPEG decode*, and JPEG is lossy. I cannot just place the eight pointer bytes I want at an offset; I have to find JPEG input that decodes to them.

At quality 100 with subsampling disabled, the round trip is effectively lossless for the values I need, so a direct attempt usually lands. To be exact about it, I run a short feedback loop: build a JPEG from a guess, decode it, compare each target offset to what I wanted, nudge the source by the error, and repeat until it matches.

The loop needs an oracle: a way to predict what the *vulnerable* `JCS_UNKNOWN` path will decode to.

The vulnerable path emits the raw components, call them `R`. Pillow's own CMYK decode of the same file returns `255 - R`, the inversion from earlier. So `255` minus whatever Pillow hands back is exactly what the buggy path will write:

```python
INV = bytes(255 - i for i in range(256))

def decode_row(jpg):
    # Pillow's CMYK decode returns 255 - R; the vulnerable JCS_UNKNOWN path writes R.
    # Inverting Pillow's own output predicts the bug, with no external libjpeg.
    px = Image.open(io.BytesIO(jpg)).tobytes()
    return px[(H - 1) * W * 4:].translate(INV)
```

The entire payload builder ends up being a few hundred lines of pure Pillow, and the feedback loop converges on the first pass because the bytes I need round-trip exactly at quality 100.

---

## Finding `system` without a leak

A type confusion that gives me a controlled call still needs a useful place to point it. The natural target is `system`, and the usual obstacle is finding it: on a position-independent binary you would need a libc leak, and a good chunk of any exploit is the plumbing to get one.

This target spares me that. The system Python interpreter on Ubuntu is a **non-PIE executable**. It loads at the fixed address `0x400000`, and because `libpython` is statically linked into the interpreter, the interpreter's own PLT entry for `system` is at a fixed address too, `0x4206c0`, no matter how the shared libraries are scattered. Point the fake vtable's `bf_releasebuffer` there and there is nothing to leak; the address was a constant the whole time.

> The *PLT* (Procedure Linkage Table) is the small trampoline a binary calls to reach an external function like `system`. In a non-PIE executable the table sits at a fixed virtual address, so the call target does not move between runs.

At the `call`, `rdi` already holds `obj`, the address of the victim object. `system` reads its argument as a C string starting there, and the first bytes of that object are inside the region I am overflowing. Write the command into them and `PyBuffer_Release` becomes `system(command)`:

```
offset 130016: "id\0..."     <- obj+0, becomes rdi, the string system() runs
offset 130024: &fake_type    <- ob_type, drives the vtable walk to 0x4206c0
```

The inline argument is short, bounded by where `ob_type` sits a few bytes later, so the command is capped at seven bytes. `id` is two of them, and `uid=0(root)` is all the proof I need.

---

## Defeating ASLR with a second bug

The pointers I plant are addresses into the decode buffer, and ASLR moves that buffer between runs. To place them, I need the heap base, which means a leak.

The same audit gave me one: an out-of-bounds *read* in Pillow's `map.c`, reachable through a McIdas AREA file opened with `Image.open`, or directly through `Image.frombuffer`. When Pillow maps a buffer as an image, it lays out the row pointers from an attacker-controlled `stride` and `offset`:

```c
// src/map.c, PyImaging_MapBuffer
for (y = 0; y < ysize; y++) {
    im->image[y] = (char *)view.buf + offset + y * stride;
}
```

`xsize`, `ysize`, `stride`, and `offset` all come from the file. The bounds check did not account for the full per-row width: each row is read at `xsize * pixelsize`, not at `stride`. Set `stride` smaller than a row and the last rows run out to `offset + (ysize - 1) * stride + xsize * pixelsize`, past the end of the mapping. Pillow reads that adjacent heap memory and hands it back as ordinary pixel data.

So I open a crafted McIdas file, read a few hundred bytes of live heap out of the returned image, and pick out a pointer I recognize. Masking off the low bits recovers the randomized heap base. That base is the only unknown in the FlashPix chain: feed it into the builder and the planted `ob_type` and vtable pointers land where they should, with nothing else changed. I ran the two bugs together against a stock, fully randomized box and got a shell.

They compose because a heap base leaked once stays valid for the life of the process. Leak with one file, exploit with the next, same base for both. That is exactly the setup a long-running service hands you, which is the next section.

---

## A shell from one `Image.open()`

The leak from the last section supplies the one random value; every other address is a constant, so the whole thing packages into a single file. The example below pins the heap base as well, so it reproduces byte for byte, but the leak is the only thing that value depends on. The victim side is the line every web application already wrote:

```python
# vulnerable.py
from PIL import Image
import sys
Image.open(sys.argv[1]).load()
```

And opening the crafted file runs the baked-in command:

```console
$ python3 make_payload.py --target 0x4206c0 --cmd id --out shell.fpx
[control] shell.fpx: S=0xdc8800 target=0x4206c0 cmd='id' craft_iters=0 bad=0
[control] opening it: vtable hijack -> call *0x4206c0 with rdi -> 'id'

$ python3 vulnerable.py shell.fpx
uid=0(root) gid=0(root) groups=0(root)
corrupted size vs. prev_size
```

The `S=0xdc8800` in the builder output is the decode buffer's address, the heap base plus a fixed offset; it is pinned here and recovered from the leak on a live target. The `uid=0(root)` line is `system("id")` running inside the process that opened the image. The `corrupted size vs. prev_size` after it is glibc noticing, on the way out, that we trampled its heap; by then the command has already run.

---

## Root cause and the fix

The overflow exists because nobody checks that the bytes libjpeg is about to write per row fit the buffer Pillow allocated for the row. Once `jpeg_start_decompress` has run, both numbers are known, so the check is a few lines at the sink:

```c
// src/libImaging/JpegDecode.c, right after jpeg_start_decompress
if (context->cinfo.output_width > (JDIMENSION)state->xsize ||
    (size_t)context->cinfo.output_components * context->cinfo.output_width >
        (size_t)state->bytes) {
    jpeg_destroy_decompress(&context->cinfo);
    state->errcode = IMAGING_CODEC_BROKEN;
    return -1;
}
```

`output_width * output_components` is exactly what libjpeg writes per scanline; `state->bytes` is exactly what the buffer holds. For every legitimate mode the two are equal, so the guard never fires on a valid image. Only the mismatched `JCS_UNKNOWN` case, four components into a two-byte buffer, trips it, and the crafted file turns into a clean `OSError` instead of a shell. It is the check that should have sat between the two layers from the start.

The vulnerability was assigned [CVE-2026-112398](https://www.cve.org/CVERecord?id=CVE-2026-112398).

---

## Good, but it needs a dependency

A shell from a single `Image.open()` is a strong result, but the whole chain depends on FlashPix, and FlashPix only loads if the optional `olefile` package is installed. It is common, but it is not default. A plain `pip install pillow` is not vulnerable to the FlashPix bug.

I wanted a bug that fires on a default install, no extras. So I went back through the audit, this time looking for attacker-controlled writes in Pillow's own Python code, rather than in a single C decoder. One that stood out was in the multi-frame `seek()` path.

---

## A reused buffer

Some formats store more than one frame in a file: animated GIFs, multi-page TIFFs, MPO stereo pairs, layered PSDs. You move between frames with `seek()`:

```python
img = Image.open("multi.ext")
img.load()        # frame 0
img.seek(1)       # frame 1
img.load()
```

On `seek()`, Pillow re-parses the target frame's header and updates the image's `mode`, size, and decode tiles. `load()` then decodes the current frame into the image buffer.

Nothing requires every frame to use the same mode. Frame 0 can be grayscale `"L"` at one byte per pixel, and frame 1 can be `"RGBA"` at four. Same width, different bytes per pixel.

The buffer is allocated in `src/PIL/ImageFile.py`:

```python
def load_prepare(self):
    # create image memory if necessary
    if self._im is None:
        self.im = core.new(self.mode, self.size)
    ...
```

It is allocated once, the first time it is needed, for whatever mode is current then. It is never reallocated when the mode changes. So:

- `Image.open()` reads frame 0: mode `"L"`.
- `load()` allocates a 1 byte/pixel buffer.
- `seek(1)` moves to frame 1 and sets mode `"RGBA"`. `_im` is not `None`, so `load_prepare` keeps the old buffer.
- `load()` decodes frame 1's 4 byte/pixel data into the 1 byte/pixel buffer.

Every row writes four bytes per pixel into room for one. The overflowing bytes are frame 1's decoded pixels, so they are attacker-controlled. It is the same primitive as the FlashPix bug, reached through an ordinary multi-frame read.

---

## Four formats, one bug

The flaw is in `ImageFile`, the base class every plugin inherits, so it is not specific to one format. Any multi-frame plugin whose `seek()` widens the mode without resetting the buffer is affected. Four qualify:

- **MPO**: stereo JPEG pairs. No dependency.
- **DCX**: multi-page PCX. No dependency.
- **PSD**: grayscale composite, then an RGBA layer. No dependency.
- **MIC**: Microsoft Image Composer. Needs `olefile`, like FlashPix.

Three of the four need nothing but Pillow. `pip install pillow`, open a file, iterate its frames, and the overflow is reachable. That is the property I was after.

---

## From crash to shell

The write is the same class as the FlashPix overflow: attacker-controlled bytes past the end of a heap buffer, with a live Python object sitting right after it. In principle the FlashPix chain applies directly, minus `olefile`: overwrite the neighbor's type pointer, aim it into a region you control, and the next `PyBuffer_Release` becomes a call.

In practice the finish depends on which decoder writes the overflow, and the default-install formats put up a fight. The RGB unpackers behind DCX and MPO write each pixel as `MAKE_UINT32(R, G, B, 255)`, which forces every fourth byte to `0xFF`. That is the byte I need to control when spraying a pointer, and `0xFF` in the top byte lands the address in non-canonical space, so the dereference faults instead of calling. Those vehicles gave me reliable, attacker-influenced crashes, not a shell.

The way through was to pick a frame whose unpacker does not force that byte. An MPO can have a CMYK JPEG as its second frame, and the CMYK unpacker (`unpackCMYKI`) inverts all four bytes without pinning any of them, so every byte of the overflow is mine again. JPEG is lossy, so I wrote a small solver that works backward from the bytes I need to the DCT coefficients that decode to them. With that, the full chain fires from a single `Image.open()` on a default install, no optional dependency, about 80% of the time.

>MIC reaches a shell too, and more reliably, but it needs `olefile`, which puts it back in the FlashPix bug's dependency bracket. The no-dependency result is the MPO one.

---

## In the wild: ComfyUI

A bug pattern is only interesting if something real reaches it. [ComfyUI](https://github.com/comfyanonymous/ComfyUI) is a widely used node-based UI for image generation that runs an HTTP server and takes image uploads. Its `LoadImage` node is where an upload gets decoded:

```python
# ComfyUI nodes.py, LoadImage.load_image (abridged)
def load_image(self, image):
    image_path = folder_paths.get_annotated_filepath(image)
    components = InputImpl.VideoFromFile(image_path).get_components()   # pyav / ffmpeg
    if components.images.shape[0] > 0:
        return (...)                                                     # pyav handled it
    # fallback: Pillow
    img = node_helpers.pillow(Image.open, image_path)
    for i in ImageSequence.Iterator(img):                               # open -> seek -> load
        ...
```

Pillow is only a fallback, tried after pyav, and there is no `try/except` around the pyav call, so if `get_components` *raises*, the node fails and Pillow is never reached. And when Pillow does run, ComfyUI iterates every frame with `ImageSequence.Iterator`, which is the `open → seek → load` sequence the seek bug needs.

So the way in is to make pyav return empty without raising. pyav probes by extension first, so a file uploaded as `.png` whose contents are not PNG fails the PNG decoder and drops to content sniffing. ffmpeg does not recognize OLE2 or MPO, so `get_components` returns zero frames and no exception. ComfyUI falls through to Pillow, Pillow recognizes the real format, and `ImageSequence.Iterator` walks it into the overflow.

Everything is driven over the HTTP API. Uploads go to `/upload/image`; the `.png` name is enough to pass, and Pillow ignores it and reads the bytes:

```python
def upload(filename, content):
    files = {"image": (filename, io.BytesIO(content), "image/png")}
    return SESSION.post(COMFY_URL + "/upload/image", files=files).json()

def queue_prompt(workflow):
    cid = uuid.uuid4().hex
    return SESSION.post(COMFY_URL + "/prompt",
                        json={"prompt": workflow, "client_id": cid}).json()
```

The workflow is two nodes, `LoadImage` feeding `SaveImage`:

```python
workflow = {
    "1": {"class_type": "LoadImage", "inputs": {"image": name}},
    "2": {"class_type": "SaveImage", "inputs": {"images": ["1", 0]}},
}
```

That `SaveImage` is the other part needed for the ASLR bypass.

- First, I upload a McIdas AREA file (the `map.c` read) under a `.png` name, run the graph, and fetch the saved "image" from `/view`: its pixels are the leaked heap bytes, and I recover the base from them.
- Then, I build the overflow payload against that base, upload it (again with a `.png` extension), and run the same graph. The second `LoadImage` hands the bytes to Pillow, `ImageSequence.Iterator` triggers the seek overflow, the planted vtable resolves, and `system()` runs:

```
$ python ./exploit.py "id"
$ cat /tmp/comfyui_rce_output.txt
uid=0(root) gid=0(root) groups=0(root)
```

The leak is a McIdas file and the overflow is the MPO/CMYK payload, so nothing on the server needs requires external dependencies. It is not one-shot though, since the worker's heap drifts between requests, so a run takes a few attempts.

>ComfyUI is one example. The same pattern reaches anything that opens user-supplied images and touches more than the first frame, which covers most thumbnailers, converters, and upload pipelines.

---

## Beaten to the punch

I sat on the seek bug for a while before reporting it. I've filed a lot of disclosures for other projects that were never fixed (not out of any bad faith on the maintainers' side, but because open-source maintainers rarely have the resources to triage and patch everything that lands in their inbox). By the time I submitted the seek bug, it was labeled "Duplicate".

Someone had already reported the same bug privately, and it was fixed in the same release under [CVE-2026-96639](https://github.com/python-pillow/Pillow/security/advisories/GHSA-v9pv-5gc8-w2m6).

It was the second time this audit that someone reached a bug ahead of me. The `map.c` read behind the ASLR leak had gone the same way: found independently and disclosed as [CVE-2026-54058](https://github.com/advisories/GHSA-62p4-gmf7-7g93) before I would have reported it. Two of the three bugs, found in parallel by other people, in the same window. LLMs are getting good!

---

## Disclosure timeline

- **May 2026.** Audited Pillow's native decoding stack and found all three bugs
- **June 4, 2026.** Disclosed the FlashPix overflow to the maintainers
- **June 5, 2026.** A first tentative patch went up for review
- **July 7, 2026.** The OOB read I used for the ASLR leak was disclosed as [CVE-2026-54058](https://github.com/advisories/GHSA-62p4-gmf7-7g93), already fixed in Pillow 12.3.0 the week before.
- **September 18, 2026.** The maintainers asked me to review a reworked FlashPix fix
- **September 19, 2026.** Fix approved
- **September 19, 2026.** Reported the multi-frame `seek()` overflow (duplicate)
- **October 16, 2026.** Both fixes ([FPX](https://github.com/python-pillow/Pillow/security/advisories/GHSA-5x8w-8jj5-q52h) and [seek](https://github.com/python-pillow/Pillow/security/advisories/GHSA-v9pv-5gc8-w2m6)) shipped in Pillow 13.0.0
