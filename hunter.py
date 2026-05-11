import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
import sys
import os
import math
import collections
import re
import psutil
import ctypes
from ctypes import wintypes
import json
from datetime import datetime
import argparse


# WINDOWS CTYPES STRUCTURES 
TH32CS_SNAPTHREAD = 0x00000004
TH32CS_SNAPMODULE = 0x00000008
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PAGE_EXECUTE_READWRITE = 0x40
ThreadQuerySetWin32StartAddress = 9

class THREADENTRY32(ctypes.Structure):
    _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD), ("th32ThreadID", wintypes.DWORD),
                ("th32OwnerProcessID", wintypes.DWORD), ("tpBasePri", wintypes.LONG), ("tpDeltaPri", wintypes.LONG),
                ("dwFlags", wintypes.DWORD)]

class MODULEENTRY32(ctypes.Structure):
    _fields_ = [("dwSize", wintypes.DWORD), ("th32ModuleID", wintypes.DWORD), ("th32ProcessID", wintypes.DWORD),
                ("GlblcntUsage", wintypes.DWORD), ("ProccntUsage", wintypes.DWORD), ("modBaseAddr", ctypes.POINTER(wintypes.BYTE)),
                ("modBaseSize", wintypes.DWORD), ("hModule", wintypes.HMODULE), ("szModule", ctypes.c_char * 256),
                ("szExePath", ctypes.c_char * 260)]

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p), ("AllocationProtect", wintypes.DWORD),
                ("RegionSize", ctypes.c_size_t), ("State", wintypes.DWORD), ("Protect", wintypes.DWORD), ("Type", wintypes.DWORD)]


# 1. CORE CONTEXT & SCORER
class ThreatScorer:
    def __init__(self):
        self.score = 0
        self.reasons = []

    def add(self, points, category, reason):
        formatted_reason = f"[+{points}] [{category}] {reason}"
        if formatted_reason not in self.reasons:
            self.score = min(100, self.score + points)
            self.reasons.append(formatted_reason)

    def get_color(self):
        return "🟢" if self.score < 30 else ("🟡" if self.score < 70 else "🔴")

# 2. HUMAN TRANSLATOR DICTIONARY
def translate_to_human(mnemonic, op_str):
    op_str = op_str if op_str else ""
    operands = [op.strip() for op in op_str.split(',')] if op_str else []
    op1 = operands[0] if len(operands) > 0 else ""
    op2 = operands[1] if len(operands) > 1 else ""
    
    mem_note = " [⚠️ MEM I/O]" if "[" in op_str else ""

    if mnemonic == "cpuid": return "Anti-VM: Check CPU Information."
    elif mnemonic == "rdtsc": return "Anti-Debug: Read Time-Stamp Counter."
    elif mnemonic in ["syscall", "sysenter"]: return "Syscall: Direct OS Kernel execution."
    elif mnemonic == "mov": return f"Copy value from '{op2}' into '{op1}'." + mem_note
    elif mnemonic == "lea": return f"Calculate memory address of '{op2}' into '{op1}'."
    elif mnemonic == "xchg": return f"Swap the contents of '{op1}' and '{op2}'." + mem_note
    elif mnemonic in ["movzx", "movsx"]: return f"Copy '{op2}' to '{op1}' and extend size." + mem_note
    elif mnemonic == "push": return f"Save '{op1}' to the top of the stack." + mem_note
    elif mnemonic == "pop": return f"Retrieve top value from stack into '{op1}'." + mem_note
    elif mnemonic in ["pushad", "pusha"]: return "Save ALL general registers to stack."
    elif mnemonic in ["popad", "popa"]: return "Restore ALL general registers from stack."
    elif mnemonic == "pushfd": return "Save EFLAGS to stack."
    elif mnemonic == "add": return f"Add '{op2}' to '{op1}'." + mem_note
    elif mnemonic == "sub": return f"Subtract '{op2}' from '{op1}'." + mem_note
    elif mnemonic == "inc": return f"Increase '{op1}' by 1." + mem_note
    elif mnemonic == "dec": return f"Decrease '{op1}' by 1." + mem_note
    elif mnemonic in ["mul", "imul"]: return f"Multiply by '{op1}'." + mem_note
    elif mnemonic in ["div", "idiv"]: return f"Divide by '{op1}'." + mem_note
    elif mnemonic == "neg": return f"Negate '{op1}'."
    elif mnemonic == "xor":
        if op1 == op2 and op1 != "": return f"Optimization: Clear '{op1}' to 0."
        return f"Bitwise XOR on '{op1}' and '{op2}' (Crypto/Obfuscation)." + mem_note
    elif mnemonic == "and": return f"Bitwise AND on '{op1}' and '{op2}'."
    elif mnemonic == "or": return f"Bitwise OR on '{op1}' and '{op2}'."
    elif mnemonic == "not": return f"Invert all bits of '{op1}'."
    elif mnemonic in ["shl", "sal"]: return f"Shift bits of '{op1}' LEFT by '{op2}'."
    elif mnemonic in ["shr", "sar"]: return f"Shift bits of '{op1}' RIGHT by '{op2}'."
    elif mnemonic in ["rol", "ror"]: return f"Rotate bits of '{op1}' (Typical in Crypto)." + mem_note
    elif mnemonic == "cmp": return f"Compare '{op1}' with '{op2}'." + mem_note
    elif mnemonic == "test": return f"Test if '{op1}' is ZERO or flags."
    elif mnemonic == "jmp": return f"Unconditional Jump to '{op1}'."
    elif mnemonic in ["je", "jz"]: return f"Jump to '{op1}' if EQUAL/ZERO."
    elif mnemonic in ["jne", "jnz"]: return f"Jump to '{op1}' if NOT EQUAL."
    elif mnemonic in ["jg", "jnle", "jge", "jnl"]: return f"Jump to '{op1}' if GREATER."
    elif mnemonic in ["jl", "jnge", "jle", "jng"]: return f"Jump to '{op1}' if LESS."
    elif mnemonic in ["ja", "jae", "jb", "jbe"]: return f"Jump to '{op1}' (unsigned)."
    elif mnemonic == "loop": return f"Loop to '{op1}'."
    elif mnemonic == "call": return f"Function Call: Execute code at '{op1}'."
    elif mnemonic == "ret": return "Return to caller."
    elif mnemonic == "leave": return "Clean up stack frame."
    elif mnemonic == "int3": return "🚨 ANTI-DEBUGGING: Software breakpoint!"
    elif mnemonic == "int": return f"Software Interrupt: '{op1}'."
    elif mnemonic == "nop": return "No Operation (Padding)."
    elif mnemonic.startswith("rep"): return f"Repeat string operation '{mnemonic[3:]}'."
    elif mnemonic in ["movs", "movsb", "movsd"]: return "String: Copy block of memory."
    elif mnemonic in ["scas", "scasb"]: return "String: Scan memory for byte."
    elif mnemonic in ["stos", "stosb"]: return "String: Fill memory with value."
    return f"Execute '{mnemonic}' on '{op_str}'." + mem_note


# 3. STRING & IOC EXTRACTOR
def extract_strings(text_data, scorer):
    print("\n[+] STRING EXTRACTION (IoCs, Mutexes, URLs, PowerShell, Base64)")
    print("-" * 100)
    
    urls = set(re.findall(r'https?://[a-zA-Z0-9./?=_-]+', text_data))
    ips = set(re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', text_data))
    powershell = set(re.findall(r'(?i)(powershell.*?-enc\s*[A-Za-z0-9+/=]+|Invoke-Expression|IEX)', text_data))
    registry = set(re.findall(r'(?i)(HKLM\\[a-zA-Z0-9_\\]+|HKCU\\[a-zA-Z0-9_\\]+|SOFTWARE\\[a-zA-Z0-9_\\]+)', text_data))
    base64_blobs = set(re.findall(r'(?:[A-Za-z0-9+/]{4}){15,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?', text_data))
    mutexes = set(re.findall(r'Global\\[a-zA-Z0-9_-]{6,}|Local\\[a-zA-Z0-9_-]{6,}', text_data))

    if urls or ips: 
        print("  🌐 Network Indicators (C2 Candidates):")
        for i, net in enumerate(list(urls) + list(ips)):
            if i < 7: print(f"    - {net}")
        scorer.add(15, "Network", "Contains hardcoded Network Indicators (URLs/IPs)")

    if powershell:
        print("  💻 Suspicious Shell/PowerShell:")
        for p in list(powershell)[:5]: print(f"    - {p[:80]}...")
        scorer.add(25, "Execution", "Contains Embedded PowerShell commands")

    if registry:
        print("  🔑 Registry Keys:")
        for r in list(registry)[:5]: print(f"    - {r}")

    if base64_blobs:
        print("  📦 Encoded Blobs (Base64 over 60 chars):")
        for b in list(base64_blobs)[:3]: print(f"    - {b[:60]}...[truncated]")
        scorer.add(20, "Obfuscation", "Contains Large Base64 Encoded Data Blobs")

    if mutexes:
        print("  🔒 Mutexes (Infection Markers):")
        for m in list(mutexes)[:5]: print(f"    - {m}")
        scorer.add(10, "Persistence", "Defines Mutexes (Common in Malware)")

    if not any([urls, ips, powershell, registry, base64_blobs, mutexes]):
        print("  🟢 No highly suspicious categorized strings detected.")


# 4. SCRIPT ANALYZER (VBS/Macro/Text)
def analyze_text_script(file_path, scorer):
    print(f"\n[*] INITIATING SCRIPT/MACRO ANALYSIS FOR: {file_path}")
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            
        extract_strings(content, scorer)
        
        print("\n[+] SUSPICIOUS SCRIPT BEHAVIORS (VBS/VBA/Macro)")
        print("-" * 100)
        
        patterns = {
            r'(?i)WScript\.Shell': ("Execution", "WScript.Shell Object found (Runs commands).", 20),
            r'(?i)Shell\.Application': ("Execution", "Shell.Application Object found.", 15),
            r'(?i)CreateObject': ("Capability", "Dynamically creating COM objects.", 5),
            r'(?i)MSXML2\.XMLHTTP|WinHttp\.WinHttpRequest': ("Network", "HTTP Request capability (Dropper).", 25),
            r'(?i)ADODB\.Stream': ("File I/O", "ADODB.Stream (Writing downloaded files).", 20),
            r'(?i)Eval\(|Execute\(': ("Obfuscation", "Dynamic code execution (Eval/Execute).", 25),
            r'(?i)document\.write': ("Web", "DOM Manipulation.", 5)
        }
        
        found = False
        for pattern, (cat, desc, points) in patterns.items():
            if re.search(pattern, content):
                print(f"  🔴 {desc}")
                scorer.add(points, cat, desc)
                found = True
                
        chr_count = len(re.findall(r'(?i)Chr\(|ChrW\(', content))
        if chr_count > 20:
            print(f"  🔴 HEAVY OBFUSCATION: Found {chr_count} instances of 'Chr()'.")
            scorer.add(30, "Obfuscation", "Heavy use of character encoding (Chr)")
            found = True

        if not found: print("  🟢 No highly suspicious VB/VBScript specific patterns detected.")

    except Exception as e:
        print(f"[-] Script Analysis Error: {e}")

# 5. STATIC PE ANALYSIS (Headers, Imports, Code CFG)
def analyze_pe_binary(file_path, scorer):
    print(f"\n[*] INITIATING ADVANCED PE FILE ANALYSIS: {file_path}")
    try:
        pe = pefile.PE(file_path)
        with open(file_path, 'rb') as f: raw_data = f.read()
        text_data = raw_data.decode('ascii', errors='ignore') + raw_data.decode('utf-16le', errors='ignore')
        extract_strings(text_data, scorer)

        print("\n[+] SECTION ANOMALIES & ENTROPY")
        print("-" * 100)
        
        align = pe.OPTIONAL_HEADER.SectionAlignment
        file_align = pe.OPTIONAL_HEADER.FileAlignment
        if align < file_align or align > 0x1000:
             print(f"  🔴 ANOMALY: Abnormal Section Alignment (Align: {hex(align)})")
             scorer.add(10, "Anomaly", "Abnormal Section Alignment")

        if hasattr(pe, 'DIRECTORY_ENTRY_TLS'):
            print("  🔴 ANOMALY: TLS Callbacks Detected! (Anti-Debug)")
            scorer.add(20, "Anti-Analysis", "TLS Callbacks present")

        IMAGE_SCN_MEM_WRITE, IMAGE_SCN_MEM_EXECUTE = 0x80000000, 0x20000000
        for section in pe.sections:
            name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
            entropy = section.get_entropy()
            chars = section.Characteristics
            is_rwx = (chars & IMAGE_SCN_MEM_WRITE) and (chars & IMAGE_SCN_MEM_EXECUTE)
            
            flags = []
            if entropy > 7.4: 
                flags.append("🔴 PACKED/ENCRYPTED")
                scorer.add(15, "Obfuscation", f"High Entropy ({entropy:.2f}) in section {name}")
            if is_rwx: 
                flags.append("🔴 SUSPICIOUS RWX")
                scorer.add(20, "Injection", f"RWX Section detected: {name}")
            if "UPX" in name:
                flags.append("🔴 UPX SIGNATURE")
                scorer.add(10, "Obfuscation", "UPX Packer signature")

            flag_str = " | ".join(flags) if flags else "🟢 Normal"
            print(f"  -> Sec: {name:<8} | Ent: {entropy:.2f} | {flag_str}")

        print("\n[+] FULL API CORRELATION & IMPORTS")
        print("-" * 100)
        imported_apis = []
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name: imported_apis.append(imp.name.decode('utf-8', errors='ignore'))
        
        if len(imported_apis) < 10:
            print(f"  🔴 ANOMALY: Tiny Import Table ({len(imported_apis)} APIs). Likely Packed.")
            scorer.add(25, "Obfuscation", "Tiny Import Table")

        behaviors = []
        if "VirtualAllocEx" in imported_apis and "CreateRemoteThread" in imported_apis: behaviors.append(("🔴 Process Injection (Classic)", 40, "Injection"))
        if "VirtualAllocEx" in imported_apis and "WriteProcessMemory" in imported_apis: behaviors.append(("🔴 Process Hollowing/Injection", 40, "Injection"))
        if "FindResourceA" in imported_apis and "LoadResource" in imported_apis: behaviors.append(("🟡 Dropper/Resource Loading", 15, "Execution"))
        if "CryptAcquireContextA" in imported_apis and "CryptDecrypt" in imported_apis: behaviors.append(("🔴 Cryptography / Ransomware behavior", 25, "Ransomware"))
        if "InternetOpenA" in imported_apis and "HttpSendRequestA" in imported_apis: behaviors.append(("🔴 C2 Communication / Dropper", 25, "Network"))
        if "GetProcAddress" in imported_apis and "LoadLibraryA" in imported_apis: behaviors.append(("🔴 Dynamic API Resolution", 15, "Evasion"))

        for api in imported_apis:
            if "IsDebuggerPresent" in api: behaviors.append(("🔴 Anti-Debugging Activity", 15, "Anti-Analysis"))
            if "SetWindowsHookEx" in api: behaviors.append(("🔴 Keylogging / Global Hooks", 25, "Spyware"))

        if behaviors:
            seen = set()
            for b_text, points, cat in behaviors:
                if b_text not in seen:
                    print(f"  {b_text}")
                    scorer.add(points, cat, b_text.replace("🔴 ", "").replace("🟡 ", ""))
                    seen.add(b_text)
        else:
            print("  🟢 No highly suspicious API correlations found.")

        # CODE DISASSEMBLY (Basic Blocks, Heuristics, Context Chaining)
        if pe.FILE_HEADER.Machine == 0x8664: md = Cs(CS_ARCH_X86, CS_MODE_64)
        elif pe.FILE_HEADER.Machine == 0x014c: md = Cs(CS_ARCH_X86, CS_MODE_32)
        else: return

        ep_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        ep_addr = pe.OPTIONAL_HEADER.ImageBase + ep_rva
        ep_data = pe.get_memory_mapped_image()[ep_rva:ep_rva+500]
        if not ep_data: return

        print("\n[+] CODE ANALYSIS (CFG, Syscalls, Hashing, Chaining)")
        print(f"{'Address':<12} | {'Instruction':<22} | {'Human Context / Heuristic'}")
        print("-" * 100)

        instructions = list(md.disasm(ep_data, ep_addr))
        sliding_window = []
        basic_blocks = []
        current_block = {"start": hex(ep_addr), "end": None}
        cfg_edges = collections.defaultdict(list)

        for i, instr in enumerate(instructions):
            asm_str = f"{instr.mnemonic} {instr.op_str}"
            human_text = translate_to_human(instr.mnemonic, instr.op_str)
            heuristic = ""

            sliding_window.append(instr)
            if len(sliding_window) > 5: sliding_window.pop(0)

            # CFG Building
            if instr.mnemonic in ["jmp", "je", "jne", "jg", "jl", "call"]:
                cfg_edges[hex(instr.address)].append(instr.op_str)
                current_block["end"] = hex(instr.address)
                basic_blocks.append(current_block)
                current_block = {"start": hex(instr.address + instr.size), "end": None}

            # Import-less Heuristics (PEB Walking)
            if "fs:" in instr.op_str and ("30" in instr.op_str or "48" in instr.op_str):
                heuristic = "🚨 PEB WALKING (x86): Resolving Kernel32 dynamically!"
                scorer.add(35, "Evasion", "Manual PEB Walking detected")
            elif "gs:" in instr.op_str and ("60" in instr.op_str or "96" in instr.op_str):
                heuristic = "🚨 PEB WALKING (x64): Resolving Kernel32 dynamically!"
                scorer.add(35, "Evasion", "Manual PEB Walking detected")

            # Syscall Correlation Stubs
            if instr.mnemonic == "syscall":
                if i > 0 and instructions[i-1].mnemonic == "mov" and "eax" in instructions[i-1].op_str:
                    heuristic = f"🚨 SYSCALL STUB: Executing syscall {instructions[i-1].op_str.split(',')[1]}"
                    scorer.add(40, "Evasion", "Direct Syscall detected")

            # Context Chaining (Indirect Call Args)
            if instr.mnemonic == "call" and not instr.op_str.startswith("0x"):
                pushed_args = [prev for prev in sliding_window if prev.mnemonic == "push"]
                if len(pushed_args) >= 2: heuristic = f"🟡 CONTEXT: Indirect Call with {len(pushed_args)} stacked args."
                else: heuristic = "🔴 INDIRECT CALL: Obfuscated destination."

            # API Hashing (Metasploit)
            if instr.mnemonic in ["ror", "rol"] and ("0xd" in instr.op_str or "13" in instr.op_str):
                heuristic = "🚨 API HASHING: ROR 13 detected (Metasploit Signature)"
                scorer.add(30, "Evasion", "API Hashing pattern found (ROR 13)")

            if heuristic or i < 20:
                prefix = ">> " if heuristic else "   "
                text_to_show = heuristic if heuristic else human_text
                print(f"{prefix}0x{instr.address:08x} | {asm_str:<22} | {text_to_show[:60]}")

            if i >= 40:
                print("   ... [Truncated for readability]")
                break

        print(f"\n  [*] CFG Summary: Detected {len(basic_blocks)} Basic Blocks.")
        for src, targets in list(cfg_edges.items())[:5]:
            print(f"      {src} --> {', '.join(targets)}")

    except Exception as e:
        print(f"[-] PE Analysis Error: {e}")

# 6. LIVE MEMORY & THREAD ANALYSIS
def analyze_real_memory(pid, scorer):
    print(f"\n[*] INITIATING LIVE PROCESS MEMORY ANALYSIS FOR PID: {pid}")
    print("-" * 100)
    
    if os.name != 'nt':
        print("[-] Live memory analysis requires Windows OS.")
        return

    k32 = ctypes.windll.kernel32
    ntdll = ctypes.windll.ntdll
    h_proc = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    
    if not h_proc:
        print("[-] Error: Could not open process memory. Run as Administrator!")
        return

    # A) THREAD START ADDRESS ANALYSIS
    print("  [*] Verifying Thread Start Addresses against loaded modules...")
    modules = []
    h_snap_mod = k32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid)
    if h_snap_mod != -1:
        me32 = MODULEENTRY32()
        me32.dwSize = ctypes.sizeof(MODULEENTRY32)
        if k32.Module32First(h_snap_mod, ctypes.byref(me32)):
            while True:
                base = ctypes.addressof(me32.modBaseAddr.contents) if me32.modBaseAddr else 0
                modules.append({"name": me32.szModule.decode('utf-8'), "start": base, "end": base + me32.modBaseSize})
                if not k32.Module32Next(h_snap_mod, ctypes.byref(me32)): break
        k32.CloseHandle(h_snap_mod)

    h_snap_th = k32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
    if h_snap_th != -1:
        te32 = THREADENTRY32()
        te32.dwSize = ctypes.sizeof(THREADENTRY32)
        if k32.Thread32First(h_snap_th, ctypes.byref(te32)):
            while True:
                if te32.th32OwnerProcessID == pid:
                    h_thread = k32.OpenThread(0x0040, False, te32.th32ThreadID)
                    if h_thread:
                        start_addr = ctypes.c_void_p()
                        status = ntdll.NtQueryInformationThread(h_thread, ThreadQuerySetWin32StartAddress, ctypes.byref(start_addr), ctypes.sizeof(start_addr), None)
                        if status == 0 and start_addr.value:
                            addr_val = start_addr.value
                            backed = any(m["start"] <= addr_val <= m["end"] for m in modules)
                            if not backed:
                                print(f"  🚨 INJECTED THREAD DETECTED: Thread {te32.th32ThreadID} starts outside known modules! ({hex(addr_val)})")
                                scorer.add(80, "Injection", f"Unbacked Thread Start Address at {hex(addr_val)}")
                        k32.CloseHandle(h_thread)
                if not k32.Thread32Next(h_snap_th, ctypes.byref(te32)): break
        k32.CloseHandle(h_snap_th)

    # B) MEMORY CARVING & RWX HUNTING
    print("\n  [*] Scanning memory pages for injected RWX regions and PE headers...")
    mbi = MEMORY_BASIC_INFORMATION()
    address = 0
    rwx_regions = 0

    while k32.VirtualQueryEx(h_proc, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)):
        if mbi.Protect == PAGE_EXECUTE_READWRITE and mbi.State == 0x1000:
            base_addr = mbi.BaseAddress or 0
            print(f"  🔴 SUSPICIOUS MEMORY: RWX Region at {hex(base_addr)} (Size: {mbi.RegionSize})")
            rwx_regions += 1
            
            # PE CARVING
            buffer = (ctypes.c_char * 2).from_buffer_copy(b'\x00\x00')
            bytes_read = ctypes.c_size_t(0)
            if k32.ReadProcessMemory(h_proc, ctypes.c_void_p(base_addr), buffer, 2, ctypes.byref(bytes_read)):
                if buffer.raw == b'MZ':
                    print(f"  🔥 PE HEADER DETECTED IN RWX MEMORY! Dumping Reflective DLL...")
                    scorer.add(60, "Injection", "Reflective DLL / MZ Header found in RWX Memory")
                    dump_buf = (ctypes.c_char * min(4096, mbi.RegionSize))()
                    k32.ReadProcessMemory(h_proc, ctypes.c_void_p(base_addr), dump_buf, ctypes.sizeof(dump_buf), ctypes.byref(bytes_read))
                    dump_name = f"dumped_PID{pid}_{hex(base_addr)}.bin"
                    with open(dump_name, "wb") as f: f.write(dump_buf.raw)
                    print(f"  [+] Dumped to disk: {dump_name}")

        address = (mbi.BaseAddress or 0) + mbi.RegionSize
        if address > 0x7FFFFFFFFFFF: break

    if rwx_regions > 0: scorer.add(50, "Injection", f"Found {rwx_regions} RWX memory regions")
    else: print("  🟢 Clean: No injected RWX memory regions found.")

    k32.CloseHandle(h_proc)

# 7. INTERACTIVE MENU & PAGINATION 
def list_and_select_process():
    print("\n[+] FETCHING RUNNING PROCESSES...")
    processes = []
    for p in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            if p.info['exe']: processes.append(p.info)
        except (psutil.AccessDenied, psutil.ZombieProcess): pass

    total_procs = len(processes)
    page_size = 30
    current_idx = 0

    while True:
        print(f"\n{'PID':<8} | {'Name':<25} | {'Executable Path'}")
        print("-" * 100)
        current_page = processes[current_idx : current_idx + page_size]
        for p in current_page: print(f"{p['pid']:<8} | {p['name']:<25} | {p['exe']}")
        print("-" * 100)
        
        page_num = (current_idx // page_size) + 1
        total_pages = (total_procs + page_size - 1) // page_size
        end_idx = min(current_idx + page_size, total_procs)
        print(f"  [Page {page_num}/{total_pages}] - Showing {current_idx + 1} to {end_idx} of {total_procs} processes.")

        prompt_text = "\n[?] Options: "
        if end_idx < total_procs: prompt_text += "[N] Next Page  "
        if current_idx > 0: prompt_text += "[P] Previous Page  "
        prompt_text += "[0] Back to Menu  [Type PID to analyze]\nChoice: "
        
        choice = input(prompt_text).strip().lower()

        if choice == '0': return None, None
        elif choice == 'n' and end_idx < total_procs: current_idx += page_size
        elif choice == 'p' and current_idx > 0: current_idx -= page_size
        else:
            try:
                target_pid = int(choice)
                for p in processes:
                    if p['pid'] == target_pid: return p['exe'], target_pid
                print("[-] PID not found.")
            except: print("[-] Invalid input.")

def interactive_mode():
    print("="*100)
    print("      🛡️ Hunter Project: THREAT HUNTER V0.1🛡️")
    print("="*100)
    print("1. Analyze a File on Disk (exe, dll, vbs, frm, bas, cls)")
    print("2. Analyze a Live Running Process (Memory Injection, RWX, Disassembly)")
    print("3. Exit")
    
    choice = input("\n[?] Select an option (1/2/3): ").strip()
    target_path, target_pid = None, None
    
    if choice == '1':
        target_path = input("[?] Enter the full path of the file: ").strip().strip('"')
    elif choice == '2':
        target_path, target_pid = list_and_select_process()
        if not target_path: return None, None
    elif choice == '3':
        sys.exit(0)
    else:
        print("[-] Invalid choice.")
        return None, None
        
    return target_path, target_pid

# 8. EXPORT REPORTER (JSON/HTML)
def export_reports(scorer, export_json=False, export_html=False):
    if not export_json and not export_html: return
    
    timestamp = datetime.now().strftime("%Y%md_%H%M%S")
    report_data = {"score": scorer.score, "alerts": scorer.reasons}
    
    if export_json:
        name = f"report_{timestamp}.json"
        with open(name, "w") as f: json.dump(report_data, f, indent=4)
        print(f"\n[+] Saved JSON Report: {name}")
        
    if export_html:
        name = f"report_{timestamp}.html"
        html = f"<html><body style='font-family:Arial; background:#1e1e1e; color:#fff;'>"
        html += f"<h1>Threat Score: {scorer.score}/100</h1>"
        for r in scorer.reasons: html += f"<div style='border-left:4px solid red; padding:10px; margin:5px; background:#2a2a2a;'>{r}</div>"
        html += "</body></html>"
        with open(name, "w") as f: f.write(html)
        print(f"[+] Saved HTML Report: {name}")

# MAIN EXECUTION
def main():
    parser = argparse.ArgumentParser(description="Hunter Project: Threat Hunter V0.1")
    parser.add_argument("-f", "--file", help="Path to static file")
    parser.add_argument("-p", "--pid", type=int, help="Process ID")
    parser.add_argument("--json", action="store_true", help="Export to JSON")
    parser.add_argument("--html", action="store_true", help="Export to HTML")
    args = parser.parse_args()

    target_path, target_pid = args.file, args.pid

    # If no CLI arguments provided, launch the Interactive Menu
    if not target_path and not target_pid:
        target_path, target_pid = interactive_mode()
        if not target_path: sys.exit(0)

    if target_path and not os.path.exists(target_path):
        print(f"[-] Error: Target path '{target_path}' not found.")
        sys.exit(1)

    scorer = ThreatScorer()

    # Step 1: Live Memory Analysis
    if target_pid:
        analyze_real_memory(target_pid, scorer)

    # Step 2: File Analysis Routing
    if target_path:
        ext = os.path.splitext(target_path)[1].lower()
        if ext in ['.exe', '.dll', '.sys']:
            analyze_pe_binary(target_path, scorer)
        elif ext in ['.vbs', '.bas', '.cls', '.frm', '.vba', '.ps1', '.txt']:
            analyze_text_script(target_path, scorer)
        else:
            print(f"[!] Unknown extension '{ext}'. Trying PE analysis, fallback to Text...")
            try:
                pefile.PE(target_path)
                analyze_pe_binary(target_path, scorer)
            except:
                analyze_text_script(target_path, scorer)

    # Step 3: Final Report
    print("\n" + "="*100)
    print(f"{scorer.get_color()} FINAL THREAT SCORE: {scorer.score}/100")
    print("="*100)
    for r in scorer.reasons: print(f"  {r}")
    
    export_reports(scorer, args.json, args.html)

if __name__ == "__main__":
    main()