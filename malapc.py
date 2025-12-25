# Donated under Volatility Foundation, Inc. Individual Contributor Licensing Agreement

import logging
import math
from typing import List, Generator, Tuple, Optional, Set, Dict

from volatility3.framework import interfaces, renderers, constants, symbols
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.framework.objects import utility
from volatility3.plugins.windows import pslist, vadinfo

vollog = logging.getLogger(__name__)

class MalAPC(interfaces.plugins.PluginInterface):
    """
    Advanced APC-based malware detection plugin v2.1
    Detects shellcode injection, process injection, and malicious APC usage patterns
    """

    _required_framework_version = (2, 4, 0)
    _version = (2, 1, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"]
            ),
            requirements.ListRequirement(
                name="pid",
                description="Filter on specific process IDs",
                element_type=int,
                optional=True
            ),
            requirements.BooleanRequirement(
                name="dump-payloads",
                description="Dump suspicious memory regions",
                default=False,
                optional=True
            ),
            requirements.IntRequirement(
                name="dump-size",
                description="Size of memory to dump (bytes)",
                default=64,
                optional=True
            ),
            requirements.BooleanRequirement(
                name="use-whitelist",
                description="Skip analysis for known legitimate processes",
                default=True,
                optional=True
            ),
            requirements.IntRequirement(
                name="min-threat-score",
                description="Minimum threat score to report (1-15)",
                default=5,
                optional=True
            ),
            requirements.BooleanRequirement(
                name="enable-jit-detection",
                description="Enable JIT compiler detection to reduce false positives",
                default=True,
                optional=True
            )
        ]

    # Suspicious memory protection flags
    SUSPICIOUS_PROTECTIONS = ["PAGE_EXECUTE_READWRITE", "PAGE_EXECUTE_WRITECOPY"]
    
    # Legitimate system processes (extended list)
    LEGITIMATE_PROCESSES = {
        "svchost.exe",          # System services
        "lsass.exe",            # Local security authority
        "wininit.exe",          # Windows initialization
        "services.exe",         # Service control manager
        "smss.exe",             # Session manager subsystem
        "csrss.exe",            # Client/server runtime subsystem
        "conhost.exe",          # Console host
        "rundll32.exe",         # DLL runner (specific contexts)
        "explorer.exe",         # Windows explorer
        "searchindexer.exe",    # Windows search
        "searchapp.exe",        # Windows search app
        "taskhostw.exe",        # Windows task host
        "dwm.exe",              # Desktop window manager
        "winlogon.exe",         # Windows logon process
        "fontdrvhost.exe",      # Font driver host
        "sihost.exe",           # Shell infrastructure host
        "ctfmon.exe",           # Text services framework
        "runtimebroker.exe",    # Runtime broker
        "dllhost.exe",          # COM surrogate
        "spoolsv.exe",          # Print spooler
        "audiodg.exe",          # Windows audio device graph isolation
    }
    
    # JIT compiler modules
    JIT_MODULES = {
        "clr.dll",              # .NET Framework JIT
        "coreclr.dll",          # .NET Core JIT
        "msjit.dll",            # Legacy JIT
        "v8.dll",               # V8 JavaScript engine
        "chakra.dll",           # Chakra JavaScript engine
        "jscript9.dll",         # IE JavaScript
        "jscript.dll",          # Legacy JavaScript
        "mshtml.dll",           # IE rendering engine
    }
    
    # JIT-enabled processes
    JIT_PROCESSES = {
        "dotnet.exe",
        "powershell.exe",
        "pwsh.exe",
        "chrome.exe",
        "msedge.exe",
        "firefox.exe",
        "iexplore.exe",
        "devenv.exe",           # Visual Studio
        "code.exe",             # VS Code
        "rider64.exe",          # JetBrains Rider
    }
    
    # Process APC baselines (expected_min, expected_max, typical_modules)
    PROCESS_APC_BASELINES = {
        "svchost.exe": {"apc_range": (1, 10), "typical_modules": {"ntdll.dll", "kernel32.dll"}},
        "lsass.exe": {"apc_range": (0, 5), "typical_modules": {"ntdll.dll"}},
        "services.exe": {"apc_range": (1, 15), "typical_modules": {"ntdll.dll", "kernel32.dll"}},
        "explorer.exe": {"apc_range": (5, 50), "typical_modules": {"ntdll.dll", "kernel32.dll", "shell32.dll"}},
        "chrome.exe": {"apc_range": (10, 100), "typical_modules": {"ntdll.dll", "kernel32.dll", "chrome.dll"}},
        "firefox.exe": {"apc_range": (10, 100), "typical_modules": {"ntdll.dll", "kernel32.dll", "xul.dll"}},
        "powershell.exe": {"apc_range": (5, 50), "typical_modules": {"ntdll.dll", "kernel32.dll", "clr.dll"}},
    }

    def _get_process_name(self, proc) -> str:
        """Helper to safely get process name as string"""
        try:
            name = utility.array_to_string(proc.ImageFileName)
            if isinstance(name, bytes):
                return name.decode('utf-8', errors='ignore')
            return name
        except:
            return "Unknown"

    def run(self):
        kernel = self.context.modules[self.config['kernel']]
        kernel_layer_name = kernel.layer_name
        symbol_table_name = kernel.symbol_table_name

        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))
        
        # Apply whitelist filtering if enabled
        whitelist_enabled = self.config.get('use-whitelist', True)
        if whitelist_enabled:
            original_filter = filter_func
            def whitelist_filter(proc):
                if not original_filter(proc):
                    return False
                proc_name = self._get_process_name(proc)
                return proc_name.lower() not in self.LEGITIMATE_PROCESSES
            filter_func = whitelist_filter

        columns = [
            ("PID", int),
            ("Process", str),
            ("TID", int),
            ("Threat Level", str),
            ("Score", int),
            ("Detection Reason", str),
            ("NormalRoutine", format_hints.Hex),
            ("KernelRoutine", format_hints.Hex),
            ("APCMode", str),
            ("VAD Protection", str),
            ("VAD Type", str),
            ("Module Context", str),
            ("Hexdump", format_hints.HexBytes)
        ]

        return renderers.TreeGrid(
            columns, 
            self._generate_detections(
                context=self.context,
                kernel_layer_name=kernel_layer_name,
                symbol_table_name=symbol_table_name,
                filter_func=filter_func
            )
        )

    def _generate_detections(
        self, 
        context: interfaces.context.ContextInterface, 
        kernel_layer_name: str, 
        symbol_table_name: str, 
        filter_func
    ) -> Generator[tuple, None, None]:
        """Generate comprehensive APC-based threat detections"""
        
        min_threat_score = self.config.get('min-threat-score', 5)
        
        for proc in pslist.PsList.list_processes(
            context=context,
            kernel_module_name=self.config['kernel'],
            filter_func=filter_func
        ):
            process_name = self._get_process_name(proc)
            process_id = int(proc.UniqueProcessId)
            
            try:
                # Get loaded modules once per process (performance optimization)
                loaded_modules = self._get_loaded_modules_detailed(context, proc)
                
                # Cache protection values per process
                try:
                    protection_values = vadinfo.VadInfo.protect_values(
                        context, kernel_layer_name, symbol_table_name
                    )
                except Exception as e:
                    vollog.debug(f"Error getting protection values for PID {process_id}: {e}")
                    protection_values = {}
                
                # Analyze each thread's APCs
                for thread in proc.ThreadListHead.to_list(
                    f"{symbol_table_name}{constants.BANG}_ETHREAD", 
                    "ThreadListEntry"
                ):
                    try:
                        thread_id = int(thread.Cid.UniqueThread)
                        apc_state = thread.Tcb.ApcState
                        
                        # Collect all APCs for this thread (for pattern analysis)
                        thread_apcs = []
                        
                        # Process each APC in the thread
                        if hasattr(apc_state, 'ApcListHead'):
                            for apc_list in apc_state.ApcListHead:
                                try:
                                    for apc in apc_list.to_list(
                                        f"{symbol_table_name}{constants.BANG}_KAPC", 
                                        "ApcListEntry"
                                    ):
                                        # Extract APC details
                                        apc_details = self._extract_apc_details(apc, apc_state, thread)
                                        
                                        if apc_details['normal_routine'] or apc_details['kernel_routine']:
                                            thread_apcs.append(apc_details)
                                            
                                            # Perform threat analysis
                                            threat_info = self._analyze_apc_threat(
                                                proc, 
                                                apc_details,
                                                kernel_layer_name,
                                                symbol_table_name,
                                                context,
                                                loaded_modules,
                                                protection_values,
                                                thread_apcs,
                                                process_name
                                            )
                                            
                                            # Only report if meets minimum threat score
                                            if threat_info['is_suspicious'] and threat_info['threat_score'] >= min_threat_score:
                                                yield (0, (
                                                    process_id,
                                                    process_name,
                                                    thread_id,
                                                    threat_info['threat_level'],
                                                    threat_info['threat_score'],
                                                    threat_info['reason'],
                                                    format_hints.Hex(apc_details['normal_routine']),
                                                    format_hints.Hex(apc_details['kernel_routine']),
                                                    apc_details['apc_mode'],
                                                    threat_info['vad_protection'],
                                                    threat_info['vad_type'],
                                                    threat_info['module_context'],
                                                    format_hints.HexBytes(threat_info['hexdump'])
                                                ))
                                                
                                except Exception as e:
                                    vollog.debug(f"Error processing APC list for TID {thread_id}: {e}")
                                    continue
                    
                    except Exception as e:
                        vollog.debug(f"Error processing thread in PID {process_id}: {e}")
                        continue
            
            except Exception as e:
                vollog.debug(f"Error processing process {process_id}: {e}")
                continue

    def _extract_apc_details(self, apc, apc_state, thread) -> dict:
        """Extract comprehensive APC details"""
        details = {
            'kernel_routine': 0,
            'normal_routine': 0,
            'apc_mode': "Unknown",
            'inserted': "Unknown",
            'kernel_apc_pending': False,
            'user_apc_pending': False,
            'thread_obj': thread
        }
        
        try:
            if hasattr(apc, 'KernelRoutine') and apc.KernelRoutine:
                details['kernel_routine'] = int(apc.KernelRoutine)
            
            if hasattr(apc, 'NormalRoutine') and apc.NormalRoutine:
                details['normal_routine'] = int(apc.NormalRoutine)
            
            if hasattr(apc, 'ApcMode'):
                details['apc_mode'] = "Kernel" if int(apc.ApcMode) == 0 else "User"
            
            if hasattr(apc, 'Inserted'):
                details['inserted'] = "Yes" if bool(apc.Inserted) else "No"
            
            if hasattr(apc_state, 'KernelApcPending'):
                details['kernel_apc_pending'] = bool(apc_state.KernelApcPending)
            
            if hasattr(apc_state, 'UserApcPending'):
                details['user_apc_pending'] = bool(apc_state.UserApcPending)
        
        except Exception as e:
            vollog.debug(f"Error extracting APC details: {e}")
        
        return details

    def _analyze_apc_threat(
        self, 
        proc, 
        apc_details: dict,
        kernel_layer_name: str,
        symbol_table_name: str,
        context: interfaces.context.ContextInterface,
        loaded_modules: dict,
        protection_values: dict,
        thread_apcs: list,
        process_name: str
    ) -> dict:
        """Comprehensive threat analysis of APC with enhanced heuristics"""
        
        threat_info = {
            'is_suspicious': False,
            'threat_level': "Clean",
            'threat_score': 0,
            'reason': "",
            'vad_protection': "N/A",
            'vad_type': "N/A",
            'module_context': "Unknown",
            'hexdump': b""
        }
        
        try:
            proc_layer_name = proc.add_process_layer()
            proc_layer = context.layers[proc_layer_name]
            
            # Analyze routines
            normal_routine = apc_details['normal_routine']
            kernel_routine = apc_details['kernel_routine']
            
            reasons = []
            threat_score = 0
            
            # CRITICAL HEURISTIC 1: Skip legitimate kernel APCs
            if (apc_details['apc_mode'] == "Kernel" and 
                self._is_kernel_address(normal_routine) and 
                self._is_kernel_address(kernel_routine)):
                # Legitimate kernel APC - skip detailed analysis
                return threat_info
            
            # CRITICAL HEURISTIC 2: User APC with kernel-space routine (HIGHLY SUSPICIOUS)
            if apc_details['apc_mode'] == "User":
                if normal_routine and self._is_kernel_address(normal_routine):
                    reasons.append("User APC with kernel-space routine (critical)")
                    threat_score += 10
                    threat_info['is_suspicious'] = True
                
                # User APC with no kernel routine suggests direct injection
                if apc_details['inserted'] == "Yes" and not kernel_routine:
                    if normal_routine and not self._find_module_for_address(normal_routine, loaded_modules):
                        reasons.append("User APC injection without module backing")
                        threat_score += 6
            
            # CRITICAL HEURISTIC 3: Kernel APC in user process (unusual)
            elif apc_details['apc_mode'] == "Kernel":
                # If kernel APC has user-space routine, it's injection
                if normal_routine and not self._is_kernel_address(normal_routine):
                    reasons.append("Kernel APC queued to user-space routine (injection)")
                    threat_score += 9
                    threat_info['is_suspicious'] = True
            
            # Check NormalRoutine
            if normal_routine and not self._is_kernel_address(normal_routine):
                normal_analysis = self._analyze_routine(
                    normal_routine, 
                    proc, 
                    protection_values, 
                    loaded_modules,
                    proc_layer,
                    process_name
                )
                
                if normal_analysis['suspicious']:
                    reasons.extend(normal_analysis['reasons'])
                    threat_score += normal_analysis['score']
                    threat_info['vad_protection'] = normal_analysis.get('protection', 'N/A')
                    threat_info['vad_type'] = normal_analysis.get('vad_type', 'N/A')
                    threat_info['module_context'] = normal_analysis.get('module', 'Unknown')
                    threat_info['hexdump'] = normal_analysis.get('hexdump', b"")
            
            # Check KernelRoutine (if in user space)
            if kernel_routine and not self._is_kernel_address(kernel_routine):
                kernel_analysis = self._analyze_routine(
                    kernel_routine, 
                    proc, 
                    protection_values, 
                    loaded_modules,
                    proc_layer,
                    process_name
                )
                
                if kernel_analysis['suspicious']:
                    reasons.extend([f"Kernel: {r}" for r in kernel_analysis['reasons']])
                    threat_score += kernel_analysis['score']
                    
                    # Update threat info if not already set
                    if threat_info['vad_protection'] == 'N/A':
                        threat_info['vad_protection'] = kernel_analysis.get('protection', 'N/A')
                        threat_info['vad_type'] = kernel_analysis.get('vad_type', 'N/A')
                        threat_info['module_context'] = kernel_analysis.get('module', 'Unknown')
                        threat_info['hexdump'] = kernel_analysis.get('hexdump', b"")
            
            # HEURISTIC 4: Cross-APC pattern detection
            pattern_detections = self._detect_malicious_patterns(
                apc_details, normal_routine, kernel_routine, thread_apcs
            )
            if pattern_detections:
                reasons.extend(pattern_detections)
                threat_score += len(pattern_detections) * 2
            
            # HEURISTIC 5: Thread context analysis
            thread_context = self._analyze_thread_context(
                apc_details['thread_obj'], proc, apc_details, context, symbol_table_name
            )
            if thread_context['suspicious_context']:
                reasons.extend(thread_context['context_reasons'])
                threat_score += 2
            
            # HEURISTIC 6: Check against process baseline
            baseline_check = self._check_against_baseline(
                process_name, normal_routine, loaded_modules
            )
            if not baseline_check['matches_baseline'] and baseline_check['confidence'] < 0.5:
                reasons.append("APC does not match process baseline")
                threat_score += 2
            
            # Determine threat level based on score
            if threat_score > 0:
                threat_info['is_suspicious'] = True
                threat_info['threat_score'] = threat_score
                threat_info['reason'] = "; ".join(reasons)
                
                if threat_score >= 10:
                    threat_info['threat_level'] = "CRITICAL"
                elif threat_score >= 8:
                    threat_info['threat_level'] = "HIGH"
                elif threat_score >= 5:
                    threat_info['threat_level'] = "MEDIUM"
                else:
                    threat_info['threat_level'] = "LOW"
        
        except Exception as e:
            vollog.debug(f"Error in threat analysis: {e}")
        
        return threat_info

    def _analyze_routine(
        self, 
        routine_addr: int, 
        proc, 
        protection_values: dict,
        loaded_modules: dict,
        proc_layer,
        process_name: str
    ) -> dict:
        """Analyze a single routine address for suspicious characteristics"""
        
        analysis = {
            'suspicious': False,
            'reasons': [],
            'score': 0,
            'protection': 'N/A',
            'vad_type': 'N/A',
            'module': 'Unknown',
            'hexdump': b""
        }
        
        # Check if in loaded module
        module_info = self._find_module_for_address(routine_addr, loaded_modules)
        if module_info:
            analysis['module'] = module_info['name']
            # Legitimate module - significantly lower suspicion
            # But still check for code caves or other anomalies
        else:
            analysis['reasons'].append("Not in loaded module")
            analysis['score'] += 4
            analysis['module'] = "NO_MODULE"
            analysis['suspicious'] = True
        
        # Check VAD characteristics
        vad_info = self._find_vad_for_address(routine_addr, proc, protection_values)
        if vad_info:
            analysis['protection'] = vad_info['protection']
            analysis['vad_type'] = vad_info['type']
            
            # ENHANCED HEURISTIC: Check for JIT allocation before flagging RWX
            if vad_info['protection'] in self.SUSPICIOUS_PROTECTIONS:
                # Check if this is legitimate JIT
                if self.config.get('enable-jit-detection', True):
                    if self._is_legitimate_jit_allocation(proc, vad_info, loaded_modules, process_name, proc_layer):
                        # JIT allocation - not suspicious
                        analysis['module'] = "JIT_COMPILER"
                        analysis['suspicious'] = False
                        analysis['score'] = 0
                        return analysis
                
                # Not JIT - suspicious RWX
                analysis['reasons'].append(f"RWX memory ({vad_info['protection']})")
                analysis['score'] += 6
                analysis['suspicious'] = True
            
            # Private executable memory without module backing
            if 'Private' in vad_info['type'] and not module_info:
                if 'EXECUTE' in vad_info['protection']:
                    # Check allocation size
                    if vad_info['size'] < 8192:  # Less than 2 pages
                        analysis['reasons'].append("Small private executable allocation (shellcode pattern)")
                        analysis['score'] += 5
                    else:
                        analysis['reasons'].append("Private executable allocation")
                        analysis['score'] += 3
                    analysis['suspicious'] = True
            
            # Read memory for analysis if suspicious
            if analysis['suspicious']:
                try:
                    dump_size = self.config.get('dump-size', 256)
                    actual_dump_size = min(dump_size, 2048)  # Cap at 2KB
                    data = proc_layer.read(routine_addr, actual_dump_size, pad=True)
                    analysis['hexdump'] = data[:actual_dump_size]
                    
                    # ENHANCED HEURISTIC: Shellcode pattern detection
                    has_shellcode, shellcode_detections, shellcode_score = self._contains_shellcode_patterns(
                        analysis['hexdump']
                    )
                    if has_shellcode:
                        analysis['reasons'].extend(shellcode_detections)
                        analysis['score'] += shellcode_score
                    
                    # ENHANCED HEURISTIC: Entropy analysis
                    entropy = self._calculate_entropy(analysis['hexdump'][:256])
                    if entropy > 7.3 and vad_info['size'] < 65536:
                        # High entropy + small size = likely shellcode/packed
                        analysis['reasons'].append(f"High entropy ({entropy:.2f}) in small region")
                        analysis['score'] += 3
                    
                except Exception as e:
                    vollog.debug(f"Error reading memory at {hex(routine_addr)}: {e}")
        
        return analysis

    def _is_legitimate_jit_allocation(
        self, 
        proc, 
        vad_info: dict, 
        loaded_modules: dict, 
        process_name: str,
        proc_layer
    ) -> bool:
        """Detect legitimate JIT compiler memory allocations"""
        
        # Check if process is JIT-enabled
        if process_name.lower() not in self.JIT_PROCESSES:
            return False
        
        # Check if JIT modules are loaded
        has_jit_module = False
        for module in loaded_modules.values():
            if module['name'].lower() in self.JIT_MODULES:
                has_jit_module = True
                break
        
        if not has_jit_module:
            return False
        
        # JIT allocations are typically larger (> 4KB)
        if vad_info.get('size', 0) < 4096:
            return False
        
        # Check entropy - JIT code has high, stable entropy
        try:
            region_start = vad_info['start']
            sample_data = proc_layer.read(region_start, min(vad_info.get('size', 256), 2048), pad=True)
            
            if len(sample_data) >= 256:
                # Calculate entropy variance across windows
                entropy_variance = self._calculate_entropy_variance(sample_data)
                
                if entropy_variance < 0.3:  # Low variance = likely JIT
                    return True
        except:
            pass
        
        return False

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data or len(data) == 0:
            return 0.0
        
        entropy = 0.0
        for i in range(256):
            count = data.count(bytes([i]))
            if count > 0:
                p_x = count / len(data)
                entropy += -p_x * math.log2(p_x)
        
        return entropy

    def _calculate_entropy_variance(self, data: bytes, window_size: int = 256) -> float:
        """Calculate entropy variance across memory region"""
        if len(data) < window_size:
            return 0.0
        
        entropies = []
        for i in range(0, len(data) - window_size, window_size // 2):
            window = data[i:i + window_size]
            entropy = self._calculate_entropy(window)
            entropies.append(entropy)
        
        if not entropies or len(entropies) < 2:
            return 0.0
        
        # Calculate variance
        mean = sum(entropies) / len(entropies)
        variance = sum((e - mean) ** 2 for e in entropies) / len(entropies)
        
        return variance

    def _contains_shellcode_patterns(self, data: bytes) -> Tuple[bool, List[str], int]:
        """Enhanced shellcode pattern detection"""
        if len(data) < 16:
            return False, [], 0
        
        detections = []
        score = 0
        
        # PATTERN 1: NOP sled (6+ consecutive NOPs)
        if b"\x90" * 6 in data:
            nop_count = data.count(b"\x90" * 6)
            detections.append(f"NOP sled detected ({nop_count} sequences)")
            score += 3
        
        # PATTERN 2: GetPC stub (CALL $+5 pattern)
        if b"\xe8\x00\x00\x00\x00" in data:
            detections.append("GetPC stub (position-independent code)")
            score += 4
        
        # PATTERN 3: PEB/TEB access patterns
        peb_patterns = [
            b"\x64\xa1\x30\x00\x00\x00",  # MOV EAX, FS:[0x30]
            b"\x65\x48\x8b\x04\x25",      # MOV RAX, GS:[0x??]
        ]
        for pattern in peb_patterns:
            if pattern in data:
                detections.append("PEB/TEB direct access (shellcode pattern)")
                score += 5
                break
        
        # PATTERN 4: Common shellcode prologue (multiple XORs)
        prologue_patterns = [
            b"\x31\xc0",  # XOR EAX, EAX
            b"\x31\xd2",  # XOR EDX, EDX
            b"\x31\xc9",  # XOR ECX, ECX
        ]
        prologue_count = sum(1 for p in prologue_patterns if p in data)
        if prologue_count >= 2:
            detections.append(f"Shellcode prologue ({prologue_count} register clears)")
            score += 3
        
        # PATTERN 5: Excessive short jumps (obfuscation)
        jmp_count = data.count(b"\xeb")
        if jmp_count > 10:
            detections.append(f"Excessive JMP instructions ({jmp_count})")
            score += 2
        
        # PATTERN 6: Direct API address loading
        if len(data) >= 4 and data[0:1] == b"\xb8":  # MOV EAX, immediate
            detections.append("Direct API address loading")
            score += 2
        
        # PATTERN 7: Stack manipulation sequences
        stack_patterns = [
            b"\x55",      # PUSH EBP
            b"\x8b\xec",  # MOV EBP, ESP
        ]
        if all(p in data[:16] for p in stack_patterns):
            # This is normal function prologue, reduce score
            score -= 1
        
        has_shellcode = score >= 3  # Require multiple indicators
        return has_shellcode, detections, score

    def _analyze_thread_context(
        self, 
        thread, 
        proc, 
        apc_details: dict, 
        context: interfaces.context.ContextInterface, 
        symbol_table_name: str
    ) -> dict:
        """Analyze thread execution context"""
        
        context_info = {
            'thread_state': 'Unknown',
            'is_alertable': False,
            'wait_reason': 'Unknown',
            'suspicious_context': False,
            'context_reasons': []
        }
        
        try:
            # Check thread state
            if hasattr(thread.Tcb, 'State'):
                state = int(thread.Tcb.State)
                if state == 4:  # Terminated
                    context_info['suspicious_context'] = True
                    context_info['context_reasons'].append("APC on terminated thread")
                elif state == 5:  # Waiting
                    context_info['is_alertable'] = True
            
            # Check wait reason
            if hasattr(thread.Tcb, 'WaitReason'):
                wait_reason = int(thread.Tcb.WaitReason)
                if wait_reason > 0 and wait_reason != 6:  # Not UserRequest
                    context_info['suspicious_context'] = True
                    context_info['context_reasons'].append("APC during non-alertable wait")
        
        except Exception as e:
            vollog.debug(f"Error analyzing thread context: {e}")
        
        return context_info

    def _is_kernel_address(self, addr: int) -> bool:
        """Check if address is in kernel space (supports both 32-bit and 64-bit)"""
        # For 64-bit systems: kernel space starts at 0xFFFF800000000000
        # Some systems use 0xF80000000000 and above
        if addr >= 0xF80000000000:
            return True
        
        # For 32-bit systems: kernel space typically starts at 0x80000000
        # Check if address looks like 32-bit kernel address
        if 0x80000000 <= addr <= 0xFFFFFFFF:
            return True
        
        return False
    
    def _detect_malicious_patterns(
        self, 
        apc_details: dict, 
        normal_routine: int, 
        kernel_routine: int,
        thread_apcs: list
    ) -> List[str]:
        """Detect malicious APC usage patterns"""
        detections = []
        
        # PATTERN 1: APC chain (multiple APCs in single thread)
        if len(thread_apcs) > 3:
            detections.append(f"APC chain detected ({len(thread_apcs)} APCs)")
        
        # PATTERN 2: User APC with suspicious characteristics
        if apc_details['apc_mode'] == "User":
            if apc_details['inserted'] == "Yes" and normal_routine and kernel_routine == 0:
                # Common injection pattern
                pass  # Already scored in main analysis
        
        # PATTERN 3: Kernel APC in user process with both routines
        if apc_details['apc_mode'] == "Kernel":
            # Only flag if NOT kernel addresses (legitimate check already done)
            if not (self._is_kernel_address(normal_routine) and self._is_kernel_address(kernel_routine)):
                if normal_routine and kernel_routine:
                    detections.append("Kernel APC with both routines in user space")
        
        # PATTERN 4: Both APC levels pending simultaneously
        if apc_details['user_apc_pending'] and apc_details['kernel_apc_pending']:
            detections.append("Both user and kernel APC pending")
        
        # PATTERN 5: Recursive APC pattern
        if len(thread_apcs) > 1:
            routine_addrs = [apc.get('normal_routine', 0) for apc in thread_apcs]
            if normal_routine in [apc.get('kernel_routine', 0) for apc in thread_apcs]:
                detections.append("Recursive APC pattern (routine points to APC)")
        
        # PATTERN 6: APC mode mismatch
        if apc_details['apc_mode'] == "User" and kernel_routine != 0:
            if not self._is_kernel_address(kernel_routine):
                detections.append("User-mode APC with user-space kernel routine")
        
        return detections

    def _check_against_baseline(
        self, 
        process_name: str, 
        routine_addr: int, 
        loaded_modules: dict
    ) -> dict:
        """Check APC characteristics against process baseline"""
        
        baseline = self.PROCESS_APC_BASELINES.get(process_name.lower())
        
        if not baseline:
            # Unknown process - no baseline
            return {'matches_baseline': False, 'confidence': 0.0}
        
        # Check if routine is in typical modules for this process
        module_info = self._find_module_for_address(routine_addr, loaded_modules)
        
        if module_info:
            module_name = module_info['name'].lower()
            if module_name in baseline['typical_modules']:
                return {'matches_baseline': True, 'confidence': 0.95}
            else:
                return {'matches_baseline': False, 'confidence': 0.6}
        
        # Not in any module - doesn't match baseline
        return {'matches_baseline': False, 'confidence': 0.2}

    def _get_loaded_modules_detailed(self, context, proc) -> dict:
        """Get detailed loaded module information"""
        modules = {}
        try:
            if hasattr(proc, 'Peb') and proc.Peb:
                peb = proc.Peb.dereference()
                if hasattr(peb, 'Ldr') and peb.Ldr:
                    ldr = peb.Ldr.dereference()
                    if hasattr(ldr, 'InLoadOrderModuleList'):
                        for entry in ldr.InLoadOrderModuleList.to_list(
                            "_LDR_DATA_TABLE_ENTRY", "InLoadOrderLinks"
                        ):
                            try:
                                base_addr = int(entry.DllBase)
                                size = int(entry.SizeOfImage)
                                
                                # Get module name
                                name = "Unknown"
                                if hasattr(entry, 'BaseDllName'):
                                    try:
                                        name = entry.BaseDllName.get_string()
                                    except:
                                        pass
                                
                                if base_addr and size:
                                    modules[base_addr] = {
                                        'name': name,
                                        'base': base_addr,
                                        'end': base_addr + size,
                                        'size': size
                                    }
                            except:
                                continue
        except:
            pass
        return modules

    def _find_module_for_address(self, addr: int, modules: dict) -> Optional[dict]:
        """Find which module contains an address"""
        for base, info in modules.items():
            if info['base'] <= addr < info['end']:
                return info
        return None

    def _find_vad_for_address(self, addr: int, proc, protection_values: dict) -> Optional[dict]:
        """Find VAD information for an address"""
        try:
            for vad in proc.get_vad_root().traverse():
                vad_start = vad.get_start()
                vad_end = vad_start + vad.get_size()
                
                if vad_start <= addr < vad_end:
                    protection = vad.get_protection(
                        protection_values, 
                        vadinfo.winnt_protections
                    )
                    
                    # Determine VAD type
                    vad_type = "Unknown"
                    if hasattr(vad, 'VadType'):
                        vad_type = str(vad.VadType)
                    
                    return {
                        'start': vad_start,
                        'end': vad_end,
                        'size': vad.get_size(),
                        'protection': protection,
                        'type': vad_type
                    }
        except Exception as e:
            vollog.debug(f"Error finding VAD for address {hex(addr)}: {e}")
        
        return None