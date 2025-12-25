# Donated under Volatility Foundation, Inc. Individual Contributor Licensing Agreement

import logging
from typing import List, Generator, Optional

from volatility3.framework import interfaces, renderers, constants, logging as vollog
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols import windows
from volatility3.plugins.windows import pslist

class APCWatch(interfaces.plugins.PluginInterface):
    """Detects Asynchronous Procedure Calls (APC) for each process"""

    _required_framework_version = (2, 0, 0)
    _version = (3, 0, 0)

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
                name="show-kernel-apcs",
                description="Include kernel-mode APCs in output",
                default=False,
                optional=True
            )
        ]

    def run(self):
        """
        Generate APC information based on _KAPC and _KAPC_STATE structures
        """
        kernel = self.context.modules[self.config['kernel']]
        symbol_table_name = kernel.symbol_table_name

        # Get configuration options
        show_kernel_apcs = self.config.get("show-kernel-apcs", False)

        # Create PID filter
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))

        # Columns for output
        columns = [
            ("Process Name", str),
            ("PID", int),
            ("TID", int),
            ("KernelRoutine", format_hints.Hex),
            ("NormalRoutine", format_hints.Hex),
            ("APCMode", str),
            ("Inserted", bool),
            ("KernelAPC", bool),
            ("SpecialAPC", bool),
            ("KernelAPCPending", bool),
            ("UserAPCPending", bool)
        ]

        return renderers.TreeGrid(
            columns, 
            self._apc_generator(symbol_table_name, filter_func, show_kernel_apcs)
        )

    def _apc_generator(self, symbol_table_name: str, filter_func, 
                      show_kernel_apcs: bool) -> Generator[tuple, None, None]:
        """
        Generate detailed APC entries from thread structures
        """
        # Use the correct Volatility 3 method signature: context, kernel_module_name, filter_func
        for proc in pslist.PsList.list_processes(self.context, self.config['kernel'], filter_func):
            process_name = proc.ImageFileName.cast(
                "string", max_length=256, errors="replace"
            )
            process_id = int(proc.UniqueProcessId)
            
            try:
                for thread in proc.ThreadListHead.to_list(
                    f"{symbol_table_name}{constants.BANG}_ETHREAD", 
                    "ThreadListEntry"
                ):
                    try:
                        thread_id = int(thread.Cid.UniqueThread)
                        
                        # Accessing KAPC_STATE
                        apc_state = thread.Tcb.ApcState

                        # Check if ApcListHead exists and has entries
                        if hasattr(apc_state, 'ApcListHead'):
                            for list_index, apc_list in enumerate(apc_state.ApcListHead):
                                try:
                                    for apc in apc_list.to_list(
                                        f"{symbol_table_name}{constants.BANG}_KAPC", 
                                        "ApcListEntry"
                                    ):
                                        try:
                                            # Safely extract APC information
                                            kernel_routine = 0
                                            normal_routine = 0
                                            apc_mode = "Unknown"
                                            inserted = False
                                            
                                            if hasattr(apc, 'KernelRoutine') and apc.KernelRoutine:
                                                kernel_routine = apc.KernelRoutine.vol.offset
                                            
                                            if hasattr(apc, 'NormalRoutine') and apc.NormalRoutine:
                                                normal_routine = apc.NormalRoutine.vol.offset
                                            
                                            if hasattr(apc, 'ApcMode'):
                                                apc_mode = "Kernel" if apc.ApcMode == 0 else "User"
                                            
                                            if hasattr(apc, 'Inserted'):
                                                inserted = bool(apc.Inserted)
                                            
                                            # Filter kernel APCs if flag not set
                                            if not show_kernel_apcs and apc_mode == "Kernel":
                                                continue
                                            
                                            # Safely extract APC state flags
                                            kernel_apc = False
                                            special_apc = False
                                            kernel_apc_pending = False
                                            user_apc_pending = False
                                            
                                            if hasattr(apc_state, 'InProgressFlags'):
                                                kernel_apc = bool(apc_state.InProgressFlags & 0x1)
                                                special_apc = bool(apc_state.InProgressFlags & 0x2)
                                            
                                            if hasattr(apc_state, 'KernelApcPending'):
                                                kernel_apc_pending = bool(apc_state.KernelApcPending)
                                            
                                            if hasattr(apc_state, 'UserApcPending'):
                                                user_apc_pending = bool(apc_state.UserApcPending)

                                            yield (0, (
                                                process_name,
                                                process_id,
                                                thread_id,
                                                format_hints.Hex(kernel_routine),
                                                format_hints.Hex(normal_routine),
                                                apc_mode,
                                                inserted,
                                                kernel_apc,
                                                special_apc,
                                                kernel_apc_pending,
                                                user_apc_pending
                                            ))
                                        
                                        except Exception as apc_error:
                                            vollog.debug(f"Error processing APC in thread {thread_id}: {apc_error}")
                                            continue
                                
                                except Exception as list_error:
                                    vollog.debug(f"Error processing APC list {list_index} in thread {thread_id}: {list_error}")
                                    continue
                    
                    except Exception as thread_error:
                        vollog.debug(f"Error processing thread: {thread_error}")
                        continue
            
            except Exception as proc_error:
                vollog.debug(f"Error processing process {process_name}: {proc_error}")
                continue