addedFunctions = ['_start', 'deregister_tm_clones', 'register_tm_clones', '__do_global_dtors_aux', '__x86.get_pc_thunk.bx', 'frame_dummy', '__libc_csu_init', '__libc_csu_fini', '__x86.get_pc_thunk.bx']
addedFunctions_armel = ['.init_proc', 'abort', '__libc_start_main', '__gmon_start__', 'printf', 'raise', '_start', 'call_gmon_start', '__do_global_dtors_aux', 'frame_dummy', '__divsi3', '__aeabi_idivmod', '__div0', '__libc_csu_fini', '__libc_csu_init', 'term_proc']
addedFunctions_mips32 = ['__start','_ftext','sub_40051C','__do_global_dtors_aux','frame_dummy','__libc_csu_fini','__libc_csu_init','__do_global_ctors_aux']
functionListStruct = []
blockListStruct = []
dataTransferInstr = ['mov','push','pop','xchg','in','out','xlat','lea','lds','les','lahf','sahf','pushf','popf']
arithmeticInstr = ['add','adc','inc','dec','sub','sbb','neg','cmp','mul','imul','div','idiv','cbw','cwd','aaa','aas','aam','aad','daa','das']
logicAndShiftBitInstr=['and','or','xor','not','test','shr','shl','sal','sar','ror','rol','rcl','rcr']
programTransferInstr=['jmp','je','jz','jne','jnz','js','jns','jp','jpe','jnp','jpo','jo','jno','jc','jnc','jb','jnae','ja','jnbe','jbe','jna','jg','jnle','jge','jnl','jl','jnge','jle','jng','call','ret','retf','jae','jnb','loop','loope','loopz','loopne','loopnz','jcxz','jecxz','int','into','iret','retn']#add a instr:retn
allTransferInstr = ['mov','push','pop','xchg','in','out','xlat','lea','lds','les','lahf','sahf','pushf','popf','jmp','je','jz','jne','jnz','js','jns','jp','jpe','jnp','jpo','jo','jno','jc','jnc','jb','jnae','ja','jnbe','jbe','jna','jg','jnle','jge','jnl','jl','jnge','jle','jng','call','ret','retf','jae','jnb','loop','loope','loopz','loopne','loopnz','jcxz','jecxz','int','into','iret']

blockNum = 0
