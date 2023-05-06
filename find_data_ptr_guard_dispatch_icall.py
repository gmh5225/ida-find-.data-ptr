import idautils 
import idc 
import idaapi 

# Get the start and end addresses of .data segment 
data_seg = idaapi.get_segm_by_name('.data') 
if data_seg: 
    data_start, data_end = data_seg.start_ea, data_seg.end_ea 
else: 
    print("Error: .data segment not found.") 
    exit() 

global_vars = {} 

# Traverse all functions in the IDB 
for function_ea in idautils.Functions(): 
    # Traverse all instruction addresses in the current function 
    for instruction_ea in idautils.FuncItems(function_ea): 
        # Check if the instruction operates on a memory location 
        if idc.is_loaded(idc.get_operand_value(instruction_ea, 1)): 
            # Get the segment address of the memory location 
            seg_ea = idaapi.getseg(idc.get_operand_value(instruction_ea, 1)).start_ea 

            # Check if the segment is the .data segment 
            if seg_ea == data_start: 
                # Get the name of the global variable being accessed 
                global_var_name = idc.get_name(idc.get_operand_value(instruction_ea, 1)) 

                # If the global variable is not already in the dictionary, add it 
                if global_var_name not in global_vars: 
                    global_vars[global_var_name] = {'refs': [], 'calls': []} 

                # Add the current instruction address to the list of references for the current global variable 
                global_vars[global_var_name]['refs'].append(instruction_ea) 

                # Traverse the next 10 instructions or until a call to '_guard_dispatch_icall' is found
                next_ea = instruction_ea;
                for _ in range(10):                
                    # Get the address of the next instruction after the current one
                    call_instr_ea = next_ea + idaapi.get_item_size(next_ea) 
                    call_ea = idc.get_operand_value(call_instr_ea, 0)          
                    # Check if the next instruction is a call instruction and the called function is '_guard_dispatch_icall'
                    called_func_name = idaapi.get_func_name(call_ea)
                    if idaapi.is_call_insn(call_instr_ea) and called_func_name == '_guard_dispatch_icall':
                        # Add the current instruction address to the list of calls for the current global variable
                        func = idaapi.get_func(call_ea)
                        if func:
                            global_vars[global_var_name]['calls'].append((call_ea, call_instr_ea))
                        break

                    # Update the value of next_ea with the address of the next instruction
                    next_ea = call_instr_ea

# Output the results to the console 
for global_var_name, info_dict in global_vars.items(): 
    # Check if the global variable has any calls to the function '_guard_dispatch_icall' and is not '__security_cookie'
    should_print = info_dict['calls'] and global_var_name != '__security_cookie'

    if should_print:
        # Print the name of the global variable
        print(".data ptr with _guard_dispatch_icall: %s" % global_var_name) 
        
        # Traverse the list of call locations for this global variable
        for call_ea, call_instr_ea in info_dict['calls']: 
            # Get the function containing the call instruction
            func = idaapi.get_func(call_instr_ea) 
            func_ea = func.start_ea 
            func_name = idaapi.get_func_name(func_ea) 
            
            # Print the name of the function and the address where it was called
            print("    Function %s (called at: 0x%x)" % (func_name, call_instr_ea))

