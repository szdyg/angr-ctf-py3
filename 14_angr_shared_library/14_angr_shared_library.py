# The shared library has the function validate, which takes a string and returns
# either true (1) or false (0). The binary calls this function. If it returns
# true, the program prints "Good Job." otherwise, it prints "Try again."
#
# Note: When you run this script, make sure you run it on 
# lib14_angr_shared_library.so, not the executable. This level is intended to 
# teach how to analyse binary formats that are not typical executables.

import angr
import claripy
import sys


def main():
    path_to_binary = './lib14_angr_shared_library.so'

    # The shared library is compiled with position-independent code. You will need
    # to specify the base address. All addresses in the shared library will be
    # base + offset, where offset is their address in the file.
    # (!)

    project = angr.Project(path_to_binary)
    base = project.entry - 0x500

    # Initialize any symbolic values here; you will need at least one to pass to
    # the validate function.

    # Begin the state at the beginning of the validate function, as if it was
    # called by the program. Determine the parameters needed to call validate and
    # replace 'parameters...' with bitvectors holding the values you wish to pass.
    # Recall that 'claripy.BVV(value, size_in_bits)' constructs a bitvector
    # initialized to a single value.
    # Remember to add the base value you specified at the beginning to the
    # function address!
    # Hint: int validate(char* buffer, int length) { ...
    # Another hint: the password is 8 bytes long.
    # (!)
    mem_addr = claripy.BVV(0x200000, 32)
    validate_function_address = 0x000006D7 + base
    initial_state = project.factory.call_state(validate_function_address, mem_addr, claripy.BVV(8, 32))

    pass1 = claripy.BVS('pass1', 8 * 8)
    initial_state.memory.store(mem_addr, pass1)


    # You will need to add code to inject a symbolic value into the program at the
    # end of the function that constrains eax to equal true (value of 1) just
    # before the function returns. There are multiple ways to do this:
    # 1. Use a hook.
    # 2. Search for the address just before the function returns and then
    #    constrain eax (this may require putting code elsewhere)
    ...

    simulation = project.factory.simgr(initial_state)

    success_address = base+0x783
    simulation.explore(find=success_address)

    if simulation.found:
        for solution_state in simulation.found:
            solution_state.add_constraints(solution_state.regs.eax != 0)
            p1 = solution_state.solver.eval(pass1, cast_to=bytes)
            print(p1)

        # Determine where the program places the return value, and constrain it so
        # that it is true. Then, solve for the solution and print it.
        # (!)
    else:
        raise Exception('Could not find the solution')


if __name__ == '__main__':
    main()
