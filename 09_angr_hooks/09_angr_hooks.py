# This level performs the following computations:
#
# 1. Get 16 bytes of user input and encrypt it.
# 2. Save the result of check_equals_AABBCCDDEEFFGGHH (or similar)
# 3. Get another 16 bytes from the user and encrypt it.
# 4. Check that it's equal to a predefined password.
#
# The ONLY part of this program that we have to worry about is #2. We will be
# replacing the call to check_equals_ with our own version, using a hook, since
# check_equals_ will run too slowly otherwise.

import angr
import claripy
import sys


def main():
    path_to_binary = './09_angr_hooks'
    project = angr.Project(path_to_binary)

    # Since Angr can handle the initial call to scanf, we can start from the beginning.
    initial_state = project.factory.entry_state()

    # Hook the address of where check_equals_ is called.
    check_equals_called_address = 0x0804933A

    # The length parameter in angr.Hook specifies how many bytes the execution
    # engine should skip after completing the hook. This will allow hooks to
    # replace certain instructions (or groups of instructions). Determine the
    # instructions involved in calling check_equals_, and then determine how many
    # bytes are used to represent them in memory. This will be the skip length.
    # (!)
    instruction_to_skip_length = 5

    @project.hook(check_equals_called_address, length=instruction_to_skip_length)
    def skip_check_equals_(state):
        param1 = 0x0804C054
        param2 = 0x10
        check_string = 'ANZXXKGKUIDGWTEK'  # :string

        input_string = state.memory.load(param1, param2)

        # gcc uses eax to store the return value, if it is an integer. We need to
        # set eax to 1 if check_against_string == user_input_string and 0 otherwise.
        # However, since we are describing an equation to be used by z3 (not to be
        # evaluated immediately), we cannot use Python if else syntax. Instead, we
        # have to use claripy's built in function that deals with if statements.
        # claripy.If(expression, ret_if_true, ret_if_false) will output an
        # expression that evaluates to ret_if_true if expression is true and
        # ret_if_false otherwise.
        # Think of it like the Python "value0 if expression else value1".
        state.regs.eax = claripy.If(input_string == check_string, claripy.BVV(1, 32), claripy.BVV(0, 32))


    simulation = project.factory.simgr(initial_state)
    simulation.explore(find=0x080493EC, avoid=0x080493DA)

    if simulation.found:
        solution_state = simulation.found[0]
        solution = solution_state.posix.dumps(sys.stdin.fileno())
        print(solution)
    else:
        raise Exception('Could not find the solution')


if __name__ == '__main__':
    main()
