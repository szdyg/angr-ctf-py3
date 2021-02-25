# This challenge is similar to the previous one. It operates under the same
# premise that you will have to replace the check_equals_ function. In this 
# case, however, check_equals_ is called so many times that it wouldn't make 
# sense to hook where each one was called. Instead, use a SimProcedure to write
# your own check_equals_ implementation and then hook the check_equals_ symbol 
# to replace all calls to scanf with a call to your SimProcedure.
#
# You may be thinking: 
#   Why can't I just use hooks? The function is called many times, but if I hook
#   the address of the function itself (rather than the addresses where it is 
#   called), I can replace its behavior everywhere. Furthermore, I can get the
#   parameters by reading them off the stack (with memory.load(regs.esp + xx)),
#   and return a value by simply setting eax! Since I know the length of the 
#   function in bytes, I can return from the hook just before the 'ret'
#   instruction is called, which will allow the program to jump back to where it
#   was before it called my hook.
# If you thought that, then congratulations! You have just invented the idea of
# SimProcedures! Instead of doing all of that by hand, you can let the already-
# implemented SimProcedures do the boring work for you so that you can focus on
# writing a replacement function in a Pythonic way.
# As a bonus, SimProcedures allow you to specify custom calling conventions, but
# unfortunately it is not covered in this CTF.

import angr
import claripy
import sys


def main():
    path_to_binary = './10_angr_simprocedures'
    project = angr.Project(path_to_binary)

    initial_state = project.factory.entry_state()

    class hook_check(angr.SimProcedure):
        def run(self, param1, param2):
            input_bvs = self.state.memory.load(param1, param2)
            check_string = 'ANZXXKGKUIDGWTEK'
            return claripy.If(input_bvs == check_string, claripy.BVV(1, 32), claripy.BVV(0, 32))

    func_name = 'check_equals_ANZXXKGKUIDGWTEK'
    project.hook_symbol(func_name, hook_check())

    simulation = project.factory.simgr(initial_state)

    simulation.explore(find=0x0804B5A5, avoid=0x0804B596)

    if simulation.found:
        solution_state = simulation.found[0]
        solution = solution_state.posix.dumps(sys.stdin.fileno())
        print(solution)
    else:
        raise Exception('Could not find the solution')


if __name__ == '__main__':
    main()
