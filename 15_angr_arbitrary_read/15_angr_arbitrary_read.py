import angr
import claripy
import sys


def main():
    path_to_binary = './15_angr_arbitrary_read'
    project = angr.Project(path_to_binary, auto_load_libs=False)
    initial_state = project.factory.entry_state()

    class scanf_hook(angr.SimProcedure):
        def run(self, format_string, param0,param1):
            scanf0 = claripy.BVS('scanf0', 4*8)
            scanf1 = claripy.BVS('scanf1', 20*8)
            for char in scanf1.chop(bits=8):
                self.state.add_constraints(char >= 'A', char <= 'Z')

            self.state.memory.store(param0, scanf0, endness=project.arch.memory_endness)
            self.state.memory.store(param1, scanf1, endness=project.arch.memory_endness)

            self.state.globals['scanf0'] = scanf0
            self.state.globals['scanf1'] = scanf1


    scanf_symbol = '__isoc99_scanf'  # :string
    project.hook_symbol(scanf_symbol, scanf_hook())

    def check_puts(state):
        puts_parameter = state.memory.load(state.regs.esp + 4, 4, endness=project.arch.memory_endness)
        if state.se.symbolic(puts_parameter):
            good_job_string_address = 0x484F4A47
            is_vulnerable_expression = puts_parameter == good_job_string_address
            copied_state = state.copy()
            copied_state.add_constraints(is_vulnerable_expression)

            if copied_state.satisfiable():
                state.add_constraints(is_vulnerable_expression)
                return True
            else:
                return False
        else:
            return False

    simulation = project.factory.simgr(initial_state)

    def is_successful(state):
        puts_address =0x08048370
        if state.addr == puts_address:
            # Return True if we determine this call to puts is exploitable.
            return check_puts(state)
        else:
            # We have not yet found a call to puts; we should continue!
            return False

    simulation.explore(find=is_successful)

    if simulation.found:
        solution_state = simulation.found[0]

        scanf0 = solution_state.globals['scanf0']
        scanf1 = solution_state.globals['scanf1']

        p0 = solution_state.solver.eval(scanf0)
        p1 = solution_state.solver.eval(scanf1, cast_to=bytes)
        print('{} {}'.format(p0, p1[::-1]))


    else:
        raise Exception('Could not find the solution')

if __name__ == '__main__':
    main()
