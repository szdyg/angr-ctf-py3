import angr
import claripy
import sys


def main():
    path_to_binary = './16_angr_arbitrary_write'
    project = angr.Project(path_to_binary)

    initial_state = project.factory.entry_state()

    class ReplacementScanf(angr.SimProcedure):
        def run(self, format_string, param0, param1):
            scanf0 = claripy.BVS('scanf0', 4 * 8)
            scanf1 = claripy.BVS('scanf1', 20 * 8)
            for char in scanf1.chop(bits=8):
                self.state.add_constraints(char >= '0', char <= 'z')

            self.state.memory.store(param0, scanf0, endness=project.arch.memory_endness)
            self.state.memory.store(param1, scanf1, endness=project.arch.memory_endness)

            self.state.globals['solutions'] = (scanf0, scanf1)

    scanf_symbol = '__isoc99_scanf'
    project.hook_symbol(scanf_symbol, ReplacementScanf())

    def check_strncpy(state):
        strncpy_dest = state.memory.load(state.regs.esp + 4, 4, endness=project.arch.memory_endness)
        strncpy_src = state.memory.load(state.regs.esp + 8, 4, endness=project.arch.memory_endness)
        strncpy_len = state.memory.load(state.regs.esp + 12, 4, endness=project.arch.memory_endness)

        src_contents = state.memory.load(strncpy_src, strncpy_len)

        if state.solver.symbolic(src_contents) and state.solver.symbolic(strncpy_dest):
            password_string = 'NDYNWEUJ'  # :string
            buffer_address = 0x57584344  # :integer, probably in hexadecimal
            does_src_hold_password = src_contents[-1:-64] == password_string
            does_dest_equal_buffer_address = strncpy_dest == buffer_address

            if state.satisfiable(extra_constraints=(does_src_hold_password, does_dest_equal_buffer_address)):
                state.add_constraints(does_src_hold_password, does_dest_equal_buffer_address)
                return True
            else:
                return False
        else:
            return False

    simulation = project.factory.simgr(initial_state)

    def is_successful(state):
        strncpy_address = 0x08048410
        if state.addr == strncpy_address:
            return check_strncpy(state)
        else:
            return False

    simulation.explore(find=is_successful)

    if simulation.found:
        solution_state = simulation.found[0]
        scanf0, scanf1 = solution_state.globals['solutions']
        p0 = (solution_state.solver.eval(scanf0))
        p1 = (solution_state.solver.eval(scanf1, cast_to=bytes))
        print('{} {}'.format(p0, p1[::-1]))

    else:
        raise Exception('Could not find the solution')


if __name__ == '__main__':
    main()
