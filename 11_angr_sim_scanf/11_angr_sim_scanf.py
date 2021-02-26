# This time, the solution involves simply replacing scanf with our own version,
# since Angr does not support requesting multiple parameters with scanf.

import angr
import claripy
import sys


def main():
    path_to_binary = './11_angr_sim_scanf'
    project = angr.Project(path_to_binary)

    initial_state = project.factory.entry_state()

    class hook_scanf(angr.SimProcedure):
        def run(self, format_string, param0, param1):
            buf0 = claripy.BVS('buf0', 4 * 8)
            buf1 = claripy.BVS('buf1', 4 * 8)

            # The scanf function writes user input to the buffers to which the
            # parameters point.
            self.state.memory.store(param0, buf0, endness=project.arch.memory_endness)
            self.state.memory.store(param1, buf1, endness=project.arch.memory_endness)

            self.state.globals['buf0'] = buf0
            self.state.globals['buf1'] = buf1

    scanf_name = '__isoc99_scanf'
    project.hook_symbol(scanf_name, hook_scanf())

    simulation = project.factory.simgr(initial_state)


    simulation.explore(find=0x080508BD, avoid=0x080508AE)

    if simulation.found:
        solution_state = simulation.found[0]
        buf0 = solution_state.globals['buf0']
        buf1 = solution_state.globals['buf1']
        p1 = solution_state.solver.eval(buf0)
        p2 = solution_state.solver.eval(buf1)
        print('{} {}'.format(p1,p2))
    else:
        raise Exception('Could not find the solution')


def main2():
    bin_path = './11_angr_sim_scanf'
    project = angr.Project(bin_path)
    init_state=project.factory.entry_state()
    sm=project.factory.simgr(init_state)
    sm.explore(find=0x080508BD, avoid=0x080508AE)

    if sm.found:
        solution_state = sm.found[0]
        print(solution_state.posix.dumps(sys.stdin.fileno()))


if __name__ == '__main__':
    main()