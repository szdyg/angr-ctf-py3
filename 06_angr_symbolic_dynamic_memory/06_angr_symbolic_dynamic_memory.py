import angr
import claripy
import sys


def main():
    path_to_binary = './06_angr_symbolic_dynamic_memory'
    project = angr.Project(path_to_binary)

    start_address = 0x080492DF
    initial_state = project.factory.blank_state(addr=start_address)

    # The binary is calling scanf("%8s %8s").
    # (!)
    pass1 = claripy.BVS('pass1', 8 * 8)
    pass2 = claripy.BVS('pass2', 8 * 8)

    # debug by ida
    buf1 = 0x09DA8170
    buf2 = 0x09DA8160

    initial_state.memory.store(buf1, pass1)
    initial_state.memory.store(buf2, pass2)

    buf1_addr = 0x0823541C
    buf2_addr = 0x08235424
    # angr 写入整形数据，指定大小端endness
    initial_state.memory.store(buf1_addr, buf1, endness=project.arch.memory_endness)
    initial_state.memory.store(buf2_addr, buf2, endness=project.arch.memory_endness)
    simulation = project.factory.simgr(initial_state)
    simulation.explore(find=0x080493A2, avoid=0x08049390)

    if simulation.found:
        solution_state = simulation.found[0]
        p1 = solution_state.se.eval(pass1,cast_to=bytes)
        p2 = solution_state.se.eval(pass2,cast_to=bytes)

        print('{} {}'.format(p1, p2))
    else:
        raise Exception('Could not find the solution')


if __name__ == '__main__':
    main()
