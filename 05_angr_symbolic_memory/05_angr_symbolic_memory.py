import angr
import claripy


def main():
    path_to_binary = './05_angr_symbolic_memory'
    project = angr.Project(path_to_binary)

    start_address = 0x08049288
    initial_state = project.factory.blank_state(addr=start_address)

    # The binary is calling scanf("%8s %8s %8s %8s").
    # (!)
    pass1 = claripy.BVS('pass1', 8 * 8)
    pass2 = claripy.BVS('pass2', 8 * 8)
    pass3 = claripy.BVS('pass3', 8 * 8)
    pass4 = claripy.BVS('pass4', 8 * 8)

    # Determine the address of the global variable to which scanf writes the user
    # input. The function 'initial_state.memory.store(address, value)' will write
    # 'value' (a bitvector) to 'address' (a memory location, as an integer.) The
    # 'address' parameter can also be a bitvector (and can be symbolic!).
    # (!)
    pass1_addr = 0x08235400
    pass2_addr = 0x08235408
    pass3_addr = 0x08235410
    pass4_addr = 0x08235418
    initial_state.memory.store(pass1_addr, pass1)
    initial_state.memory.store(pass2_addr, pass2)
    initial_state.memory.store(pass3_addr, pass3)
    initial_state.memory.store(pass4_addr, pass4)

    simulation = project.factory.simgr(initial_state)

    simulation.explore(find=0x080492F1, avoid=0x080492DF)

    if simulation.found:
      solution_state = simulation.found[0]

      # Solve for the symbolic values. We are trying to solve for a string.
      # Therefore, we will use eval, with named parameter cast_to=str
      # which returns a string instead of an integer.
      # (!)
      p1 = solution_state.se.eval(pass1, cast_to=bytes).decode('utf-8')
      p2 = solution_state.se.eval(pass2, cast_to=bytes).decode('utf-8')
      p3 = solution_state.se.eval(pass3, cast_to=bytes).decode('utf-8')
      p4 = solution_state.se.eval(pass4, cast_to=bytes).decode('utf-8')

      print('{} {} {} {}'.format(p1,p2,p3,p4))
    else:
      raise Exception('Could not find the solution')


if __name__ == '__main__':
  main()
