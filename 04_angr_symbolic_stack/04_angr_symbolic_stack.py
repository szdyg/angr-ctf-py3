# This challenge will be more challenging than the previous challenges that you
# have encountered thus far. Since the goal of this CTF is to teach symbolic
# execution and not how to construct stack frames, these comments will work you
# through understanding what is on the stack.
#   ! ! !
# IMPORTANT: Any addresses in this script aren't necessarily right! Dissassemble
#            the binary yourself to determine the correct addresses!
#   ! ! !

import angr
import claripy

def main():
  path_to_binary = './04_angr_symbolic_stack'
  project = angr.Project(path_to_binary)

  start_address = 0x0804938E
  initial_state = project.factory.blank_state(addr=start_address)


  initial_state.regs.ebp=initial_state.regs.esp
  initial_state.regs.esp -=8

  pass1 = claripy.BVS('pass1', 4 * 8)
  pass2 = claripy.BVS('pass2', 4 * 8)

  initial_state.stack_push(pass1)
  initial_state.stack_push(pass2)

  simulation = project.factory.simgr(initial_state)

  simulation.explore(find=0x080493DB, avoid=0x080493C6)

  if simulation.found:
    solution_state = simulation.found[0]
    p1 = solution_state.se.eval(pass1)
    p2 = solution_state.se.eval(pass2)

    print('{} {}'.format(p1,p2))
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main()
