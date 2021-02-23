# Angr doesn't currently support reading multiple things with scanf (Ex: 
# scanf("%u %u).) You will have to tell the simulation engine to begin the
# program after scanf is called and manually inject the symbols into registers.

import angr
import claripy
import sys

def main():
  path_to_binary = './03_angr_symbolic_registers'
  project = angr.Project(path_to_binary)

  # Sometimes, you want to specify where the program should start. The variable
  # start_address will specify where the symbolic execution engine should begin.
  # Note that we are using blank_state, not entry_state.
  # (!)
  start_address = 0x080494F4  # :integer (probably hexadecimal)
  initial_state = project.factory.blank_state(addr=start_address)

  # Create a symbolic bitvector (the datatype Angr uses to inject symbolic
  # values into the binary.) The first parameter is just a name Angr uses
  # to reference it. 
  # You will have to construct multiple bitvectors. Copy the two lines below
  # and change the variable names. To figure out how many (and of what size)
  # you need, dissassemble the binary and determine the format parameter passed
  # to scanf.
  # (!)
  pass1 = claripy.BVS('pass1', 4 * 8)
  pass2 = claripy.BVS('pass2', 4 * 8)
  pass3 = claripy.BVS('pass3', 4 * 8)

  # Set a register to a symbolic value. This is one way to inject symbols into
  # the program.
  # initial_state.regs stores a number of convenient attributes that reference
  # registers by name. For example, to set eax to password0, use:
  #
  # initial_state.regs.eax = password0
  #
  # You will have to set multiple registers to distinct bitvectors. Copy and
  # paste the line below and change the register. To determine which registers
  # to inject which symbol, dissassemble the binary and look at the instructions
  # immediately following the call to scanf.
  # (!)
  initial_state.regs.eax=pass1
  initial_state.regs.ebx = pass2
  initial_state.regs.edx = pass3

  simulation = project.factory.simgr(initial_state)

  def is_successful(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return b'Good Job.' in stdout_output

  def should_abort(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return b'Try again.' in stdout_output

  simulation.explore(find=is_successful, avoid=should_abort)

  if simulation.found:
    solution_state = simulation.found[0]

    # Solve for the symbolic values. If there are multiple solutions, we only
    # care about one, so we can use eval, which returns any (but only one)
    # solution. Pass eval the bitvector you want to solve for.
    # (!)
    p1 = solution_state.se.eval(pass1)
    p2 = solution_state.se.eval(pass2)
    p3 = solution_state.se.eval(pass3)


    # Aggregate and format the solutions you computed above, and then print
    # the full string. Pay attention to the order of the integers, and the
    # expected base (decimal, octal, hexadecimal, etc).
    print('{:x}  {:x}  {:x}'.format(p1,p2,p3))

  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main()
