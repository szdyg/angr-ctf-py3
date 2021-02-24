# This challenge could, in theory, be solved in multiple ways. However, for the
# sake of learning how to simulate an alternate filesystem, please solve this
# challenge according to structure provided below. As a challenge, once you have
# an initial solution, try solving this in an alternate way.
#
# Problem description and general solution strategy:
# The binary loads the password from a file using the fread function. If the
# password is correct, it prints "Good Job." In order to keep consistency with
# the other challenges, the input from the console is written to a file in the 
# ignore_me function. As the name suggests, ignore it, as it only exists to
# maintain consistency with other challenges.
# We want to:
# 1. Determine the file from which fread reads.
# 2. Use Angr to simulate a filesystem where that file is replaced with our own
#    simulated file.
# 3. Initialize the file with a symbolic value, which will be read with fread
#    and propogated through the program.
# 4. Solve for the symbolic input to determine the password.

import angr
import claripy


def main():
    path_to_binary = './07_angr_symbolic_file'
    project = angr.Project(path_to_binary)
    start_address = 0x080493F1
    initial_state = project.factory.blank_state(addr=start_address)

    filename = 'ANZXXKGK.txt'
    symbolic_file_size_bytes = 0x40

    pass1 = claripy.BVS('pass1', symbolic_file_size_bytes * 8)
    pass_file = angr.storage.SimFile(filename, content=pass1, size=symbolic_file_size_bytes)

    initial_state.fs.insert(filename, pass_file)

    simulation = project.factory.simgr(initial_state)

    simulation.explore(find=0x080494BF, avoid=0x080494A8)

    if simulation.found:
        solution_state = simulation.found[0]
        p1 = solution_state.se.eval(pass1, cast_to=bytes).decode('utf-8')
        print(p1)

    else:
        raise Exception('Could not find the solution')


if __name__ == '__main__':
    main()
