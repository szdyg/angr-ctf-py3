# When you construct a simulation manager, you will want to enable Veritesting:
# project.factory.simgr(initial_state, veritesting=True)
# Hint: use one of the first few levels' solutions as a reference.

import angr
import sys


def main():
    bin_path = './12_angr_veritesting'
    project = angr.Project(bin_path, auto_load_libs=False)
    init_state = project.factory.entry_state()
    simgr = project.factory.simgr(init_state, veritesting=True)

    def is_successful(state):
        stdout_output = state.posix.dumps(1)
        return b'Good Job.' in stdout_output

    def should_abort(state):
        stdout_output = state.posix.dumps(1)
        return b'Try again.' in stdout_output

    simgr.explore(find=is_successful, avoid=should_abort)

    if simgr.found:
        state = simgr.found[0]
        print(state.posix.dumps(sys.stdin.fileno()))
    else:
        print('not found')


if __name__ == '__main__':
    main()
