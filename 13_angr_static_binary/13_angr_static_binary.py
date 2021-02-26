# This challenge is the exact same as the first challenge, except that it was
# compiled as a static binary. Normally, Angr automatically replaces standard
# library functions with SimProcedures that work much more quickly.
#
# Here are a few SimProcedures Angr has already written for you. They implement
# standard library functions. You will not need all of them:
# angr.SIM_PROCEDURES['libc']['malloc']
# angr.SIM_PROCEDURES['libc']['fopen']
# angr.SIM_PROCEDURES['libc']['fclose']
# angr.SIM_PROCEDURES['libc']['fwrite']
# angr.SIM_PROCEDURES['libc']['getchar']
# angr.SIM_PROCEDURES['libc']['strncmp']
# angr.SIM_PROCEDURES['libc']['strcmp']
# angr.SIM_PROCEDURES['libc']['scanf']
# angr.SIM_PROCEDURES['libc']['printf']
# angr.SIM_PROCEDURES['libc']['puts']
# angr.SIM_PROCEDURES['libc']['exit']
#
# As a reminder, you can hook functions with something similar to:
# project.hook(malloc_address, angr.SIM_PROCEDURES['libc']['malloc'])
#
# There are many more, see:
# https://github.com/angr/angr/tree/master/angr/procedures/libc
#
# Additionally, note that, when the binary is executed, the main function is not
# the first piece of code called. In the _start function, __libc_start_main is 
# called to start your program. The initialization that occurs in this function
# can take a long time with Angr, so you should replace it with a SimProcedure.
# angr.SIM_PROCEDURES['glibc']['__libc_start_main']
# Note 'glibc' instead of 'libc'.


import angr
import sys


def main():
    bin_path = './13_angr_static_binary'
    project = angr.Project(bin_path)
    printf_addr = 0x0804FA40
    scanf_addr = 0x0804FAA0
    strcmp_addr = 0x0805DC30
    puts_addr = 0x08050380
    main_addr = 0x08048CF0

    init_state = project.factory.entry_state()
    sm = project.factory.simgr(init_state)

    project.hook(printf_addr, angr.SIM_PROCEDURES['libc']['printf']())
    project.hook(scanf_addr, angr.SIM_PROCEDURES['libc']['scanf']())
    project.hook(strcmp_addr, angr.SIM_PROCEDURES['libc']['strcmp']())
    project.hook(puts_addr, angr.SIM_PROCEDURES['libc']['puts']())
    project.hook(main_addr, angr.SIM_PROCEDURES['glibc']['__libc_start_main']())

    sm.explore(find=0x08048A49, avoid=0x08048A38)
    if sm.found:
        state = sm.found[0]
        print(state.posix.dumps(sys.stdin.fileno()))


if __name__ == '__main__':
    main()
