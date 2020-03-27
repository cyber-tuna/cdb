#include <stdio.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>
#include <sys/user.h>
#include <stdint.h>
#include <signal.h>
#include <stdlib.h>
#include <stdbool.h>
#include <inttypes.h>

#include <capstone/capstone.h>

#define CODE "\x55\x48\x8b\x05\xb8\x13\x00\x00"

//Breakpoint struct for storing breakpoint metadata
struct breakpoint {
	void *address;
	uint64_t saved_instruction;
};

//Global list of breakpoints
struct breakpoint breakpoints[1]; 

//Return the instruction pointer (rip) of the tracee
uint64_t get_rip(pid_t child)
{
	struct user_regs_struct regs;
	ptrace(PTRACE_GETREGS, child, NULL, &regs);
	return regs.rip; 
}

void tracee() {
	//Inform the kernel that this process is to be debugged by parent process
	//The tracee will stop each time a signal is delivered to the process
	ptrace(PTRACE_TRACEME, 0, NULL, NULL);

	char *argv[] = { "/home/jpatten/checkouts/cdb/hello", NULL};
	char *envp[] = { NULL };

	//Launch /bin/ls. Calls to execve in the tracee will cause it to be sent
	//a SIGTRAP signal. This gives the parent a chance to gain control before
	//the new program begins.
	if(execve("/home/jpatten/checkouts/cdb/hello", argv, envp)) {
		printf("Error execve\n");
	}
}

void continue_execution(pid_t pid) {
	int status;
	pid_t c;
	ptrace(PTRACE_CONT, pid, NULL, NULL);

	c = waitpid(pid, &status, 0);

	siginfo_t info;
    ptrace(PTRACE_GETSIGINFO, pid, NULL, &info);

	if(WSTOPSIG(status) == SIGTRAP) {
		printf("SIGTRAP\n");
		printf("%d\n", info.si_code);
		if(info.si_code == 128) {
			printf("Breakpoint triggered\n");

			//Restore the original instruction and decrement the PC by one
			ptrace(PTRACE_POKEDATA, pid, breakpoints[0].address, breakpoints[0].saved_instruction);
			uint64_t rip = get_rip(pid);
			rip -= 1;
			struct user_regs_struct regs;
			ptrace(PTRACE_GETREGS, pid, NULL, &regs);
			regs.rip = rip;
			ptrace(PTRACE_SETREGS, pid, NULL, &regs);
		}	

	}
	
	if(WIFEXITED(status)) {
		printf("Child exited normally\n");
	}	
}

void tracer(pid_t child) {
	printf("Debugging PID %d\n", child);
	pid_t c;
	int status;
	char command;

	c = waitpid(child, &status, 0);
	if(WIFEXITED(status)) {
		printf("Child exited normally\n");
	}	

	while(1) {
		printf("cdb>");
		command = getchar();
		getchar();
		printf("command: %c\n", command);
		if(command == 'c') {
			continue_execution(child);	
		} 
		else if(command == 'q') {
			//Kill the child process
			kill(child, SIGKILL);

			//Detach the tracer from the tracee. This also restarts the 
			//stopped tracee (in same way as PTRACE_CONT).
			ptrace(PTRACE_DETACH, child, NULL, NULL);
			wait(&status);
			break;
		} 
		else if(command == 'r') {
			struct user_regs_struct regs;
			ptrace(PTRACE_GETREGS, child, NULL, &regs);
			printf("rax: 0x%llx\n", regs.rax);
			printf("rbx: 0x%llx\n", regs.rbx);
			printf("rcx: 0x%llx\n", regs.rcx);
			printf("rdx: 0x%llx\n", regs.rdx);
			printf("rsi: 0x%llx\n", regs.rsi);
			printf("rdi: 0x%llx\n", regs.rdi);
			printf("rbp: 0x%llx\n", regs.rbp);
			printf("r15: 0x%llx\n", regs.r15);
			printf("r14: 0x%llx\n", regs.r14);
			printf("r13: 0x%llx\n", regs.r13);
			printf("r12: 0x%llx\n", regs.r12);
			printf("r11: 0x%llx\n", regs.r11);
			printf("r10: 0x%llx\n", regs.r10);
			printf("r9: 0x%llx\n", regs.r9);
			printf("r8: 0x%llx\n", regs.r8);
			printf("rip: 0x%llx\n", regs.rip);
			printf("rsp: 0x%llx\n", regs.rsp);
			printf("eflags: 0x%llx\n", regs.eflags);
		} 
		else if(command == 'i') {
			struct user u;
			ptrace(PTRACE_PEEKUSER, child, NULL, &u); 
			printf("Code start: 0x%llx\n", u.start_code);
			printf("Stack start: 0x%llx\n", u.start_stack);

		}
		//Single step functionality
		else if(command == 's') {
			ptrace(PTRACE_SINGLESTEP, child, NULL, NULL); 
		}
		else if(command == 'd') {
			csh handle;
			cs_insn *insn;
			size_t count;
			char code[40];
			uint64_t pc = get_rip(child);
			uint64_t read_addr = pc;
			uint64_t return_data;
			for(int i=0;i<10;i++){
				read_addr = pc + (8*i);
				return_data = ptrace(PTRACE_PEEKDATA, child, (void*)read_addr, NULL);
				code[7 + (8*i)] = (return_data >> 56) & 0xFF;
				code[6 + (8*i)] = (return_data >> 48) & 0xFF;
				code[5 + (8*i)] = (return_data >> 40) & 0xFF;
				code[4 + (8*i)] = (return_data >> 32) & 0xFF;
				code[3 + (8*i)] = (return_data >> 24) & 0xFF;
				code[2 + (8*i)] = (return_data >> 16) & 0xFF;
				code[1 + (8*i)] = (return_data >> 8) & 0xFF;
				code[0 + (8*i)] = return_data & 0xFF;
			}

			if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
				printf("cs_open error\n");
			count = cs_disasm(handle, code, 40, pc, 0, &insn);
			if (count > 0) {
				size_t j;
				for (j = 0; j < count; j++) {
					printf("0x%"PRIx64":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic,
							insn[j].op_str);
					if(strcmp(insn[j].mnemonic, "ret") == 0) {
						break;
					}
				}
		
				cs_free(insn, count);
			} else
				printf("ERROR: Failed to disassemble given code!\n");
		
			cs_close(&handle);
		}
		else if(command == 'b') {
			printf("(v)iew, (s)et, (c)lear\n");
			char option;
			option = getchar();
			getchar();
			if(option == 'v') {
				printf("Breakpoint address: %p\n", breakpoints[0].address);	
			}
			else if(option == 's') {
				char addr[20];
				memset(addr, 0, 9);
				uint64_t return_data;
				struct breakpoint br;
				scanf("%s", addr);
				getchar();
				uint64_t addr_hex = strtol(addr, NULL, 16);
				
				br.address = (void*)addr_hex;
				return_data = ptrace(PTRACE_PEEKDATA, child, br.address, NULL);

				br.saved_instruction = return_data;
				breakpoints[0] = br;

				//Overwrite the first byte of the instruction at breakpoint address
				//with the INT 3 instruction. Upon execution in the tracee, an interrupt 
				//will be triggered - the handler (registered by the OS) sends a SIGSTOP to 
				//the tracee and a SIGTRAP to the tracer.
				uint64_t int3 = 0xcc;
				uint64_t breakpoint = (return_data & ~0xff) | int3;

				ptrace(PTRACE_POKEDATA, child, br.address, breakpoint);
				return_data = ptrace(PTRACE_PEEKDATA, child, br.address, NULL);
			}
			else if(option == 'c') {
				
			}
			else {
				printf("Unknown option\n");
			}
			
		}
		else {
			printf("Invalid command\n");
		}

	}
}

int main() {
	printf("Welcome to cdb\n");

	uint64_t return_data = 0xffeeddccbbaa9988;

	pid_t child;
	child = fork();

	if(child == 0) {
		tracee();
	} else {
		tracer(child);
	}
	return 0;
}
