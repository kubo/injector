#if defined(__x86_64__)
#define handle_offset 0
#define dlopen_addr_offset 8
#define dlerror_addr_offset 16
#define dlflags_offset 24
#define file_path_offset 28
#define page_size 4096
	.text
	.global	injector_shellcode
	.hidden	injector_shellcode
	.type	injector_shellcode, @function
	// void *injector_shellcode(injector_shellcode_arg_t *arg) {
injector_shellcode:
	//   // prolog
	pushq	%rbx
	movq	%rdi, %rbx
	//   int dlflags = arg->dlflags;
	movl	dlflags_offset(%rbx), %esi
	//   const char *file_path = arg->file_path;
	leaq	file_path_offset(%rbx), %rdi
	//   void *handle = dlopen(file_path, dlflags);
	call	*dlopen_addr_offset(%rbx)
	//   arg->handle = handle;
	movq	%rax, handle_offset(%rbx)
	//   arg->file_path[0] = '\0';
	movb	$0, file_path_offset(%rbx)
	//   if (handle != NULL) return;
	test	%rax, %rax
	jnz	.exit
	//   if (arg->dlerror_addr == 0) return;
	cmpq	$0, dlerror_addr_offset(%rbx)
	je	.exit
	//   char *errmsg = dlerror();
	call	*dlerror_addr_offset(%rbx)
	//   if (errmsg == NULL) return;
	test	%rax, %rax
	jz	.exit
	//   char *dest = arg->file_path
	leaq	file_path_offset(%rbx), %rdi
	//   char *end = (char*)arg + page_size;
	leaq	page_size(%rbx), %rcx
.loop:
	//   char c = *(errmsg++);
	movb	(%rax), %dl
	addq	$1, %rax
	//   *(dest++) = c;
	movb	%dl, (%rdi)
	addq	$1, %rdi
	//   if (c == 0) return;
	testb	%dl, %dl
	jz	.exit
	//   if (dest < end) goto loop;
	cmpq	%rdi, %rcx
	ja	.loop
.exit:
	//   // epilog
	popq	%rbx
	ret
	// }
	.size	injector_shellcode, . - injector_shellcode

	.balign  4
	.global	injector_shellcode_size
	.hidden	injector_shellcode_size
	.type	injector_shellcode_size, @object
	.size	injector_shellcode_size, 4
injector_shellcode_size:
	// distance from injector_shellcode to current.
	.int	. - injector_shellcode
#endif
