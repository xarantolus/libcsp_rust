.syntax unified
.thumb

@ R9-saving trampolines for ROPI-RWPI ARM targets.
@
@ libcsp C code is compiled without ROPI-RWPI, so it may corrupt or not set R9
@ before calling these Rust callbacks. Each trampoline saves R9, reloads
@ __data_start (the static-base register for the linked binary), calls the
@ *_impl Rust function exported by export_arch!, then restores R9 before
@ returning (preserving AAPCS callee-save semantics).
@
@ The six functions below are the only ones that access Rust statics through R9:
@   csp_get_ms / csp_get_ms_isr  - read the kernel time spinlock
@   csp_malloc / csp_calloc / csp_free  - access GLOBAL_ALLOCATOR
@   csp_queue_create              - calls malloc internally

.macro trampoline name
.thumb_func
.global csp_\name
.type   csp_\name, %function
csp_\name:
    push {r9, lr}
    ldr  r9, =__data_start
    bl   csp_\name\()_impl
    pop  {r9, pc}
    .size csp_\name, . - csp_\name
.endm

trampoline get_ms
trampoline get_ms_isr
trampoline malloc
trampoline calloc
trampoline free
trampoline queue_create
