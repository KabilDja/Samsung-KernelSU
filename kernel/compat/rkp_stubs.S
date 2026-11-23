/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Keep RKP call-through trampolines in the module's executable image.
 * A separately module_alloc()'d page is not necessarily admitted for execution
 * by Samsung's protection layer, even after set_memory_x() clears PTE_PXN.
 * Slots are populated through the normal arm64 text-patching API before use.
 */
	.section .text, "ax"
	.balign 16
	.global ksu_rkp_stub_pool
	.type ksu_rkp_stub_pool, %object
ksu_rkp_stub_pool:
	/* 256 slots, 16 bytes each. Unused slots trap if reached by mistake. */
	.fill 1024, 4, 0xd4200000
	.size ksu_rkp_stub_pool, . - ksu_rkp_stub_pool
