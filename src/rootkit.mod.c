#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/elfnote-lto.h>
#include <linux/export-internal.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

#ifdef CONFIG_UNWINDER_ORC
#include <asm/orc_header.h>
ORC_HEADER;
#endif

BUILD_SALT;
BUILD_LTO_INFO;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef CONFIG_MITIGATION_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif



static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0x49cd25ed, "alloc_workqueue" },
	{ 0x52c5c991, "__kmalloc_noprof" },
	{ 0xb742fd7, "simple_strtol" },
	{ 0x14c8a475, "register_ftrace_function" },
	{ 0x69acdf38, "memcpy" },
	{ 0x37a0cba, "kfree" },
	{ 0xd889815a, "path_put" },
	{ 0xbdfb6dbb, "__fentry__" },
	{ 0x65487097, "__x86_indirect_thunk_rax" },
	{ 0x122c3a7e, "_printk" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0xb2fcb56d, "queue_delayed_work_on" },
	{ 0x389ea62d, "init_task" },
	{ 0x87a21cb3, "__ubsan_handle_out_of_bounds" },
	{ 0x94524bcf, "ftrace_set_filter_ip" },
	{ 0x9765b730, "nf_unregister_net_hook" },
	{ 0x3b8a8086, "nf_register_net_hook" },
	{ 0x9f031ccc, "init_net" },
	{ 0xe007de41, "kallsyms_lookup_name" },
	{ 0x52d1abe3, "unregister_ftrace_function" },
	{ 0xa7eedcc4, "call_usermodehelper" },
	{ 0x1e6d26a8, "strstr" },
	{ 0x4c03a563, "random_kmalloc_seed" },
	{ 0x8c03d20c, "destroy_workqueue" },
	{ 0x11089ac7, "_ctype" },
	{ 0x1b68ffc7, "kern_path" },
	{ 0x5b8239ca, "__x86_return_thunk" },
	{ 0xe2d5255a, "strcmp" },
	{ 0xe7ffefbd, "skb_trim" },
	{ 0xf8f8a1b5, "kobject_del" },
	{ 0x9fa7184a, "cancel_delayed_work_sync" },
	{ 0xc6f46339, "init_timer_key" },
	{ 0xffeedf6a, "delayed_work_timer_fn" },
	{ 0xd01eb0cb, "kmalloc_trace_noprof" },
	{ 0x754d539c, "strlen" },
	{ 0xb0075aec, "kmalloc_caches" },
	{ 0x64f32516, "module_layout" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "555885351F076CBF13D28F4");
