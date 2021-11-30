
#include <iostream>
#include <unicorn/unicorn.h>
#include "PELoader.h"



static bool hook_mem_invalid(uc_engine* uc, uc_mem_type type,
	uint64_t address, int size, int64_t value, void* user_data)
{
	uint32_t eip, esi;
	auto err = uc_reg_read(uc, UC_X86_REG_EIP, &eip);
	err = uc_reg_read(uc, UC_X86_REG_ESI, &esi);
	char data[100];
	err = uc_mem_read(uc, eip, data, 10);
	std::cout << "address:" << address << std::endl;
	// Stop emulation.
	return false;
}

static void hook_code(uc_engine* uc, uint64_t addr, uint32_t size, void* user_data)
{
	//TODO:读取并反汇编后打印
	std::cout << "[hook_code]addr: " << addr << ", size:" << size << std::endl;
}


static void hook_iat(uc_engine* uc, uint64_t addr, uint32_t size, void* user_data)
{
	auto iat = reinterpret_cast<std::vector<IATItem>*>(user_data);

	std::cout << "address:" << addr << std::endl;

	for (auto const& item : *iat)
	{
		if (item.fake_proc_addr == addr)
		{
			std::cout << "dll:" << item.dll << ", proc:" << item.proc_name << std::endl;
			if (item.dll == "user32.dll" && item.proc_name == "MessageBoxA")
			{
				uint32_t esp;
				auto err = uc_reg_read(uc, UC_X86_REG_ESP, &esp);
				uint32_t ret;
				err = uc_mem_read(uc, esp, &ret, 4);
				uint32_t hwnd;
				err = uc_mem_read(uc, esp + 4, &hwnd, 4);
				uint32_t lpText;
				err = uc_mem_read(uc, esp + 8, &lpText, 4);
				uint32_t lpCaption;
				err = uc_mem_read(uc, esp + 12, &lpCaption, 4);
				uint32_t uType;
				err = uc_mem_read(uc, esp + 16, &uType, 4);


				std::string txt;
				for (int i = 0; lpText != 0; ++i)
				{
					char c;
					err = uc_mem_read(uc, lpText + i, &c, 1);
					if (c == 0)
					{
						break;
					}

					txt.push_back(c);
				}

				std::string caption;
				for (int i = 0; lpCaption != 0; ++i)
				{
					char c;
					err = uc_mem_read(uc, lpCaption + i, &c, 1);
					if (c == 0)
					{
						break;
					}

					caption.push_back(c);
				}

				std::cout << "hwnd:" << hwnd << ", lpCaption:" << caption << ", lpText:" << txt << ", uType" << uType << ", return:" << ret << std::endl;

				//设置返回值为IDOK
				uint32_t eax = 1;
				err = uc_reg_write(uc, UC_X86_REG_EAX, &eax);

				//stdcall,需要平衡栈
				esp += 20;
				err = uc_reg_write(uc, UC_X86_REG_ESP, &esp);

				//返回到调用位置
				err = uc_reg_write(uc, UC_X86_REG_EIP, &ret);
			}
			if (item.dll == "user32.dll" && item.proc_name == "FindWindowA")
			{
				uint32_t esp;
				auto err = uc_reg_read(uc, UC_X86_REG_ESP, &esp);
				uint32_t ret;
				err = uc_mem_read(uc, esp, &ret, 4);
				uint32_t lpClassName;
				err = uc_mem_read(uc, esp + 4, &lpClassName, 4);
				uint32_t lpWindowName;
				err = uc_mem_read(uc, esp + 8, &lpWindowName, 4);

				std::string class_name;
				for (int i = 0; lpClassName != 0; ++i)
				{
					char c;
					err = uc_mem_read(uc, lpClassName + i, &c, 1);
					if (c == 0)
					{
						break;
					}

					class_name.push_back(c);
				}

				std::string win_name;
				for (int i = 0; lpWindowName != 0; ++i)
				{
					char c;
					err = uc_mem_read(uc, lpWindowName + i, &c, 1);
					if (c == 0)
					{
						break;
					}

					win_name.push_back(c);
				}

				std::cout << "lpClassName:" << class_name << ", lpWindowName:" << win_name << ", return:" << ret << std::endl;

				//设置返回值为null
				uint32_t eax = 0;
				err = uc_reg_write(uc, UC_X86_REG_EAX, &eax);

				//stdcall,需要平衡栈
				esp += 4 * 3;
				err = uc_reg_write(uc, UC_X86_REG_ESP, &esp);

				//返回到调用位置
				err = uc_reg_write(uc, UC_X86_REG_EIP, &ret);
			}
			if (item.dll == "kernel32.dll" && item.proc_name == "OutputDebugStringA")
			{
				uint32_t esp;
				auto err = uc_reg_read(uc, UC_X86_REG_ESP, &esp);
				uint32_t ret;
				err = uc_mem_read(uc, esp, &ret, 4);
				uint32_t lpOutputString;
				err = uc_mem_read(uc, esp + 4, &lpOutputString, 4);

				std::string out_str;
				for (int i = 0; lpOutputString != 0; ++i)
				{
					char c;
					err = uc_mem_read(uc, lpOutputString + i, &c, 1);
					if (c == 0)
					{
						break;
					}

					out_str.push_back(c);
				}

				std::cout << "lpOutputString:" << out_str << ", return:" << ret << std::endl;

				//stdcall,需要平衡栈
				esp += 4 * 2;
				err = uc_reg_write(uc, UC_X86_REG_ESP, &esp);

				//返回到调用位置
				err = uc_reg_write(uc, UC_X86_REG_EIP, &ret);
			}
			break;
		}

	}

}

int main()
{
	std::cout << std::hex;

	PELoader loader;
	if (!loader.load("test\\console.exe"))
	{
		std::cout << "load exe failed" << std::endl;

		return 1;
	}

	uc_engine* uc;
	auto err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
	if (err)
	{
		printf("Failed on uc_open() with error returned: %u\n", err);
		return 1;
	}

	//加载所有的区段到内存
	for (auto const& header : loader.sec_headers())
	{
		uint64_t mem_address = loader.base() + header.VirtualAddress;
		std::vector<char> data(header.SizeOfRawData);
		loader.readOffset(data.data(), data.size(), header.PointerToRawData);
		err = uc_mem_map(uc, mem_address, (header.SizeOfRawData / 0x1000 + 1) * 0x1000, UC_PROT_ALL);
		err = uc_mem_write(uc, mem_address, data.data(), data.size());
	}

	//将IAT指向该区域，然后hook这里获取调用的目标dll和proc name
	std::vector<uint8_t> iat_stub(loader.iat().size(), 0x90);
	err = uc_mem_map(uc, 0x70000000, (iat_stub.size() / 0x1000 + 1) * 0x1000, UC_PROT_ALL);
	//填充IAT
	int i = 0;
	for (auto& item : loader.iat())
	{
		uint32_t fake_proc_addr = 0x70000000 + i;
		err = uc_mem_write(uc, item.va, &fake_proc_addr, 4);
		item.fake_proc_addr = fake_proc_addr;
		++i;
	}
	uc_hook trace;
	err = uc_hook_add(uc, &trace, UC_HOOK_CODE, hook_iat, &loader.iat(), 0x70000000, 0x70000000 + iat_stub.size() + 1);


	//开辟栈空间
	err = uc_mem_map(uc, 0x100000, 0x100000, UC_PROT_ALL);

	//准备跳转到ep的stub代码
	err = uc_mem_map(uc, 0x301000, 0x1000, UC_PROT_ALL);
	const uint8_t stub[] = "\xff\xd6\x90\x90";		//call esi
	err = uc_mem_write(uc, 0x301000, stub, sizeof(stub) - 1);

	//设置入口点和栈地址
	uint32_t esi = loader.ep(), esp = 0x200000;
	err = uc_reg_write(uc, UC_X86_REG_ESI, &esi);
	err = uc_reg_write(uc, UC_X86_REG_ESP, &esp);

	err = uc_hook_add(uc, &trace, UC_HOOK_MEM_READ_UNMAPPED, hook_mem_invalid, nullptr, 1, 0);
	err = uc_hook_add(uc, &trace, UC_HOOK_MEM_FETCH_UNMAPPED, hook_mem_invalid, nullptr, 1, 0);
	err = uc_hook_add(uc, &trace, UC_HOOK_CODE, hook_code, nullptr, 1, 0);
	//开始执行代码
	err = uc_emu_start(uc, 0x301000, 0x301002, 0, 0);

	if (err)
	{
		std::cout << "执行失败" << std::endl;
		return 1;
	}

	std::cout << "执行成功" << std::endl;
	return 0;
}