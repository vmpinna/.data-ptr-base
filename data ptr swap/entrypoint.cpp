#include "Memory.h"

__int64(__fastcall* original_function)(void*, void*, void*);
__int64 __fastcall hooked_function(void* a1, void* a2, void* a3)
{
	if (ExGetPreviousMode() != UserMode)
	{
		return original_function(a1, a2, a3);
	}

	if (!a1)
	{
		return original_function(a1, a2, a3);
	}

	WRITE_STRUCT* w = (WRITE_STRUCT*)a1;

	if (w->special != 0x33C624A290)
	{
		return original_function(a1, a2, a3);
	}

	if (w->write)
	{
		if (!w->address || !w->target_pid || !w->size)
			return STATUS_INVALID_PARAMETER;

		PEPROCESS proc;
		if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)w->target_pid, &proc)))
			return STATUS_INVALID_PARAMETER_1;
		
		PHYSICAL_ADDRESS ToRead = { 0 };
		ToRead.QuadPart = LONGLONG(w->address);

		PVOID pmapped_mem = MmMapIoSpaceEx(ToRead, w->size, PAGE_READWRITE);

		if (!pmapped_mem)
			return STATUS_UNSUCCESSFUL;

		memcpy(pmapped_mem, w->buffer, w->size);
		MmUnmapIoSpace(pmapped_mem, w->size);

		return STATUS_SUCCESS;
	}

	else if (w->read)
	{
		if (!w->address || !w->target_pid || !w->size)
			return STATUS_INVALID_PARAMETER;

		PEPROCESS proc;
		if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)w->target_pid, &proc)))
			return STATUS_INVALID_PARAMETER_1;

		SIZE_T bytes = 0;

		MM_COPY_ADDRESS ToRead = { 0 };
		ToRead.PhysicalAddress.QuadPart = (LONGLONG)w->address;
		NTSTATUS status = MmCopyMemory(w->buffer, ToRead, w->size, MM_COPY_MEMORY_PHYSICAL, &bytes);

		if (!NT_SUCCESS(status))
			return STATUS_UNSUCCESSFUL;

		return STATUS_SUCCESS;
	}

	else if (w->request_base)
	{
		PEPROCESS target_proc;
		PsLookupProcessByProcessId((HANDLE)w->target_pid, &target_proc);
		w->process_base = PsGetProcessSectionBaseAddress(target_proc);

		ObDereferenceObject(target_proc);
	}

	return STATUS_SUCCESS;
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT drv_obj, PUNICODE_STRING reg_pth)
{
	UNREFERENCED_PARAMETER(drv_obj);
	UNREFERENCED_PARAMETER(reg_pth);

	DbgPrintEx(0, 0, "[+] Driver successfully loaded.");

	PVOID image_base = memory::GetSystemBaseModule("\\SystemRoot\\System32\\win32kbase.sys");
	if (!image_base)
	{
		DbgPrintEx(0, 0, "[-] Failed to find image base.");
		return STATUS_UNSUCCESSFUL;
	}

	DbgPrintEx(0, 0, "[+] Found image base!");

	PBYTE function_address = memory::FindPattern(image_base, "\x74\x10\x4C\x8B\xC6\x48\x8B\xD5\xFF\x15\x00\x00\x00\x00", "xxxxxxxxxx????");
	if (!function_address)
	{
		DbgPrintEx(0, 0, "[-] Failed to find QWord Pointer. [1]");
		return STATUS_UNSUCCESSFUL;
	}

	DbgPrintEx(0, 0, "[+] Found QWord Pointer [1]: 0x%llx", function_address);

	UINT64 deref_pointer1 = (UINT64)(function_address) - 0xA;
	deref_pointer1 = (UINT64)deref_pointer1 + *(PINT)((PBYTE)deref_pointer1 + 3) + 7;

	DbgPrintEx(0, 0, "[+] Dereferanced Pointer [1]: 0x%llx", &deref_pointer1);

	if (NT_SUCCESS(memory::FindProcessByName("explorer.exe", &target)))
	{
		DbgPrintEx(0, 0, "[+] Found explorer.exe: %p", target);

		KeAttachProcess(target);
		*(void**)&original_function = _InterlockedExchangePointer((void**)deref_pointer1, (void**)hooked_function);
		KeDetachProcess();
	}
	else
	{
		DbgPrintEx(0, 0, "[!] Failed to find explorer.exe");
		return STATUS_UNSUCCESSFUL;
	}

	DbgPrintEx(0, 0, "[+] Swapped QWord Pointer");

	return STATUS_SUCCESS;
}