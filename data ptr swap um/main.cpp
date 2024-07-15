#pragma once
#include "Memory.h"

int main()
{
	if (!setup_driver())
	{
		std::cout << "[!] Failed to setup communication." << std::endl;
		return 0;
	}

	std::cout << "[+] Communication established!" << std::endl;

	pid = get_pid(L"notepad.exe");
	if (!pid)
	{
		std::cout << "[!] Failed to get PID of notepad.exe" << std::endl;
		return 0;
	}

	std::cout << "[+] PID: " << pid << std::endl;

	std::getchar();
	return 0;

}