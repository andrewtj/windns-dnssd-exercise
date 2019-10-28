#include "pch.h"
#include <iostream>
#include <windows.h>
#include <WinDNS.h>
#include <assert.h>
#include <mutex>

/*

Browse:
* Callback only happens once
* BrowseCallbackV2 can't be used because DNS_QUERY_REQUEST_VERSION2 isn't defined

Query:
* Does get called regularly
* Does not consistently get called; misses changes from macOS/mDNSResponder and even more from Avahi/Ubuntu

Resolve:
* Works for one shot; haven't tested updating a service while a resolve is active

Registration
* Works but you have to obtain the system's mDNS hostname somehow (reverse lookup seems the best bet)

*/

DNS_SERVICE_BROWSE_CALLBACK BrowseCallback;

DNS_QUERY_COMPLETION_ROUTINE BrowseCallbackV2;

MDNS_QUERY_CALLBACK QueryCallback;

DNS_SERVICE_RESOLVE_COMPLETE ResolveCallback;

DNS_SERVICE_REGISTER_COMPLETE RegisterCallback;

static std::mutex STDOUT;

int main()
{
	DNS_STATUS err;
	DNS_SERVICE_BROWSE_REQUEST bRequest;
	PDNS_SERVICE_INSTANCE regInstance;
	MDNS_QUERY_REQUEST queryRequest;
	DNS_SERVICE_REGISTER_REQUEST regRequest;
	DNS_SERVICE_CANCEL bCancel;
	MDNS_QUERY_HANDLE queryHandle;
	DNS_SERVICE_CANCEL regCancel;
	wchar_t regName[255];

	memset(&bRequest, 0, sizeof(DNS_SERVICE_BROWSE_REQUEST));
	memset(&regRequest, 0, sizeof(DNS_SERVICE_REGISTER_REQUEST));
	memset(&queryRequest, 0, sizeof(MDNS_QUERY_REQUEST));
	memset(&bCancel, 0, sizeof(DNS_SERVICE_CANCEL));
	memset(&queryHandle, 0, sizeof(MDNS_QUERY_HANDLE));
	memset(&regCancel, 0, sizeof(DNS_SERVICE_CANCEL));

	bRequest.Version = DNS_QUERY_REQUEST_VERSION1;
	bRequest.pBrowseCallback = BrowseCallback;
	// DNS_QUERY_REQUEST_VERSION2 isn't defined
	// bRequest.Version = DNS_QUERY_REQUEST_VERSION1;
	// bRequest.pBrowseCallbackV2 = BrowseCallbackV2;
	bRequest.InterfaceIndex = 0;
	bRequest.QueryName = L"_windns-example._udp";

	err = DnsServiceBrowse(&bRequest, &bCancel);
	assert(err == DNS_REQUEST_PENDING);

	queryRequest.Version = DNS_QUERY_REQUEST_VERSION1;
	queryRequest.Query = L"_windns-example._udp.local";
	queryRequest.QueryType = DNS_TYPE_PTR;
	queryRequest.QueryOptions = DNS_QUERY_STANDARD;
	queryRequest.fAnswerReceived = 0;
	queryRequest.pQueryCallback = QueryCallback;

	err = DnsStartMulticastQuery(&queryRequest, &queryHandle);
	if (err != ERROR_SUCCESS) {
		DWORD lastErr = GetLastError();
		std::lock_guard<std::mutex> guard(STDOUT);
		std::cout << "DnsStartMulticastQuery err: " << std::hex << err << " " << lastErr << std::endl;
	}
	assert(err == ERROR_SUCCESS);

	regInstance = DnsServiceConstructInstance(
		L"initial._windns-example._udp.local",
		L"example.com",
		NULL,
		NULL,
		1,
		0,
		0,
		0,
		NULL,
		NULL
	);
	assert(regInstance != NULL);

	regRequest.Version = DNS_QUERY_REQUEST_VERSION1;
	regRequest.InterfaceIndex = 0;
	regRequest.pServiceInstance = regInstance;
	regRequest.pRegisterCompletionCallback = RegisterCallback;
	regRequest.pQueryContext = (PVOID)0xc0ffee;
	regRequest.hCredentials = NULL;
	regRequest.unicastEnabled = false;

	err = DnsServiceRegister(&regRequest, &regCancel);
	assert(err == DNS_REQUEST_PENDING);

	for (unsigned char i = 0; i < 100; i++) {
		Sleep(50000);

		err = DnsServiceDeRegister(&regRequest, &regCancel);
		assert(err == DNS_REQUEST_PENDING);

		Sleep(10000);
		wsprintf(regName, L"iter%d._windns-example._udp.local", i);

		regInstance->pszInstanceName = regName;
		err = DnsServiceRegister(&regRequest, &regCancel);
		assert(err == DNS_REQUEST_PENDING);
	}

}

void __stdcall BrowseCallback(DWORD Status, PVOID pQueryContext, PDNS_RECORD pDnsRecord)
{
	std::lock_guard<std::mutex> guard(STDOUT);
	std::cout << "Browse Callback - status: " << Status << std::endl;
	WCHAR unknownData[] = L"unknown";
	for (PDNS_RECORD cur = pDnsRecord; cur != NULL; cur = cur->pNext)
	{
		PWSTR target = (cur->wType == DNS_TYPE_PTR) ? &cur->Data.PTR.pNameHost[0] : &unknownData[0];
		std::wcout << " [BC] " << cur->pName << " " << cur->wType << " " << cur->dwTtl << " " << target << std::endl;
	}
	if (pDnsRecord) {
		DnsRecordListFree(pDnsRecord, DnsFreeRecordList);
	}
}

void __stdcall ResolveCallback(DWORD Status, PVOID pQueryContext, PDNS_SERVICE_INSTANCE pInstance)
{
	std::lock_guard<std::mutex> guard(STDOUT);
	if (pInstance) {
		std::wcout << "Resolve Callback - status: " << Status << " host: " << pInstance->pszHostName << " port: " << pInstance->wPort << " props: " << pInstance->dwPropertyCount << std::endl;
		DnsServiceFreeInstance(pInstance);
	}
	else {
		std::cout << "Resolve Callback - status: " << Status << std::endl;
	}
}

void __stdcall QueryCallback(PVOID pQueryContext, PMDNS_QUERY_HANDLE pQueryHandle, PDNS_QUERY_RESULT pQueryResults) {
	{
		std::lock_guard<std::mutex> guard(STDOUT);
		std::cout << "Query Callback" << std::endl;
	}
	WCHAR unknownData[] = L"unknown";
	for (PDNS_RECORD cur = pQueryResults->pQueryRecords; cur != NULL; cur = cur->pNext)
	{
		PWSTR target = (cur->wType == DNS_TYPE_PTR) ? &cur->Data.PTR.pNameHost[0] : &unknownData[0];
		{
			std::lock_guard<std::mutex> guard(STDOUT);
			std::wcout << " [QC] " << cur->pName << " " << cur->wType << " " << cur->dwTtl << " " << target << std::endl;
		}
		if (cur->wType != DNS_TYPE_PTR) {
			continue;
		}

		DNS_SERVICE_RESOLVE_REQUEST resolveRequest;
		memset(&resolveRequest, 0, sizeof(DNS_SERVICE_RESOLVE_REQUEST));
		resolveRequest.Version = DNS_QUERY_REQUEST_VERSION1;
		resolveRequest.QueryName = cur->Data.PTR.pNameHost;
		resolveRequest.pResolveCompletionCallback = ResolveCallback;

		DNS_SERVICE_CANCEL resolveCancel;
		memset(&resolveCancel, 0, sizeof(DNS_SERVICE_CANCEL));

		DNS_STATUS err = DnsServiceResolve(&resolveRequest, &resolveCancel);
		assert(err == DNS_REQUEST_PENDING);
		{
			std::lock_guard<std::mutex> guard(STDOUT);
			std::wcout << " [QC] Started resolve for " << resolveRequest.QueryName << std::endl;
		}

		Sleep(5000);
		err = DnsServiceResolveCancel(&resolveCancel);
		assert(err == ERROR_SUCCESS);

		{
			std::lock_guard<std::mutex> guard(STDOUT);
			std::wcout << " [QC] Stopped resolve for " << resolveRequest.QueryName << std::endl;
		}
	}
	if (pQueryResults->pQueryRecords) {
		DnsRecordListFree(pQueryResults->pQueryRecords, DnsFreeRecordList);
	}
}

void __stdcall BrowseCallbackV2(PVOID pQueryContext, PDNS_QUERY_RESULT pQueryResults)
{
	{
		std::lock_guard<std::mutex> guard(STDOUT);
		std::cout << "Browse Callback V2" << std::endl;
	}
	WCHAR unknownData[] = L"unknown";
	for (PDNS_RECORD cur = pQueryResults->pQueryRecords; cur != NULL; cur = cur->pNext)
	{
		PWSTR target = (cur->wType == DNS_TYPE_PTR) ? &cur->Data.PTR.pNameHost[0] : &unknownData[0];
		{
			std::lock_guard<std::mutex> guard(STDOUT);
			std::wcout << " [B2] " << cur->pName << " " << cur->wType << " " << cur->dwTtl << " " << target << std::endl;
		}
		if (cur->wType != DNS_TYPE_PTR || true) {
			continue;
		}

		DNS_SERVICE_RESOLVE_REQUEST resolveRequest;
		memset(&resolveRequest, 0, sizeof(DNS_SERVICE_RESOLVE_REQUEST));
		resolveRequest.Version = DNS_QUERY_REQUEST_VERSION1;
		resolveRequest.QueryName = cur->Data.PTR.pNameHost;
		resolveRequest.pResolveCompletionCallback = ResolveCallback;

		DNS_SERVICE_CANCEL resolveCancel;

		DNS_STATUS err = DnsServiceResolve(&resolveRequest, &resolveCancel);
		assert(err == DNS_REQUEST_PENDING);
		{
			std::lock_guard<std::mutex> guard(STDOUT);
			std::wcout << " [B2] Started resolve for " << resolveRequest.QueryName << std::endl;
		}

		Sleep(5000);
		err = DnsServiceResolveCancel(&resolveCancel);
		assert(err == DNS_REQUEST_PENDING);

		{
			std::lock_guard<std::mutex> guard(STDOUT);
			std::wcout << " [B2] Stopped resolve for " << resolveRequest.QueryName << std::endl;
		}
	}
	if (pQueryResults->pQueryRecords) {
		DnsRecordListFree(pQueryResults->pQueryRecords, DnsFreeRecordList);
	}
}

void __stdcall RegisterCallback(DWORD Status, PVOID pQueryContext, PDNS_SERVICE_INSTANCE pInstance)
{
	std::lock_guard<std::mutex> guard(STDOUT);
	std::wcout << "Register callback " << Status << " " << pInstance->pszInstanceName << std::endl;
}