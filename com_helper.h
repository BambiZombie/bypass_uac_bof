#pragma once
#include <Windows.h>
#include <process.h>
#include <taskschd.h>

// define the export for linking

//DEFINE_GUID(IID_ElevatedFactoryServer, 0x804BD226, 0xAF47, 0x04D71, 0xB4, 0x92, 0x44, 0x3A, 0x57, 0x61, 0x0B, 0x08);
//DEFINE_GUID(CLSID_TaskScheduler, 0x0f87369f, 0xa4e5, 0x4cfc, 0xbd, 0x3e, 0x73, 0xe6, 0x15, 0x45, 0x72, 0xdd);
//DEFINE_GUID(IID_ITaskService, 0x2FABA4C7, 0x4DA9, 0x4013, 0x96, 0x97, 0x20, 0xCC, 0x3F, 0xD4, 0x0F, 0x85);

#define T_CLSID_VirtualFactoryServer         L"{A6BFEA43-501F-456F-A845-983D3AD7B8F0}"
#define T_CLSID_ElevatedFactoryServer		 L"{804BD226-AF47-4D71-B492-443A57610B08}"
#define T_ELEVATION_MONIKER_ADMIN            L"Elevation:Administrator!new:"

//#ifndef UCM_DEFINE_GUID
//#define UCM_DEFINE_GUID(name, l, w1, w2, b1, b2, b3, b4, b5, b6, b7, b8) \
//     EXTERN_C const GUID DECLSPEC_SELECTANY name \
//                = { l, w1, w2, { b1, b2,  b3,  b4,  b5,  b6,  b7,  b8 } }  
//#endif
//
//	UCM_DEFINE_GUID(IID_ElevatedFactoryServer, 0x804BD226, 0xAF47, 0x04D71, 0xB4, 0x92, 0x44, 0x3A, 0x57, 0x61, 0x0B, 0x08);

typedef interface IElevatedFactoryServer IElevatedFactoryServer;

typedef struct IElevatedFactoryServerVtbl {

	BEGIN_INTERFACE

		HRESULT(STDMETHODCALLTYPE* QueryInterface)(
			__RPC__in IElevatedFactoryServer* This,
			__RPC__in REFIID riid,
			_COM_Outptr_ void** ppvObject);

	ULONG(STDMETHODCALLTYPE* AddRef)(
		__RPC__in IElevatedFactoryServer* This);

	ULONG(STDMETHODCALLTYPE* Release)(
		__RPC__in IElevatedFactoryServer* This);

	HRESULT(STDMETHODCALLTYPE* ServerCreateElevatedObject)(
		__RPC__in IElevatedFactoryServer* This,
		__RPC__in REFCLSID rclsid,
		__RPC__in REFIID riid,
		_COM_Outptr_ void** ppvObject);

	//incomplete definition

	END_INTERFACE

} *PIElevatedFactoryServerVtbll;

interface IElevatedFactoryServer { CONST_VTBL struct IElevatedFactoryServerVtbl* lpVtbl; };