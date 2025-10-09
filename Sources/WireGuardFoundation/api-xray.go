package main

/*
#include <stdint.h>
#include <stdlib.h>

typedef void (*libxray_sockcallback)(uintptr_t fd, void* ctx);
static inline void libxray_invokesockcallback(libxray_sockcallback cb, uintptr_t fd, void* ctx)
{
	cb(fd, ctx);
}

*/
import "C"
import (
	"syscall"
	"unsafe"

	"github.com/amnezia-vpn/amnezia-libxray/nodep"
	"github.com/amnezia-vpn/amnezia-libxray/xray"
	"github.com/amnezia-vpn/amnezia-xray-core/transport/internet"
)

// Read geo data and cut the codes we need.
// datDir means the dir which geo dat are in.
// dstDir means the dir which new geo dat are in.
// cutCodePath means geoCutCode json file path
//
// This function is used to reduce memory when init instance.
// You can cut the country codes which rules and nameservers contain.
//
//export LibXrayCutGeoData
func LibXrayCutGeoData(datDir, dstDir, cutCodePath *C.char) *C.char {
	err := xray.CutGeoData(C.GoString(datDir), C.GoString(dstDir), C.GoString(cutCodePath))
	return C.CString(nodep.WrapError(err))
}

// Read geo data and write all codes to text file.
// datDir means the dir which geo dat are in.
// name means the geo dat file name, like "geosite", "geoip"
// geoType must be the value of geoType
//
//export LibXrayLoadGeoData
func LibXrayLoadGeoData(datDir, name, geoType *C.char) *C.char {
	err := xray.LoadGeoData(C.GoString(datDir), C.GoString(name), C.GoString(geoType))
	return C.CString(nodep.WrapError(err))
}

// Ping Xray config and find the delay and country code of its outbound.
// datDir means the dir which geosite.dat and geoip.dat are in.
// configPath means the config.json file path.
// timeout means how long the http request will be cancelled if no response, in units of seconds.
// url means the website we use to test speed. "https://www.google.com" is a good choice for most cases.
// proxy means the local http/socks5 proxy, like "socks5://[::1]:1080".
//
//export LibXrayPing
func LibXrayPing(datDir, configPath *C.char, timeout int, url, proxy *C.char) *C.char {
	return C.CString(xray.Ping(C.GoString(datDir), C.GoString(configPath), timeout, C.GoString(url), C.GoString(proxy)))
}

// query system stats and outbound stats.
// server means The API server address, like "127.0.0.1:8080".
// dir means the dir which result json will be wrote to.
//
//export LibXrayQueryStats
func LibXrayQueryStats(server, dir *C.char) *C.char {
	err := xray.QueryStats(C.GoString(server), C.GoString(dir))
	return C.CString(nodep.WrapError(err))
}

// convert text to uuid
//
//export LibXrayCustomUUID
func LibXrayCustomUUID(text *C.char) *C.char {
	return C.CString(xray.CustomUUID(C.GoString(text)))
}

// Test Xray Config.
// datDir means the dir which geosite.dat and geoip.dat are in.
// configPath means the config.json file path.
//
//export LibXrayTestXray
func LibXrayTestXray(datDir, configPath *C.char) *C.char {
	err := xray.TestXray(C.GoString(datDir), C.GoString(configPath))
	return C.CString(nodep.WrapError(err))
}

// Run Xray instance.
// datDir means the dir which geosite.dat and geoip.dat are in.
// configPath means the config.json file path.
// maxMemory means the soft memory limit of golang, see SetMemoryLimit to find more information.
//
//export LibXrayRunXray
func LibXrayRunXray(datDir, configPath *C.char, maxMemory int64) *C.char {
	err := xray.RunXray(C.GoString(datDir), C.GoString(configPath), maxMemory)
	return C.CString(nodep.WrapError(err))
}

// Stop Xray instance.
//
//export LibXrayStopXray
func LibXrayStopXray() *C.char {
	err := xray.StopXray()
	return C.CString(nodep.WrapError(err))
}

// Xray's version
//
//export LibXrayXrayVersion
func LibXrayXrayVersion() *C.char {
	return C.CString(xray.XrayVersion())
}

//export LibXraySetSockCallback
func LibXraySetSockCallback(cb C.libxray_sockcallback, ctx unsafe.Pointer) *C.char {
	err := internet.RegisterDialerController(func(net, addr string, conn syscall.RawConn) error {
		conn.Control(func(fd uintptr) {
			C.libxray_invokesockcallback(cb, C.uintptr_t(fd), ctx)
		})
		return nil
	})

	if err != nil {
		return C.CString(err.Error())
	}
	return nil
}
