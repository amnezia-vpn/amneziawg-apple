// SPDX-License-Identifier: MIT
#include <assert.h>
#include "../Sources/WireGuardApp/UI/macOS/View/highlighter.c"

int main(void)
{
	const char *valid[] = {
		"srv://_wireguard._udp.vpn.example.com", "srv://_awg._udp.vpn.example.com.",
		"srv://_wg._UDP.example.com", "vpn.example.com:51820", "192.0.2.1:51820", "[2001:db8::1]:51820"
	};
	const char *invalid[] = {
		"srv://", "srv://vpn.example.com", "srv://_wg._tcp.example.com", "srv://_wg._udp.",
		"srv://_wg._udp.example.com:51820", "srv://_wg._udp.example.com/path",
		"srv://_wg._udp.example.com?port=1", "srv://_wg._udp..example.com", "srv://_wg._udp.example.com.."
	};
	for (size_t i = 0; i < sizeof(valid) / sizeof(valid[0]); ++i)
		assert(is_valid_endpoint((string_span_t){ valid[i], strlen(valid[i]) }));
	for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i)
		assert(!is_valid_endpoint((string_span_t){ invalid[i], strlen(invalid[i]) }));
	return 0;
}
