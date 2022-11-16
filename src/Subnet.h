/**
 * This code was tested against C++20
 *
 * @author Ludvik Jerabek
 * @package slanalyzer
 * @version 1.0.0
 * @license MIT
 */
#ifndef SLANALYZER_SUBNET_H
#define SLANALYZER_SUBNET_H

#include <arpa/inet.h>
#include <stdexcept>
#include "re2/re2.h"

namespace Proofpoint {
class Subnet {
public:
	class SubnetArgumentException : public std::invalid_argument {
		using std::invalid_argument::invalid_argument;
	};
	enum ByteOrder {
	  NETWORK,
	  HOST,
	};
public:
	static bool IsValidIp(const std::string& address);
	static bool IsValidCidr(const std::string& cidr, std::string& network, std::string& bits);
	static bool IsValidCidr(const std::string& cidr);
	static std::string GetAddress(in_addr_t address, ByteOrder order = HOST);
public:
	explicit Subnet(const std::string& cidr);
	explicit Subnet(const std::string& network, const std::string& netmask);
	explicit Subnet(const in_addr_t& network, const in_addr_t& netmask, ByteOrder order);
	inline bool InSubnet(in_addr_t address, Proofpoint::Subnet::ByteOrder order) const
	{
		if (order==ByteOrder::NETWORK) {
			address = ntohl(address);
		}
		return !((address ^ net) & mask);
	}
	inline bool InSubnet(const std::string& ip_address) const
	{
		in_addr address{0};
		if (inet_pton(AF_INET, ip_address.c_str(), &address)==0) return false;
		return !((ntohl(address.s_addr) ^ net) & mask);
	}
	[[nodiscard]] std::string GetNet() const;
	[[nodiscard]] std::string GetMask() const;
	[[nodiscard]] std::string GetMin() const;
	[[nodiscard]] std::string GetMax() const;
	[[nodiscard]] std::string GetBroadcast() const;
	[[nodiscard]] std::string GetWildcard() const;
	[[nodiscard]] in_addr_t GetNetAddress(ByteOrder order = HOST) const;
	[[nodiscard]] in_addr_t GetMaskAddress(ByteOrder order = HOST) const;
	[[nodiscard]] in_addr_t GetMinAddress(ByteOrder order = HOST) const;
	[[nodiscard]] in_addr_t GetMaxAddress(ByteOrder order = HOST) const;
	[[nodiscard]] in_addr_t GetBroadcastAddress(ByteOrder order = HOST) const;
	[[nodiscard]] in_addr_t GetWildcardAddress(ByteOrder order = HOST) const;
	[[nodiscard]] uint32_t GetAddressableHosts() const;
private:
	inline static RE2 ip_matcher = R"(^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$)";
	inline static RE2 cidr_matcher = R"(^((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))(?:\/)((?:3[0-2]|2[0-9]|1[0-9]|[0-9]))$)";
private:
	// Network Address (host order)
	in_addr_t net;
	// Subnet Mask (host order)
	in_addr_t mask;
	// Lowest Address (host order)
	in_addr_t min{};
	// Highest Address
	in_addr_t max{};
	// Broadcast
	in_addr_t bcast{};
	// Wildcard
	in_addr_t wmask{};
	// Maximum addressable
	uint32_t hosts{};
};
}
#endif //SLANALYZER_SUBNET_H
